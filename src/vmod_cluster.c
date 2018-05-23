/*-
 * Copyright 2018 UPLEX - Nils Goroll Systemoptimierung
 * All rights reserved
 *
 * Author: Nils Goroll <nils.goroll@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <cache/cache.h>
#include <vcl.h>
#include <vrt_obj.h>

#include "vcc_cluster_if.h"

struct vmod_cluster_cluster_param {
	unsigned				magic;
#define VMOD_CLUSTER_CLUSTER_PARAM_MAGIC	0x3ba2a0d5
	VCL_BOOL				uncacheable_direct;
	VCL_BACKEND				cluster;
	VCL_BACKEND				real;
	int					nblack;
	int					spcblack;
	VCL_BACKEND				blacklist[];
};

struct vmod_cluster_cluster {
	unsigned				magic;
#define VMOD_CLUSTER_CLUSTER_MAGIC		0x4e25630b
	VCL_BACKEND				dir;
	const struct vmod_cluster_cluster_param *param;
};

static VCL_BACKEND vmod_cluster_resolve(VRT_CTX, VCL_BACKEND);
static VCL_BOOL vmod_cluster_healthy(VRT_CTX, VCL_BACKEND, VCL_TIME *);

static const struct vdi_methods vmod_cluster_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"cluster",
	.resolve =	vmod_cluster_resolve,
	.healthy =	vmod_cluster_healthy,
}};

#define param_sz(p, spc) (sizeof(*(p)) + (spc) * sizeof(*(p)->blacklist))

/*
 * return the appropriate parameters for the context, writeable
 * for nblack == -1: do not create, return NULL if don't exist
 */
static struct vmod_cluster_cluster_param *
cluster_task_param_l(VRT_CTX, struct vmod_cluster_cluster *vc, int nblack)
{
	int nspc;
	const int nspc_initial = 2;
	struct vmod_priv *task;
	struct vmod_cluster_cluster_param *p = NULL;
	const struct vmod_cluster_cluster_param *o = NULL;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	assert(ctx->method == 0 ||
	    ctx->method & (VCL_MET_INIT | VCL_MET_BACKEND_FETCH));

	task = VRT_priv_task(ctx, vc);
	if (task == NULL) {
		VRT_fail(ctx, "no priv_task");
		return (NULL);
	}

	if (task->priv) {
		CAST_OBJ_NOTNULL(p, task->priv,
		    VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
		if (nblack <= p->spcblack)
			return (p);
		nspc = RUP2(nblack, 2);
		o = p;
	} else if (nblack == -1) {
		return (NULL);
	} else if (ctx->method & VCL_MET_INIT) {
		nspc = nspc_initial;
	} else if (ctx->method & VCL_MET_BACKEND_FETCH) {
		o = vc->param;
		if (nblack <= o->spcblack)
			nspc = o->spcblack;
		else
			nspc = RUP2(nblack, 2);
	} else {
		INCOMPL();
	}

	if (ctx->method & VCL_MET_INIT) {
		p = realloc(p, param_sz(p, nspc));
		if (o == NULL)
			INIT_OBJ(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
		vc->param = p;
	} else {
		AN(o);
		p = WS_Alloc(ctx->ws, param_sz(p, nspc));
		if (p == NULL)
			return (NULL);
		memcpy(p, o, param_sz(o, o->nblack));
	}
	p->spcblack = nspc;
	task->priv = p;
	return (p);
}

static const struct vmod_cluster_cluster_param *
cluster_task_param_r(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	const struct vmod_cluster_cluster_param *o;

	if (ctx->method != 0 &&
	    (ctx->method & (VCL_MET_INIT | VCL_MET_BACKEND_FETCH)) == 0)
		return (vc->param);

	o = cluster_task_param_l(ctx, vc, -1);
	if (o != NULL)
		return (o);
	o = vc->param;
	AN(o);
	return (o);
}

static void
cluster_blacklist_add(struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	assert(p->nblack < p->spcblack);
	p->blacklist[p->nblack++] = b;
}

static void
cluster_blacklist_del(struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	for (i = 0; i < p->nblack; i++)
		if (p->blacklist[i] == b) {
			p->nblack--;
			if (i < p->nblack)
				memmove(&p->blacklist[i],
				    &p->blacklist[i+1],
				    (p->nblack - i) * sizeof(*p->blacklist));
			return;
		}
}

static int
cluster_blacklisted(const struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	for (i = 0; i < p->nblack; i++)
		if (p->blacklist[i] == b)
			return (1);
	return (0);
}

VCL_VOID
vmod_cluster__init(VRT_CTX,
    struct vmod_cluster_cluster **vcp, const char *vcl_name,
    struct vmod_cluster__init_arg *args)
{
	struct vmod_cluster_cluster *vc;
	struct vmod_cluster_cluster_param *p;

	AN(vcp);
	AZ(*vcp);
	ALLOC_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);
	if (vc == NULL) {
		VRT_fail(ctx, "vc alloc failed");
		return;
	}
	AN(vc);
	p = cluster_task_param_l(ctx, vc, 0);
	if (p == NULL) {
		FREE_OBJ(vc);
		return;
	}
	AN(vc->param);
	*vcp = vc;
	p->uncacheable_direct = args->uncacheable_direct;
	p->cluster = args->cluster;
	if (args->valid_real)
		p->real = args->real;
	if (args->valid_deny)
		cluster_blacklist_add(p, args->deny);
	vc->dir = VRT_AddDirector(ctx, vmod_cluster_methods, vc,
	    "%s", vcl_name);
}

VCL_VOID
vmod_cluster__fini(struct vmod_cluster_cluster **vcp)
{
	struct vmod_cluster_cluster *vc = *vcp;

	*vcp = NULL;
	if (vc == NULL)
		return;
	CHECK_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);
	VRT_DelDirector(&vc->dir);
	free(TRUST_ME(vc->param));
	FREE_OBJ(vc);
}

#define cluster_methods (VCL_MET_INIT | VCL_MET_BACKEND_FETCH)
#define cluster_check(ctx, name) do {					\
		if ((ctx->method & cluster_methods) == 0) {		\
			VRT_fail(ctx,					\
			    "cluster." #name " can not be called here"); \
			return;						\
		}							\
	} while(0)

VCL_VOID
vmod_cluster_deny(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, deny);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (cluster_blacklisted(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->nblack + 1);
	cluster_blacklist_add(pl, b);
}

VCL_VOID
vmod_cluster_allow(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, allow);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (! cluster_blacklisted(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->nblack + 1);
	cluster_blacklist_del(pl, b);
}

VCL_VOID
vmod_cluster_set_real(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, set_real);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (pr->real == b)
		return;

	pl = cluster_task_param_l(ctx, vc, 0);
	pl->real = b;
}

VCL_VOID
vmod_cluster_set_uncacheable_direct(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BOOL direct)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, set_uncacheable_direct);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (pr->uncacheable_direct == direct)
		return;

	pl = cluster_task_param_l(ctx, vc, 0);
	pl->uncacheable_direct = direct;
}

static VCL_BACKEND
cluster_resolve(VRT_CTX,
    const struct vmod_cluster_cluster_param *pr)
{
	VCL_BACKEND r;

	if (pr->uncacheable_direct && ctx->bo &&
	    (ctx->bo->do_pass || ctx->bo->uncacheable))
		return (pr->real);

	AN(pr->cluster);
	r = VRT_DirectorResolve(ctx, pr->cluster);

	if (cluster_blacklisted(pr, r))
		r = pr->real;

	return (r);
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
vmod_cluster_resolve(VRT_CTX, VCL_BACKEND dir)
{
	return (cluster_resolve(ctx,
	    cluster_task_param_r(ctx, dir->priv)));
}

#define be_task_param_l(pl, pr, ctx, vc, arg)	do {			\
		if ((pl) != NULL) {					\
			(void)0;					\
		} else if ((arg)->resolve == vmod_enum_LAZY) {		\
			(pr) = (pl) = cluster_task_param_l(		\
			    (ctx), (vc), (pr)->nblack + 1);		\
		} else {						\
			(pr) = (pl) = alloca(param_sz(pl, (pr)->nblack + 1)); \
			INIT_OBJ((pl), VMOD_CLUSTER_CLUSTER_PARAM_MAGIC); \
		} \
	} while (0)

VCL_BACKEND
vmod_cluster_backend(VRT_CTX,
    struct vmod_cluster_cluster *vc,
    struct vmod_cluster_backend_arg *arg)
{
	int modify = arg->valid_deny || arg->valid_real ||
	    arg->valid_uncacheable_direct;
	const struct vmod_cluster_cluster_param *pr = NULL;
	struct vmod_cluster_cluster_param *pl = NULL;

	if (! modify) {
		if (arg->resolve == vmod_enum_LAZY)
			return (vc->dir);
		return (vmod_cluster_resolve(ctx, vc->dir));
	}

	AN(modify);

	if (arg->resolve == vmod_enum_LAZY &&
	    (ctx->method & cluster_methods) == 0) {
		VRT_fail(ctx, "cluster.backend(resolve=LAZY)"
		    " can not be called here");
		return NULL;
	}
	pr = cluster_task_param_r(ctx, vc);
	if (arg->valid_deny && arg->deny != NULL &&
	    ! cluster_blacklisted(pr, arg->deny)) {
		be_task_param_l(pl, pr, ctx, vc, arg);
		cluster_blacklist_add(pl, arg->deny);
	}
	if (arg->valid_real &&
	    pr->real != arg->real) {
		be_task_param_l(pl, pr, ctx, vc, arg);
		pl->real = arg->real;
	}
	if (arg->valid_uncacheable_direct &&
	    pr->uncacheable_direct != arg->valid_uncacheable_direct) {
		be_task_param_l(pl, pr, ctx, vc, arg);
		pl->uncacheable_direct = arg->valid_uncacheable_direct;
	}
	if (arg->resolve == vmod_enum_LAZY)
		return (vc->dir);

	return (cluster_resolve(ctx, pr));
}

static VCL_BOOL
vmod_cluster_healthy(VRT_CTX, VCL_BACKEND be, VCL_TIME *c)
{
	be = vmod_cluster_resolve(ctx, be);
	return VRT_Healthy(ctx, be, c);
}
