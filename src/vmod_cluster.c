/*-
 * Copyright 2018, 2019 UPLEX - Nils Goroll Systemoptimierung
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
#include "vmod_compat.h"

/* ------------------------------------------------------------
 */

enum resolve_e {
	_RESOLVE_E_INVALID = 0,
#define VMODENUM(x) x,
#include "tbl_resolve.h"
	_RESOLVE_E_MAX
};

static const char * const resolve_s[_RESOLVE_E_MAX] = {
#define VMODENUM(x) [x] = #x,
#include "tbl_resolve.h"
	[_RESOLVE_E_INVALID] = "*invalid*",
};

static enum resolve_e
parse_resolve_e(VCL_ENUM e)
{
#define VMODENUM(n) if (e == VENUM(n)) return(n);
#include "tbl_resolve.h"
       WRONG("illegal resolve enum");
}

struct vmod_cluster_cluster_param {
	unsigned				magic;
#define VMOD_CLUSTER_CLUSTER_PARAM_MAGIC	0x3ba2a0d5
	VCL_BOOL				uncacheable_direct;
	VCL_BOOL				direct;
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
 * return a writable task param struct for the current context
 * with sufficient space for nblack blacklist entries
 *
 * nblack:
 * -1: do not create, return NULL if don't exist
 *
 * spc:
 * - NULL:
 *   - in INIT, create on heap
 *   - else create on workspace
 * - otherwise return new object here. Size must be
 *   param_sz(..., nblack)
 */
static struct vmod_cluster_cluster_param *
cluster_task_param_l(VRT_CTX, struct vmod_cluster_cluster *vc,
    int nblack, void *spc)
{
	struct vmod_priv *task = NULL;
	struct vmod_cluster_cluster_param *p = NULL;
	const struct vmod_cluster_cluster_param *o;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	if (ctx->method != 0 &&
	    (ctx->method & (VCL_MET_INIT | VCL_MET_BACKEND_FETCH)) == 0) {
		/* .backend called with resolve = DEEP anywhere */
		AN(spc);
	} else {
		task = VRT_priv_task(ctx, vc);
		if (task == NULL) {
			VRT_fail(ctx, "no priv_task");
			return (NULL);
		}
	}

	/*
	 * p = writable params
	 * o = previous params we inherit
	 */
	o = vc->param;
	if (task && task->priv) {
		CAST_OBJ_NOTNULL(p, task->priv,
		    VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
		o = p;
	} else if (ctx->method & VCL_MET_INIT) {
		CHECK_OBJ_ORNULL(o,
		    VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	} else {
		CHECK_OBJ_NOTNULL(o,
		    VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	}

	if (nblack == -1)
		return (p);

	if (o && nblack < o->nblack)
		nblack = o->nblack;
	/*
	 * make the (new) allocation and copy or return if not required
	 * if space was provided, we always return it
	 */
	if (spc) {
		p = spc;
		if (o) {
			assert (nblack >= o->nblack);
			memcpy(p, o, param_sz(o, o->nblack));
		}
	} else if (p && nblack <= p->spcblack) {
		return (p);
	} else {
		nblack = RUP2(nblack, 2);
		if (ctx->method & VCL_MET_INIT) {
			p = realloc(p, param_sz(p, nblack));
			vc->param = p;
		} else {
			AN(o);
			p = WS_Alloc(ctx->ws, param_sz(p, nblack));
			if (p == NULL)
				return (NULL);
			memcpy(p, o, param_sz(o, o->nblack));
		}
		AN(task);
		task->priv = p;
	}

	if (o == NULL)
		INIT_OBJ(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);

	p->spcblack = nblack;

	return (p);
}

static const struct vmod_cluster_cluster_param *
cluster_task_param_r(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	const struct vmod_cluster_cluster_param *o;

	if (ctx->method != 0 &&
	    (ctx->method & (VCL_MET_INIT | VCL_MET_BACKEND_FETCH)) == 0)
		return (vc->param);

	o = cluster_task_param_l(ctx, vc, -1, NULL);
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
	VCL_BACKEND bl;
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	for (i = 0; i < p->nblack; i++) {
		bl = p->blacklist[i];
		CHECK_OBJ_NOTNULL(bl, DIRECTOR_MAGIC);
		if (bl == b)
			return (1);
	}
	return (0);
}

VCL_VOID
vmod_cluster__init(VRT_CTX,
    struct vmod_cluster_cluster **vcp, const char *vcl_name,
    struct VARGS(cluster__init) *args)
{
	struct vmod_cluster_cluster *vc;
	struct vmod_cluster_cluster_param *p;
	const int nblack_initial = 2;

	AN(vcp);
	AZ(*vcp);
	ALLOC_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);
	if (vc == NULL) {
		VRT_fail(ctx, "vc alloc failed");
		return;
	}
	AN(vc);
	p = cluster_task_param_l(ctx, vc, nblack_initial, NULL);
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
#define cluster_check(ctx, name, ret) do {				\
		if ((ctx->method & cluster_methods) == 0) {		\
			VRT_fail(ctx,					\
			    "cluster." #name " can not be called here"); \
			return ret;					\
		}							\
	} while(0)

VCL_VOID
vmod_cluster_deny(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, deny, );

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (cluster_blacklisted(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->nblack + 1, NULL);
	cluster_blacklist_add(pl, b);
}

VCL_VOID
vmod_cluster_allow(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	cluster_check(ctx, allow, );

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (! cluster_blacklisted(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->nblack, NULL);
	cluster_blacklist_del(pl, b);
}

VCL_BOOL
vmod_cluster_is_denied(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;

	cluster_check(ctx, is_denied, 0);
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);

	return (cluster_blacklisted(pr, b));
}

VCL_BACKEND
vmod_cluster_get_cluster(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	const struct vmod_cluster_cluster_param *pr;

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);

	return (pr->cluster);
}

/* set a simple parameter attribute */
#define CLUSTER_L(ctx, vc, att, val)					\
	const struct vmod_cluster_cluster_param *pr;			\
	struct vmod_cluster_cluster_param *pl;				\
									\
	cluster_check(ctx, set_ ## att, );				\
									\
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);		\
									\
	pr = cluster_task_param_r(ctx, vc);				\
	if (pr->att == (val))						\
		return;						\
									\
	pl = cluster_task_param_l(ctx, vc, 0, NULL);			\
	pl->att = (val)

/* get a simple parameter attribute */
#define CLUSTER_R(ctx, vc, att, ret)					\
	const struct vmod_cluster_cluster_param *pr;			\
									\
	cluster_check(ctx, get_ ## att, ret);				\
									\
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);		\
									\
	pr = cluster_task_param_r(ctx, vc);				\
									\
	return (pr->att)

VCL_VOID
vmod_cluster_set_real(VRT_CTX, struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	CLUSTER_L(ctx, vc, real, b);
}

VCL_BACKEND
vmod_cluster_get_real(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	CLUSTER_R(ctx, vc, real, NULL);
}

VCL_VOID
vmod_cluster_set_uncacheable_direct(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BOOL bool)
{
	CLUSTER_L(ctx, vc, uncacheable_direct, bool);
}

VCL_BOOL
vmod_cluster_get_uncacheable_direct(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	CLUSTER_R(ctx, vc, uncacheable_direct, 0);
}

VCL_VOID
vmod_cluster_set_direct(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BOOL bool)
{
	CLUSTER_L(ctx, vc, direct, bool);
}

VCL_BOOL
vmod_cluster_get_direct(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	CLUSTER_R(ctx, vc, direct, 0);
}

static inline VCL_BACKEND
real_resolve(VRT_CTX, VCL_BACKEND r, enum resolve_e resolve)
{
	switch (resolve) {
	case SHALLOW:
	case CLD:
		return (r);
	case DEEP:
		return (VRT_DirectorResolve(ctx, r));
	default:
		WRONG("illegal resolve argument");
	}
}

static VCL_BACKEND
decide(VRT_CTX,
    const struct vmod_cluster_cluster_param *pr, enum resolve_e resolve)
{
	VCL_BACKEND r;

	if (pr->direct ||
	    (pr->uncacheable_direct && ctx->bo &&
	    (ctx->bo->do_pass || ctx->bo->uncacheable)))
		return (real_resolve(ctx, pr->real, resolve));

	AN(pr->cluster);
	r = VRT_DirectorResolve(ctx, pr->cluster);

	if (r == NULL)
		return (NULL);

	if (cluster_blacklisted(pr, r))
		return (real_resolve(ctx, pr->real, resolve));

	switch (resolve) {
	case SHALLOW:
		return (pr->cluster);
	case CLD:
	case DEEP:
		return (r);
	default:
		WRONG("illegal resolve argument");
	}
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
vmod_cluster_resolve(VRT_CTX, VCL_BACKEND dir)
{
	return (decide(ctx,
	    cluster_task_param_r(ctx, dir->priv), DEEP));
}

static VCL_BACKEND
cluster_choose(VRT_CTX,
    struct vmod_cluster_cluster *vc,
    enum resolve_e resolve,
    struct VARGS(cluster_backend) *arg)
{
	int modify = arg->valid_deny || arg->valid_real ||
	    arg->valid_uncacheable_direct;
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl = NULL;
	void *spc = NULL;
	int nblack;

	if (! modify) {
		if (resolve == LAZY)
			return (vc->dir);
		pr = cluster_task_param_r(ctx, vc);
		return (decide(ctx, pr, resolve));
	}

	AN(modify);

	if (resolve == LAZY &&
	    (ctx->method & cluster_methods) == 0) {
		VRT_fail(ctx, "cluster.backend(resolve=%s)"
		    " can not be called here", resolve_s[resolve]);
		return NULL;
	}

	pr = cluster_task_param_r(ctx, vc);
	CHECK_OBJ_NOTNULL(pr, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);

	char pstk[param_sz(pr, pr->nblack + 1)];
	nblack = pr->nblack;

	if ((ctx->method & cluster_methods) == 0)
		spc = pstk;

	if (arg->valid_deny && arg->deny != NULL &&
	    ! cluster_blacklisted(pr, arg->deny)) {
		if (pl == NULL) {
			nblack = pr->nblack + 1;
			pr = pl = cluster_task_param_l(ctx, vc,
			    nblack, spc);
		}
		cluster_blacklist_add(pl, arg->deny);
	}
	if (arg->valid_real && pr->real != arg->real) {
		if (pl == NULL)
			pr = pl = cluster_task_param_l(ctx, vc, nblack, spc);
		pl->real = arg->real;
	}
	if (arg->valid_uncacheable_direct &&
	    pr->uncacheable_direct != arg->uncacheable_direct) {
		if (pl == NULL)
			pr = pl = cluster_task_param_l(ctx, vc, nblack, spc);
		pl->uncacheable_direct = arg->uncacheable_direct;
	}
	if (resolve == LAZY)
		return (vc->dir);

	return (decide(ctx, pr, resolve));
}

VCL_BACKEND
vmod_cluster_backend(VRT_CTX,
    struct vmod_cluster_cluster *vc,
    struct VARGS(cluster_backend) *arg)
{
	return (cluster_choose(ctx, vc, parse_resolve_e(arg->resolve), arg));
}

/*
 * layered directors may not be prepared to resolve outside a VCL task, so when
 * called from the cli (no method, no vcl), just return healthy if either the
 * real or the cluster backend is healthy
 */

static VCL_BOOL
vmod_cluster_healthy(VRT_CTX, VCL_BACKEND be, VCL_TIME *c)
{
	const struct vmod_cluster_cluster *vc;
	const struct vmod_cluster_cluster_param *p;
	VCL_BOOL r;

	if (ctx->vcl && ctx->method) {
		be = vmod_cluster_resolve(ctx, be);
		return (VRT_Healthy(ctx, be, c));
	}

	CAST_OBJ_NOTNULL(vc, be->priv, VMOD_CLUSTER_CLUSTER_MAGIC);
	p = vc->param;
	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	r = VRT_Healthy(ctx, p->cluster, c);
	if (r)
		return (r);
	return (VRT_Healthy(ctx, p->real, c));
}
