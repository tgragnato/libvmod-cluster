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

enum decision_e {
	D_NULL = 0,
	D_CLUSTER,
	D_REAL
};

struct vmod_cluster_cluster_param {
	unsigned				magic;
#define VMOD_CLUSTER_CLUSTER_PARAM_MAGIC	0x3ba2a0d5

#define BOOL_FIELDS				\
	BOOLF(uncacheable_direct)		\
	BOOLF(direct)
#define BACKEND_FIELDS				\
	BACKF(cluster)				\
	BACKF(real)
#define BOOLF(x) VCL_BOOL x;
	BOOL_FIELDS
#undef BOOLF
#define BACKF(x) VCL_BACKEND x;
	BACKEND_FIELDS
#undef BACKF

	int					ndeny;
	int					spcdeny;
	VCL_BACKEND				denylist[];
};

struct vmod_cluster_cluster {
	unsigned				magic;
#define VMOD_CLUSTER_CLUSTER_MAGIC		0x4e25630b
	VCL_BACKEND				dir;
	struct vmod_cluster_cluster_param	*param;
};

static VCL_BACKEND vmod_cluster_resolve(VRT_CTX, VCL_BACKEND);
static VCL_BOOL vmod_cluster_healthy(VRT_CTX, VCL_BACKEND, VCL_TIME *);
static void vmod_cluster_release(VCL_BACKEND);

static void v_matchproto_(vdi_destroy_f)
vmod_cluster_destroy(VCL_BACKEND dir)
{
	struct vmod_cluster_cluster *vc;
	struct vmod_cluster_cluster_param *p;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vc, dir->priv, VMOD_CLUSTER_CLUSTER_MAGIC);
	TAKE_OBJ_NOTNULL(p, &vc->param, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);

	FREE_OBJ(p);
}

static const struct vdi_methods vmod_cluster_methods[1] = {{
	.magic =	VDI_METHODS_MAGIC,
	.type =		"cluster",
	.resolve =	vmod_cluster_resolve,
	.healthy =	vmod_cluster_healthy,
	.release =	vmod_cluster_release,
	.destroy =	vmod_cluster_destroy
}};

#define param_sz(p, spc) (sizeof(*(p)) + (spc) * sizeof(*(p)->denylist))

static void
cluster_task_param_init(struct vmod_cluster_cluster_param *p, size_t sz)
{

	AN(p);
	assert(sz > sizeof *p);

	INIT_OBJ(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	p->spcdeny = (sz - sizeof *p) / sizeof *p->denylist;
}

static void
cluster_task_param_deref(struct vmod_cluster_cluster_param *p)
{
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);

#define BACKF(x) VRT_Assign_Backend(&p->x, NULL);
	BACKEND_FIELDS
#undef BACKF

	for (i = 0; i < p->ndeny; i++)
		VRT_Assign_Backend(&p->denylist[i], NULL);
}

static void
cluster_task_param_cp(struct vmod_cluster_cluster_param *dst,
    const struct vmod_cluster_cluster_param *src, size_t sz)
{
	int i;

	AN(dst);
	CHECK_OBJ_NOTNULL(src, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	cluster_task_param_init(dst, sz);

#define BOOLF(x) dst->x = src->x;
	BOOL_FIELDS
#undef BOOLF
#define BACKF(x) VRT_Assign_Backend(&dst->x, src->x);
	BACKEND_FIELDS
#undef BACKF

	assert(dst->spcdeny >= src->ndeny);
	for (i = 0; i < src->ndeny; i++)
		VRT_Assign_Backend(&dst->denylist[i], src->denylist[i]);
	dst->ndeny = src->ndeny;
}

static void
priv_fini(VRT_CTX, void *pp)
{
	struct vmod_cluster_cluster_param *p;

	CAST_OBJ_NOTNULL(p, pp, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	cluster_task_param_deref(p);
	memset(p, 0, sizeof *p);
}

static const struct vmod_priv_methods priv_methods[1] = {{
	.magic = VMOD_PRIV_METHODS_MAGIC,
	.type = "vmod_cluster",
	.fini = priv_fini
}};

static void v_matchproto_(vdi_release_f)
vmod_cluster_release(VCL_BACKEND dir)
{
	struct vmod_cluster_cluster *vc;
	struct vmod_cluster_cluster_param *p;

	CHECK_OBJ_NOTNULL(dir, DIRECTOR_MAGIC);
	CAST_OBJ_NOTNULL(vc, dir->priv, VMOD_CLUSTER_CLUSTER_MAGIC);
	p = vc->param;
	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);

	cluster_task_param_deref(p);
}

/*
 * return a writable task param struct for the current context
 * with sufficient space for ndeny denylist entries
 *
 * ndeny:
 * -1: do not create, return NULL if don't exist
 *
 * spc:
 * - NULL:
 *   - in INIT, create on heap
 *   - else create on workspace
 * - otherwise return new object here. Size must be
 *   param_sz(..., ndeny)
 */
static struct vmod_cluster_cluster_param *
cluster_task_param_l(VRT_CTX, struct vmod_cluster_cluster *vc,
    int ndeny, void *spc)
{
	struct vmod_priv *task = NULL;
	struct vmod_cluster_cluster_param *p = NULL;
	const struct vmod_cluster_cluster_param *o;
	size_t sz;

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
		p = (void *)o;
	} else {
		CHECK_OBJ_NOTNULL(o,
		    VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	}

	if (ndeny == -1)
		return (p);

	if (spc == NULL && o != NULL && ndeny < o->ndeny)
		ndeny = o->ndeny;
	/*
	 * make the (new) allocation and copy or return if not required
	 * if space was provided, we always return it
	 */
	if (spc) {
		p = spc;
		sz = param_sz(o, ndeny);
		if (o)
			cluster_task_param_cp(p, o, sz);
		else
			cluster_task_param_init(p, sz);
	} else if (p && ndeny <= p->spcdeny) {
		return (p);
	} else {
		ndeny = RUP2(ndeny, 2);
		AN(task);
		if (ctx->method & VCL_MET_INIT) {
			// one reference before/after, no need for ...param_cp
			sz = param_sz(o, ndeny);
			p = realloc(p, sz);
			AN(p);
			if (o)
				p->spcdeny = ndeny;
			else
				cluster_task_param_init(p, sz);
			vc->param = p;
		} else {
			AN(o);
			sz = param_sz(p, ndeny);
			p = WS_Alloc(ctx->ws, sz);
			if (p == NULL)
				return (NULL);
			cluster_task_param_cp(p, o, sz);
			task->methods = priv_methods;
			if (task->priv != NULL)
				cluster_task_param_deref(task->priv);
		}
		task->priv = p;
	}

	AN(p);

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
cluster_deny(VRT_CTX, struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	if (b == NULL) {
		VRT_fail(ctx, "Can not deny the NULL backend");
		return;
	}
	assert(p->ndeny < p->spcdeny);
	VRT_Assign_Backend(&p->denylist[p->ndeny++], b);
}

static void
cluster_allow(VRT_CTX, struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	if (b == NULL) {
		VRT_fail(ctx, "Can not allow the NULL backend");
		return;
	}
	for (i = 0; i < p->ndeny; i++)
		if (p->denylist[i] == b) {
			VRT_Assign_Backend(&p->denylist[i], NULL);
			p->ndeny--;
			if (i < p->ndeny)
				memmove(&p->denylist[i],
				    &p->denylist[i+1],
				    (p->ndeny - i) * sizeof(*p->denylist));
			return;
		}
}

static int
cluster_denied(const struct vmod_cluster_cluster_param *p,
    VCL_BACKEND b)
{
	VCL_BACKEND bl;
	int i;

	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	for (i = 0; i < p->ndeny; i++) {
		bl = p->denylist[i];
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
	const int ndeny_initial = 2;

	AN(vcp);
	AZ(*vcp);
	ALLOC_OBJ(vc, VMOD_CLUSTER_CLUSTER_MAGIC);
	if (vc == NULL) {
		VRT_fail(ctx, "vc alloc failed");
		return;
	}
	AN(vc);
	p = cluster_task_param_l(ctx, vc, ndeny_initial, NULL);
	if (p == NULL) {
		FREE_OBJ(vc);
		return;
	}
	AN(vc->param);
	*vcp = vc;
	p->uncacheable_direct = args->uncacheable_direct;
	VRT_Assign_Backend(&p->cluster, args->cluster);
	if (args->valid_real)
		VRT_Assign_Backend(&p->real, args->real);
	if (args->valid_deny)
		cluster_deny(ctx, p, args->deny);
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
	FREE_OBJ(vc);
}

#define cluster_methods (VCL_MET_INIT | VCL_MET_BACKEND_FETCH)

VCL_VOID
vmod_cluster_deny(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	AN(ctx->method & cluster_methods);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (cluster_denied(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->ndeny + 1, NULL);
	cluster_deny(ctx, pl, b);
}

VCL_VOID
vmod_cluster_allow(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;
	struct vmod_cluster_cluster_param *pl;

	AN(ctx->method & cluster_methods);

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);
	if (! cluster_denied(pr, b))
		return;

	pl = cluster_task_param_l(ctx, vc, pr->ndeny, NULL);
	cluster_allow(ctx, pl, b);
}

VCL_BOOL
vmod_cluster_is_denied(VRT_CTX,
    struct vmod_cluster_cluster *vc, VCL_BACKEND b)
{
	const struct vmod_cluster_cluster_param *pr;

	AN(ctx->method & cluster_methods);
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);

	return (cluster_denied(pr, b));
}

VCL_BACKEND
vmod_cluster_get_cluster(VRT_CTX, struct vmod_cluster_cluster *vc)
{
	const struct vmod_cluster_cluster_param *pr;

	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);

	pr = cluster_task_param_r(ctx, vc);

	return (pr->cluster);
}

#define SET_real(dst, src)			\
	VRT_Assign_Backend(&(dst), src)
#define SET_direct(dst, src) (dst) = (src)
#define SET_uncacheable_direct(dst, src) (dst) = (src)

/* set a simple parameter attribute */
#define CLUSTER_L(ctx, vc, att, val)					\
	const struct vmod_cluster_cluster_param *pr;			\
	struct vmod_cluster_cluster_param *pl;				\
									\
	AN(ctx->method & cluster_methods);				\
									\
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);		\
									\
	pr = cluster_task_param_r(ctx, vc);				\
	if (pr->att == (val))						\
		return;						\
									\
	pl = cluster_task_param_l(ctx, vc, 0, NULL);			\
	if (pl == NULL)							\
		return;							\
	SET_ ## att(pl->att, val)

/* get a simple parameter attribute */
#define CLUSTER_R(ctx, vc, att, ret)					\
	const struct vmod_cluster_cluster_param *pr;			\
									\
	AN(ctx->method & cluster_methods);				\
									\
	CHECK_OBJ_NOTNULL(vc, VMOD_CLUSTER_CLUSTER_MAGIC);		\
									\
	pr = cluster_task_param_r(ctx, vc);				\
	AN(pr);								\
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

static inline VCL_BACKEND
decide(VRT_CTX, const struct vmod_cluster_cluster_param *pr,
    enum resolve_e resolve, enum decision_e *decision)
{
	VCL_BACKEND r;

	if (pr->direct ||
	    (pr->uncacheable_direct && ctx->bo &&
	    (ctx->bo->uncacheable ||  ctx->bo->is_hitmiss ||
             ctx->bo->is_hitpass)))
		goto real;

	AN(pr->cluster);
	r = VRT_DirectorResolve(ctx, pr->cluster);

	if (r == NULL) {
		if (decision != NULL)
			*decision = D_NULL;
		return (NULL);
	}

	if (cluster_denied(pr, r))
		goto real;

	if (decision != NULL)
		*decision = D_CLUSTER;

	switch (resolve) {
	case SHALLOW:
		return (pr->cluster);
	case CLD:
	case DEEP:
		return (r);
	default:
		WRONG("illegal resolve argument");
	}
  real:
	if (decision != NULL)
		*decision = D_REAL;
	return (real_resolve(ctx, pr->real, resolve));
}

static VCL_BACKEND v_matchproto_(vdi_resolve_f)
vmod_cluster_resolve(VRT_CTX, VCL_BACKEND dir)
{
	return (decide(ctx,
	cluster_task_param_r(ctx, dir->priv), DEEP, NULL));
}

static const struct vmod_cluster_cluster_param *
cluster_update_by_args(VRT_CTX, struct vmod_cluster_cluster *vc,
    const struct vmod_cluster_cluster_param *pr,
    const struct VARGS(cluster_cluster_selected) *arg,
    void *spc)
{
	struct vmod_cluster_cluster_param *pl = NULL;
	int ndeny;

	CHECK_OBJ_NOTNULL(pr, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	ndeny = pr->ndeny;

	if (arg->valid_deny && arg->deny != NULL &&
	    ! cluster_denied(pr, arg->deny)) {
		pr = pl = cluster_task_param_l(ctx, vc, ++ndeny, spc);
		if (pl == NULL)
			return (NULL);
		cluster_deny(ctx, pl, arg->deny);
	}
	AN(pr);
	if (arg->valid_real && pr->real != arg->real) {
		if (pl == NULL)
			pr = pl = cluster_task_param_l(ctx, vc, ndeny, spc);
		if (pl == NULL)
			return (NULL);
		VRT_Assign_Backend(&pl->real, arg->real);
	}
	AN(pr);
	if (arg->valid_uncacheable_direct &&
	    pr->uncacheable_direct != arg->uncacheable_direct) {
		if (pl == NULL)
			pr = pl = cluster_task_param_l(ctx, vc, ndeny, spc);
		if (pl == NULL)
			return (NULL);
		pl->uncacheable_direct = arg->uncacheable_direct;
	}
	return (pr);
}

static VCL_BACKEND
cluster_choose(VRT_CTX,
    struct vmod_cluster_cluster *vc,
    enum resolve_e resolve, enum decision_e *decision,
    const struct VARGS(cluster_cluster_selected) *arg)
{
	int modify = arg->valid_deny || arg->valid_real ||
	    arg->valid_uncacheable_direct;
	const struct vmod_cluster_cluster_param *pr;
	void *spc = NULL;
	VCL_BACKEND r;

	if (decision != NULL)
		*decision = D_NULL;

	if (! modify) {
		if (resolve == LAZY)
			return (vc->dir);
		pr = cluster_task_param_r(ctx, vc);
		return (decide(ctx, pr, resolve, decision));
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

	char pstk[param_sz(pr, pr->ndeny + 1)];

	if ((ctx->method & cluster_methods) == 0)
		spc = pstk;

	pr = cluster_update_by_args(ctx, vc, pr, arg, spc);
	if (pr == NULL)
		return (NULL);

	if (resolve == LAZY)
		return (vc->dir);

	r = decide(ctx, pr, resolve, decision);

	// XXX cast
	if (spc)
		cluster_task_param_deref((void *)pr);

	return (r);
}

#define arg2csarg(arg) {{						\
	.valid_deny = arg->valid_deny,					\
	.valid_real = arg->valid_real,					\
	.valid_uncacheable_direct = arg->valid_uncacheable_direct,	\
	.valid_direct = arg->valid_direct,				\
	.deny = arg->deny,						\
	.real = arg->real,						\
	.uncacheable_direct = arg->uncacheable_direct,			\
	.direct = arg->direct						\
}}


VCL_BACKEND
vmod_cluster_backend(VRT_CTX,
    struct vmod_cluster_cluster *vc,
    struct VARGS(cluster_backend) *arg)
{
	enum resolve_e res = parse_resolve_e(arg->resolve);
	struct VARGS(cluster_cluster_selected) csarg[1] = arg2csarg(arg);

	return (cluster_choose(ctx, vc, res, NULL, csarg));
}

static enum decision_e
cluster_selected(VRT_CTX, const char *func,
    struct VPFX(cluster_cluster) *vc,
    struct VARGS(cluster_cluster_selected) *arg)
{
	enum decision_e decision;
	VCL_BACKEND b;

	if (ctx->method != VCL_MET_BACKEND_FETCH) {
		VRT_fail(ctx,
		    "cluster.%s can not be called here", func);
		return (D_NULL);
	}

	b = cluster_choose(ctx, vc, CLD, &decision, arg);

	if (decision == D_NULL || b == NULL)
		return (D_NULL);

	assert(b != vc->dir);
	VRT_l_bereq_backend(ctx, b);

	return (decision);
}

VCL_BOOL
vmod_cluster_cluster_selected(VRT_CTX,
    struct VPFX(cluster_cluster) *vc,
    struct VARGS(cluster_cluster_selected) *arg)
{
	enum decision_e decision;

	decision = cluster_selected(ctx, "cluster_selected", vc, arg);

	if (decision == D_NULL)
		return (0);

	return (decision == D_CLUSTER);
}

VCL_BOOL
vmod_cluster_real_selected(VRT_CTX,
    struct VPFX(cluster_cluster) *vc,
    struct VARGS(cluster_real_selected) *arg)
{
	enum decision_e decision;
	struct VARGS(cluster_cluster_selected) csarg[1] = arg2csarg(arg);

	decision = cluster_selected(ctx, "real_selected", vc, csarg);

	if (decision == D_NULL)
		return (0);

	return (decision == D_REAL);
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

	if (ctx->vcl && ctx->method) {
		be = vmod_cluster_resolve(ctx, be);
		return (VRT_Healthy(ctx, be, c));
	}

	CAST_OBJ_NOTNULL(vc, be->priv, VMOD_CLUSTER_CLUSTER_MAGIC);
	p = vc->param;
	CHECK_OBJ_NOTNULL(p, VMOD_CLUSTER_CLUSTER_PARAM_MAGIC);
	return (VRT_Healthy(ctx, p->cluster, c) ||
	    VRT_Healthy(ctx, p->real, c));
}
