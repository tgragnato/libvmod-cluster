/* compatibility with pre 7.0 vmodtool */

#ifndef VENUM
#define VENUM(x) vmod_enum_ ## x
#endif

#ifndef VARGS
#define VARGS(x) vmod_ ## x ## _arg
#endif

#ifndef VPFX
#define VPFX(x) vmod_ ## x
#endif

/* ------------------------------------------------------------
 * workaround missing VRT_DirectorResolve
 * Ref https://github.com/varnishcache/varnish-cache/pull/2680
 */
#if ! HAVE_DECL_VRT_DIRECTORRESOLVE
#include <cache/cache_director.h>

static inline VCL_BACKEND
VRT_DirectorResolve(VRT_CTX, VCL_BACKEND d)
{
	VCL_BACKEND d2;

	for (; d != NULL && d->vdir->methods->resolve != NULL; d = d2) {
		CHECK_OBJ_NOTNULL(d, DIRECTOR_MAGIC);
		AN(d->vdir);
		d2 = d->vdir->methods->resolve(ctx, d);
	}
	CHECK_OBJ_ORNULL(d, DIRECTOR_MAGIC);
	if (d != NULL)
		AN(d->vdir);
	return (d);
}
#endif
