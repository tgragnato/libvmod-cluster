/* compatibility with pre 7.0 vmodtool */

#ifndef VENUM
#define VENUM(x) vmod_enum_ ## x
#endif

#ifndef VARGS
#define VARGS(x) vmod_ ## x ## _arg
#endif
