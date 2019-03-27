ACLOCAL_AMFLAGS = -I m4 -I @VARNISHAPI_DATAROOTDIR@/aclocal

vmod_cluster_vcl_DATA = \
	vcl/vshard.inc.vcl \
	vcl/vshard_probe.inc.vcl

EXTRA_DIST = $(vmod_cluster_vcl_DATA)

DISTCHECK_CONFIGURE_FLAGS = RST2MAN=:

SUBDIRS = src
