AM_CFLAGS = $(VARNISHAPI_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_cluster.la

libvmod_cluster_la_LDFLAGS = $(VMOD_LDFLAGS)
libvmod_cluster_la_SOURCES = \
	vmod_cluster.c \
	tbl_resolve.h \
	vmod_compat.h

nodist_libvmod_cluster_la_SOURCES = \
	vcc_cluster_if.c \
	vcc_cluster_if.h

@BUILD_VMOD_CLUSTER@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"

TESTS = \
	vtc/cfg.vtc		\
	vtc/cld.vtc		\
	vtc/selected.vtc	\
	vtc/deep.vtc		\
	vtc/deep_stk.vtc	\
	vtc/direct.vtc		\
	vtc/shallow.vtc		\
	vtc/lazy.vtc		\
	vtc/lazy_shard.vtc

# Documentation

dist_doc_DATA = \
	vmod_cluster.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_cluster.3


.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
