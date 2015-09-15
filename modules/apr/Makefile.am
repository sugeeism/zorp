# vim: sts=4 ts=4 noet ai

pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @zorp_libdir@
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = APR.py

pkglib_LTLIBRARIES = libapr.la

libapr_la_SOURCES = apr.cc

EXTRA_DIST = $(pkgdata_DATA)
