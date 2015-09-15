pkgdatadir = @ZORP_PYTHON_DIR@
pkglibdir = @zorp_libdir@
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = AnyPy.py

pkglib_LTLIBRARIES = libanypy.la

libanypy_la_SOURCES = anypy.cc

EXTRA_DIST = $(pkgdata_DATA)
