SUBDIRS = . messages tests

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@
AM_CFLAGS = @CFLAGS@ -W

pkgdata_DATA = Http.py

pkglib_LTLIBRARIES = libhttp.la

libhttp_la_SOURCES = http.c httpproto.c httpfltr.c httpfltr.h httpmisc.c httphdr.c httpftp.c http.h \
                     httpcommon.h http-audit-common.h http-audit-data-exchange.h \
                     http-audit-data-exchange.c http-audit-stream.h http-audit-stream.c http-audit-repository.h \
                     http-audit-repository.c

EXTRA_DIST =  $(pkgdata_DATA)
