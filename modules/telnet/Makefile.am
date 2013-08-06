SUBDIRS = .

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp

LIBS     = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

if PRO
    LIBS     += @TRE_LIBS@
    CPPFLAGS += @TRE_CFLAGS@
endif

pkgdata_DATA = Telnet.py

pkglib_LTLIBRARIES = libtelnet.la

libtelnet_la_SOURCES = telnet.c telnetpolicy.c telnetsuboption.c telnet.h telnetpolicy.h telnetsuboption.h telnettls.c telnettls.h telnetprotocol.c telnetprotocol.h telnetstate.c telnetstate.h telnetlineedit.c telnetlineedit.h telnetoption.c telnetoption.h telnetpatternmatch.c telnetpatternmatch.h

EXTRA_DIST = $(pkgdata_DATA) 
