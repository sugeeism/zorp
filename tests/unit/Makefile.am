LIBS = @ZORP_LIBS@ @MODULES_LIBS@ @DEPS_LIBS@

check_PROGRAMS = pystruct test_audit test_szig test_dynexpect test_proxy test_start_audit

if ALERTING_ENABLED
check_PROGRAMS += test_alerting
endif


pystruct_SOURCES = pystruct.c
test_audit_SOURCES = test_audit.c
test_szig_SOURCES = test_szig.c
test_dynexpect_SOURCES = test_dynexpect.c
test_proxy_SOURCES = helpers/zproxy.c test_proxy.c
test_start_audit_SOURCES = helpers/zproxy.c helpers/start_audit.c test_start_audit.c

if ALERTING_ENABLED
test_alerting_SOURCES = test_alerting.c
endif

TESTS = pystruct test_audit test_szig test_proxy test_start_audit

if ALERTING_ENABLED
TESTS += test_alerting
endif

EXTRA_DIST = pystruct.py helpers/zproxy.h
