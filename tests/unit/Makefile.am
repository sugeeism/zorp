LIBS = @ZORP_LIBS@ @MODULES_LIBS@ @DEPS_LIBS@
LDADD = -lboost_unit_test_framework
CPPFLAGS = @MODULES_CPPFLAGS@ -DBOOST_TEST_DYN_LINK=1

check_PROGRAMS = test_pystruct test_szig test_proxy


test_pystruct_SOURCES = test_pystruct.cc
test_szig_SOURCES = test_szig.cc
test_dynexpect_SOURCES = test_dynexpect.cc
test_proxy_SOURCES = helpers/zproxy.cc test_proxy.cc

TESTS = $(check_PROGRAMS)

EXTRA_DIST = pystruct.py helpers/zproxy.h helpers/zproxy.h
