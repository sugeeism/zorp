EXTRA_DIST = test_inetdomain.py test_zone.py test_matcher.py test_dispatch.py test_nat.py test_log.py test_service.py

noinst_SCRIPTS = runtest.sh

TESTS = runalltests.sh

.PHONY: mkzorp
mkzorp:
	make -C ../../zorp

runtest.sh: mkzorp
