# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Zorp import log
from traceback import *
import unittest

config.options.kzorp_enabled = FALSE

class TestLog(unittest.TestCase):

    def test_log_arguments(self):
        log("session_id", "core.error", 1, "test_format='%s'", "test_value")
        log("session_id", "core.error", 1, "test_format='%s'", ("test_value", ))
        log("session_id", "core.error", 1, "test_format='%s'" % "test_value")
        log("session_id", "core.error", 1, "test_format='%s'" % ("test_value", ))


def init(names, virtual_name, is_master):
    unittest.main(argv=('',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
