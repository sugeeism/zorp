# vim: ts=8 sts=4 expandtab autoindent

############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

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
