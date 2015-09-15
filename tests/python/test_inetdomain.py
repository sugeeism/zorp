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
from socket import inet_ntoa, inet_aton
from traceback import print_exc
import struct
import unittest

config.options.kzorp_enabled = FALSE

class TestInetDomain(unittest.TestCase):
    def test_attributes(self):
        dom = InetDomain("192.168.0.1/24")
        self.assertEqual(dom.addr_str(), "192.168.0.1")
        self.assertEqual(dom.broadcast(), struct.unpack("I", inet_aton("192.168.0.255"))[0])
        self.assertEqual(dom.netmask_int(), struct.unpack("I", inet_aton("255.255.255.0"))[0])

def init(names, virtual_name, is_master):
    unittest.main(argv=('',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
