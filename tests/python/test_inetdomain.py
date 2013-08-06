# vim: ts=8 sts=4 expandtab autoindent
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
