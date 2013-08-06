# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Plug import *
from Zorp.Session import MasterSession
from traceback import *

from Zorp.NAT import getNATPolicy, NAT_SNAT, NAT_DNAT
import unittest

config.options.kzorp_enabled = FALSE

class TestGeneralNAT(unittest.TestCase):

    def tearDown(self):
        """Clean up global state."""
        del self.session

        import Zorp.Globals
        Zorp.Globals.services.clear()
        Zorp.Globals.nat_policies.clear()

    def setUp(self):
        """Construct a fake session object."""
        self.session = MasterSession()
        self.session.setService(Service("service1", PlugProxy))

    def performTranslation(self, nat_policy_name, addresses, nat_type):
        nat = getNATPolicy(nat_policy_name)
        return nat.performTranslation(self.session, addresses, nat_type)

    def checkDNAT(self, nat_policy_name, addresses, expected_result):
        return self.assertEqual(str(self.performTranslation(nat_policy_name, addresses, NAT_DNAT)), str(expected_result))

    def test_simple_dnat(self):
        """Test if DNAT works at all."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                        ]))
        self.checkDNAT("test", (None, SockAddrInet('9.255.255.255', 8888)), SockAddrInet('9.255.255.255', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.0', 8888)), SockAddrInet('20.0.0.0', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.255.255.255', 8888)), SockAddrInet('20.255.255.255', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.0', 8888)), SockAddrInet('11.0.0.0', 8888))

    def test_ipv6_dnat(self):
        """Test if DNAT works for IPv6 addresses"""
        NATPolicy('test', GeneralNAT(
                        [(Inet6Subnet('::/128'), Inet6Subnet('1200::/8'), Inet6Subnet('2300::/8'))
                        ]))
        self.checkDNAT("test", (None, SockAddrInet6('1234::', 8888)), SockAddrInet6('2334::', 8888))
        self.checkDNAT("test", (None, SockAddrInet6('1300::', 8888)), SockAddrInet6('1300::', 8888))

    def test_multiple_ranges_dnat(self):
        """Test if DNAT works with multiple ranges."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                         (InetDomain('0.0.0.0/32'), InetDomain('11.0.0.0/8'), InetDomain('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.1', 8888)), SockAddrInet('192.168.0.1', 8888))

    def test_overlapping_ranges_ordering(self):
        """Test what happens if there were overlapping ranges specified."""
        NATPolicy('large_first', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                         (InetDomain('0.0.0.0/32'), InetDomain('10.128.0.0/9'), InetDomain('21.0.0.0/9')),
                        ]))
        self.checkDNAT("large_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("large_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('20.128.0.0', 8888))

        NATPolicy('small_first', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('10.128.0.0/9'), InetDomain('21.0.0.0/9')),
                         (InetDomain('0.0.0.0/32'), InetDomain('10.0.0.0/8'), InetDomain('20.0.0.0/8')),
                        ]))
        self.checkDNAT("small_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("small_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('21.0.0.0', 8888))

    def test_destination_out_of_range(self):
        """Test if the result is properly capped."""
        NATPolicy('test', GeneralNAT(
                        [(InetDomain('0.0.0.0/32'), InetDomain('11.0.0.0/8'), InetDomain('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('11.255.255.255', 8888)), SockAddrInet('192.168.0.255', 8888))



def zorp():
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
