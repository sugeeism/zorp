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
from Zorp.Plug import *
from Zorp.Session import MasterSession
from Zorp.NAT import getNATPolicy, NAT_SNAT, NAT_DNAT
from Zorp.Exceptions import UserException
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
        self.session = MasterSession(Service("service1", PlugProxy), None, None, DBSockAddr(SockAddrInet('127.0.0.1', 1234), ZD_PROTO_TCP), None, instance_id=1)

    def performTranslation(self, nat_policy_name, addresses, nat_type):
        nat = getNATPolicy(nat_policy_name)
        return nat.performTranslation(self.session, addresses, nat_type)

    def checkDNAT(self, nat_policy_name, addresses, expected_result):
        return self.assertEqual(str(self.performTranslation(nat_policy_name, addresses, NAT_DNAT)), str(expected_result))

    def test_simple_dnat(self):
        """Test if DNAT works at all."""
        NATPolicy('test', GeneralNAT(
                        [(InetSubnet('0.0.0.0/32'), InetSubnet('10.0.0.0/8'), InetSubnet('20.0.0.0/8')),
                        ]))
        self.checkDNAT("test", (None, SockAddrInet('9.255.255.255', 8888)), None)
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.0', 8888)), SockAddrInet('20.0.0.0', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('10.255.255.255', 8888)), SockAddrInet('20.255.255.255', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.0', 8888)), None)

    def test_ipv6_dnat(self):
        """Test if DNAT works for IPv6 addresses"""
        NATPolicy('test', GeneralNAT(
                        [(Inet6Subnet('::/128'), Inet6Subnet('1200::/8'), Inet6Subnet('2300::/8'))
                        ]))
        self.checkDNAT("test", (None, SockAddrInet6('1234::', 8888)), SockAddrInet6('2334::', 8888))
        self.checkDNAT("test", (None, SockAddrInet6('1300::', 8888)), None)

    def test_multiple_ranges_dnat(self):
        """Test if DNAT works with multiple ranges."""
        NATPolicy('test', GeneralNAT(
                        [(InetSubnet('0.0.0.0/32'), InetSubnet('10.0.0.0/8'), InetSubnet('20.0.0.0/8')),
                         (InetSubnet('0.0.0.0/32'), InetSubnet('11.0.0.0/8'), InetSubnet('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('10.0.0.1', 8888)), SockAddrInet('20.0.0.1', 8888))
        self.checkDNAT("test", (None, SockAddrInet('11.0.0.1', 8888)), SockAddrInet('192.168.0.1', 8888))

    def test_overlapping_ranges_ordering(self):
        """Test what happens if there were overlapping ranges specified."""
        NATPolicy('large_first', GeneralNAT(
                        [(InetSubnet('0.0.0.0/32'), InetSubnet('10.0.0.0/8'), InetSubnet('20.0.0.0/8')),
                         (InetSubnet('0.0.0.0/32'), InetSubnet('10.128.0.0/9'), InetSubnet('21.0.0.0/9')),
                        ]))
        self.checkDNAT("large_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("large_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('20.128.0.0', 8888))

        NATPolicy('small_first', GeneralNAT(
                        [(InetSubnet('0.0.0.0/32'), InetSubnet('10.128.0.0/9'), InetSubnet('21.0.0.0/9')),
                         (InetSubnet('0.0.0.0/32'), InetSubnet('10.0.0.0/8'), InetSubnet('20.0.0.0/8')),
                        ]))
        self.checkDNAT("small_first", (None, SockAddrInet('10.127.255.255', 8888)), SockAddrInet('20.127.255.255', 8888))
        self.checkDNAT("small_first", (None, SockAddrInet('10.128.0.0', 8888)), SockAddrInet('21.0.0.0', 8888))

    def test_destination_out_of_range(self):
        """Test if the result is properly capped."""
        NATPolicy('test', GeneralNAT(
                        [(InetSubnet('0.0.0.0/32'), InetSubnet('11.0.0.0/8'), InetSubnet('192.168.0.0/24')),
                        ]))

        self.checkDNAT("test", (None, SockAddrInet('11.255.255.255', 8888)), SockAddrInet('192.168.0.255', 8888))


class TestNAT6446(unittest.TestCase):

    def tearDown(self):
        """Clean up global state."""
        del self.session

        import Zorp.Globals
        Zorp.Globals.services.clear()
        Zorp.Globals.nat_policies.clear()

    def setUp(self):
        """Construct a fake session object."""
        self.session = MasterSession(Service("service1", PlugProxy), None, None, DBSockAddr(SockAddrInet('127.0.0.1', 1234), ZD_PROTO_TCP), None, instance_id=1)

    def performTranslation(self, nat_policy_name, addresses, nat_type):
        nat = getNATPolicy(nat_policy_name)
        return nat.performTranslation(self.session, addresses, nat_type)

    def checkDNAT(self, nat_policy_name, addresses, expected_result):
        return self.assertEqual(str(self.performTranslation(nat_policy_name, addresses, NAT_DNAT)), str(expected_result))

    def test_nat64(self):
        """Test if DNAT64 works."""
        NATPolicy('test32', NAT64(prefix_mask=32))
        NATPolicy('test40', NAT64(prefix_mask=40))
        NATPolicy('test48', NAT64(prefix_mask=48))
        NATPolicy('test56', NAT64(prefix_mask=56))
        NATPolicy('test64', NAT64(prefix_mask=64))
        NATPolicy('test96', NAT64(prefix_mask=96))
        self.checkDNAT("test32", (None, SockAddrInet6('2001:db8:c000:221::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test40", (None, SockAddrInet6('2001:db8:1c0:2:21::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test48", (None, SockAddrInet6('2001:db8:122:c000:2:2100::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test56", (None, SockAddrInet6('2001:db8:122:3c0:0:221::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test64", (None, SockAddrInet6('2001:db8:122:344:c0:2:2100::', 8888)), SockAddrInet('192.0.2.33', 8888))
        self.checkDNAT("test96", (None, SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888)), SockAddrInet('192.0.2.33', 8888))

    def test_nat46(self):
        """Test if DNAT64 works."""
        NATPolicy('test32', NAT46(prefix="2001:db8:122:344::", prefix_mask=32))
        NATPolicy('test40', NAT46(prefix="2001:db8:122:344::", prefix_mask=40))
        NATPolicy('test48', NAT46(prefix="2001:db8:122:344::", prefix_mask=48))
        NATPolicy('test56', NAT46(prefix="2001:db8:122:344::", prefix_mask=56))
        NATPolicy('test64', NAT46(prefix="2001:db8:122:344::", prefix_mask=64))
        NATPolicy('test96', NAT46(prefix="2001:db8:122:344::", prefix_mask=96))
        self.checkDNAT("test32", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:c000:221::', 8888))
        self.checkDNAT("test40", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:1c0:2:21::', 8888))
        self.checkDNAT("test48", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:c000:2:2100::', 8888))
        self.checkDNAT("test56", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:3c0:0:221::', 8888))
        self.checkDNAT("test64", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344:c0:2:2100::', 8888))
        self.checkDNAT("test96", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888))

    def test_nat46_suffix(self):
        """Test if DNAT64 works."""
        NATPolicy('test32', NAT46(prefix="2001:db8:122:344::", prefix_mask=32, suffix="::1"))
        NATPolicy('test40', NAT46(prefix="2001:db8:122:344::", prefix_mask=40, suffix="::2"))
        NATPolicy('test48', NAT46(prefix="2001:db8:122:344::", prefix_mask=48, suffix="::6"))
        NATPolicy('test56', NAT46(prefix="2001:db8:122:344::", prefix_mask=56, suffix="::12"))
        NATPolicy('test64', NAT46(prefix="2001:db8:122:344::", prefix_mask=64, suffix="::24"))
        self.checkDNAT("test32", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:c000:221::1', 8888))
        self.checkDNAT("test40", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:1c0:2:21::2', 8888))
        self.checkDNAT("test48", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:c000:2:2100::6', 8888))
        self.checkDNAT("test56", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:3c0:0:221::12', 8888))
        self.checkDNAT("test64", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344:c0:2:2100:24', 8888))

    def test_nat64_incorrect_proto(self):
        exc = None
        NATPolicy('test96', NAT64(prefix_mask=96))
        try:
            self.checkDNAT("test96", (None, SockAddrInet('192.0.2.33', 8888)), SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "NAT64 might only be used to translate IPv6 addresses; family='2'")

    def test_nat46_incorrect_proto(self):
        exc = None
        NATPolicy('test96', NAT46(prefix="2001:db8:122:344::", prefix_mask=96))
        try:
            self.checkDNAT("test96", (None, SockAddrInet6('2001:db8:122:344::192.0.2.33', 8888)), SockAddrInet('192.0.2.33', 8888))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "NAT46 might only be used to translate IPv4 addresses; family='10'")

    def test_nat64_incorrect_prefix(self):
        exc = None
        try:
            NATPolicy('test96', NAT64(prefix_mask=71))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "Prefix mask must be one of: (32, 40, 48, 56, 64, 96); mask='71'")

    def test_nat46_incorrect_prefix(self):
        exc = None
        try:
            NATPolicy('test96', NAT46(prefix="almafa", prefix_mask=71))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "Invalid prefix string specified; error='illegal IP address string passed to inet_pton'")
        exc = None
        try:
            NATPolicy('test96_2', NAT46(prefix="2001:db8:122:344::", prefix_mask=71))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "Prefix mask must be one of: (32, 40, 48, 56, 64, 96); mask='71'")

    def test_nat46_incorrect_suffix(self):
        exc = None
        try:
            NATPolicy('test96', NAT46(suffix="sadfafwe", prefix="2001:db8:122:344::", prefix_mask=96))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "Invalid suffix string specified; error='illegal IP address string passed to inet_pton'")
        exc = None
        try:
            NATPolicy('test32', NAT46(prefix="2001:db8:122:344::", prefix_mask=32, suffix="::2001:db8:122:344"))
        except UserException, e:
            exc = e
        self.assertEqual(exc.detail, "Suffix length doesn't match the configured mask, the first 12 bytes should be zeroes")

def zorp():
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
