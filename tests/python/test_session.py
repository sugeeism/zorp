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
from Zorp.Zorp import quit
from Zorp.Proxy import Proxy
from Zorp.Http import HttpProxy
from Zorp.Session import MasterSession, StackedSession
import Zorp.Globals
import Zorp.Resolver
import socket
import unittest

config.options.kzorp_enabled = FALSE

InetZone("internet", "0.0.0.0/0")


class DummyResolver(Zorp.Resolver.AbstractResolver):

    def resolve(self, host, port):
        return SockAddrInet("127.0.0.1", port)

ResolverPolicy("test_resolver", DummyResolver())


class TestSessionBase(unittest.TestCase):

    def setUp(self):
        self.service = Service("testservice", HttpProxy, resolver_policy="test_resolver")
        self.address = SockAddrInet("127.0.0.1", 80)
        self.mastersession = MasterSession(self.service, client_stream=None, client_local=None, client_listen=DBSockAddr(self.address, ZD_PROTO_TCP), client_address=self.address, instance_id=1)
        self.session = StackedSession(self.mastersession)

    def tearDown(self):
        del self.session
        del self.mastersession
        del self.service
        del self.address
        Zorp.Globals.services.clear()


class TestTopLevelProxySession(TestSessionBase):

    def test_construction(self):
        self.assertTrue(isinstance(self.mastersession, MasterSession))
        self.assertTrue(isinstance(self.session, StackedSession))

    def test_construction_initializes_protocol(self):
        master = MasterSession(self.service, None, None, DBSockAddr(SockAddrInet('127.0.0.1', 1234), ZD_PROTO_TCP), None, instance_id=1)
        self.assertEqual(master.protocol, ZD_PROTO_TCP)
        self.assertEqual(master.protocol_name, "TCP")

    def test_client_zone_lookup(self):
        self.assertEqual(self.session.client_address, self.address)
        self.assertEqual(self.session.client_zone.name, "internet")

    def test_setServerAddress(self):
        self.session.setServerAddress(self.address)
        self.assertEqual(self.session.server_address, self.address)
        self.assertEqual(self.session.server_zone.name, "internet")

    def test_setTargetAddress(self):
        self.session.setTargetAddress(self.address)
        self.assertEqual(self.session.target_address, (self.address, ))
        self.assertEqual(len(self.session.target_zone), 1)
        self.assertEqual(self.session.target_zone[0].name, "internet")

    def test_setProxy(self):
        """Check the final session ID constructed when an associated proxy was created and the proxy is properly set in the session"""
        (client_stream, server_stream) = streamPair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.session.client_stream = client_stream
        proxy = HttpProxy(self.session)
        self.assertEqual(self.session.session_id, "svc//" + self.service.name + ":1" + "//http")
        self.assertEqual(self.session.proxy, proxy)
        self.assertEqual(self.session.http, proxy)
        self.assertEqual(proxy.session, self.session)


class TestStackedProxySession(TestSessionBase):

    def test_stacking_inherit_target_address(self):
        """Stacked proxies should inherit the target address of their parent"""
        self.session.setTargetAddress(self.address)
        ss = StackedSession(self.session)
        self.assertEqual(ss.target_address, (self.address, ))

    def test_stacking_override_target_address(self):
        """Stacked proxies can override their target own address without affecting their parent session"""
        self.session.setTargetAddress(self.address)
        ss = StackedSession(self.session)
        address2 = SockAddrInet("10.0.0.1", 90)
        ss.setTargetAddress(address2)
        self.assertEqual(ss.target_address, (address2, ))
        self.assertEqual(self.session.target_address, (self.address, ))


def init(name, virtual_name, is_master):
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
