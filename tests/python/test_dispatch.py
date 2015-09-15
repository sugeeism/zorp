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
from Zorp.Zorp import quit

import unittest

config.options.kzorp_enabled = FALSE

class TestDispatcher(unittest.TestCase):

    def setUp(self):
        Service('test', PlugProxy)

    def tearDown(self):
        import Zorp.Globals
        Zorp.Globals.services.clear()

    def test_keyword_args(self):
        """Test keyword argument that is processed by the C code."""
        Listener(SockAddrInet('0.0.0.0', 1999), 'test', transparent=TRUE)
        Listener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test', transparent=TRUE)
        Listener(DBIface('eth0', 1999), 'test', transparent=TRUE)
        Receiver(SockAddrInet('0.0.0.0', 1999), 'test', transparent=TRUE)
        Receiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test', transparent=TRUE)
        Receiver(DBIface('eth0', 1999), 'test', transparent=TRUE)
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)

        ZoneListener(SockAddrInet('0.0.0.0', 1999), {'all': 'test'}, transparent=TRUE)
        ZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'}, transparent=TRUE)
        ZoneListener(DBIface('eth0', 1999), {'all': 'test'}, transparent=TRUE)
        ZoneReceiver(SockAddrInet('0.0.0.0', 1999), {'all': 'test'}, transparent=TRUE)
        ZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'}, transparent=TRUE)
        ZoneReceiver(DBIface('eth0', 1999), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)

        CSZoneListener(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneListener(DBIface('eth0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneReceiver(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneReceiver(DBIface('eth0', 1999), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)

    def test_constructors(self):
        """No keyword arguments."""
        Listener(SockAddrInet('0.0.0.0', 1999), 'test')
        Listener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test')
        Listener(DBIface('eth0', 1999), 'test')
        Receiver(SockAddrInet('0.0.0.0', 1999), 'test')
        Receiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), 'test')
        Receiver(DBIface('eth0', 1999), 'test')
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test')
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test')

        ZoneListener(SockAddrInet('0.0.0.0', 1999), {'all': 'test'})
        ZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'})
        ZoneListener(DBIface('eth0', 1999), {'all': 'test'})
        ZoneReceiver(SockAddrInet('0.0.0.0', 1999), {'all': 'test'})
        ZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {'all': 'test'})
        ZoneReceiver(DBIface('eth0', 1999), {'all': 'test'})
        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'})
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'})

        CSZoneListener(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'})
        CSZoneListener(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'})
        CSZoneListener(DBIface('eth0', 1999), {('all', 'all'): 'test'})
        CSZoneReceiver(SockAddrInet('0.0.0.0', 1999), {('all', 'all'): 'test'})
        CSZoneReceiver(DBSockAddr(SockAddrInet('0.0.0.0', 1999)), {('all', 'all'): 'test'})
        CSZoneReceiver(DBIface('eth0', 1999), {('all', 'all'): 'test'})
        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})
        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})

def zorp():
    unittest.main(argv=('/'))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
