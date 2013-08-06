# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Zorp import quit, ZV_ACCEPT, ZV_REJECT
from Zorp.Zone import Zone
from Zorp.Session import MasterSession
from Zorp.Plug import PlugProxy
import unittest

config.options.kzorp_enabled = FALSE

class TestLimitTargetZones(unittest.TestCase):

    def setUp(self):
        Zone('internet', ('0.0.0.0/0', '0::0/0'))
        Zone('intranet', ('10.0.0.0/8', ), admin_parent='internet')
        Zone('office1', ('10.1.0.0/16', '10.5.0.0/16'), admin_parent='intranet')
        Zone('disconnected', ('192.168.0.0/16', ))
        self.session = MasterSession()

    def tearDown(self):
        del self.session
        import Zorp.Globals
        Zorp.Globals.services.clear()

    def checkZone(self, zone_name, expected):
        self.session.server_zone = Zone.lookup_by_name(zone_name)
        self.assertEqual(expected, self.session.isServerPermitted())

    def test_default(self):
        """Check that the default is no restrictions."""
        s = Service('empty', PlugProxy)
        self.session.setService(s)

        self.checkZone('internet', ZV_ACCEPT)
        self.checkZone('office1', ZV_ACCEPT)

    def test_none(self):
        """Check that None means no restrictions"""
        s = Service('none', PlugProxy, limit_target_zones_to=None)
        self.session.setService(s)

        self.checkZone('internet', ZV_ACCEPT)
        self.checkZone('office1', ZV_ACCEPT)

    def test_none(self):
        """Check that an empty list means no restrictions"""
        s = Service('none', PlugProxy, limit_target_zones_to=())
        self.session.setService(s)

        self.checkZone('internet', ZV_ACCEPT)
        self.checkZone('office1', ZV_ACCEPT)

    def test_match(self):
        """Check for matches recursively"""
        s = Service('match', PlugProxy, limit_target_zones_to=('internet',))
        self.session.setService(s)

        self.checkZone('internet', ZV_ACCEPT)
        self.checkZone('intranet', ZV_ACCEPT)
        self.checkZone('office1', ZV_ACCEPT)
        self.checkZone('disconnected', ZV_REJECT)

def init(names, virtual_name, is_master):
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
