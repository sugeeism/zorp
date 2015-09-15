#!/usr/bin/env python

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

import unittest, os
from Zorp.InstancesConf import InstancesConf

class TestInstancesConf(unittest.TestCase):

    def setUp(self):
        self.instance_name = 'default'
        self.zorp_argv = ''
        self.zorpctl_argv = {
                             "num_of_processes" : 4,
                             "auto_restart" : False,
                             "auto_start" : False,
                            }

        zorpctl_argv = "--num-of-processes 4"
        if not self.zorpctl_argv["auto_restart"]:
            zorpctl_argv += " --no-auto-restart"
        if not self.zorpctl_argv["auto_start"]:
            zorpctl_argv += " --no-auto-start"

        self.filename = 'testfile_instances.conf'
        testfile = open(self.filename, 'w')
        testfile.write("%s %s -- %s" % (self.instance_name, self.zorp_argv, zorpctl_argv))
        testfile.close()

    def __del__(self):
        os.remove(self.filename)

    def test_instance_generation(self):
        try:
             instancesconf = InstancesConf()
             instancesconf.instances_conf_path = self.filename
             for instance in instancesconf:
                 self.assertEquals(instance.name, self.instance_name)
                 self.assertEquals(instance.number_of_processes, self.zorpctl_argv["num_of_processes"])
                 self.assertEquals(instance.auto_restart, self.zorpctl_argv["auto_restart"])
                 self.assertEquals(instance.auto_start, self.zorpctl_argv["auto_start"])
        except IOError as e:
             self.assertFalse("Something went wrong while initializing InstancesConf object: %s" % e.message)

if __name__ == '__main__':
    unittest.main()
