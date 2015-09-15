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
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from Zorp.Instance import Instance
from zorpctl.ProcessAlgorithms import StatusAlgorithm

class TestStatusAlgorithm(unittest.TestCase):

    def setUp(self):
        handler_mock = HandlerMock
        test_policy_file = open('test_policy_file', 'w')
        test_policy_file.close()
        time_stamp = os.path.getmtime('test_policy_file')
        szig = SZIG("", handler_mock)
        szig.handler.data["info"]["policy"]["file"] = 'test_policy_file'
        szig.handler.data["info"]["policy"]["file_stamp"] = time_stamp
        szig.handler.data["info"]["policy"]["reload_stamp"] = time_stamp

        self.algorithm = StatusAlgorithm()
        self.algorithm.setInstance(Instance(name='testinstance', process_num=0))
        self.algorithm.szig = szig
        self.algorithm.pidfiledir = self.test_dir = './var/run/zorp/'

        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

        self.test_pid_file = 'zorp-testinstance#0.pid'
        pid_file = open(self.test_dir + self.test_pid_file, 'w')
        pid_file.write('123456')
        pid_file.close()

    def __del__(self):
        os.remove("test_policy_file")
        os.remove(self.test_dir + self.test_pid_file)
        os.removedirs(self.test_dir)

    def test_status(self):
        status = self.algorithm.status()
        self.assertEquals(status.pid, 123456)
        self.assertEquals(status.threads, self.algorithm.szig.handler.data['stats']['threads_running'])
        self.assertEquals(status.policy_file, self.algorithm.szig.handler.data['info']['policy']['file'])
        self.assertEquals(status.reload_timestamp, self.algorithm.szig.handler.data['info']['policy']['reload_stamp'])
        self.assertEquals(status.timestamp_szig, self.algorithm.szig.handler.data['info']['policy']['file_stamp'])

if __name__ == '__main__':
    unittest.main()
