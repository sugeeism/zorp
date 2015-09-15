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

import unittest
from HandlerMock import HandlerMock
from zorpctl.szig import SZIG
from zorpctl.PluginAlgorithms import *
from zorpctl.CommandResults import CommandResultSuccess

class TestGetAlgorithms(unittest.TestCase):

    def setUp(self):
        handler_mock = HandlerMock
        self.szig = SZIG("", handler_mock)
        self.data = handler_mock().data

    def test_get_sessions_running_algorithm(self):
        algorithm = GetSessionsRunningAlgorithm()
        algorithm.szig = self.szig
        self.assertEquals(algorithm.get(), self.data["stats"]["sessions_running"])

    def test_get_thread_rate_algorithm(self):
        algorithm = GetThreadRateAlgorithm()
        algorithm.szig = self.szig
        result = algorithm.get()
        self.assertEquals(result["max"], self.data["stats"]["thread_rate_max"])
        self.assertEquals(result["avg15"], self.data["stats"]["thread_rate_avg15"])
        self.assertEquals(result["avg5"], self.data["stats"]["thread_rate_avg5"])
        self.assertEquals(result["avg1"], self.data["stats"]["thread_rate_avg1"])

    def test_get_threads_running_algorithm(self):
        algorithm = GetThreadsRunningAlgorithm()
        algorithm.szig = self.szig
        self.assertEquals(algorithm.get(), self.data["stats"]["threads_running"])

    def test_get_services_algorithm(self):
        algorithm = GetServicesAlgorithm()
        algorithm.szig = self.szig
        self.assertEquals(algorithm.services().value, self.data["service"].keys())

    def test_service_rate_algorithm(self):
        algorithm = GetServiceRateAlgorithm()
        algorithm.szig = self.szig
        rate = {}
        for service in self.data["service"].keys():
            avg1 = self.data["service"][service]["rate_avg1"]
            avg5 = self.data["service"][service]["rate_avg5"]
            avg15 = self.data["service"][service]["rate_avg15"]
            rate[service] = {"avg1" : avg1, "avg5" : avg5, "avg15" : avg15}

        services = CommandResultSuccess("", self.data["service"].keys())
        self.assertEquals(algorithm.getServiceRate(services), rate)

if __name__ == '__main__':
    unittest.main()
