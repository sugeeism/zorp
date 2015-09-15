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

from Zorp import log, CORE_SESSION, CORE_POLICY, Globals, TRUE, ZD_PROTO_AUTO
from Dispatch import BaseDispatch
from Session import MasterSession
from Proxy import Proxy
from Detector import DetectResult

class DetectorProxy(Proxy):
    """<class internal="yes" abstract="yes">
    <summary>
      Class for automatic protocol detection.
    </summary>
    </class>
    """
    name = "apr"
    def __init__(self, session):
        Proxy.__init__(self, session)

        log(self.session.session_id, CORE_SESSION, 5, "Proxy start")
        self._detector_config = session.service.detector_config
        self.results = {}

    def config(self):
        self.timeout = 5000
        for detector_name in self._detector_config.iterkeys():
            self.results[detector_name] = DetectResult.UNDECIDED
        detector_policy = Globals.detectors.get(detector_name, None)
        if not detector_policy:
            raise ValueError, "No such detector defined; detector='%s'" % (detector_name,)

        if detector_policy.detector.server_side_protocol:
            self.need_server_connect = True

    def startService(self, service):
        session = MasterSession(service=service,
                                client_stream=self.session.client_stream,
                                client_local=self.session.client_local,
                                client_listen=self.session.client_listen,
                                client_address=self.session.client_address)

        BaseDispatch.startService(service, session)

    def detect(self, side, data):
        service = None

        count_nomatch_detectors = 0
        for detector_name, service_name in self._detector_config.iteritems():
            if (self.results[detector_name] == DetectResult.NOMATCH):
                count_nomatch_detectors += 1
                continue

            detector = Globals.detectors.get(detector_name, None)
            if not detector:
                raise ValueError, "No such detector defined; detector='%s'" % (detector_name,)

            res = detector.detect(side, data)
            self.results[detector_name] = res.result
            if res.result == DetectResult.MATCH:
                service = Globals.services.get(service_name, None)
                if not service:
                    raise ValueError, "No such service defined; service='%s'" % (service_name,)
                log(self.session.session_id, CORE_POLICY, 3, "Detector starting service; service='%s'" % service)
                return service
            elif res.result == DetectResult.NOMATCH:
                count_nomatch_detectors += 1
            elif res.result == DetectResult.COPY_CLIENT:
                self.need_server_connect = TRUE
                self.copy_client_data = res.bytes_to_copy

        if len(self._detector_config) == count_nomatch_detectors:
            self.quit = TRUE
        return service
