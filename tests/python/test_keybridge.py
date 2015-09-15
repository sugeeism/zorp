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

from Zorp.Keybridge import *
import unittest
import threading
import tempfile
import os
from multiprocessing import Process

class DummyKeybridge(X509KeyBridge):
    def __init__(self, serial_file, key_pem):
        self.serials = []
        self.serial_file = serial_file
        super(DummyKeybridge, self).__init__(key_pem, "/tmp")

    def _load_privatekey(self, key_file, trusted_ca_files, untrusted_ca_files, key_passphrase):
        self.trusted_ca = ""
        self.key = ""
        pass

    def getCachedKey(self, cert_file, cert_server):
        raise KeyError

    def _save_new_cert(self, orig_blob, ca_pair, cert_file, serial):
        self.serials.append(serial)
        return None

    def _dump_privatekey(self):
        return None

    def _get_serial_filename(self):
        return self.serial_file

class TestKeybridge(unittest.TestCase):
    def setUp(self):

        temp_file = tempfile.NamedTemporaryFile()
        self.serial_file = temp_file.name
        temp_file.close()
        self.keybridge = DummyKeybridge(self.serial_file, key_pem=None)
        pass

    def tearDown(self):
        try:
            os.remove(self.serial_file)
        except OSError:
            pass

    def starter(self):
        dummy_selector = {}
        dummy_selector['bridge-trusted-key'] = "blob"
        for x in range(0,2):
            self.keybridge.getKeypair(dummy_selector)

    def test_threads(self):
        NUM_THREADS = 4
        for num in range(0,4):
            threads = []
            for i in range(NUM_THREADS):
                t = threading.Thread(target=self.starter)
                t.start()
                threads.append(t)
            for t in threads:
                t.join()

            count = 1
            for serial in self.keybridge.serials:
                count = count + 1
                self.assertEqual(count, serial)

    '''def test_processes(self):
        NUM_PROCESSES = 4
        procs = []
        for i in range(NUM_PROCESSES):
            p = Process(target=self.starter)
            p.start()
            procs.append(p)
        for p in procs:
            p.join()

        count = 1
        for serial in self.keybridge.serials:
            count = count + 1
            self.assertEqual(count, serial)
    '''

def init(name, virtual_name, is_master):
    unittest.main(argv=('',))
