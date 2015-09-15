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

import fcntl

from Zorp import log, CORE_ERROR

class FileLock(object):
    '''
    File based locking, usable as a context manager
    '''

    def __init__(self, filename=None):
        self.filename = filename
        self.lock_fd = self._open_lockfile(filename)

    def _open_lockfile(self, filename):
        try:
            try:
                fd = open(filename, 'r+')
            except IOError:
                fd = open(filename, 'w')
            return fd
        except IOError, e:
            log(None, CORE_ERROR, 3, "Error opening lock file; file='%s', error='%s'", (e.filename, e.strerror))

    def acquire(self):
        self._lock_file_exclusively(self.lock_fd)

    def release(self):
        self._unlock_file(self.lock_fd)

    def _lock_file_exclusively(self, fd):
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock_file(self, fd):
        fcntl.flock(fd, fcntl.LOCK_UN)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False
