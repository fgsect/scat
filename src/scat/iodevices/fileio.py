#!/usr/bin/env python3
# coding: utf8

import gzip, bz2
import scat.util as util

class FileIO:
    def _open_file(self, fname):
        if self.f:
            self.f.close()

        if fname.find('.gz') > 0:
            self.f = gzip.open(fname, 'rb')
        elif fname.find('.bz2') > 0:
            self.f = bz2.open(fname, 'rb')
        else:
            self.f = open(fname, 'rb')

    def __init__(self, fnames):
        self.fnames = fnames[:]
        self.fnames.reverse()
        self.fname = ''
        self.file_available = True
        self.f = None
        self.block_until_data = False

        self.open_next_file()

    def read(self, read_size, decode_hdlc = False):
        buf = b''
        try:
            buf = self.f.read(read_size)
            buf = bytes(buf)
        except:
            return b''
        if decode_hdlc:
            buf = util.unwrap(buf)
        return buf

    def open_next_file(self):
        try:
            self.fname = self.fnames.pop()
        except IndexError:
            self.file_available = False
            return
        self._open_file(self.fname)

    def write(self, write_buf, encode_hdlc = False):
        pass

    def write_then_read_discard(self, write_buf, read_size, encode_hdlc = False):
        self.write(write_buf)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        if self.f:
            self.f.close()
