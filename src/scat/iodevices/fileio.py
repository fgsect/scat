#!/usr/bin/env python3
# coding: utf8

import gzip, bz2
import scat.util as util
from scat.iodevices.abstractio import AbstractIO

class FileIO(AbstractIO):
    def _open_file(self, fname: str):
        if self.f:
            self.f.close()

        if fname.find('.gz') > 0:
            self.f = gzip.open(fname, 'rb')
        elif fname.find('.bz2') > 0:
            self.f = bz2.open(fname, 'rb')
        else:
            self.f = open(fname, 'rb')

    def __init__(self, fnames: list[str]):
        self.fnames = fnames[:]
        self.fnames.reverse()
        self.fname = ''
        self.file_available = True
        self.f = None
        self.block_until_data = False

        self.open_next_file()

    def read(self, read_size: int, decode_hdlc: bool = False) -> bytes:
        buf = b''
        if self.f:
            try:
                buf = self.f.read(read_size)
                buf = bytes(buf)
            except:
                return b''
        if decode_hdlc:
            buf = util.unwrap(buf)
        return buf

    def open_next_file(self) -> None:
        try:
            self.fname = self.fnames.pop()
        except IndexError:
            self.file_available = False
            return
        self._open_file(self.fname)

    def write(self, write_buf: bytes, encode_hdlc: bool = False) -> None:
        pass

    def write_then_read_discard(self, write_buf: bytes, read_size: int, encode_hdlc: bool = False) -> None:
        self.write(write_buf)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        if self.f:
            self.f.close()
