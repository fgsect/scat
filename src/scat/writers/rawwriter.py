#!/usr/bin/env python3
# coding: utf8

from scat.writers.abstractwriter import AbstractWriter

class RawWriter(AbstractWriter):
    def __init__(self, fname: str, header: bytes=b'', trailer: bytes=b''):
        self.raw_file = open(fname, 'wb')
        self.raw_file.write(header)
        self.trailer = trailer

    def __enter__(self):
        return self

    def write_cp(self, sock_content: bytes, radio_id: int=0, ts: None = None):
        self.raw_file.write(sock_content)

    def write_up(self, sock_content: bytes, radio_id: int=0, ts: None = None):
        self.raw_file.write(sock_content)

    def __exit__(self, exc_type, exc_value, traceback):
        self.raw_file.write(self.trailer)
        self.raw_file.close()
