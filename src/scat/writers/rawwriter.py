#!/usr/bin/env python3
# coding: utf8

import datetime

class RawWriter:
    def __init__(self, fname, header=b'', trailer=b''):
        self.raw_file = open(fname, 'wb')
        self.raw_file.write(header)
        self.trailer = trailer

    def __enter__(self):
        return self

    def write_cp(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        self.raw_file.write(sock_content)

    def write_up(self, sock_content, radio_id=0, ts=datetime.datetime.now()):
        self.raw_file.write(sock_content)

    def __exit__(self, exc_type, exc_value, traceback):
        self.raw_file.write(self.trailer)
        self.raw_file.close()
