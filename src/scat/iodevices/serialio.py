#!/usr/bin/env python3
# coding: utf8

import serial
import scat.util as util

class SerialIO:
    def __init__(self, port_name, baudrate=115200, rts=True, dsr=True):
        self.port = serial.Serial(port_name, baudrate=baudrate, timeout=0.5, rtscts=rts, dsrdtr=dsr)
        self.block_until_data = True

    def __enter__(self):
        return self

    def read(self, read_size, decode_hdlc = False):
        buf = b''
        buf = self.port.read(read_size)
        buf = bytes(buf)
        if decode_hdlc:
            buf = util.unwrap(buf)
        return buf

    def write(self, write_buf, encode_hdlc = False):
        if encode_hdlc:
            write_buf = util.wrap(write_buf)
        self.port.write(write_buf)

    def write_then_read_discard(self, write_buf, read_size = 0x1000, encode_hdlc = False):
        self.write(write_buf, encode_hdlc)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        self.port.close()
