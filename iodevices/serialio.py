#!/usr/bin/env python3
# coding: utf8

import serial

class SerialIO:
    def __init__(self, port_name):
        self.port = serial.Serial(port_name, baudrate=115200, timeout=0.1, rtscts=True, dsrdtr=True)
        self.block_until_data = True

    def __enter__(self):
        return self

    def read(self, read_size):
        buf = b''
        buf = self.port.read(read_size)
        buf = bytes(buf)
        return buf

    def write(self, write_buf):
        self.port.write(write_buf)

    def write_then_read_discard(self, write_buf, read_size):
        self.write(write_buf)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        self.port.close()
