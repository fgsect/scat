#!/usr/bin/env python3
# coding: utf8

import serial
import scat.util as util
from scat.iodevices.abstractio import AbstractIO

class SerialIO(AbstractIO):
    def __init__(self, port_name: str, baudrate: int=115200, rts: bool=True, dsr: bool=True):
        self.port = serial.Serial(port_name, baudrate=baudrate, timeout=0.5, rtscts=rts, dsrdtr=dsr)
        self.block_until_data = True
        self.file_available = False
        self.fname = ''

    def __enter__(self):
        return self

    def open_next_file(self) -> None:
        pass

    def read(self, read_size: int, decode_hdlc: bool = False) -> bytes:
        buf = b''
        buf = self.port.read(read_size)
        buf = bytes(buf)
        if decode_hdlc:
            buf = util.unwrap(buf)
        return buf

    def write(self, write_buf: bytes, encode_hdlc: bool = False) -> None:
        if encode_hdlc:
            write_buf = util.wrap(write_buf)
        self.port.write(write_buf)

    def write_then_read_discard(self, write_buf: bytes, read_size: int = 0x1000, encode_hdlc: bool = False) -> None:
        self.write(write_buf, encode_hdlc)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        self.port.close()
