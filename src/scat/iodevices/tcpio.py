#!/usr/bin/env python3
# coding: utf8

import sys
from socket import socket, AF_INET, SOCK_STREAM
import scat.util as util
from scat.iodevices.abstractio import AbstractIO

class TCPIO(AbstractIO):
    def __init__(self, address: str, port: int):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.block_until_data = True
        
        try:
            self.socket.connect((address, port))
            self.socket.settimeout(0.1)
        except ConnectionRefusedError as e:
            print(f'Error: Port connection refused addr: {address}:{port} is diag running?')
            sys.exit(1)

    def open_next_file(self) -> None:
        pass

    def read(self, read_size: int, decode_hdlc: bool = False) -> bytes:
        try:
            buf = self.socket.recv(read_size)
            if decode_hdlc:
                buf = util.unwrap(buf)
            return buf
        except TimeoutError:
            return b''
    
    def write(self, write_buf: bytes, encode_hdlc:bool = False) -> None:
        if encode_hdlc:
            write_buf: bytes = util.wrap(write_buf)
        self.socket.send(write_buf)
    
    def write_then_read_discard(self, write_buf: bytes, read_size: int = 0x1000, encode_hdlc: bool = False) -> None:
        self.write(write_buf, encode_hdlc)
        self.read(read_size)

    def __exit__(self, exc_type, exc_value, traceback):
        self.socket.close()
    