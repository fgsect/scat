#!/usr/bin/env python3
# coding: utf8

import socket
import struct

class SocketWriter:
    def __init__(self, base_address, port_cp = 4729, port_up = 47290):
        self.base_address = struct.unpack('!I', socket.inet_pton(socket.AF_INET, base_address))[0]
        self.port_cp = port_cp
        self.sock_cp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_cp_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.port_up = port_up
        self.sock_up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_up_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __enter__(self):
        return self

    def write_cp(self, sock_content, radio_id=0, ts=None):
        if radio_id <= 0:
            dest_address = self.base_address
        else:
            dest_address = self.base_address + radio_id
        dest_address_str = socket.inet_ntoa(struct.pack('!I', dest_address))
        self.sock_cp.sendto(sock_content, (dest_address_str, self.port_cp))

    def write_up(self, sock_content, radio_id=0, ts=None):
        if radio_id <= 0:
            dest_address = self.base_address
        else:
            dest_address = self.base_address + radio_id
        dest_address_str = socket.inet_ntoa(struct.pack('!I', dest_address))
        self.sock_up.sendto(sock_content, (dest_address_str, self.port_up))

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock_cp_recv.close()
        self.sock_up_recv.close()
