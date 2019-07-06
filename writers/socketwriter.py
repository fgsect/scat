#!/usr/bin/env python3
# coding: utf8

import socket

class SocketWriter:
    def __init__(self, ip_cp, port_cp, ip_up, port_up):
        self.ip_cp = ip_cp
        self.port_cp = port_cp
        self.sock_cp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_cp_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.ip_up = ip_up
        self.port_up = port_up
        self.sock_up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_up_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __enter__(self):
        return self

    def write_cp(self, sock_content, ts=None):
        self.sock_cp.sendto(sock_content, (self.ip_cp, self.port_cp))

    def write_up(self, sock_content, ts=None):
        self.sock_up.sendto(sock_content, (self.ip_up, self.port_up))

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock_cp_recv.close()
        self.sock_up_recv.close()
