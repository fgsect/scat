#!/usr/bin/env python3
# coding: utf8

import datetime
import struct

from scat.writers.abstractwriter import AbstractWriter

class PcapWriter(AbstractWriter):
    def __init__(self, filename: str, port_cp: int = 4729, port_up: int = 47290):
        self.port_cp = port_cp
        self.port_up = port_up
        self.ip_id = 0
        self.base_address = 0x7f000001
        self.pcap_file = open(filename, 'wb')
        self.eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'
        pcap_global_hdr = struct.pack('<LHHLLLL',
                0xa1b2c3d4,
                2,
                4,
                0,
                0,
                0xffff,
                1,
                )
        self.pcap_file.write(pcap_global_hdr)

    def __enter__(self):
        return self

    def write_pkt(self, sock_content: bytes, port: int, radio_id: int=0, ts: datetime.datetime = datetime.datetime.now()) -> None:
        pcap_hdr = struct.pack('<LLLL',
                int(ts.timestamp()) % 4294967296,
                ts.microsecond,
                len(sock_content) + 8 + 20 + 14,
                len(sock_content) + 8 + 20 + 14,
                )

        if radio_id <= 0:
            dest_address = self.base_address
        else:
            dest_address = self.base_address + radio_id
        ip_hdr = struct.pack('!BBHHBBBBHLL',
                0x45,                        # version, IHL, dsf
                0x00,
                len(sock_content) + 8 + 20,  # length
                self.ip_id,                  # id
                0x40,                        # flags/fragment offset
                0x00,
                0x40,                        # TTL
                0x11,                        # proto = udp
                0xffff,                      # header checksum
                0x7f000001,                  # src address
                dest_address,                # dest address
                )
        udp_hdr = struct.pack('!HHHH',
                13337,                 # source port
                port,                  # destination port
                len(sock_content) + 8, # length
                0xffff,                # checksum
                )

        self.pcap_file.write(pcap_hdr + self.eth_hdr + ip_hdr + udp_hdr + sock_content)
        self.ip_id += 1
        if self.ip_id > 65535:
            self.ip_id = 0

    def write_cp(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now()):
        self.write_pkt(sock_content, self.port_cp, radio_id, ts)

    def write_up(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now()):
        self.write_pkt(sock_content, self.port_up, radio_id, ts)

    def __exit__(self, exc_type, exc_value, traceback):
        self.pcap_file.close()
