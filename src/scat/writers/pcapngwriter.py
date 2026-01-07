#!/usr/bin/env python3
# coding: utf8

import struct
import datetime

from scat.writers.abstractwriter import AbstractWriter

class PcapngWriter(AbstractWriter):
    def __init__(self, filename: str, port_cp: int = 4729, port_up: int = 47290,
                 shb_options: list[bytes] = None, idb_options: list[bytes] = None):
        self.port_cp = port_cp
        self.port_up = port_up
        self.ip_id = 0
        self.base_address = 0x7f000001
        self.pcapng_file = open(filename, 'wb')
        self.eth_hdr = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00'

        # Section Header Block (SHB)
        shb_content = struct.pack('<LHHQ',
                0x1a2b3c4d,           # Byte-order magic
                0x0001,                   # Major version
                0x0000,                   # Minor version
                0xffffffffffffffff,       # Section length (size unknown)
        )

        shb_options_data = b''
        if shb_options is not None and len(shb_options) > 0:

            shb_options_data = b''.join(shb_options)
            shb_options_data += struct.pack('<HH',
                                        0,  # 00 00 = opt_endofopt
                                        0  # 00 00 = opt_endofopt length (must be 0)
                                        )

        section_header_block = self._create_pcapng_block(0x0a0d0d0a, shb_content + shb_options_data)

        # Interface Description Block (IDB)
        idb_content = struct.pack('<HxxL',
                0x0001,         # Link type (Ethernet)
                0x00000000,         # Snap length (no limit)
                )

        idb_options_data = b''
        if idb_options is not None and len(idb_options) > 0:
            idb_options_data = b''.join(idb_options)
            idb_options_data += struct.pack('<HH',
                                            0,  # 00 00 = opt_endofopt
                                            0  # 00 00 = opt_endofopt length (must be 0)
                                            )

        interface_description_block = self._create_pcapng_block(0x00000001, idb_content + idb_options_data)

        self.pcapng_file.write(section_header_block)
        self.pcapng_file.write(interface_description_block)

    def __enter__(self):
        return self

    def write_epb(self, sock_content: bytes, port: int, radio_id: int=0, ts: datetime.datetime = datetime.datetime.now(), epb_options: list[bytes] = None) -> None:

        if radio_id <= 0:
            dest_address = self.base_address
        else:
            dest_address = self.base_address + radio_id

        ip_hdr = struct.pack('!BBHHBBBBHLL',
                             0x45,  # version, IHL, dsf
                             0x00,
                             len(sock_content) + 8 + 20,  # length
                             self.ip_id,  # id
                             0x40,  # flags/fragment offset
                             0x00,
                             0x40,  # TTL
                             0x11,  # proto = udp
                             0xffff,  # header checksum
                             0x7f000001,  # src address
                             dest_address,  # dest address
                             )
        udp_hdr = struct.pack('!HHHH',
                              13337,  # source port
                              port,  # destination port
                              len(sock_content) + 8,  # length
                              0xffff,  # checksum
                              )

        packet_data = self.eth_hdr + ip_hdr + udp_hdr + sock_content

        # Enhanced Packet Block (EPB)

        timestamp_us = int(ts.timestamp() * 1000000)
        timestamp_upper = (timestamp_us >> 32) & 0xFFFFFFFF
        timestamp_lower = timestamp_us & 0xFFFFFFFF

        epb_header = struct.pack('<LLLLL',
                   0,             # Interface ID
                   timestamp_upper,   # Timestamp (high)
                   timestamp_lower,   # Timestamp (low)
                   len(packet_data),  # Captured packet length
                   len(packet_data),  # Original packet length
                   )

        options_data = b''
        if epb_options is not None and len(epb_options) > 0:
            padding_len = (4 - (len(packet_data) % 4)) % 4  # outer %4 for case where len(packet_data) % 4 == 0
            packet_data = packet_data + b'\x00' * padding_len

            options_data = b''.join(epb_options)
            options_data += struct.pack('<HH',
                                        0,  # 00 00 = opt_endofopt
                                        0       # 00 00 = opt_endofopt length (must be 0)
                                        )

        epb_content = epb_header + packet_data + options_data
        enhanced_packet_block = self._create_pcapng_block(0x00000006, epb_content)
        self.pcapng_file.write(enhanced_packet_block)

        self.ip_id += 1
        if self.ip_id > 65535:
            self.ip_id = 0

    def write_cp(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now()):
        self.write_epb(sock_content, self.port_cp, radio_id, ts)

    def write_up(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now()):
        self.write_epb(sock_content, self.port_up, radio_id, ts)

    def write_ng_cp(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now(), epb_options: list[bytes] = None):
        self.write_epb(sock_content, self.port_cp, radio_id, ts, epb_options)

    def write_ng_up(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime=datetime.datetime.now(), epb_options: list[bytes] = None):
        self.write_epb(sock_content, self.port_up, radio_id, ts, epb_options)

    def __exit__(self, exc_type, exc_value, traceback):
        self.pcapng_file.close()

    @classmethod
    def create_comment_option(cls, comment: str) -> bytes:

        comment_bytes = comment.encode('utf-8')

        option = struct.pack('<HH',
                             1,                 # option type (1 for comment)
                             len(comment_bytes)     # option length
                             )
        option += comment_bytes

        padding_len = (4 - (len(option) % 4)) % 4  # outer %4 for case where len(option) % 4 == 0
        option += b'\x00' * padding_len

        return option

    def _create_pcapng_block(self, block_type: int, content: bytes) -> bytes:

        padding_len = (4 - (len(content) % 4)) % 4  # outer %4 for case where len(content) % 4 == 0
        padded_content = content + b'\x00' * padding_len

        block_length = (4    # block type
                        + 4  # block length
                        + len(padded_content)
                        + 4  # block length
                        )

        block = struct.pack('<LL', block_type, block_length)
        block += padded_content
        block += struct.pack('<L', block_length)

        return block
