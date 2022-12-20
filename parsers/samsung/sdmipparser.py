#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmIpParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            (sdm_command_group.CMD_IP_DATA << 8) | 0x00: lambda x: self.sdm_ip_data(x),
        }

    def sdm_ip_data(self, pkt):
        pkt = pkt[11:-1]

        ip_hdr = struct.unpack('<BLHHHH', pkt[0:13])
        # 00 ts(uint32) stamp(uint16) dir(uint16) ?(uint16) len(uint16)
        # 0: Data type (0x00: IP, 0x10: Unknown)
        # 1: TS
        # 2: Packet #
        # 3: Direction
        # 4: Unknown
        # 5: Length
        ip_payload = pkt[13:]

        if ip_hdr[0] == 0x00:
            if ip_hdr[5] != len(ip_payload):
                self.parent.logger.log(logging.WARNING, 'IP length mismatch, expected %04x, got %04x' % (ip_hdr[5], len(ip_payload)))
            return {'up': ip_payload}
