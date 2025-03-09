#!/usr/bin/env python3

import struct
import logging
import binascii
from collections import namedtuple

import scat.parsers.samsung.sdmcmd as sdmcmd

class SdmIpParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        g = (sdmcmd.sdm_command_group.CMD_IP_DATA << 8)
        self.process = {
            g | 0x00: lambda x: self.sdm_ip_data(x),
            g | 0x10: lambda x: self.sdm_0x0710(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def sdm_ip_data(self, pkt):
        pkt = pkt[15:-1]

        header_struct = namedtuple('SdmIpData', 'seq_num direction ethertype length')
        header = header_struct._make(struct.unpack('<HHHH', pkt[0:8]))
        payload = pkt[8:]

        if header.length != len(payload):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'IP length mismatch, expected 0x{:04x}, got 0x{:04x}'.format(header.length, len(payload)))
        else:
            return {'layer': 'ip', 'up': [payload]}

    def sdm_0x0710(self, pkt):
        pkt = pkt[15:-1]
        header_struct = namedtuple('Sdm0x0710Data', 'seq_num direction')
        header = header_struct._make(struct.unpack('<HH', pkt[0:4]))
        payload = pkt[4:]
        return {'stdout': 'SDM 0x0710: {}, {}'.format(header, binascii.hexlify(payload).decode())}
