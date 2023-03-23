#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging
import binascii
from collections import namedtuple

class SdmIpParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_IP_DATA << 8) | 0x00: lambda x: self.sdm_ip_data(x),
            (sdm_command_group.CMD_IP_DATA << 8) | 0x10: lambda x: self.sdm_0x0710(x),
        }

    def set_model(self, model):
        self.model = model

    def sdm_ip_data(self, pkt):
        # Unknown: 0x0800, 0x150D
        pkt = pkt[15:-1]

        header_struct = namedtuple('SdmIpData', 'seq_num direction unknown length')
        header = header_struct._make(struct.unpack('<HHHH', pkt[0:8]))
        payload = pkt[8:]

        if header.length != len(payload):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'IP length mismatch, expected 0x{:04x}, got 0x{:04x}'.format(header.length, len(payload)))
        else:
            return {'up': [payload]}

    def sdm_0x0710(self, pkt):
        pkt = pkt[15:-1]
        header_struct = namedtuple('Sdm0x0710Data', 'seq_num direction')
        header = header_struct._make(struct.unpack('<HH', pkt[0:4]))
        payload = pkt[4:]
        return {'stdout': 'SDM 0x0710: {}, {}'.format(header, binascii.hexlify(payload).decode('utf-8'))}
