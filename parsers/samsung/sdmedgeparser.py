#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging
import binascii
from collections import namedtuple

class SdmEdgeParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x00: lambda x: self.sdm_edge_dummy(x, 0x00),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x01: lambda x: self.sdm_edge_dummy(x, 0x01),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x02: lambda x: self.sdm_edge_dummy(x, 0x02),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x03: lambda x: self.sdm_edge_dummy(x, 0x03),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x04: lambda x: self.sdm_edge_dummy(x, 0x04),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x05: lambda x: self.sdm_edge_dummy(x, 0x05),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x06: lambda x: self.sdm_edge_dummy(x, 0x06),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_3G_NCELL_INFO: lambda x: self.sdm_edge_gsm_serving_cell(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x08: lambda x: self.sdm_edge_dummy(x, 0x08),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x09: lambda x: self.sdm_edge_dummy(x, 0x09),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0a: lambda x: self.sdm_edge_dummy(x, 0x0a),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0b: lambda x: self.sdm_edge_dummy(x, 0x0b),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0c: lambda x: self.sdm_edge_dummy(x, 0x0c),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0d: lambda x: self.sdm_edge_dummy(x, 0x0d),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0e: lambda x: self.sdm_edge_dummy(x, 0x0e),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x0f: lambda x: self.sdm_edge_dummy(x, 0x0f),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x10: lambda x: self.sdm_edge_dummy(x, 0x10),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x11: lambda x: self.sdm_edge_dummy(x, 0x11),
        }

    def sdm_edge_dummy(self, pkt, num):
        pkt = pkt[15:-1]
        print("GSM {:#x}: {}".format(num, binascii.hexlify(pkt).decode('utf-8')))
        # 2c00 | 3d | 22 | 00 | 08 | 01 | 62f220 | 01 | 3401 | 2e06 | 0001 0001 01 000000000000000021011c1cffffffffc202

    def sdm_edge_0x05(self, pkt):
        pkt = pkt[15:-1]
        print("GSM 0x05: {}".format(binascii.hexlify(pkt).decode('utf-8')))
        # 2c00 | 3d | 22 | 00 | 08 | 01 | 62f220 | 01 | 3401 | 2e06 | 0001 0001 01 000000000000000021011c1cffffffffc202

    def sdm_edge_gsm_serving_cell(self, pkt):
        '''
        0x07: 'GsmServ',
            "bsic",  '>B',  1 bytes, pos:20, # 7bit
            "arfcn", '>H',  2 bytes, pos:26, # 10bit
            "mcc",   '<2s', 2 bytes, pos:39, # bcd encoded
            "mnc",   '<1s', 1 bytes, pos:41, # bcd encoded
            "lac",   '>H',  2 bytes, pos:42,
            "cid",   '>H',  2 bytes, pos:45,
        ], []),
        if pkt[0] == 0x07:
        '''
        pkt = pkt[15:-1]
        print("GSM 0x07: {}".format(binascii.hexlify(pkt).decode('utf-8')))
        # 00000000a843c745989153645c99d5420f0000000200000054b6c5455003c8427918164200000000 | 2c003d2200080162f2200134989153647d02000000000000420000004838e4

    def sdm_edge_0x10(self, pkt):
        pkt = pkt[15:-1]
        print("GSM 0x10: {}".format(binascii.hexlify(pkt).decode('utf-8')))

    def sdm_edge_0x11(self, pkt):
        pkt = pkt[15:-1]
        print("GSM 0x11: {}".format(binascii.hexlify(pkt).decode('utf-8')))
        #                          | P-TMSI   |        | RAC  | LAC  | TMSI
        # 022f2600 00000000 000301 | f1dd934d | 000134 | 0100 | 3401 | 0c43177d |000001010000020000010000000000000000000000000000000000000000000000000000
        # 022f2600 00000000 000201 | f6dd9361 | 000134 | 0100 | 3401 | 0c43177d |000001010000040000010000000000000000000000000000000000000000000000000000