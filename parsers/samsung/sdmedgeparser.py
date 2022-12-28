#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmEdgeParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x05: lambda x: self.sdm_edge_0x05(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_GSM_SERVING_CELL: lambda x: self.sdm_edge_gsm_serving_cell(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x10: lambda x: self.sdm_edge_0x10(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | 0x11: lambda x: self.sdm_edge_0x11(x),
        }

    def sdm_edge_0x05(self, pkt):
        pkt = pkt[11:-1]
        print(util.xxd(pkt))

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
        pkt = pkt[11:-1]
        print(util.xxd(pkt))

    def sdm_edge_0x10(self, pkt):
        pkt = pkt[11:-1]
        print(util.xxd(pkt))

    def sdm_edge_0x11(self, pkt):
        pkt = pkt[11:-1]
        print(util.xxd(pkt))