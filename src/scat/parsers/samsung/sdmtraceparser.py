#!/usr/bin/env python3

import struct
import logging
import binascii
from collections import namedtuple

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmTraceParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        g = (sdmcmd.sdm_command_group.CMD_TRACE_DATA << 8)
        self.process = {
            g | 0x90: lambda x: self.sdm_trace_0x90(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def sdm_trace_0x90(self, pkt):
        pkt = pkt[15:-1]

        if self.parent:
            if not self.parent.trace:
                return None

        item_struct = namedtuple('SdmTrace0x90', 'trace_item_id trace_item_level')
        item = item_struct._make(struct.unpack('<HH', pkt[0:4]))
        content = pkt[4:]

        item_str = ''

        if self.parent and self.parent.trace_group:
            if item.trace_item_id in self.parent.trace_group:
                item_str = '{} ({:#x})'.format(self.parent.trace_group[item.trace_item_id][0],
                                               item.trace_item_id)
            else:
                item_str = 'UNKNOWN ({:#x})'.format(item.trace_item_id)
        else:
            item_str = 'UNKNOWN ({:#x})'.format(item.trace_item_id)

        # could be some offset? content length = 972, increment 976
        stdout = "Trace Response: {} {:#x}, Body: {}".format(item_str,
            item.trace_item_level, binascii.hexlify(pkt).decode('utf-8'))
        return {'stdout': stdout.rstrip()}
