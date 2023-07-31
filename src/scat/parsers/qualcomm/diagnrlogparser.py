#!/usr/bin/env python3

from scat.parsers.qualcomm import diagcmd
import scat.util as util

import struct
from collections import namedtuple
import logging

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # NR
            0xB822: lambda x, y, z: self.parse_nr_mib_info(x, y, z), # NR RRC MIB Info
            0xB826: lambda x, y, z: self.parse_cacombos(x, y, z), # NR RRC Supported CA Combos
        }

    def parse_nr_mib_info(self, pkt_header, pkt_body, args):
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        item_struct = namedtuple('QcDiagNrMibInfo', 'pci nrarfcn props')
        scs_map = {
            0: 15,
            1: 30,
            2: 60,
            3: 120,
        }

        scs_str = ''
        if pkt_ver == 0x03: # Version 3
            item = item_struct._make(struct.unpack('<HI4s', pkt_body[4:14]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b11000000) >> 6
        elif pkt_ver == 0x20000: # Version 131072
            item = item_struct._make(struct.unpack('<HI5s', pkt_body[4:15]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b10000000) >> 7 | ((item.props[4] & 0b00000001) << 1)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MIB Information packet version {}'.format(pkt_ver))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        if scs in scs_map:
            scs_str = '{} kHz'.format(scs_map[scs])

        if len(scs_str) > 0:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}, SCS: {}'.format(item.nrarfcn, item.pci, sfn, scs_str)
        else:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}'.format(item.nrarfcn, item.pci, sfn)
        return {'stdout': stdout}

    def parse_cacombos(self, pkt_header, pkt_body, args):
        self.parent.logger.log(logging.WARNING, "0xB826 " + util.xxd_oneline(pkt_body))
