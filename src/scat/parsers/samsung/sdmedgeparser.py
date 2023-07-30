#!/usr/bin/env python3

from scat.parsers.samsung.sdmcmd import *
import scat.util as util

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
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_SCELL_INFO: lambda x: self.sdm_edge_scell_info(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_NCELL_INFO: lambda x: self.sdm_edge_dummy(x, 0x06),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_3G_NCELL_INFO: lambda x: self.sdm_edge_dummy(x, 0x07),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_HANDOVER_INFO: lambda x: self.sdm_edge_dummy(x, 0x08),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_HANDOVER_HISTORY_INFO: lambda x: self.sdm_edge_dummy(x, 0x09),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_MEAS_INFO: lambda x: self.sdm_edge_dummy(x, 0x0b),
        }

    def set_model(self, model):
        self.model = model

    def sdm_edge_dummy(self, pkt, num):
        pkt = pkt[15:-1]
        print("GSM {:#x}: {}".format(num, binascii.hexlify(pkt).decode('utf-8')))

    def sdm_edge_scell_info(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmEdgeSCellInfo', '''arfcn bsic rxlev nco crh nmo
        lai rac cid''')
        struct_str = '<HBBBBB 5s BH'

        scell_info = header._make(struct.unpack(struct_str, pkt[0:struct.calcsize(struct_str)]))
        plmn_str = util.unpack_mcc_mnc(scell_info.lai[0:3])
        lac = struct.unpack('>H', scell_info.lai[3:5])[0]
        cid = struct.unpack('>H', struct.pack('<H',scell_info.cid))[0]

        stdout = 'EDGE Serving Cell Info: ARFCN: {}, BSIC: {:#x}, RxLev: {}, PLMN: MCC {:x}/MNC {:x}, LAC: {:#x}, RAC: {:#x}, CID: {:#x}\n'.format(
            scell_info.arfcn, scell_info.bsic, scell_info.rxlev - 110, plmn_str[0], plmn_str[1], lac, scell_info.rac, cid
        )

        return {'stdout': stdout.rstrip()}

    def sdm_edge_ncell_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_3g_ncell_info(self, pkt):
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
        return {'stdout': ''}

    def sdm_edge_handover_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_handover_history_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_meas_info(self, pkt):
        return {'stdout': ''}
