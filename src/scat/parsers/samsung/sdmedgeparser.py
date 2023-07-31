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
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_3G_NCELL_INFO: lambda x: self.sdm_edge_3g_ncell_info(x),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_HANDOVER_INFO: lambda x: self.sdm_edge_dummy(x, 0x08),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_HANDOVER_HISTORY_INFO: lambda x: self.sdm_edge_dummy(x, 0x09),
            (sdm_command_group.CMD_EDGE_DATA << 8) | sdm_edge_data.EDGE_MEAS_INFO: lambda x: self.sdm_edge_meas_info(x),
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

        if scell_info.arfcn > 1024:
            # Invalid measurement
            return {'stdout': ''}

        stdout = 'EDGE Serving Cell Info: ARFCN: {}, BSIC: {:#x}, RxLev: {} (RSSI: {}), PLMN: MCC {:x}/MNC {:x}, LAC: {:#x}, RAC: {:#x}, CID: {:#x}\n'.format(
            scell_info.arfcn, scell_info.bsic, scell_info.rxlev, scell_info.rxlev - 110, plmn_str[0], plmn_str[1], lac, scell_info.rac, cid
        )

        return {'stdout': stdout.rstrip()}

    def sdm_edge_ncell_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_3g_ncell_info(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        stdout = ''
        num_3g_cells = pkt[0]

        if num_3g_cells > 10:
            num_3g_cells = 10

        stdout += 'EDGE 3G Neighbor Cell Info: {} Cells\n'.format(num_3g_cells)

        pos = 1
        n_meas = namedtuple('SdmEdge3GNCellNCell', 'uarfcn psc rssi rscp ecno')
        for i in range(num_3g_cells):
            n_meas_pkt = n_meas._make(struct.unpack('<HHBBB', pkt[pos:pos+7]))
            stdout += "NCell {}: UARFCN {}, PSC {}, RSSI {}, RSCP {}, Ec/No {}\n".format(
                i, n_meas_pkt.uarfcn, n_meas_pkt.psc,
                n_meas_pkt.rssi, n_meas_pkt.rscp * -1, n_meas_pkt.ecno / -10
            )
            pos += 7

        return {'stdout': stdout.rstrip()}

    def sdm_edge_handover_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_handover_history_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_meas_info(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header_s = namedtuple('SdmEdgeSCellMeasInfo', 'arfcn bsic rxlev rxlev_p rxq_p rxlev_s rxq_s txlev')
        header_n = namedtuple('SdmEdgeNCellMeasInfo', 'arfcn bsic rxlev unk')

        scell_meas_info = header_s._make(struct.unpack('<HHHHHHHH', pkt[0:16]))
        extra = pkt[16:]

        if scell_meas_info.arfcn < 1024:
            stdout = 'EDGE Measurement Info (Serving Cell): ARFCN {}, BSIC {:#04x}, RxLev {} (RSSI {}), TxLev {}\n'.format(
                scell_meas_info.arfcn, scell_meas_info.bsic,
                scell_meas_info.rxlev, scell_meas_info.rxlev - 110, scell_meas_info.txlev)
        else:
            stdout = ''

        for i in range(int(len(extra)/10)):
            ncell_meas_info = header_n._make(struct.unpack('<HHHL', extra[i*10:(i+1)*10]))
            if ncell_meas_info.arfcn < 1024:
                stdout += 'EDGE Measurement Info (Neighbor Cell): ARFCN {}, BSIC {:#04x}, RxLev {} (RSSI {})\n'.format(
                    ncell_meas_info.arfcn, ncell_meas_info.bsic & 0b111111,
                    ncell_meas_info.rxlev, ncell_meas_info.rxlev - 110)

        return {'stdout': stdout.rstrip()}
