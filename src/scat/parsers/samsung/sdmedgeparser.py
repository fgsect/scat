#!/usr/bin/env python3

from collections import namedtuple
import binascii
import struct

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmEdgeParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_EDGE_DATA << 8)
        c = sdmcmd.sdm_edge_data
        self.process = {
            g | c.EDGE_SCELL_INFO: lambda x: self.sdm_edge_scell_info(x),
            g | c.EDGE_NCELL_INFO: lambda x: self.sdm_edge_ncell_info(x),
            g | c.EDGE_3G_NCELL_INFO: lambda x: self.sdm_edge_3g_ncell_info(x),
            g | c.EDGE_HANDOVER_INFO: lambda x: self.sdm_edge_dummy(x, 0x08),
            g | c.EDGE_HANDOVER_HISTORY_INFO: lambda x: self.sdm_edge_handover_history_info(x),
            g | c.EDGE_MEAS_INFO: lambda x: self.sdm_edge_meas_info(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def sdm_edge_dummy(self, pkt, num):
        pkt = pkt[15:-1]
        print("GSM {:#x}: {}".format(num, binascii.hexlify(pkt).decode()))

    def sdm_edge_scell_info(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmEdgeSCellInfo', '''arfcn bsic rxlev nco crh nmo lai rac cid''')
        struct_str = '<HBBBBB 5s BH'

        scell_info = header._make(struct.unpack(struct_str, pkt[0:struct.calcsize(struct_str)]))
        lai_val = util.unpack_lai(scell_info.lai)
        cid = struct.unpack('>H', struct.pack('<H',scell_info.cid))[0]

        if scell_info.arfcn > 1024:
            # Invalid measurement
            return {'stdout': ''}

        if self.display_format == 'd':
            lac_rac_cid_str = 'LAC/RAC/CID: {}/{}/{}'.format(lai_val[2], scell_info.rac, cid)
        elif self.display_format == 'x':
            lac_rac_cid_str = 'xLAC/xRAC/xCID: {:x}/{:x}/{:x}'.format(lai_val[2], scell_info.rac, cid)
        elif self.display_format == 'b':
            lac_rac_cid_str = 'LAC/RAC/CID: {}/{}/{} ({:#x}/{:#x}/{:#x})'.format(lai_val[2], scell_info.rac, cid, lai_val[2], scell_info.rac, cid)

        stdout = 'EDGE Serving Cell Info: ARFCN: {}, BSIC: {:#x}, MCC/MNC: {}/{}, {}, RxLev: {} (RSSI: {})\n'.format(
            scell_info.arfcn, scell_info.bsic, lai_val[0], lai_val[1], lac_rac_cid_str, scell_info.rxlev, scell_info.rxlev - 110,
        )

        if self.parent:
            self.parent.gsm_last_arfcn[sdm_pkt_hdr.radio_id] = scell_info.arfcn

        return {'stdout': stdout.rstrip()}

    def sdm_edge_ncell_info(self, pkt):
        pkt = pkt[15:-1]
        stdout = ''
        num_identified_cells = pkt[0]
        num_ncells = pkt[109]

        if num_identified_cells > 6:
            num_identified_cells = 6
        if num_ncells > 10:
            num_ncells = 10

        if (num_identified_cells + num_ncells) > 0:
            stdout += 'EDGE Neighbor Cell Info: Identified: {}, Neighbor: {}\n'.format(
                num_identified_cells, num_ncells)

        pos = 1
        identified_meas = namedtuple('SdmEdgeNCellIdCell', 'arfcn bsic rxlev c1 c2 c31 c32 unk lai gprs_raclr')
        for i in range(num_identified_cells):
            identified_meas_pkt = identified_meas._make(struct.unpack('<HBBbbhhH5sb', pkt[pos:pos+18]))

            lai_val = util.unpack_lai(identified_meas_pkt.lai)
            if self.display_format == 'd':
                lai_str = 'MCC/MNC: {}/{}, LAC: {}'.format(*lai_val)
            elif self.display_format == 'x':
                lai_str = 'MCC/MNC: {}/{}, xLAC: {:x}'.format(*lai_val)
            elif self.display_format == 'b':
                lai_str = 'MCC/MNC: {}/{}, LAC: {} ({:#x})'.format(*lai_val, lai_val[2])

            stdout += "EDGE Neighbor Cell Info: Identified Cell {}: ARFCN: {}, {}, C1: {}, C2: {}, C31: {}, C32: {}, GPRS RA Colour: {}, RxLev: {} (RSSI: {})\n".format(
                i, identified_meas_pkt.arfcn, lai_str, identified_meas_pkt.c1, identified_meas_pkt.c2,
                identified_meas_pkt.c31, identified_meas_pkt.c32,
                identified_meas_pkt.gprs_raclr, identified_meas_pkt.rxlev, identified_meas_pkt.rxlev - 110,
            )
            pos += 18

        pos = 110
        n_meas = namedtuple('SdmEdgeNCellNCell', 'arfcn rxlev')
        for i in range(num_ncells):
            n_meas_pkt = n_meas._make(struct.unpack('<HB', pkt[pos:pos+3]))
            stdout += "EDGE Neighbor Cell Info: Neighbor Cell {}: ARFCN: {}, RxLev: {} (RSSI: {})\n".format(
                i, n_meas_pkt.arfcn, n_meas_pkt.rxlev, n_meas_pkt.rxlev - 110
            )
            pos += 3

        return {'stdout': stdout.rstrip()}

    def sdm_edge_3g_ncell_info(self, pkt):
        pkt = pkt[15:-1]
        stdout = ''
        num_3g_cells = pkt[0]

        if num_3g_cells > 10:
            num_3g_cells = 10

        if num_3g_cells > 0:
            stdout += 'EDGE 3G Neighbor Cell Info: {} Cells\n'.format(num_3g_cells)

        pos = 1
        n_meas = namedtuple('SdmEdge3GNCellNCell', 'uarfcn psc rssi rscp ecno')
        for i in range(num_3g_cells):
            n_meas_pkt = n_meas._make(struct.unpack('<HHBBB', pkt[pos:pos+7]))
            stdout += "NCell {}: UARFCN: {}, PSC: {}, RSSI: {}, RSCP: {}, Ec/No: {}\n".format(
                i, n_meas_pkt.uarfcn, n_meas_pkt.psc,
                n_meas_pkt.rssi, n_meas_pkt.rscp * -1, n_meas_pkt.ecno / -10
            )
            pos += 7

        return {'stdout': stdout.rstrip()}

    def sdm_edge_handover_info(self, pkt):
        return {'stdout': ''}

    def sdm_edge_handover_history_info(self, pkt):
        pkt = pkt[15:-1]
        header_234 = namedtuple('SdmEdgeHandoverHistoryInfo234', 'arfcn bsic uarfcn psc earfcn pci')
        stdout = ''

        if len(pkt) >= 12:
            ho_history_info = header_234._make(struct.unpack('<HHHHHH', pkt[0:12]))
            extra = pkt[12:]
        elif len(pkt) >= 8:
            ho_history_info = header_234._make(struct.unpack('<HHHH', pkt[0:8]) + (0xffff, 0xffff))
            extra = pkt[8:]
        else:
            ho_history_info = None
            extra = pkt

        if ho_history_info:
            stdout += 'EDGE Handover History Info: '
            if ho_history_info.arfcn != 0xffff:
                stdout += 'ARFCN: {}/BSIC: {} '.format(ho_history_info.arfcn, ho_history_info.bsic)
            if ho_history_info.uarfcn != 0xffff:
                stdout += 'UARFCN: {}/PSC: {} '.format(ho_history_info.uarfcn, ho_history_info.psc)
            if ho_history_info.earfcn != 0xffff:
                stdout += 'EARFCN: {}/PCI: {} '.format(ho_history_info.earfcn, ho_history_info.pci)
            stdout += '\n'

        if len(extra) > 0:
            stdout += 'Extra: {}\n'.format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_edge_meas_info(self, pkt):
        pkt = pkt[15:-1]
        header_s = namedtuple('SdmEdgeSCellMeasInfo', 'arfcn bsic rxlev rxlev_p rxq_p rxlev_s rxq_s txlev')
        header_n = namedtuple('SdmEdgeNCellMeasInfo', 'arfcn bsic rxlev unk')

        scell_meas_info = header_s._make(struct.unpack('<HHHHHHHH', pkt[0:16]))
        extra = pkt[16:]

        if scell_meas_info.arfcn < 1024 and scell_meas_info.rxlev > 0:
            stdout = 'EDGE Measurement Info (Serving Cell): ARFCN: {}, BSIC: {:#04x}, RxLev: {} (RSSI: {}), TxLev: {}\n'.format(
                scell_meas_info.arfcn, scell_meas_info.bsic,
                scell_meas_info.rxlev, scell_meas_info.rxlev - 110, scell_meas_info.txlev)
        else:
            stdout = ''

        for i in range(int(len(extra)/10)):
            ncell_meas_info = header_n._make(struct.unpack('<HHHL', extra[i*10:(i+1)*10]))
            if ncell_meas_info.arfcn < 1024 and ncell_meas_info.rxlev > 0:
                stdout += 'EDGE Measurement Info (Neighbor Cell): ARFCN: {}, BSIC: {:#04x}, RxLev: {} (RSSI: {})\n'.format(
                    ncell_meas_info.arfcn, ncell_meas_info.bsic & 0b111111,
                    ncell_meas_info.rxlev, ncell_meas_info.rxlev - 110)

        return {'stdout': stdout.rstrip()}
