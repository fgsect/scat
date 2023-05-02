#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar
import logging
from collections import namedtuple

class DiagLteLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.no_process = {
        }

        self.process = {
            # LTE
            # LTE ML1
            #0xB179: lambda x, y, z: self.parse_lte_ml1_connected_intra_freq_meas(x, y, z), # LTE ML1 Connected Mode LTE Intra-Freq Measurements
            0xB17F: lambda x, y, z: self.parse_lte_ml1_scell_meas(x, y, z), # LTE ML1 Serving Cell Meas and Eval
            0xB180: lambda x, y, z: self.parse_lte_ml1_ncell_meas(x, y, z), # LTE ML1 Neighbor Measurements
            #0xB181 LTE ML1 Intra Frequency Cell Reselection
            #0xB192: lambda x, y, z: self.parse_lte_ml1_ncell_meas_rr(x, y, z), # LTE ML1 Neighbor Cell Meas Request/Response
            0xB193: lambda x, y, z: self.parse_lte_ml1_scell_meas_response(x, y, z), # LTE ML1 Serving Cell Meas Response
            #0xB194: lambda x, y, z: self.parse_lte_ml1_search_rr(x, y, z), # LTE ML1 Search Request/Response
            #0xB195: lambda x, y, z: self.parse_lte_ml1_connected_ncell_meas_rr(x, y, z), # LTE ML1 Connected Neighbor Meas Request/Response
            0xB197: lambda x, y, z: self.parse_lte_ml1_cell_info(x, y, z), # LTE ML1 Serving Cell Info

            # LTE MAC
            #0xB167: lambda x, y, z: parse_lte_msg1_report(x, y, z), # LTE RAR (Msg1) Report
            #0xB168: lambda x, y, z: parse_lte_msg2_report(x, y, z), # LTE RAR (Msg2) Report
            #0xB169: lambda x, y, z: parse_lte_msg3_report(x, y, z), # LTE UE Identification Message (Msg3) Report
            #0xB16A: lambda x, y, z: parse_lte_msg3_report(x, y, z), # LTE Contention Resolution Message (Msg4) Report
            0xB061: lambda x, y, z: self.parse_lte_mac_rach_trigger(x, y, z), # LTE MAC RACH Trigger
            0xB062: lambda x, y, z: self.parse_lte_mac_rach_response(x, y, z), # LTE MAC RACH Response
            0xB063: lambda x, y, z: self.parse_lte_mac_dl_block(x, y, z), # LTE MAC DL Transport Block
            0xB064: lambda x, y, z: self.parse_lte_mac_ul_block(x, y, z), # LTE MAC UL Transport Block

            # LTE RLC

            # LTE PDCP
            #0xB0A0: lambda x, y, z: self.parse_lte_pdcp_dl_cfg(x, y, z), # LTE PDCP DL Config
            #0xB0B0: lambda x, y, z: self.parse_lte_pdcp_ul_cfg(x, y, z), # LTE PDCP UL Config
            #0xB0A1: lambda x, y, z: self.parse_lte_pdcp_dl_data(x, y, z), # LTE PDCP DL Data PDU
            #0xB0B1: lambda x, y, z: self.parse_lte_pdcp_ul_data(x, y, z), # LTE PDCP UL Data PDU
            #0xB0A2: lambda x, y, z: self.parse_lte_pdcp_dl_ctrl(x, y, z), # LTE PDCP DL Ctrl PDU
            #0xB0B2: lambda x, y, z: self.parse_lte_pdcp_ul_ctrl(x, y, z), # LTE PDCP UL Ctrl PDU
            0xB0A3: lambda x, y, z: self.parse_lte_pdcp_dl_cip(x, y, z), # LTE PDCP DL Cipher Data PDU
            0xB0B3: lambda x, y, z: self.parse_lte_pdcp_ul_cip(x, y, z), # LTE PDCP UL Cipher Data PDU
            0xB0A5: lambda x, y, z: self.parse_lte_pdcp_dl_srb_int(x, y, z), # LTE PDCP DL SRB Integrity Data PDU
            0xB0B5: lambda x, y, z: self.parse_lte_pdcp_ul_srb_int(x, y, z), # LTE PDCP UL SRB Integrity Data PDU

            # LTE RRC
            0xB0C0: lambda x, y, z: self.parse_lte_rrc(x, y, z), # LTE RRC OTA Message
            0xB0C1: lambda x, y, z: self.parse_lte_mib(x, y, z), # LTE RRC MIB Message
            0xB0C2: lambda x, y, z: self.parse_lte_rrc_cell_info(x, y, z), # LTE RRC Serving Cell Info

            # LTE CA COMBOS
            # 0xB0CD: lambda x, y, z: self.parse_cacombos(x, y, z),

            # LTE NAS
            0xB0E0: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS ESM RX Enc
            0xB0E1: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS ESM TX Enc
            0xB0EA: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS EMM RX Enc
            0xB0EB: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS EMM TX Enc
            0xB0E2: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS ESM RX
            0xB0E3: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS ESM TX
            0xB0EC: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS EMM RX
            0xB0ED: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS EMM TX
        }

    # LTE

    def parse_lte_ml1_scell_meas(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        item_struct = namedtuple('QcDiagLteMl1ScellMeas', 'rrc_rel reserved1 earfcn pci_serv_layer_prio meas_rsrp avg_rsrp rsrq rssi rxlev s_search')
        if pkt_version == 4: # Version 4
            # Version, RRC standard release, EARFCN, PCI - Serving Layer Priority
            # Measured, Average RSRP, Measured, Average RSRQ, Measured RSSI
            # Q_rxlevmin, P_max, Max UE TX Power, S_rxlev, Num DRX S Fail
            # S Intra Searcn, S Non Intra Search, Meas Rules Updated, Meas Rules
            # R9 Info (last 4b) - Q Qual Min, S Qual, S Intra Search Q, S Non Intra Search Q
            item = item_struct._make(struct.unpack('<BHHHLLLLLL', pkt_body[1:32]))
        elif pkt_version == 5: # Version 5
            # EARFCN -> 4 bytes
            # PCI, Serv Layer Priority -> 4 bytes
            item = item_struct._make(struct.unpack('<BHLLLLLLLL', pkt_body[1:36]))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet version 0x{:02x}'.format(pkt_version))
            return None

        pci = item.pci_serv_layer_prio & 0x1ff
        serv_layer_priority = item.pci_serv_layer_prio >> 9
        meas_rsrp = item.meas_rsrp & 0xfff
        avg_rsrp = item.avg_rsrp & 0xfff

        meas_rsrq = item.rsrq & 0x3ff
        avg_rsrq = (item.rsrq >> 20) & 0x3ff

        meas_rssi = (item.rssi >> 10) # TODO: get to know exact bit mask

        q_rxlevmin = item.rxlev & 0x3f
        p_max = (item.rxlev >> 6) & 0x7f
        max_ue_tx_pwr = (item.rxlev >> 13) & 0x3f
        s_rxlev = (item.rxlev >> 19) & 0x7f
        num_drx_s_fail = (item.rxlev >> 26)

        s_intra_search = item.s_search & 0x3f
        s_non_intra_search = (item.s_search >> 6) & 0x3f

        if pkt_version == 4:
            if item.rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt_body[32:36])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(item.rrc_rel))
        elif pkt_version == 5:
            if item.rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt_body[36:40])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(item.rrc_rel))

        real_rsrp = -180 + meas_rsrp * 0.0625
        real_rssi = -110 + meas_rssi * 0.0625
        real_rsrq = -30 + meas_rsrq * 0.0625

        return {'stdout': 'LTE SCell: EARFCN {}, PCI {:3d}, Measured RSRP {:.2f}, Measured RSSI {:.2f}'.format(item.earfcn, pci, real_rsrp, real_rssi)}

    def parse_lte_ml1_ncell_meas(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        stdout = ''

        item_struct = namedtuple('QcDiagLteMl1NcellMeas', 'rrc_rel reserved1 earfcn q_rxlevmin_n_cells')
        n_cell_struct = namedtuple('QcDiagLteMl1NcellMeasNcell', 'val0 val1 val2 val3 n_freq_offset val5 ant0_offset ant1_offset')

        pos = 0
        if pkt_version == 4: # Version 4
            # Version, RRC standard release, EARFCN, Q_rxlevmin, Num Cells, Cell Info
            # Cell Info - PCI, Measured RSSI, Measured RSRP, Average RSRP
            #    Measured RSRQ, Average RSRQ, S_rxlev, Freq Offset
            #    Ant0 Frame Offset, Ant0 Sample Offset, Ant1 Frame Offset, Ant1 Sample Offset
            #    S_qual
            item = item_struct._make(struct.unpack('<BHHH', pkt_body[1:8]))
            pos = 8
        elif pkt_version == 5: # Version 5
            # EARFCN -> 4 bytes
            item = item_struct._make(struct.unpack('<BHLL', pkt_body[1:12]))
            pos = 12
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Meas packet version 0x{:02x}'.format(pkt_version))
            return None

        q_rxlevmin = item.q_rxlevmin_n_cells & 0x3f
        n_cells = item.q_rxlevmin_n_cells >> 6
        stdout += 'LTE NCell: EARFCN {}, number of cells: {}\n'.format(item.earfcn, n_cells)

        for i in range(n_cells):
            n_cell_pkt = pkt_body[pos + 32 * i:pos + 32 * (i + 1)]
            n_cell = n_cell_struct._make(struct.unpack('<LLLLHHLL', n_cell_pkt[0:28]))

            n_pci = n_cell.val0 & 0x1ff
            n_meas_rssi = (n_cell.val0 >> 9) & 0x7ff
            n_meas_rsrp = (n_cell.val0 >> 20)
            n_avg_rsrp = (n_cell.val1 >> 12) & 0xfff
            n_meas_rsrq = (n_cell.val2 >> 12) & 0x3ff
            n_avg_rsrq = n_cell.val3 & 0x3ff
            n_s_rxlev = (n_cell.val3 >> 20) & 0x3f
            n_ant0_frame_offset = n_cell.ant0_offset & 0x7ff
            n_ant0_sample_offset = (n_cell.ant0_offset >> 11)
            n_ant1_frame_offset = n_cell.ant1_offset & 0x7ff
            n_ant1_sample_offset = (n_cell.ant1_offset >> 11)

            if item.rrc_rel == 1: # Rel 9
                r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                n_s_qual = r9_info_interim[0]
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Cell Meas packet - RRC version {}'.format(item.rrc_rel))

            n_real_rsrp = -180 + n_meas_rsrp * 0.0625
            n_real_rssi = -110 + n_meas_rssi * 0.0625
            n_real_rsrq = -30 + n_meas_rsrq * 0.0625

            stdout += '└── Neighbor cell {}: PCI {:3d}, RSRP {:.2f}, RSSI {:.2f}\n'.format(i, n_pci, n_real_rsrp, n_real_rssi)
        return {'stdout': stdout.rstrip()}

    def parse_lte_ml1_scell_meas_response(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        stdout = ''

        # First 4b: Version, Number of subpackets, reserved
        # 01 | 01 | 35 0c
        subpkt_struct = namedtuple('QcDiagLteMl1Subpkt', 'id version size')
        if pkt_version == 1: # Version 1
            num_subpkts = pkt_body[1]
            pos = 4

            for x in range(num_subpkts):
                # 4b: Subpacket ID, Subpacket version, Subpacket size
                # 19 | 30 | 40 02
                subpkt_header = subpkt_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
                subpkt_body = pkt_body[pos+4:pos+4+subpkt_header.size]
                pos += subpkt_header.size

                if subpkt_header.id == 0x19:
                    # Serving Cell Measurement Result
                    # EARFCN, num of cell, valid RX data
                    if subpkt_header.version == 36:
                        subpkt_scell_meas_v36_struct = namedtuple('QcDiagLteMl1SubpktScellMeasV36', 'earfcn num_cells valid_rx')
                        subpkt_scell_meas_v36 = subpkt_scell_meas_v36_struct._make(struct.unpack('<LHH', subpkt_body[0:8]))
                        stdout += 'LTE ML1 SCell Meas Response: EARFCN {}, Number of cells = {}, Valid RX = {}\n'.format(subpkt_scell_meas_v36.earfcn,
                            subpkt_scell_meas_v36.num_cells, subpkt_scell_meas_v36.valid_rx)

                        pos_meas = 8
                        for y in range(subpkt_scell_meas_v36.num_cells):
                            interim = struct.unpack('<HHH', subpkt_body[pos_meas:pos_meas+6])
                            pci = interim[0] & 0x1ff
                            scell_idx = (interim[0] >> 9) & 7
                            is_scell = (interim[0] >> 12) & 1

                            sfn = interim[2] & 0x3ff
                            subfn = (interim[2] >> 10) & 0xf

                            interim = struct.unpack('<LLLLLLLLLLLL', subpkt_body[pos_meas+16:pos_meas+64])
                            rsrp0 = (float((interim[0] >> 10) & 4095)) * 0.0625 - 180.0
                            rsrp1 = (float((interim[1] >> 12) & 4095)) * 0.0625 - 180.0
                            rsrp2 = (float((interim[2] >> 12) & 4095)) * 0.0625 - 180.0
                            rsrp3 = (float((interim[4]) & 4095)) * 0.0625 - 180.0
                            rsrp = (float((interim[4] >> 12) & 4095) + 640) * 0.0625 - 180.0
                            frsrp = (float((interim[5] >> 12) & 4095)) * 0.0625 - 180.0

                            rsrq0 = (float((interim[6]) & 1023)) * 0.0625 - 30.0
                            rsrq1 = (float((interim[6] >> 20) & 1023)) * 0.0625 - 30.0
                            rsrq2 = (float((interim[7] >> 10) & 1023)) * 0.0625 - 30.0
                            rsrq3 = (float((interim[7] >> 20) & 1023)) * 0.0625 - 30.0
                            rsrq = (float((interim[8]) & 1023)) * 0.0625 - 30.0
                            frsrq = (float((interim[8] >> 20) & 1023)) * 0.0625 - 30.0

                            rssi0 = (float((interim[9]) & 2047)) * 0.0625 - 110.0
                            rssi1 = (float((interim[9] >> 11) & 2047)) * 0.0625 - 110.0
                            rssi2 = (float((interim[10]) & 2047)) * 0.0625 - 110.0
                            rssi3 = (float((interim[10] >> 11) & 2047)) * 0.0625 - 110.0
                            rssi = (float((interim[11]) & 1023)) * 0.0625 - 110.0
                            resid_freq_error = struct.unpack('<H', subpkt_body[pos_meas+70:pos_meas+72])[0]

                            interim = struct.unpack('<LL', subpkt_body[pos_meas+80:pos_meas+88])
                            snr0 = (float((interim[0]) & 511)) * 0.1 - 20.0
                            snr1 = (float((interim[0] >> 9) & 511)) * 0.1 - 20.0
                            snr2 = (float((interim[1]) & 511)) * 0.1 - 20.0
                            snr3 = (float((interim[1] >> 9) & 511)) * 0.1 - 20.0

                            interim = struct.unpack('<LLllll', subpkt_body[pos_meas+104:pos_meas+128])
                            prj_sir = interim[0]
                            if prj_sir & (1 << 31):
                                prj_sir = prj_sir - 4294967296
                            prj_sir = prj_sir / 16

                            posticrsrq = (float((interim[1]))) * 0.0625 - 30.0

                            cinr0 = interim[2]
                            cinr1 = interim[3]
                            cinr2 = interim[4]
                            cinr3 = interim[5]

                            pos_meas += 128
                            stdout += 'LTE ML1 SCell Meas Response (Cell {}): PCI {}, Serving cell index {}, is_serving_cell = {}\n'.format(y, pci, scell_idx, is_scell)
                    elif subpkt_header.version == 48:
                        # EARFCN, num of cell, valid RX data
                        subpkt_scell_meas_v48_struct = namedtuple('QcDiagLteMl1SubpktScellMeasV48', 'earfcn num_cells valid_rx rx_map')
                        subpkt_scell_meas_v48 = subpkt_scell_meas_v48_struct._make(struct.unpack('<LHHL', subpkt_body[0:12]))
                        stdout += 'LTE ML1 SCell Meas Response: EARFCN {}, Number of cells = {}, Valid RX = {}\n'.format(subpkt_scell_meas_v48.earfcn,
                            subpkt_scell_meas_v48.num_cells, subpkt_scell_meas_v48.valid_rx)

                        pos_meas = 12
                        for y in range(subpkt_scell_meas_v48.num_cells):
                            interim = struct.unpack('<HHH', subpkt_body[pos_meas:pos_meas+6])
                            pci = interim[0] & 0x1ff
                            scell_idx = (interim[0] >> 9) & 7
                            is_scell = (interim[0] >> 12) & 1

                            sfn = interim[2] & 0x3ff
                            subfn = (interim[2] >> 10) & 0xf

                            interim = struct.unpack('<LLLLLLLLLLLL', subpkt_body[pos_meas+16:pos_meas+64])
                            rsrp0 = (float((interim[0] >> 10) & 4095)) * 0.0625 - 180.0
                            rsrp1 = (float((interim[1] >> 12) & 4095)) * 0.0625 - 180.0
                            rsrp2 = (float((interim[2] >> 12) & 4095)) * 0.0625 - 180.0
                            rsrp3 = (float((interim[4]) & 4095)) * 0.0625 - 180.0
                            rsrp = (float((interim[4] >> 12) & 4095) + 640) * 0.0625 - 180.0
                            frsrp = (float((interim[5] >> 12) & 4095)) * 0.0625 - 180.0

                            rsrq0 = (float((interim[6]) & 1023)) * 0.0625 - 30.0
                            rsrq1 = (float((interim[6] >> 20) & 1023)) * 0.0625 - 30.0
                            rsrq2 = (float((interim[7] >> 10) & 1023)) * 0.0625 - 30.0
                            rsrq3 = (float((interim[7] >> 20) & 1023)) * 0.0625 - 30.0
                            rsrq = (float((interim[8]) & 1023)) * 0.0625 - 30.0
                            frsrq = (float((interim[8] >> 20) & 1023)) * 0.0625 - 30.0

                            rssi0 = (float((interim[9]) & 2047)) * 0.0625 - 110.0
                            rssi1 = (float((interim[9] >> 11) & 2047)) * 0.0625 - 110.0
                            rssi2 = (float((interim[10]) & 2047)) * 0.0625 - 110.0
                            rssi3 = (float((interim[10] >> 11) & 2047)) * 0.0625 - 110.0
                            rssi = (float((interim[11]) & 1023)) * 0.0625 - 110.0
                            resid_freq_error = struct.unpack('<H', subpkt_body[pos_meas+84:pos_meas+86])[0]

                            interim = struct.unpack('<LL', subpkt_body[pos_meas+92:pos_meas+100])
                            snr0 = (float((interim[0]) & 511)) * 0.1 - 20.0
                            snr1 = (float((interim[0] >> 9) & 511)) * 0.1 - 20.0
                            snr2 = (float((interim[1]) & 511)) * 0.1 - 20.0
                            snr3 = (float((interim[1] >> 9) & 511)) * 0.1 - 20.0

                            interim = struct.unpack('<LLllll', subpkt_body[pos_meas+116:pos_meas+140])
                            prj_sir = interim[0]
                            if prj_sir & (1 << 31):
                                prj_sir = prj_sir - 4294967296
                            prj_sir = prj_sir / 16

                            posticrsrq = (float((interim[1]))) * 0.0625 - 30.0

                            cinr0 = interim[2]
                            cinr1 = interim[3]
                            cinr2 = interim[4]
                            cinr3 = interim[5]

                            pos_meas += 140
                            stdout += 'LTE ML1 SCell Meas Response (Cell {}): PCI {}, Serving cell index {}, is_serving_cell = {}\n'.format(y, pci, scell_idx, is_scell)

                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas Serving Cell Measurement Result subpacket version {}'.format(subpkt_header.version))
                else:
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas subpacket ID 0x{:02x}'.format(subpkt_header.id))

            return {'stdout': stdout.rstrip()}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas Response packet version 0x{:02x}'.format(pkt_version))
            return None

    def parse_lte_ml1_cell_info(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        prb_to_mhz = {6: 1.4, 15: 3, 25: 5, 50: 10, 75: 15, 100: 20}
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagLteMl1CellInfo', 'dl_bandwidth sfn earfcn pci_pbch_phich pss sss ref_time mib_bytes freq_offset num_antennas')
        item = None
        mib_payload = b''
        stdout = ''

        if pkt_version == 1: # Version 1
            # Version, DL BW, SFN, EARFCN, (Cell ID, PBCH, PHICH Duration, PHICH Resource), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            item = item_struct._make(struct.unpack('<BHHHLLQLhH', pkt_body[1:32]))
        elif pkt_version == 2: # Version 2
            # Version, DL BW, SFN, EARFCN, (Cell ID 9, PBCH 1, PHICH Duration 3, PHICH Resource 3), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            item = item_struct._make(struct.unpack('<BHLLLLQLhH', pkt_body[1:36]))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 cell info packet version 0x{:02x}'.format(pkt_version))
            return None

        pci = item.pci_pbch_phich & 0x1ff
        pbch = (item.pci_pbch_phich >> 9) & 0x1
        phich_duration = (item.pci_pbch_phich >> 10) & 0x7
        phich_resource = (item.pci_pbch_phich >> 13) & 0x7

        if self.parent:
            self.parent.lte_last_bw_dl[radio_id] = item.dl_bandwidth
            self.parent.lte_last_cell_id[radio_id] = pci
            self.parent.lte_last_earfcn_dl[radio_id] = item.earfcn

        mib_payload = struct.pack('!L', item.mib_bytes)[0:3]
        if item.dl_bandwidth in prb_to_mhz:
            stdout = 'LTE ML1 Cell Info: EARFCN {}, PCI {}, Bandwidth {} MHz, Num antennas {}'.format(item.earfcn, pci, prb_to_mhz[item.dl_bandwidth], item.num_antennas)
        else:
            stdout = 'LTE ML1 Cell Info: EARFCN {}, PCI {}, Bandwidth {} PRBs, Num antennas {}'.format(item.earfcn, pci, item.dl_bandwidth, item.num_antennas)

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = item.earfcn,
            sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'cp': [gsmtap_hdr + mib_payload], 'ts': pkt_ts, 'stdout': stdout}

    def parse_lte_mac_rach_trigger(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        num_subpacket = pkt_body[1]

        if pkt_version != 0x01:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC RACH trigger packet version 0x{:02x}'.format(pkt_version))
            return None

        pos = 4
        for i in range(num_subpacket):
            subpkt_mac_struct = namedtuple('QcDiagLteMacSubpkt', 'id version size')
            subpkt_mac = subpkt_mac_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_mac.size]
            pos += subpkt_mac.size

            if subpkt_mac.id == 0x03:
                pass
            elif subpkt_mac.id == 0x05:
                pass
            else:
                self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH trigger Subpacket ID 0x{:02x}'.format(subpkt_mac.id))

        return None

    def parse_lte_mac_rach_response(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        num_subpacket = pkt_body[1]

        if pkt_version != 0x01:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC RACH response packet version 0x{:02x}'.format(pkt_version))
            return None

        pos = 4
        for i in range(num_subpacket):
            subpkt_mac_struct = namedtuple('QcDiagLteMacSubpkt', 'id version size')
            subpkt_mac = subpkt_mac_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_mac.size]
            pos += subpkt_mac.size

            if subpkt_mac.id == 0x06: # RACH Attempt
                subpkt_mac_rach_attempt_struct = namedtuple('QcDiagLteMacSubpktRachAttempt', 'num_attempt rach_result contention msg_bitmask')
                subpkt_mac_rach_attempt_struct_v3 = namedtuple('QcDiagLteMacSubpktRachAttemptV3', 'subid cellid num_attempt rach_result contention msg_bitmask')
                subpkt_mac_rach_attempt = None

                subpkt_mac_rach_attempt_msg1_struct = namedtuple('QcDiagLteMacSubpktRachAttemptMsg1', 'preamble_index preamble_index_mask preamble_power_offset')
                subpkt_mac_rach_attempt_msg2_struct = namedtuple('QcDiagLteMacSubpktRachAttemptMsg2', 'backoff result tc_rnti ta')
                subpkt_mac_rach_attempt_msg3_struct = namedtuple('QcDiagLteMacSubpktRachAttemptMsg3', 'grant_raw grant harq_id mac_pdu')
                rach_msg1 = None
                rach_msg2 = None
                rach_msg3 = None

                if subpkt_mac.version == 0x02: # Version 2
                    subpkt_mac_rach_attempt = subpkt_mac_rach_attempt_struct._make(struct.unpack('<BBBB', subpkt_body[0:4]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x01: # Msg1
                        rach_msg1 = subpkt_mac_rach_attempt_msg1_struct._make(struct.unpack('<BBh', subpkt_body[4:8]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x02: # Msg2
                        rach_msg2 = subpkt_mac_rach_attempt_msg2_struct._make(struct.unpack('<HBHH', subpkt_body[8:15]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x04: # Msg3
                        rach_msg3 = subpkt_mac_rach_attempt_msg3_struct._make(struct.unpack('<LHB10s', subpkt_body[15:32]))
                elif subpkt_mac.version == 0x03: # Version 3
                    subpkt_mac_rach_attempt = subpkt_mac_rach_attempt_struct_v3._make(struct.unpack('<BBBBBB', subpkt_body[0:6]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x01: # Msg1
                        rach_msg1 = subpkt_mac_rach_attempt_msg1_struct._make(struct.unpack('<BBh', subpkt_body[6:10]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x02: # Msg2
                        rach_msg2 = subpkt_mac_rach_attempt_msg2_struct._make(struct.unpack('<HBHH', subpkt_body[10:17]))
                    if subpkt_mac_rach_attempt.msg_bitmask & 0x04: # Msg3
                        rach_msg3 = subpkt_mac_rach_attempt_msg3_struct._make(struct.unpack('<LHB10s', subpkt_body[17:34]))
                else:
                    self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH Response Subpacket version {}'.format(subpkt_mac.version))
                    self.parent.logger.log(logging.DEBUG, util.xxd(subpkt_body))
                    continue

                if subpkt_mac_rach_attempt.rach_result != 0x00: # RACH Failure, 0x00 == Success
                    self.parent.logger.log(logging.WARNING, 'RACH result is not success: {}'.format(subpkt_mac_rach_attempt.rach_result))
                    continue

                if subpkt_mac_rach_attempt.msg_bitmask & 0x07 != 0x07:
                    self.parent.logger.log(logging.WARNING, 'Not all msgs are present: not generating RAR and MAC PDU')
                    continue

                pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
                ts_sec = calendar.timegm(pkt_ts.timetuple())
                ts_usec = pkt_ts.microsecond

                # MAC header required by Wireshark MAC-LTE: radioType, direction, rntiType
                # Additional headers required for each message types

                # RAR generated from Msg1/Msg2/Msg3
                # RAR payload: E = 0, T = 1, RAPID (7b) | TA (12b), UL Grant (20b), TC-RNTI (16b)

                mac_header_rar = struct.pack('!BBBBBBB',
                    util.mac_lte_radio_types.FDD_RADIO,
                    util.mac_lte_direction_types.DIRECTION_DOWNLINK,
                    util.mac_lte_rnti_types.RA_RNTI,
                    util.mac_lte_tags.MAC_LTE_SEND_PREAMBLE_TAG,
                    rach_msg1.preamble_index,
                    subpkt_mac_rach_attempt.num_attempt,
                    util.mac_lte_tags.MAC_LTE_PAYLOAD_TAG)

                gsmtap_hdr = util.create_gsmtap_header(
                    version = 3,
                    payload_type = util.gsmtap_type.LTE_MAC,
                    arfcn = 0,
                    device_sec = ts_sec,
                    device_usec = ts_usec)

                grant = struct.unpack('>L', struct.pack('<L', rach_msg3.grant_raw))[0] & 0xfffff
                rar_body = struct.pack('!BBBHH',
                    (1 << 6) | (rach_msg1.preamble_index & 0x3f),
                    (rach_msg2.ta & 0x0ff0) >> 4,
                    ((rach_msg2.ta & 0x000f) << 4) | ((grant & 0x0f0000) >> 16),
                    grant & 0x00ffff,
                    rach_msg2.tc_rnti)

                packet_mac_rar = gsmtap_hdr + mac_header_rar + rar_body

                # MAC PDU in Msg3
                mac_header_msg = struct.pack('!BBBBHBBBB',
                    util.mac_lte_radio_types.FDD_RADIO,
                    util.mac_lte_direction_types.DIRECTION_UPLINK,
                    util.mac_lte_rnti_types.C_RNTI,
                    util.mac_lte_tags.MAC_LTE_RNTI_TAG,
                    rach_msg2.tc_rnti,
                    util.mac_lte_tags.MAC_LTE_SEND_PREAMBLE_TAG,
                    rach_msg1.preamble_index,
                    subpkt_mac_rach_attempt.num_attempt,
                    util.mac_lte_tags.MAC_LTE_PAYLOAD_TAG)

                packet_mac_pdu = gsmtap_hdr + mac_header_msg + rach_msg3.mac_pdu

                return {'cp': [packet_mac_rar, packet_mac_pdu], 'ts': pkt_ts}
            else:
                self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH Response Subpacket ID 0x{:02x}'.format(subpkt_mac.id))

    def create_lte_mac_gsmtap_packet(self, pkt_ts, is_downlink, header, body):
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        # RNTI Type: {0: C-RNTI, 2: P-RNTI, 3: RA-RNTI, 4: T-C-RNTI, 5: SI-RNTI}
        rnti_type_map = {
            0: util.mac_lte_rnti_types.C_RNTI,
            2: util.mac_lte_rnti_types.P_RNTI,
            3: util.mac_lte_rnti_types.RA_RNTI,
            4: util.mac_lte_rnti_types.C_RNTI,
            5: util.mac_lte_rnti_types.SI_RNTI}
        ws_rnti_type = 0
        if header['rnti_type'] in rnti_type_map:
            ws_rnti_type = rnti_type_map[header['rnti_type']]

        # MAC header required by Wireshark MAC-LTE: radioType, direction, rntiType
        # Additional headers required for each message types
        mac_hdr = struct.pack('!BBBBHB',
            util.mac_lte_radio_types.FDD_RADIO,
            util.mac_lte_direction_types.DIRECTION_DOWNLINK if is_downlink else util.mac_lte_direction_types.DIRECTION_UPLINK,
            ws_rnti_type,
            util.mac_lte_tags.MAC_LTE_FRAME_SUBFRAME_TAG,
            (header['sfn'] << 4) | header['subfn'],
            util.mac_lte_tags.MAC_LTE_PAYLOAD_TAG)

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_MAC,
            arfcn = 0,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return gsmtap_hdr + mac_hdr + body

    def parse_lte_mac_dl_block(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        num_subpacket = pkt_body[1]
        mac_pkts = []

        if pkt_version != 0x01:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC DL transport block packet version 0x{:02x}'.format(pkt_version))
            return None

        pos = 4
        for i in range(num_subpacket):
            subpkt_mac_struct = namedtuple('QcDiagLteMacSubpkt', 'id version size')
            subpkt_mac = subpkt_mac_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_mac.size]
            pos += subpkt_mac.size

            if subpkt_mac.id == 0x07: # DL Transport Block
                n_samples = subpkt_body[0]
                subpkt_mac_dl_tb_struct = namedtuple('QcDiagLteMacSubpktDlTransportBlock', 'sfn_subfn rnti_type harq_id pmch_id dl_tbs rlc_pdus padding header_len')
                subpkt_mac_dl_tb_struct_v4 = namedtuple('QcDiagLteMacSubpktDlTransportBlockV4', 'subid cellid sfn_subfn rnti_type harq_id pmch_id dl_tbs rlc_pdus padding header_len')
                subpkt_mac_dl_tb = None
                mac_hdr = b''

                subpkt_pos = 1
                for j in range(n_samples):
                    if subpkt_mac.version == 0x02:
                        subpkt_mac_dl_tb = subpkt_mac_dl_tb_struct._make(struct.unpack('<HBBHHBHB', subpkt_body[subpkt_pos:subpkt_pos+12]))
                        mac_hdr = subpkt_body[subpkt_pos+12:subpkt_pos+12+subpkt_mac_dl_tb.header_len]
                        subpkt_pos += (12 + subpkt_mac_dl_tb.header_len)
                    elif subpkt_mac.version == 0x04:
                        subpkt_mac_dl_tb = subpkt_mac_dl_tb_struct_v4._make(struct.unpack('<BBHBBHHBHB', subpkt_body[subpkt_pos:subpkt_pos+14]))
                        mac_hdr = subpkt_body[subpkt_pos+14:subpkt_pos+14+subpkt_mac_dl_tb.header_len]
                        subpkt_pos += (14 + subpkt_mac_dl_tb.header_len)
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected MAC DL Subpacket version {}'.format(subpkt_mac.version))
                            return None

                    sfn = subpkt_mac_dl_tb.sfn_subfn >> 4
                    subfn = subpkt_mac_dl_tb.sfn_subfn & 0xf

                    pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
                    mac_pkts.append(self.create_lte_mac_gsmtap_packet(pkt_ts, True,
                        {'sfn': sfn, 'subfn': subfn,
                        'rnti_type': subpkt_mac_dl_tb.rnti_type, 'harq_id': subpkt_mac_dl_tb.harq_id,
                        'pmch_id': subpkt_mac_dl_tb.pmch_id, 'dl_tbs': subpkt_mac_dl_tb.dl_tbs,
                        'rlc_pdus': subpkt_mac_dl_tb.rlc_pdus, 'padding': subpkt_mac_dl_tb.padding},
                        mac_hdr))

        return {'cp': mac_pkts, 'ts': pkt_ts}

    def parse_lte_mac_ul_block(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        num_subpacket = pkt_body[1]
        mac_pkts = []

        if pkt_version != 0x01:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC DL transport block packet version 0x{:02x}'.format(pkt_version))
            return None

        pos = 4
        for i in range(num_subpacket):
            subpkt_mac_struct = namedtuple('QcDiagLteMacSubpkt', 'id version size')
            subpkt_mac = subpkt_mac_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_mac.size]
            pos += subpkt_mac.size

            if subpkt_mac.id == 0x08: # UL Transport Block
                n_samples = subpkt_body[0]
                subpkt_mac_ul_tb_struct = namedtuple('QcDiagLteMacSubpktUlTransportBlock', 'sfn_subfn rnti_type harq_id grant rlc_pdus padding bsr_event bsr_trig header_len')
                subpkt_mac_ul_tb_struct_v2 = namedtuple('QcDiagLteMacSubpktUlTransportBlockV4', 'subid cellid harq_id rnti_type sfn_subfn grant rlc_pdus padding bsr_event bsr_trig header_len')
                subpkt_mac_ul_tb = None
                mac_hdr = b''

                subpkt_pos = 1
                for j in range(n_samples):
                    if subpkt_mac.version == 0x01:
                        subpkt_mac_ul_tb = subpkt_mac_ul_tb_struct._make(struct.unpack('<HBBHBHBBB', subpkt_body[subpkt_pos:subpkt_pos+12]))
                        mac_hdr = subpkt_body[subpkt_pos+12:subpkt_pos+12+subpkt_mac_ul_tb.header_len]
                        subpkt_pos += (12 + subpkt_mac_ul_tb.header_len)
                    elif subpkt_mac.version == 0x02:
                        subpkt_mac_ul_tb = subpkt_mac_ul_tb_struct_v2._make(struct.unpack('<BBBBHHBHBBB', subpkt_body[subpkt_pos:subpkt_pos+14]))
                        mac_hdr = subpkt_body[subpkt_pos+14:subpkt_pos+14+subpkt_mac_ul_tb.header_len]
                        subpkt_pos += (14 + subpkt_mac_ul_tb.header_len)
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected MAC UL Subpacket version {}'.format(subpkt_mac.version))
                            return None

                    sfn = subpkt_mac_ul_tb.sfn_subfn >> 4
                    subfn = subpkt_mac_ul_tb.sfn_subfn & 0xf

                    # BSR Event: {0: None, 1: Periodic, 2: High Data Arrival}
                    # BSR Trig: {0: No BSR, 3: S-BSR, 4: Pad L-BSR}
                    pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
                    mac_pkts.append(self.create_lte_mac_gsmtap_packet(pkt_ts, False,
                        {'sfn': sfn, 'subfn': subfn,
                        'rnti_type': subpkt_mac_ul_tb.rnti_type, 'harq_id': subpkt_mac_ul_tb.harq_id,
                        'grant': subpkt_mac_ul_tb.grant, 'rlc_pdus': subpkt_mac_ul_tb.rlc_pdus,
                        'padding': subpkt_mac_ul_tb.padding},
                        mac_hdr))

        return {'cp': mac_pkts, 'ts': pkt_ts}

    def parse_lte_pdcp_dl_cip(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        rbid = -1
        pdcp_pkts = []

        if pkt_version == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt_body[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt_body[pos:pos+4])
                subpkt = pkt_body[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0xC3:
                    if subpkt_version == 0x18:
                        # 01 | 01 | 22 00 | C3 | 18 | 48 00 | 8E 57 8A BF BE 9D B2 38 13 BE 85 12 95 18 9A 29 | 55 4C 9B 9C 2D 35 A9 F8 D9 28 4D CF 08 EB 09 40 | 03 | 03 | 02 00 | [21 40 | 08 00 | 03 00 | 17 22 | 02 00 00 00 | 00 | 02 F4 CE] | [22 42 | 07 00 | 03 00 | 17 22 | 00 00 00 00 | 00 | 00 28 E0]
                        ck_srb = subpkt[0:16]
                        ck_drb = subpkt[16:32]
                        ciphering_algo_srb, ciphering_algo_drb, num_pdus = struct.unpack('<BBH', subpkt[32:36])

                        pos_sample = 36
                        for y in range(num_pdus):
                            # cfg, pdu_size, log_size, sfn_subfn, count, is_compressed
                            # Ciphering: NONE: 0x07, AES: 0x03
                            pdu_hdr = struct.unpack('<HHHHLB', subpkt[pos_sample:pos_sample + 13])
                            pdcp_pdu = subpkt[pos_sample + 13: pos_sample + 13 + pdu_hdr[2]]

                            # V24: config index 6b, rb mode 1b, sn length 2b (5, 7, 12, 15), rbid-1 5b, valid 1b
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0180) >> 7
                            rbid = (pdu_hdr[0] & 0x3e00) >> 9
                            valid = (pdu_hdr[0] & 0x4000) >> 14

                            sn_length_map = {
                                0: util.pdcp_sn_length_types.PDCP_SN_LENGTH_5_BITS,
                                1: util.pdcp_sn_length_types.PDCP_SN_LENGTH_7_BITS,
                                2: util.pdcp_sn_length_types.PDCP_SN_LENGTH_12_BITS,
                                3: util.pdcp_sn_length_types.PDCP_SN_LENGTH_15_BITS,
                                4: util.pdcp_sn_length_types.PDCP_SN_LENGTH_18_BITS,
                            }

                            if sn_length in sn_length_map:
                                sn_length = sn_length_map[sn_length]

                            # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                            # Has header on PDU, CP (0x01), no ROHC
                            # Direction: Downlink (0x01)
                            ws_hdr = struct.pack('!BBBBBBB',
                                0x00,
                                util.pdcp_plane_types.SIGNALING_PLANE if rbid == 0 or rbid == 1 else util.pdcp_plane_types.USER_PLANE,
                                0x00,
                                util.pdcp_lte_tags.PDCP_LTE_SEQNUM_LENGTH_TAG,
                                sn_length,
                                util.pdcp_lte_tags.PDCP_LTE_DIRECTION_TAG,
                                util.pdcp_lte_direction_types.DIRECTION_DOWNLINK)

                            if rbid == 0 or rbid == 1:
                                # SRB1, always DCCH
                                # SRB2, always DCCH
                                ws_hdr += struct.pack('!BB',
                                    util.pdcp_lte_tags.PDCP_LTE_LOG_CHAN_TYPE_TAG,
                                    util.pdcp_logical_channel_types.Channel_DCCH)

                            ws_hdr += struct.pack('!B',
                                util.pdcp_lte_tags.PDCP_LTE_PAYLOAD_TAG)
                            self.parent.writer.write_up(b'pdcp-lte' + ws_hdr + pdcp_pdu)
                            pos_sample += (13 + pdu_hdr[2])

                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL Cipher Data Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue
            return {'up': pdcp_pkts, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL Cipher Data packet version {:02x}'.format(pkt_version))

    def parse_lte_pdcp_ul_cip(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        pdcp_pkts = []

        if pkt_version == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt_body[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt_body[pos:pos+4])
                subpkt = pkt_body[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0xC3:
                    if subpkt_version == 0x1A:
                        # 01 | 01 | 00 00 | C3 | 1A | 4C 00 | 8E 57 8A BF BE 9D B2 38 13 BE 85 12 95 18 9A 29 | 55 4C 9B 9C 2D 35 A9 F8 D9 28 4D CF 08 EB 09 40 | 03 | 03 | 02 00 | [04 47 | 2E 04 | 04 00 | 10 22 | 00 00 00 00 | 00 | 80 00 60 00] | [04 47 | 2E 04 | 04 00 | 18 22 | 01 00 00 00 | 00 | 80 01 60 00 ] | 80 00
                        ck_srb = subpkt[0:16]
                        ck_drb = subpkt[16:32]
                        ciphering_algo_srb, ciphering_algo_drb, num_pdus = struct.unpack('<BBH', subpkt[32:36])

                        pos_sample = 36
                        for y in range(num_pdus):
                            # cfg, pdu_size, log_size, sfn_subfn, count, is_compressed
                            # Ciphering: NONE: 0x07, AES: 0x03
                            pdu_hdr = struct.unpack('<HHHHLB', subpkt[pos_sample:pos_sample + 13])
                            pdcp_pdu = subpkt[pos_sample + 13: pos_sample + 13 + pdu_hdr[2]]

                            # V26: config index 6b, rb mode 1b, sn length 2b (5, 7, 12, 15), rbid-1 5b, valid 1b
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0180) >> 7
                            rbid = (pdu_hdr[0] & 0x3e00) >> 9
                            valid = (pdu_hdr[0] & 0x4000) >> 14

                            sn_length_map = {
                                0: util.pdcp_sn_length_types.PDCP_SN_LENGTH_5_BITS,
                                1: util.pdcp_sn_length_types.PDCP_SN_LENGTH_7_BITS,
                                2: util.pdcp_sn_length_types.PDCP_SN_LENGTH_12_BITS,
                                3: util.pdcp_sn_length_types.PDCP_SN_LENGTH_15_BITS,
                                4: util.pdcp_sn_length_types.PDCP_SN_LENGTH_18_BITS,
                            }

                            if sn_length in sn_length_map:
                                sn_length = sn_length_map[sn_length]

                            # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                            # Has header on PDU, CP (0x01), no ROHC
                            # Direction: Downlink (0x01)
                            ws_hdr = struct.pack('!BBBBBBB',
                                0x00,
                                util.pdcp_plane_types.SIGNALING_PLANE if rbid == 0 or rbid == 1 else util.pdcp_plane_types.USER_PLANE,
                                0x00,
                                util.pdcp_lte_tags.PDCP_LTE_SEQNUM_LENGTH_TAG,
                                sn_length,
                                util.pdcp_lte_tags.PDCP_LTE_DIRECTION_TAG,
                                util.pdcp_lte_direction_types.DIRECTION_UPLINK)

                            if rbid == 0 or rbid == 1:
                                # SRB1, always DCCH
                                # SRB2, always DCCH
                                ws_hdr += struct.pack('!BB',
                                    util.pdcp_lte_tags.PDCP_LTE_LOG_CHAN_TYPE_TAG,
                                    util.pdcp_logical_channel_types.Channel_DCCH)

                            ws_hdr += struct.pack('!B',
                                util.pdcp_lte_tags.PDCP_LTE_PAYLOAD_TAG)
                            pdcp_pkts.append(b'pdcp-lte' + ws_hdr + pdcp_pdu)
                            pos_sample += (13 + pdu_hdr[2])

                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL Cipher Data Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue

            return {'up': pdcp_pkts, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL Cipher Data packet version 0x{:02x}'.format(pkt_version))

    # 0x4021: 01|00 000|0 00|10 0001 (valid, bearer id=0, mode=AM, sn=5b, cidx = 33)
    # 0x4222: 01|00 001|0 00|10 0010 (valid, bearer id=1, mode=AM, sn=5b, cidx = 34)
    # 0x4101: 01|00 000|1 00|00 0001 (valid, bearer id=0, mode=AM, sn=12b, cidx = 1)
    # 0x4543: 01|00 010|1 01|00 0011 (valid, bearer id=2, mode=UM, sn=12b, cidx = 3)
    # 0x4905: 01|00 100|1 00|00 0101 (valid, bearer id=4, mode=AM, sn=12b, cidx = 5)
    # 0x4704: 01|00 011|1 00|00 0100 (valid, bearer id=3, mode=AM, sn=12b, cidx = 4)
    # sn: 5b (SRB), 7, 12, 15, 16b (DRB)
    # 33.401 B.2.1: IK(128b), COUNT(32b), BEARER(5b), DIRECTION(1b)
    # EIA2: AES 128bit, CMAC mode (M0..M31 = COUNT, M32...M36 = BEARER, M37 = DIRECTION, M38..M63 = 0, M64... = Message)
    # TODO: what is for 32 byte number

    def parse_lte_pdcp_dl_srb_int(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        rbid = -1
        pdcp_pkts = []

        if pkt_version == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt_body[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt_body[pos:pos+4])
                subpkt = pkt_body[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0xC6:
                    if subpkt_version == 0x01 or subpkt_version == 0x28:
                        ck_srb = subpkt[0:16]
                        ik_srb = subpkt[16:32]
                        ciphering_algo, integrity_algo, num_pdus = struct.unpack('<BBH', subpkt[32:36])

                        pos_sample = 36
                        for y in range(num_pdus):
                            # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I, XMAC-I
                            # Ciphering: NONE: 0x07, AES: 0x03
                            # Integrity: NONE: 0x07, AES: 0x02
                            pdu_hdr = struct.unpack('<HHHHLLL', subpkt[pos_sample:pos_sample + 20])
                            pdcp_pdu = subpkt[pos_sample + 20: pos_sample + 20 + pdu_hdr[2]]

                            # V1: config index 6b, rb mode 1b (AM=0, UM=1), sn length 2b (5, 7, 12), rbid-1 5b, valid 1b, reserved 1b
                            # V40: config index 6b, rb mode 1b, sn length 3b (5, 7, 12, 15, 18), rbid-1 5b, valid 1b
                            if subpkt_version == 0x01:
                                config_index = pdu_hdr[0] & 0x003f
                                rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                                sn_length = (pdu_hdr[0] & 0x0180) >> 7
                                rbid = (pdu_hdr[0] & 0x3e00) >> 9
                                valid = (pdu_hdr[0] & 0x4000) >> 14
                            elif subpkt_version == 0x40:
                                config_index = pdu_hdr[0] & 0x003f
                                rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                                sn_length = (pdu_hdr[0] & 0x0380) >> 7
                                rbid = (pdu_hdr[0] & 0x7c00) >> 10
                                valid = (pdu_hdr[0] & 0x8000) >> 15
                            else:
                                if self.parent:
                                    self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL PDU Subpacket version %s' % subpkt_version)
                                break

                            sn_length_map = {
                                0: util.pdcp_sn_length_types.PDCP_SN_LENGTH_5_BITS,
                                1: util.pdcp_sn_length_types.PDCP_SN_LENGTH_7_BITS,
                                2: util.pdcp_sn_length_types.PDCP_SN_LENGTH_12_BITS,
                                3: util.pdcp_sn_length_types.PDCP_SN_LENGTH_15_BITS,
                                4: util.pdcp_sn_length_types.PDCP_SN_LENGTH_18_BITS,
                            }

                            if sn_length in sn_length_map:
                                sn_length = sn_length_map[sn_length]

                            # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                            # Has header on PDU, CP (0x01), no ROHC
                            # Direction: Downlink (0x01)
                            ws_hdr = struct.pack('!BBBBBBB',
                                0x00,
                                util.pdcp_plane_types.SIGNALING_PLANE,
                                0x00,
                                util.pdcp_lte_tags.PDCP_LTE_SEQNUM_LENGTH_TAG,
                                sn_length,
                                util.pdcp_lte_tags.PDCP_LTE_DIRECTION_TAG,
                                util.pdcp_lte_direction_types.DIRECTION_DOWNLINK)

                            if rbid == 0 or rbid == 1:
                                # SRB1, always DCCH
                                # SRB2, always DCCH
                                ws_hdr += struct.pack('!BB',
                                    util.pdcp_lte_tags.PDCP_LTE_LOG_CHAN_TYPE_TAG,
                                    util.pdcp_logical_channel_types.Channel_DCCH)

                            ws_hdr += struct.pack('!B',
                                util.pdcp_lte_tags.PDCP_LTE_PAYLOAD_TAG)
                            pdcp_pkts.append(b'pdcp-lte' + ws_hdr + pdcp_pdu)
                            pos_sample += (20 + pdu_hdr[2])

                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL SRB Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue

            return {'up': pdcp_pkts, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL SRB packet version 0x{:02x}'.format(pkt_version))

    def parse_lte_pdcp_ul_srb_int(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        rbid = -1
        pdcp_pkts = []

        if pkt_version == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt_body[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt_body[pos:pos+4])
                subpkt = pkt_body[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0xC7:
                    if subpkt_version == 0x01 or subpkt_version == 0x28:
                        # 01 | 01 | 18 61 | C7 | 01 | 58 00 | A3 97 33 2D 66 B7 10 76 E3 F0 B9 85 EF 0A 61 31 | 38 63 BC 49 5C 42 45 ED 7B 5F C4 FE 2A 64 62 E7 | 03 | 02 | 01 00 | [22 42 | 1D 00 | 1D 00 | 00 40 | 00 00 00 00 | BB 53 CC DA | 00 48 02 A4 E9 88 34 BD A0 FD C4 5C D1 28 87 E7 11 BC 73 DE A9 BC 87 FC 20 DA CC 53 BB B0 07 00
                        ck_srb = subpkt[0:16]
                        ik_srb = subpkt[16:32]
                        ciphering_algo, integrity_algo, num_pdus = struct.unpack('<BBH', subpkt[32:36])

                        pos_sample = 36
                        for y in range(num_pdus):
                            # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I
                            # Ciphering: NONE: 0x07, AES: 0x03
                            # Integrity: NONE: 0x07, AES: 0x02
                            pdu_hdr = struct.unpack('<HHHHLL', subpkt[pos_sample:pos_sample + 16])
                            pdcp_pdu = subpkt[pos_sample + 16: pos_sample + 16 + pdu_hdr[2]]

                            # V1: config index 6b, rb mode 1b (AM=0, UM=1), sn length 2b (5, 7, 12), rbid-1 5b, valid 1b, reserved 1b
                            # V40: config index 6b, rb mode 1b, sn length 3b (5, 7, 12, 15, 18), rbid-1 5b, valid 1b
                            if subpkt_version == 0x01:
                                config_index = pdu_hdr[0] & 0x003f
                                rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                                sn_length = (pdu_hdr[0] & 0x0180) >> 7
                                rbid = (pdu_hdr[0] & 0x3e00) >> 9
                                valid = (pdu_hdr[0] & 0x4000) >> 14
                            elif subpkt_version == 0x40:
                                config_index = pdu_hdr[0] & 0x003f
                                rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                                sn_length = (pdu_hdr[0] & 0x0380) >> 7
                                rbid = (pdu_hdr[0] & 0x7c00) >> 10
                                valid = (pdu_hdr[0] & 0x8000) >> 15
                            else:
                                self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL PDU Subpacket version %s' % subpkt_version)
                                break

                            sn_length_map = {
                                0: util.pdcp_sn_length_types.PDCP_SN_LENGTH_5_BITS,
                                1: util.pdcp_sn_length_types.PDCP_SN_LENGTH_7_BITS,
                                2: util.pdcp_sn_length_types.PDCP_SN_LENGTH_12_BITS,
                                3: util.pdcp_sn_length_types.PDCP_SN_LENGTH_15_BITS,
                                4: util.pdcp_sn_length_types.PDCP_SN_LENGTH_18_BITS,
                            }

                            if sn_length in sn_length_map:
                                sn_length = sn_length_map[sn_length]

                            # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                            # Has header on PDU, CP (0x01), no ROHC
                            # Direction: Uplink (0x00)
                            ws_hdr = struct.pack('!BBBBBBB',
                                0x00,
                                util.pdcp_plane_types.SIGNALING_PLANE,
                                0x00,
                                util.pdcp_lte_tags.PDCP_LTE_SEQNUM_LENGTH_TAG,
                                sn_length,
                                util.pdcp_lte_tags.PDCP_LTE_DIRECTION_TAG,
                                util.pdcp_lte_direction_types.DIRECTION_UPLINK)

                            if rbid == 0 or rbid == 1:
                                # SRB1, always DCCH
                                # SRB2, always DCCH
                                ws_hdr += struct.pack('!BB',
                                    util.pdcp_lte_tags.PDCP_LTE_LOG_CHAN_TYPE_TAG,
                                    util.pdcp_logical_channel_types.Channel_DCCH)

                            ws_hdr += struct.pack('!B',
                                util.pdcp_lte_tags.PDCP_LTE_PAYLOAD_TAG)
                            pdcp_pkts.append(b'pdcp-lte' + ws_hdr + pdcp_pdu)
                            pos_sample += (16 + pdu_hdr[2])

                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unexpected PDCP UL SRB Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue

            return {'up': pdcp_pkts, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP UL SRB packet version 0x{:02x}'.format(pkt_version))

    def parse_lte_mib(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        prb_to_mhz = {6: 1.4, 15: 3, 25: 5, 50: 10, 75: 15, 100: 20}

        item_struct = namedtuple('QcDiagLteMib', 'pci earfcn sfn tx_antenna bandwidth')
        item_struct_v17 = namedtuple('QcDiagLteMibV17', 'pci earfcn sfn sfn_msb4 hsfn_lsb2 sib1_sch_info si_value_tag access_barring opmode_type opmode_info tx_antenna')
        item = None

        if pkt_version == 1:
            item = item_struct._make(struct.unpack('<HHH BB', pkt_body[1:10]))
        elif pkt_version == 2:
            item = item_struct._make(struct.unpack('<HLH BB', pkt_body[1:12]))
        elif pkt_version == 17:
            item = item_struct_v17._make(struct.unpack('<HLH BBBBB BHB', pkt_body[1:18]))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MIB packet version 0x{:02x}'.format(pkt_version))
            return None

        stdout = ''
        if pkt_version == 1 or pkt_version == 2:
            if item.bandwidth in prb_to_mhz:
                stdout = 'LTE MIB Info: EARFCN {}, SFN {:4}, Bandwidth {} MHz, TX antennas {}'.format(item.earfcn, item.sfn, prb_to_mhz[item.bandwidth], item.tx_antenna)
            else:
                stdout = 'LTE MIB Info: EARFCN {}, SFN {:4}, Bandwidth {} PRBs, TX antennas {}'.format(item.earfcn, item.sfn, item.bandwidth, item.tx_antenna)

        elif pkt_version == 17:
            # MIB for NB-IoT (only 1 PRB)
            stdout = 'LTE MIB-NB Info: EARFCN {}, SFN {:4}, TX antennas {}'.format(item.earfcn, item.sfn, item.tx_antenna)

        return {'stdout': stdout}

    def parse_lte_rrc_cell_info(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        prb_to_mhz = {6: 1.4, 15: 3, 25: 5, 50: 10, 75: 15, 100: 20}
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagLteRrcServCellInfo', 'pci dl_earfcn ul_earfcn dl_bw ul_bw cell_id tac band mcc mnc_digit mnc allowed_access')
        if pkt_version == 2:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            item = item_struct._make(struct.unpack('<H HH BB LH L HBH B', pkt_body[1:25]))
        elif pkt_version == 3:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            item = item_struct._make(struct.unpack('<H LL BB LH L HBH B', pkt_body[1:29]))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE RRC cell info packet version 0x{:02x}'.format(pkt_version))
            return None

        if self.parent:
            self.parent.lte_last_cell_id[radio_id] = item.pci
            self.parent.lte_last_earfcn_dl[radio_id] = item.dl_earfcn
            self.parent.lte_last_earfcn_ul[radio_id] = item.ul_earfcn
            self.parent.lte_last_bw_dl[radio_id] = item.dl_bw
            self.parent.lte_last_bw_ul[radio_id] = item.ul_bw

        bw_str = ''
        if item.dl_bw in prb_to_mhz and item.ul_bw in prb_to_mhz:
            bw_str = '{}/{} MHz'.format(prb_to_mhz[item.dl_bw], prb_to_mhz[item.ul_bw])
        else:
            bw_str = '{}/{} PRBs'.format(item.dl_bw, item.ul_bw)

        if item.mnc_digit == 2:
            stdout = 'LTE RRC SCell Info: EARFCN {}/{}, Band {}, Bandwidth {}, PCI {}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {:02}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        elif item.mnc_digit == 3:
            stdout = 'LTE RRC SCell Info: EARFCN {}/{}, Band {}, Bandwidth {}, PCI {}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {:03}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        else:
            stdout = 'LTE RRC SCell Info: EARFCN {}/{}, Band {}, Bandwidth {}, PCI {}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        return {'stdout': stdout}

    def parse_lte_rrc(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        msg_content = b''

        item_struct = namedtuple('QcDiagLteRrcOtaPacket', 'rrc_rel_maj rrc_rel_min rbid pci earfcn sfn_subfn pdu_num len')
        item_struct_v5 = namedtuple('QcDiagLteRrcOtaPacketV5', 'rrc_rel_maj rrc_rel_min rbid pci earfcn sfn_subfn pdu_num sib_mask len')
        item_struct_v25 = namedtuple('QcDiagLteRrcOtaPacketV25', 'rrc_rel_maj rrc_rel_min nr_rrc_rel_maj nr_rrc_rel_min rbid pci earfcn sfn_subfn pdu_num sib_mask len')
        item = None

        if pkt_version >= 25:
            # Version 25, 26, 27
            item = item_struct_v25._make(struct.unpack('<BBBB BHLH BLH', pkt_body[1:21]))
            msg_content = pkt_body[21:]
        elif pkt_version >= 8:
            # Version 8, 9, 12, 13, 15, 16, 19, 20, 22, 24
            item = item_struct_v5._make(struct.unpack('<BB BHLH BLH', pkt_body[1:19]))
            msg_content = pkt_body[19:]
        elif pkt_version >= 5:
            # Version 6, 7
            item = item_struct_v5._make(struct.unpack('<BB BHHH BLH', pkt_body[1:17]))
            msg_content = pkt_body[17:]
        else:
            # Version 2, 3, 4
            item = item_struct._make(struct.unpack('<BB BHHH BH', pkt_body[1:13]))
            msg_content = pkt_body[13:]

        if item.len != len(msg_content):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(msg_content), item.len))
            return None

        sfn = (item.sfn_subfn) >> 4
        subfn = (item.sfn_subfn) & 0xf

        if pkt_version in (0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0d, 0x16):
            # RRC Packet <v9, v13, v22
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                3: util.gsmtap_lte_rrc_types.MCCH,
                4: util.gsmtap_lte_rrc_types.PCCH,
                5: util.gsmtap_lte_rrc_types.DL_CCCH,
                6: util.gsmtap_lte_rrc_types.DL_DCCH,
                7: util.gsmtap_lte_rrc_types.UL_CCCH,
                8: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt_version in (0x09, 0x0c):
            # RRC Packet v9-v12
            rrc_subtype_map = {
                8: util.gsmtap_lte_rrc_types.BCCH_BCH,
                9: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                10: util.gsmtap_lte_rrc_types.MCCH,
                11: util.gsmtap_lte_rrc_types.PCCH,
                12: util.gsmtap_lte_rrc_types.DL_CCCH,
                13: util.gsmtap_lte_rrc_types.DL_DCCH,
                14: util.gsmtap_lte_rrc_types.UL_CCCH,
                15: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt_version in (0x0e,):
            # RRC Packet v14
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                4: util.gsmtap_lte_rrc_types.MCCH,
                5: util.gsmtap_lte_rrc_types.PCCH,
                6: util.gsmtap_lte_rrc_types.DL_CCCH,
                7: util.gsmtap_lte_rrc_types.DL_DCCH,
                8: util.gsmtap_lte_rrc_types.UL_CCCH,
                9: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt_version in (0x0f, 0x10):
            # RRC Packet v15, v16
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                4: util.gsmtap_lte_rrc_types.MCCH,
                5: util.gsmtap_lte_rrc_types.PCCH,
                6: util.gsmtap_lte_rrc_types.DL_CCCH,
                7: util.gsmtap_lte_rrc_types.DL_DCCH,
                8: util.gsmtap_lte_rrc_types.UL_CCCH,
                9: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt_version in (0x13, 0x1a, 0x1b):
            # RRC Packet v19, v26, v27
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                3: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                6: util.gsmtap_lte_rrc_types.MCCH,
                7: util.gsmtap_lte_rrc_types.PCCH,
                8: util.gsmtap_lte_rrc_types.DL_CCCH,
                9: util.gsmtap_lte_rrc_types.DL_DCCH,
                10: util.gsmtap_lte_rrc_types.UL_CCCH,
                11: util.gsmtap_lte_rrc_types.UL_DCCH,
                45: util.gsmtap_lte_rrc_types.BCCH_BCH_NB,
                46: util.gsmtap_lte_rrc_types.BCCH_DL_SCH_NB,
                47: util.gsmtap_lte_rrc_types.PCCH_NB,
                48: util.gsmtap_lte_rrc_types.DL_CCCH_NB,
                49: util.gsmtap_lte_rrc_types.DL_DCCH_NB,
                50: util.gsmtap_lte_rrc_types.UL_CCCH_NB,
                52: util.gsmtap_lte_rrc_types.UL_DCCH_NB
            }
        elif pkt_version in (0x14, 0x18, 0x19):
            # RRC Packet v20, v24, v25
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                4: util.gsmtap_lte_rrc_types.MCCH,
                5: util.gsmtap_lte_rrc_types.PCCH,
                6: util.gsmtap_lte_rrc_types.DL_CCCH,
                7: util.gsmtap_lte_rrc_types.DL_DCCH,
                8: util.gsmtap_lte_rrc_types.UL_CCCH,
                9: util.gsmtap_lte_rrc_types.UL_DCCH,
                54: util.gsmtap_lte_rrc_types.BCCH_BCH_NB,
                55: util.gsmtap_lte_rrc_types.BCCH_DL_SCH_NB,
                56: util.gsmtap_lte_rrc_types.PCCH_NB,
                57: util.gsmtap_lte_rrc_types.DL_CCCH_NB,
                58: util.gsmtap_lte_rrc_types.DL_DCCH_NB,
                59: util.gsmtap_lte_rrc_types.UL_CCCH_NB,
                61: util.gsmtap_lte_rrc_types.UL_DCCH_NB
            }
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload type 0x{:02x} for LTE RRC OTA packet version 0x{:02x} is not known'.format(item.pdu_num, pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if not (item.pdu_num in rrc_subtype_map):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload type 0x{:02x} for LTE RRC OTA packet version 0x{:02x} is not known'.format(item.pdu_num, pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None
        gsmtap_subtype = rrc_subtype_map[item.pdu_num]

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = item.earfcn,
            frame_number = sfn,
            sub_type = gsmtap_subtype,
            sub_slot = subfn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}

    def parse_lte_nas(self, pkt_header, pkt_body, args, plain = False):
        pkt_version = pkt_body[0]

        item_struct = namedtuple('QcDiagLteNasMsg', 'vermaj vermid vermin')
        item = item_struct._make(struct.unpack('<BBB', pkt_body[1:4]))
        msg_content = pkt_body[4:]

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_NAS,
            arfcn = 0,
            sub_type = 0 if plain else 1,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}

    def parse_cacombos(self, pkt_header, pkt_body, args):
        self.parent.logger.log(logging.WARNING, "0xB0CD " + util.xxd_oneline(pkt_body))
