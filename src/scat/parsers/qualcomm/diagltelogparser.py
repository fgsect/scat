#!/usr/bin/env python3

from collections import namedtuple
from packaging import version
import binascii
import bitstring
import calendar
import logging
import struct

bitstring_ver = version.parse(bitstring.__version__)
if bitstring_ver >= version.parse('4.2.0'):
    bitstring.options.lsb0 = True
elif bitstring_ver >= version.parse('4.0.0'):
    bitstring.lsb0 = True
elif bitstring_ver >= version.parse('3.1.7'):
    bitstring.set_lsb0(True)
else:
    raise Exception("SCAT requires bitstring>=3.1.7, recommends bitstring>=4.0.0")

import scat.parsers.qualcomm.diagcmd as diagcmd
import scat.util as util

class DiagLteLogParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        self.rrc_segments = dict()
        self.first_segment_item = None

        self.no_process = {
        }

        i = diagcmd.diag_log_get_lte_item_id
        c = diagcmd.diag_log_code_lte
        self.process = {
            # ML1
            # i(c.LOG_LTE_ML1_MAC_RAR_MSG1_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_RAR_MSG2_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_MAC_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_ML1_CONNECTED_MODE_INTRA_FREQ_MEAS): lambda x, y, z: self.parse_lte_ml1_connected_intra_freq_meas(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL): lambda x, y, z: self.parse_lte_ml1_scell_meas(x, y, z),
            i(c.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS): lambda x, y, z: self.parse_lte_ml1_ncell_meas(x, y, z),
            # i(c.LOG_LTE_ML1_INTRA_FREQ_CELL_RESELECTION)
            # i(c.LOG_LTE_ML1_NEIGHBOR_CELL_MEAS_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_ncell_meas_rr(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE): lambda x, y, z: self.parse_lte_ml1_scell_meas_response(x, y, z),
            # i(c.LOG_LTE_ML1_SEARCH_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_search_rr(x, y, z),
            # i(c.LOG_LTE_ML1_CONNECTED_MODE_NEIGHBOR_MEAS_REQ_RESPONSE): lambda x, y, z: self.parse_lte_ml1_connected_ncell_meas_rr(x, y, z),
            i(c.LOG_LTE_ML1_SERVING_CELL_INFO): lambda x, y, z: self.parse_lte_ml1_cell_info(x, y, z),

            # MAC
            i(c.LOG_LTE_MAC_RACH_TRIGGER): lambda x, y, z: self.parse_lte_mac_rach_trigger(x, y, z),
            i(c.LOG_LTE_MAC_RACH_RESPONSE): lambda x, y, z: self.parse_lte_mac_rach_response(x, y, z),
            i(c.LOG_LTE_MAC_DL_TRANSPORT_BLOCK): lambda x, y, z: self.parse_lte_mac_dl_block(x, y, z),
            i(c.LOG_LTE_MAC_UL_TRANSPORT_BLOCK): lambda x, y, z: self.parse_lte_mac_ul_block(x, y, z),

            # RLC

            # PDCP
            # i(c.LOG_LTE_PDCP_DL_CONFIG): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_CONFIG): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_DL_DATA_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_DATA_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_DL_CONTROL_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            # i(c.LOG_LTE_PDCP_UL_CONTROL_PDU): lambda x, y, z: self.parse_lte_dummy(x, y, z),
            i(c.LOG_LTE_PDCP_DL_CIPHER_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_dl_cip(x, y, z),
            i(c.LOG_LTE_PDCP_UL_CIPHER_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_ul_cip(x, y, z),
            i(c.LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_dl_srb_int(x, y, z),
            i(c.LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU): lambda x, y, z: self.parse_lte_pdcp_ul_srb_int(x, y, z),

            # RRC
            i(c.LOG_LTE_RRC_OTA_MESSAGE): lambda x, y, z: self.parse_lte_rrc(x, y, z),
            i(c.LOG_LTE_RRC_MIB_MESSAGE): lambda x, y, z: self.parse_lte_mib(x, y, z),
            i(c.LOG_LTE_RRC_SERVING_CELL_INFO): lambda x, y, z: self.parse_lte_rrc_cell_info(x, y, z),

            # CA COMBOS
            i(c.LOG_LTE_RRC_SUPPORTED_CA_COMBOS): lambda x, y, z: self.parse_lte_cacombos(x, y, z),

            # NAS
            i(c.LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, False),
            i(c.LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
            i(c.LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_lte_nas(x, y, z, True),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    # def parse_lte_dummy(self, pkt_header, pkt_body, args):
    #     return {'stdout': 'LTE Dummy 0x{:04x}: {}'.format(pkt_header.log_id, binascii.hexlify(pkt_body).decode())}

    def parse_rsrp(self, rsrp):
        return -180 + rsrp * 0.0625

    def parse_rsrq(self, rsrq):
        return -30 + rsrq * 0.0625

    def parse_rssi(self, rssi):
        return -110 + rssi * 0.0625

    # ML1

    def parse_lte_ml1_scell_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
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
            item = item_struct._make(struct.unpack('<BHLH2xLLLLLL', pkt_body[1:36]))
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        pci_serv_layer_prio_bits = bitstring.Bits(uint=item.pci_serv_layer_prio, length=16)
        pci = pci_serv_layer_prio_bits[0:9].uint
        serv_layer_priority = pci_serv_layer_prio_bits[9:16].uint
        meas_rsrp = item.meas_rsrp & 0xfff
        avg_rsrp = item.avg_rsrp & 0xfff

        rsrq_bits = bitstring.Bits(uint=item.rsrq, length=32)
        meas_rsrq = rsrq_bits[0:10].uint
        avg_rsrq = rsrq_bits[20:30].uint

        rssi_bits = bitstring.Bits(uint=item.rssi, length=32)
        meas_rssi = rssi_bits[10:21].uint

        rxlev_bits = bitstring.Bits(uint=item.rxlev, length=32)
        q_rxlevmin = rxlev_bits[0:6].uint
        p_max = rxlev_bits[6:13].uint
        max_ue_tx_pwr = rxlev_bits[13:19].uint
        s_rxlev = rxlev_bits[19:26].uint
        num_drx_s_fail = rxlev_bits[26:32].uint

        s_search_bits = bitstring.Bits(uint=item.s_search, length=32)
        s_intra_search = s_search_bits[0:6].uint
        s_non_intra_search = s_search_bits[6:12].uint

        if pkt_version == 4:
            if item.rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt_body[32:36])[0]
                r9_data_bits = bitstring.Bits(uint=r9_data_interim, length=32)
                q_qual_min = r9_data_bits[0:7].uint
                s_qual = r9_data_bits[7:14].uint
                s_intra_search_q = r9_data_bits[14:20].uint
                s_nonintra_search_q = r9_data_bits[20:26].uint
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(item.rrc_rel))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
        elif pkt_version == 5:
            if item.rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt_body[36:40])[0]
                r9_data_bits = bitstring.Bits(uint=r9_data_interim, length=32)
                q_qual_min = r9_data_bits[0:7].uint
                s_qual = r9_data_bits[7:14].uint
                s_intra_search_q = r9_data_bits[14:20].uint
                s_nonintra_search_q = r9_data_bits[20:26].uint
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(item.rrc_rel))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

        real_rsrp = self.parse_rsrp(meas_rsrp)
        real_rssi = self.parse_rssi(meas_rssi)
        real_rsrq = self.parse_rsrq(meas_rsrq)

        return {'stdout': 'LTE SCell: EARFCN: {}, PCI: {:3d}, Measured RSRP: {:.2f}, Measured RSSI: {:.2f}, Measured RSRQ: {:.2f}'.format(item.earfcn, pci, real_rsrp, real_rssi, real_rsrq),
                'ts': pkt_ts}

    def parse_lte_ml1_ncell_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
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
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Meas packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        q_rxlevmin = item.q_rxlevmin_n_cells & 0x3f
        n_cells = item.q_rxlevmin_n_cells >> 6
        stdout += 'LTE NCell: EARFCN: {}, number of cells: {}\n'.format(item.earfcn, n_cells)

        for i in range(n_cells):
            n_cell_pkt = pkt_body[pos + 32 * i:pos + 32 * (i + 1)]
            n_cell = n_cell_struct._make(struct.unpack('<LLLLHHLL', n_cell_pkt[0:28]))

            val0_bits = bitstring.Bits(uint=n_cell.val0, length=32)
            n_pci = val0_bits[0:9].uint
            n_meas_rssi = val0_bits[9:20].uint
            n_meas_rsrp = val0_bits[20:32].uint
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
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Neighbor Cell Meas packet - RRC version {}'.format(item.rrc_rel))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

            n_real_rsrp = self.parse_rsrp(n_meas_rsrp)
            n_real_rssi = self.parse_rssi(n_meas_rssi)
            n_real_rsrq = self.parse_rsrq(n_meas_rsrq)

            stdout += '└── Neighbor cell {}: PCI: {:3d}, RSRP: {:.2f}, RSSI: {:.2f}, RSRQ: {:.2f}\n'.format(i, n_pci, n_real_rsrp, n_real_rssi, n_real_rsrq)
        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def parse_lte_ml1_scell_meas_response_cell_v36(self, cell_id, cell_bytes, rsrp_offset=16, snr_offset=80, sir_cinr_offset=104):
        interim = struct.unpack('<HHH', cell_bytes[0:6])
        val0_bits = bitstring.Bits(uint=interim[0], length=16)
        pci = val0_bits[0:9].uint
        scell_idx = val0_bits[9:12].uint
        is_scell = val0_bits[12:13].uint

        val2_bits = bitstring.Bits(uint=interim[2], length=16)
        sfn = val2_bits[0:10].uint
        subfn = val2_bits[10:14].uint

        interim = struct.unpack('<LLLLLLLLLLLL', cell_bytes[rsrp_offset:rsrp_offset+48])
        val_bits = bitstring.Bits().join([bitstring.Bits(uint=x, length=32) for x in interim][::-1])

        rsrp0 = self.parse_rsrp(val_bits[10:22].uint)
        rsrp1 = self.parse_rsrp(val_bits[44:56].uint)
        rsrp2 = self.parse_rsrp(val_bits[76:88].uint)
        rsrp3 = self.parse_rsrp(val_bits[96:108].uint)
        rsrp = self.parse_rsrp(val_bits[108:120].uint) + 40
        frsrp = self.parse_rsrp(val_bits[140:152].uint)

        rsrq0 = self.parse_rsrq(val_bits[160:170].uint)
        rsrq1 = self.parse_rsrq(val_bits[180:190].uint)
        rsrq2 = self.parse_rsrq(val_bits[202:212].uint)
        rsrq3 = self.parse_rsrq(val_bits[212:222].uint)
        rsrq = self.parse_rsrq(val_bits[224:234].uint)
        frsrq = self.parse_rsrq(val_bits[244:254].uint)

        rssi0 = self.parse_rssi(val_bits[256:267].uint)
        rssi1 = self.parse_rssi(val_bits[267:278].uint)
        rssi2 = self.parse_rssi(val_bits[288:299].uint)
        rssi3 = self.parse_rssi(val_bits[299:310].uint)
        rssi = self.parse_rssi(val_bits[320:331].uint)

        # resid_freq_error = struct.unpack('<H', cell_bytes[70:72])[0]

        interim = struct.unpack('<LL', cell_bytes[snr_offset:snr_offset+8])
        val_bits = bitstring.Bits().join([bitstring.Bits(uint=x, length=32) for x in interim][::-1])
        snr0 = val_bits[0:9].uint * 0.1 - 20.0
        snr1 = val_bits[9:18].uint * 0.1 - 20.0
        snr2 = val_bits[32:41].uint * 0.1 - 20.0
        snr3 = val_bits[42:50].uint * 0.1 - 20.0

        interim = struct.unpack('<LLllll', cell_bytes[sir_cinr_offset:sir_cinr_offset+24])
        prj_sir = interim[0]
        if prj_sir & (1 << 31):
            prj_sir = prj_sir - 4294967296
        prj_sir = prj_sir / 16

        posticrsrq = (float((interim[1]))) * 0.0625 - 30.0

        cinr0 = interim[2]
        cinr1 = interim[3]
        cinr2 = interim[4]
        cinr3 = interim[5]

        return 'LTE ML1 SCell Meas Response (Cell {}): PCI: {}, SFN/SubFN: {}/{}, Serving cell index: {}, is_serving_cell: {}\n'.format(cell_id, pci, sfn, subfn, scell_idx, is_scell)

    def parse_lte_ml1_scell_meas_response_cell_v48(self, cell_id, cell_bytes):
        # resid_freq_error = struct.unpack('<H', cell_bytes[84:86])[0]
        return self.parse_lte_ml1_scell_meas_response_cell_v36(cell_id, cell_bytes, snr_offset=92, sir_cinr_offset=116)

    def parse_lte_ml1_scell_meas_response_cell_v60(self, cell_id, cell_bytes):
        pass

    def parse_lte_ml1_scell_meas_response(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
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
                        stdout += 'LTE ML1 SCell Meas Response: EARFCN: {}, Number of cells: {}, Valid RX: {}\n'.format(subpkt_scell_meas_v36.earfcn,
                            subpkt_scell_meas_v36.num_cells, subpkt_scell_meas_v36.valid_rx)

                        pos_meas = 8
                        for y in range(subpkt_scell_meas_v36.num_cells):
                            stdout += self.parse_lte_ml1_scell_meas_response_cell_v36(y, subpkt_body[pos_meas:pos_meas+128])
                            pos_meas += 128
                    elif subpkt_header.version == 48 or subpkt_header.version == 50:
                        # EARFCN, num of cell, valid RX data
                        subpkt_scell_meas_v48_struct = namedtuple('QcDiagLteMl1SubpktScellMeasV48', 'earfcn num_cells valid_rx rx_map')
                        subpkt_scell_meas_v48 = subpkt_scell_meas_v48_struct._make(struct.unpack('<LHHL', subpkt_body[0:12]))
                        stdout += 'LTE ML1 SCell Meas Response: EARFCN: {}, Number of cells: {}, Valid RX: {}\n'.format(subpkt_scell_meas_v48.earfcn,
                            subpkt_scell_meas_v48.num_cells, subpkt_scell_meas_v48.valid_rx)

                        pos_meas = 12
                        for y in range(subpkt_scell_meas_v48.num_cells):
                            stdout += self.parse_lte_ml1_scell_meas_response_cell_v48(y, subpkt_body[pos_meas:pos_meas+140])
                            pos_meas += 140
                    # elif subpkt_header.version == 60:
                    #     subpkt_scell_meas_v60_struct = namedtuple('QcDiagLteMl1SubpktScellMeasV60', 'earfcn num_cells')
                    #     subpkt_scell_meas_v60 = subpkt_scell_meas_v60_struct._make(struct.unpack('<LL', subpkt_body[0:8]))
                    #     stdout += 'LTE ML1 SCell Meas Response: EARFCN {}, Number of cells = {}\n'.format(subpkt_scell_meas_v60.earfcn,
                    #         subpkt_scell_meas_v60.num_cells)

                    #     pos_meas = 8
                    #     for y in range(subpkt_scell_meas_v60.num_cells):
                    #         # stdout += self.parse_lte_ml1_scell_meas_response_cell_v60(y, subpkt_body[pos_meas:pos_meas+148])
                    #         pos_meas += 148
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas Serving Cell Measurement Result subpacket version {}'.format(subpkt_header.version))
                            self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                else:
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas subpacket ID 0x{:02x}'.format(subpkt_header.id))
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

            return {'stdout': stdout.rstrip(), 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas Response packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 cell info packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        pci_pbch_phich_bits = bitstring.Bits(uint=item.pci_pbch_phich % 65536, length=16)
        pci = pci_pbch_phich_bits[0:9].uint
        pbch = pci_pbch_phich_bits[9:10].uint
        phich_duration = pci_pbch_phich_bits[10:13].uint
        phich_resource = pci_pbch_phich_bits[13:16].uint

        if self.parent:
            self.parent.lte_last_bw_dl[radio_id] = item.dl_bandwidth
            self.parent.lte_last_cell_id[radio_id] = pci
            self.parent.lte_last_earfcn_dl[radio_id] = item.earfcn

        mib_payload = struct.pack('!L', item.mib_bytes)[0:3]
        if item.dl_bandwidth in prb_to_mhz:
            stdout = 'LTE ML1 Cell Info: EARFCN: {}, PCI: {}, Bandwidth: {} MHz, Num antennas: {}'.format(item.earfcn, pci, prb_to_mhz[item.dl_bandwidth], item.num_antennas)
        else:
            stdout = 'LTE ML1 Cell Info: EARFCN: {}, PCI: {}, Bandwidth: {} PRBs, Num antennas: {}'.format(item.earfcn, pci, item.dl_bandwidth, item.num_antennas)

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if self.gsmtapv3:
            gsmtapv3_metadata = dict()
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = pci
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.SFN] = item.sfn
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.LTE_RRC,
                arfcn = item.earfcn,
                sub_type = util.gsmtapv3_lte_rrc_types.BCCH_BCH,
                device_sec = ts_sec,
                device_usec = ts_usec,
                metadata=gsmtapv3_metadata)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = item.earfcn,
                sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
                device_sec = ts_sec,
                device_usec = ts_usec)

        return {'layer': 'rrc', 'cp': [gsmtap_hdr + mib_payload], 'ts': pkt_ts, 'stdout': stdout}

    # MAC

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
            version = 2,
            payload_type = util.gsmtap_type.LTE_MAC,
            arfcn = 0,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return gsmtap_hdr + mac_hdr + body


    def parse_lte_mac_subpkt_v1(self, pkt_header, pkt_body, args):
        num_subpacket = pkt_body[1]
        mac_pkts = []

        pos = 4
        for i in range(num_subpacket):
            subpkt_mac_struct = namedtuple('QcDiagLteMacSubpkt', 'id version size')
            subpkt_mac = subpkt_mac_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_mac.size]
            pos += (4 + subpkt_mac.size)

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
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH Response Subpacket version {}'.format(subpkt_mac.version))
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                    continue

                if subpkt_mac_rach_attempt.rach_result != 0x00: # RACH Failure, 0x00 == Success
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'RACH result is not success: {}'.format(subpkt_mac_rach_attempt.rach_result))
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                    continue

                if subpkt_mac_rach_attempt.msg_bitmask & 0x07 != 0x07:
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, 'Not all msgs are present: not generating RAR and MAC PDU')
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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
                    version = 2,
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
                mac_pkts.append(packet_mac_rar)

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
                mac_pkts.append(packet_mac_pdu)

            elif subpkt_mac.id == 0x07: # DL Transport Block
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
                            self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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
            elif subpkt_mac.id == 0x08: # UL Transport Block
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
                            self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unhandled LTE MAC Subpacket ID 0x{:02x}'.format(subpkt_mac.id))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                continue

        if len(mac_pkts) > 0:
            return {'layer': 'mac', 'cp': mac_pkts, 'ts': pkt_ts}

    def parse_lte_mac_rach_trigger(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_mac_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC RACH trigger packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

    def parse_lte_mac_rach_response(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_mac_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC RACH response packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

    def parse_lte_mac_dl_block(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_mac_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC DL transport block packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

    def parse_lte_mac_ul_block(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_mac_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC UL transport block packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

    # PDCP

    def parse_lte_pdcp_subpkt_v1(self, pkt_header, pkt_body, args):
        rbid = -1
        pdcp_pkts = []

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)

        # pkt[1]: Number of Subpackets
        # pkt[2:4]: Reserved
        n_subpackets = pkt_body[1]
        pos = 4

        for x in range(n_subpackets):
            subpkt_pdcp_struct = namedtuple('QcDiagLtePdcpSubpkt', 'id version size')
            subpkt_pdcp = subpkt_pdcp_struct._make(struct.unpack('<BBH', pkt_body[pos:pos+4]))
            subpkt_body = pkt_body[pos+4:pos+4+subpkt_pdcp.size]
            pos += (4 + subpkt_pdcp.size)

            if subpkt_pdcp.id == 0xC3: # DL/UL Ciphered PDU
                if subpkt_pdcp.version in (0x18, 0x1a):
                    # DL
                    # 01 | 01 | 22 00 | C3 | 18 | 48 00 | 8E 57 8A BF BE 9D B2 38 13 BE 85 12 95 18 9A 29 | 55 4C 9B 9C 2D 35 A9 F8 D9 28 4D CF 08 EB 09 40 | 03 | 03 | 02 00 | [21 40 | 08 00 | 03 00 | 17 22 | 02 00 00 00 | 00 | 02 F4 CE] | [22 42 | 07 00 | 03 00 | 17 22 | 00 00 00 00 | 00 | 00 28 E0]
                    # UL
                    # 01 | 01 | 00 00 | C3 | 1A | 4C 00 | 8E 57 8A BF BE 9D B2 38 13 BE 85 12 95 18 9A 29 | 55 4C 9B 9C 2D 35 A9 F8 D9 28 4D CF 08 EB 09 40 | 03 | 03 | 02 00 | [04 47 | 2E 04 | 04 00 | 10 22 | 00 00 00 00 | 00 | 80 00 60 00] | [04 47 | 2E 04 | 04 00 | 18 22 | 01 00 00 00 | 00 | 80 01 60 00 ] | 80 00
                    ck_srb = subpkt_body[0:16]
                    ck_drb = subpkt_body[16:32]
                    ciphering_algo_srb, ciphering_algo_drb, num_pdus = struct.unpack('<BBH', subpkt_body[32:36])

                    pos_sample = 36
                    for y in range(num_pdus):
                        # cfg, pdu_size, log_size, sfn_subfn, count, is_compressed
                        # Ciphering: NONE: 0x07, AES: 0x03
                        pdu_hdr = struct.unpack('<HHHHLB', subpkt_body[pos_sample:pos_sample + 13])
                        pdcp_pdu = subpkt_body[pos_sample + 13: pos_sample + 13 + pdu_hdr[2]]

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
                        ws_hdr = struct.pack('!BBBBBBB',
                            0x00,
                            util.pdcp_plane_types.SIGNALING_PLANE if rbid == 0 or rbid == 1 else util.pdcp_plane_types.USER_PLANE,
                            0x00,
                            util.pdcp_lte_tags.PDCP_LTE_SEQNUM_LENGTH_TAG,
                            sn_length,
                            util.pdcp_lte_tags.PDCP_LTE_DIRECTION_TAG,
                            util.pdcp_lte_direction_types.DIRECTION_DOWNLINK if pkt_header.log_id == diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_PDCP_DL_CIPHER_DATA_PDU) else util.pdcp_lte_direction_types.DIRECTION_UPLINK)

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
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP Cipher Data Subpacket version %s' % subpkt_pdcp.version)
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                    continue
            elif subpkt_pdcp.id == 0xC6: # SRB Integrity DL
                if subpkt_pdcp.version in (0x01, 0x28):
                    ck_srb = subpkt_body[0:16]
                    ik_srb = subpkt_body[16:32]
                    ciphering_algo, integrity_algo, num_pdus = struct.unpack('<BBH', subpkt_body[32:36])

                    pos_sample = 36
                    for y in range(num_pdus):
                        # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I, XMAC-I
                        # Ciphering: NONE: 0x07, AES: 0x03
                        # Integrity: NONE: 0x07, AES: 0x02
                        pdu_hdr = struct.unpack('<HHHHLLL', subpkt_body[pos_sample:pos_sample + 20])
                        pdcp_pdu = subpkt_body[pos_sample + 20: pos_sample + 20 + pdu_hdr[2]]

                        # V1: config index 6b, rb mode 1b (AM=0, UM=1), sn length 2b (5, 7, 12), rbid-1 5b, valid 1b, reserved 1b
                        # V40: config index 6b, rb mode 1b, sn length 3b (5, 7, 12, 15, 18), rbid-1 5b, valid 1b
                        if subpkt_pdcp.version == 0x01:
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0180) >> 7
                            rbid = (pdu_hdr[0] & 0x3e00) >> 9
                            valid = (pdu_hdr[0] & 0x4000) >> 14
                        elif subpkt_pdcp.version == 0x40:
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0380) >> 7
                            rbid = (pdu_hdr[0] & 0x7c00) >> 10
                            valid = (pdu_hdr[0] & 0x8000) >> 15
                        else:
                            if self.parent:
                                self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL PDU Subpacket version %s' % subpkt_pdcp.version)
                                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL SIB Integrity Protected Data Subpacket version %s' % subpkt_pdcp.version)
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                    continue
            elif subpkt_pdcp.id == 0xC7: # SRB Integrity UL
                if subpkt_pdcp.version in (0x01, 0x28):
                    ck_srb = subpkt_body[0:16]
                    ik_srb = subpkt_body[16:32]
                    ciphering_algo, integrity_algo, num_pdus = struct.unpack('<BBH', subpkt_body[32:36])

                    pos_sample = 36
                    for y in range(num_pdus):
                        # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I
                        # Ciphering: NONE: 0x07, AES: 0x03
                        # Integrity: NONE: 0x07, AES: 0x02
                        pdu_hdr = struct.unpack('<HHHHLL', subpkt_body[pos_sample:pos_sample + 16])
                        pdcp_pdu = subpkt_body[pos_sample + 16: pos_sample + 16 + pdu_hdr[2]]

                        # V1: config index 6b, rb mode 1b (AM=0, UM=1), sn length 2b (5, 7, 12), rbid-1 5b, valid 1b, reserved 1b
                        # V40: config index 6b, rb mode 1b, sn length 3b (5, 7, 12, 15, 18), rbid-1 5b, valid 1b
                        if subpkt_pdcp.version == 0x01:
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0180) >> 7
                            rbid = (pdu_hdr[0] & 0x3e00) >> 9
                            valid = (pdu_hdr[0] & 0x4000) >> 14
                        elif subpkt_pdcp.version == 0x40:
                            config_index = pdu_hdr[0] & 0x003f
                            rb_mode = (pdu_hdr[0] & 0x0040) >> 6
                            sn_length = (pdu_hdr[0] & 0x0380) >> 7
                            rbid = (pdu_hdr[0] & 0x7c00) >> 10
                            valid = (pdu_hdr[0] & 0x8000) >> 15
                        else:
                            self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL PDU Subpacket version %s' % subpkt_pdcp.version)
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
                    self.parent.logger.log(logging.WARNING, 'Unexpected PDCP Subpacket ID 0x{:02x}'.format(subpkt_pdcp.id))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                continue

        if len(pdcp_pkts) > 0:
            return {'layer': 'pdcp', 'up': pdcp_pkts, 'ts': pkt_ts}

    def parse_lte_pdcp_dl_cip(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_pdcp_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL Cipher Data packet version {:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

    def parse_lte_pdcp_ul_cip(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_pdcp_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP UL Cipher Data packet version {:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

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

        if pkt_version == 0x01:
            return self.parse_lte_pdcp_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL SRB Integrity Protected Data packet version {:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

    def parse_lte_pdcp_ul_srb_int(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]

        if pkt_version == 0x01:
            return self.parse_lte_pdcp_subpkt_v1(pkt_header, pkt_body, args)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown PDCP UL SRB Integrity Protected Data packet version {:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

    # RRC

    def parse_lte_mib(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
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
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE MIB packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        stdout = ''
        if pkt_version == 1 or pkt_version == 2:
            if item.bandwidth in prb_to_mhz:
                stdout = 'LTE MIB Info: EARFCN: {}, SFN: {:4}, Bandwidth: {} MHz, TX antennas: {}'.format(item.earfcn, item.sfn, prb_to_mhz[item.bandwidth], item.tx_antenna)
            else:
                stdout = 'LTE MIB Info: EARFCN: {}, SFN: {:4}, Bandwidth: {} PRBs, TX antennas: {}'.format(item.earfcn, item.sfn, item.bandwidth, item.tx_antenna)

        elif pkt_version == 17:
            # MIB for NB-IoT (only 1 PRB)
            stdout = 'LTE MIB-NB Info: EARFCN: {}, SFN: {:4}, TX antennas: {}'.format(item.earfcn, item.sfn, item.tx_antenna)

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_lte_rrc_cell_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
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
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE RRC cell info packet version 0x{:02x}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
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

        if self.display_format == 'd':
            tac_cid_fmt = 'TAC/CID: {}/{}'.format(item.tac, item.cell_id)
        elif self.display_format == 'x':
            tac_cid_fmt = 'xTAC/xCID: {:x}/{:x}'.format(item.tac, item.cell_id)
        elif self.display_format == 'b':
            tac_cid_fmt = 'TAC/CID: {}/{} ({:#x}/{:#x})'.format(item.tac, item.cell_id, item.tac, item.cell_id)

        if item.mnc_digit == 2:
            stdout = 'LTE RRC SCell Info: EARFCN: {}/{}, Band: {}, Bandwidth: {}, PCI: {}, MCC: {}, MNC: {:02}, {}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        elif item.mnc_digit == 3:
            stdout = 'LTE RRC SCell Info: EARFCN: {}/{}, Band: {}, Bandwidth: {}, PCI: {}, MCC: {}, MNC: {:03}, {}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        else:
            stdout = 'LTE RRC SCell Info: EARFCN: {}/{}, Band: {}, Bandwidth: {}, PCI: {}, MCC: {}, MNC: {}, {}'.format(item.dl_earfcn,
                item.ul_earfcn, item.band, bw_str, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_lte_rrc(self, pkt_header, pkt_body, args):
        pkt_version = pkt_body[0]
        msg_content = b''

        item_struct = namedtuple('QcDiagLteRrcOtaPacket', 'rrc_rel_maj rrc_rel_min rbid pci earfcn sfn_subfn pdu_num len')
        item_struct_v5 = namedtuple('QcDiagLteRrcOtaPacketV5', 'rrc_rel_maj rrc_rel_min rbid pci earfcn sfn_subfn pdu_num sib_mask len')
        item_struct_v25 = namedtuple('QcDiagLteRrcOtaPacketV25', 'rrc_rel_maj rrc_rel_min nr_rrc_rel_maj nr_rrc_rel_min rbid pci earfcn sfn_subfn pdu_num sib_mask len')
        item_struct_v30 = namedtuple('QcDiagLteRrcOtaPacketV30', 'rrc_rel_maj rrc_rel_min nr_rrc_rel_maj nr_rrc_rel_min rbid pci earfcn sfn_subfn pdu_num sib_mask len unk1 unk2 segment_id')
        item = None

        if pkt_version >= 30:
            # Version 30
            item = item_struct_v30._make(struct.unpack('<BBBB BHLH BLHBBB', pkt_body[1:24]))
            msg_content = pkt_body[24:]
        elif pkt_version >= 25:
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
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        if pkt_version >= 30:
            if item.segment_id == 0:
                # Not segmented RRC, check previously cached
                pass
            elif item.segment_id in range(1, 7):
                # Part of the segment, leading is 1
                self.rrc_segments[item.segment_id] = msg_content
                self.first_segment_item = item
                return None
            elif item.segment_id == 7:
                # End of segmented RRC
                segment_joined = b''
                for i in range(1, 7):
                    if i in self.rrc_segments:
                        segment_joined += self.rrc_segments[i]
                segment_joined += msg_content
                msg_content = segment_joined
                self.rrc_segments = dict()
                self.first_segment_item = None

        sfn_subfn_bits = bitstring.Bits(uint=item.sfn_subfn, length=16)
        subfn = sfn_subfn_bits[0:4].uint
        sfn = sfn_subfn_bits[4:16].uint

        t_v2 = util.gsmtap_lte_rrc_types
        t_v3 = util.gsmtapv3_lte_rrc_types
        if pkt_version in (0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0d, 0x16):
            # RRC Packet <v9, v13, v22
            rrc_subtype_map = {
                1: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                2: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                3: (t_v2.MCCH, t_v3.MCCH),
                4: (t_v2.PCCH, t_v3.PCCH),
                5: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                6: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                7: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                8: (t_v2.UL_DCCH, t_v3.UL_DCCH)
            }
        elif pkt_version in (0x09, 0x0c):
            # RRC Packet v9-v12
            rrc_subtype_map = {
                8: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                9: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                10: (t_v2.MCCH, t_v3.MCCH),
                11: (t_v2.PCCH, t_v3.PCCH),
                12: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                13: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                14: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                15: (t_v2.UL_DCCH, t_v3.UL_DCCH)
            }
        elif pkt_version in (0x0e,):
            # RRC Packet v14
            rrc_subtype_map = {
                1: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                2: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                4: (t_v2.MCCH, t_v3.MCCH),
                5: (t_v2.PCCH, t_v3.PCCH),
                6: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                7: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                8: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                9: (t_v2.UL_DCCH, t_v3.UL_DCCH)
            }
        elif pkt_version in (0x0f, 0x10):
            # RRC Packet v15, v16
            rrc_subtype_map = {
                1: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                2: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                4: (t_v2.MCCH, t_v3.MCCH),
                5: (t_v2.PCCH, t_v3.PCCH),
                6: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                7: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                8: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                9: (t_v2.UL_DCCH, t_v3.UL_DCCH)
            }
        elif pkt_version in (0x13, 0x1a, 0x1b, 0x1d, 0x1e):
            # RRC Packet v19, v26, v27, v29, v30
            rrc_subtype_map = {
                1: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                3: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                6: (t_v2.MCCH, t_v3.MCCH),
                7: (t_v2.PCCH, t_v3.PCCH),
                8: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                9: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                10: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                11: (t_v2.UL_DCCH, t_v3.UL_DCCH),
                45: (t_v2.BCCH_BCH_NB, t_v3.BCCH_BCH_NB),
                46: (t_v2.BCCH_DL_SCH_NB, t_v3.BCCH_DL_SCH_NB),
                47: (t_v2.PCCH_NB, t_v3.PCCH_NB),
                48: (t_v2.DL_CCCH_NB, t_v3.DL_CCCH_NB),
                49: (t_v2.DL_DCCH_NB, t_v3.DL_DCCH_NB),
                50: (t_v2.UL_CCCH_NB, t_v3.UL_CCCH_NB),
                52: (t_v2.UL_DCCH_NB, t_v3.UL_DCCH_NB)
            }
        elif pkt_version in (0x14, 0x18, 0x19):
            # RRC Packet v20, v24, v25
            rrc_subtype_map = {
                1: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
                2: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
                4: (t_v2.MCCH, t_v3.MCCH),
                5: (t_v2.PCCH, t_v3.PCCH),
                6: (t_v2.DL_CCCH, t_v3.DL_CCCH),
                7: (t_v2.DL_DCCH, t_v3.DL_DCCH),
                8: (t_v2.UL_CCCH, t_v3.UL_CCCH),
                9: (t_v2.UL_DCCH, t_v3.UL_DCCH),
                54: (t_v2.BCCH_BCH_NB, t_v3.BCCH_BCH_NB),
                55: (t_v2.BCCH_DL_SCH_NB, t_v3.BCCH_DL_SCH_NB),
                56: (t_v2.PCCH_NB, t_v3.PCCH_NB),
                57: (t_v2.DL_CCCH_NB, t_v3.DL_CCCH_NB),
                58: (t_v2.DL_DCCH_NB, t_v3.DL_DCCH_NB),
                59: (t_v2.UL_CCCH_NB, t_v3.UL_CCCH_NB),
                61: (t_v2.UL_DCCH_NB, t_v3.UL_DCCH_NB),
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

        if self.gsmtapv3:
            gsmtapv3_metadata = dict()
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = item.pci
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.SFN] = sfn
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.SUBFN] = subfn
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.LTE_RRC,
                arfcn = item.earfcn,
                sub_type = gsmtap_subtype[1],
                device_sec = ts_sec,
                device_usec = ts_usec,
                metadata=gsmtapv3_metadata)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = item.earfcn,
                frame_number = sfn,
                sub_type = gsmtap_subtype[0],
                device_sec = ts_sec,
                device_usec = ts_usec)

        return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}

    def parse_lte_cacombos(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if self.parent:
            if not self.parent.cacombos:
                return None

        return {'stdout': 'LTE UE CA Combos Raw: {}'.format(binascii.hexlify(pkt_body).decode()), 'ts': pkt_ts}

    # NAS

    def parse_lte_nas(self, pkt_header, pkt_body, args, plain = False):
        pkt_version = pkt_body[0]

        item_struct = namedtuple('QcDiagLteNasMsg', 'vermaj vermid vermin')
        item = item_struct._make(struct.unpack('<BBB', pkt_body[1:4]))
        msg_content = pkt_body[4:]

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if self.gsmtapv3:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NAS_EPS,
                arfcn = 0,
                sub_type = 0 if plain else 1,
                device_sec = ts_sec,
                device_usec = ts_usec)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_NAS,
                arfcn = 0,
                sub_type = 0 if plain else 1,
                device_sec = ts_sec,
                device_usec = ts_usec)

        return {'layer': 'nas', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}
