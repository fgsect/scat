#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagLteLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.no_process = {
            0xB061: 'LTE MAC RACH Trigger',
        }

        self.process = {
            # LTE
            # LTE ML1
            #0xB179: lambda x, y, z: self.parse_lte_ml1_connected_intra_freq_meas(x, y, z), # LTE ML1 Connected Mode LTE Intra-Freq Measurements
            0xB17F: lambda x, y, z: self.parse_lte_ml1_scell_meas(x, y, z), # LTE ML1 Serving Cell Meas and Eval
            0xB180: lambda x, y, z: self.parse_lte_ml1_ncell_meas(x, y, z), # LTE ML1 Neighbor Measurements
            #0xB181 LTE ML1 Intra Frequency Cell Reselection
            # 01 02 F8 14 0A 02 0C 00 16 0D 00 00 61 03 00 00 0B 20 84 00 00 00 00 00 02 00 00 00 40 06 00 00 79 25 12 12 A0 4B F8 02 7F F9 CB 38 E3 DE CB 0F 30 48 F8 02 62 11 CB 31 C7 9E CB 0F 5A 45 08 03 4E 71 CA 2E BB 1E CB 0F 15 43 EF 02 39 C9 C9 29 A7 DE CA 0F 16 0D 00 00 79 0F 00 0A 61 4D 5B 03 85 31 8B 4C 34 DF CE 0F 38 18 00 00 79 1C 12 0E 67 62 8E 03 36 B2 11 41 04 DF 0E 00 66 56 8D 03 D2 91 0E 33 CC 5E CD 0F EB 4F 88 03 9E F1 0C 20 80 5E CC 0F
            # 01 03 FC 14 0A 02 0C 00 9C 18 00 00 D6 02 00 00 05 19 10 00 01 00 00 00 85 40 00 00 04 00 00 00 0B 20 38 00 01 00 00 00 03 00 00 00 9C 18 00 00 79 0D 00 04 D6 56 A0 03 B6 69 CD 3F 0A 9F CE 0F 22 0B 00 00 79 07 0C 0C 09 07 00 00 79 06 0C 0C 7D 00 00 00 79 04 16 0A
            #0xB192: lambda x, y, z: self.parse_lte_ml1_ncell_meas_rr(x, y, z), # LTE ML1 Neighbor Cell Meas Request/Response
            # 01 02 02 00 1A 02 1C 00 16 0D 00 00 21 00 00 00 60 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1B 04 40 00 16 0D 00 00 01 00 00 00 60 01 00 00 81 13 38 00 82 23 38 00 82 23 38 00 DD 74 03 0C C0 74 D3 0D B5 00 00 00 D2 90 06 00 00 00 00 00 32 00 31 00 FE 06 03 00 FE 06 03 00 00 00 00 00
            # 01 02 02 00 1A 02 3C 00 38 18 00 00 23 00 00 00 67 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 66 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 EB 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1B 04 A8 00 38 18 00 00 03 00 00 00 67 00 00 00 B6 64 4B 00 49 94 44 00 B6 64 4B 00 06 19 F4 10 0F 3D F4 10 C1 01 00 00 4A 09 0E 00 00 00 00 00 35 00 37 00 A2 58 00 00 A2 58 00 00 00 00 00 00 66 00 00 00 71 14 47 00 D3 33 3D 00 71 14 47 00 C0 00 93 09 99 00 03 0C C2 01 00 00 4B 11 0E 00 00 00 00 00 35 00 37 00 82 58 00 00 82 58 00 00 00 00 00 00 EB 01 00 00 35 54 43 00 AD D3 3A 00 35 54 43 00 83 0C 62 08 86 18 62 08 C3 01 00 00 38 19 0E 00 00 00 00 00 35 00 37 00 52 69 00 00 52 69 00 00 00 00 00 00
            0xB193: lambda x, y, z: self.parse_lte_ml1_scell_meas_response(x, y, z), # LTE ML1 Serving Cell Meas Response
            #0xB194: lambda x, y, z: self.parse_lte_ml1_search_rr(x, y, z), # LTE ML1 Search Request/Response
            #0xB195: lambda x, y, z: self.parse_lte_ml1_connected_ncell_meas_rr(x, y, z), # LTE ML1 Connected Neighbor Meas Request/Response
            0xB197: lambda x, y, z: self.parse_lte_ml1_cell_info(x, y, z), # LTE ML1 Serving Cell Info

            # LTE MAC
            #0xB167: lambda x, y, z: parse_lte_msg1_report(x, y, z), # LTE RAR (Msg1) Report
            #0xB168: lambda x, y, z: parse_lte_msg2_report(x, y, z), # LTE RAR (Msg2) Report
            #0xB169: lambda x, y, z: parse_lte_msg3_report(x, y, z), # LTE UE Identification Message (Msg3) Report
            #0xB16A: lambda x, y, z: parse_lte_msg3_report(x, y, z), # LTE Contention Resolution Message (Msg4) Report
            #0xB061: lambda x, y, z: self.parse_lte_mac_rach_trigger(x, y, z), # LTE MAC RACH Trigger
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
            0xB0C1: lambda x, y, z: self.parse_lte_mib(x, y, z), # LTE RRC MIB Message
            0xB0C2: lambda x, y, z: self.parse_lte_rrc_cell_info(x, y, z), # LTE RRC Serving Cell Info
            0xB0C0: lambda x, y, z: self.parse_lte_rrc(x, y, z), # LTE RRC OTA Message
            #LTE CA COMBOS
            0xB0CD: lambda x, y, z: self.parse_cacombos(x, y, z),
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

    def parse_lte_ml1_scell_meas(self, pkt_ts, pkt, radio_id):
        # Version 1b
        if pkt[0] == 5: # Version 5
            # EARFCN -> 4 bytes
            # PCI, Serv Layer Priority -> 4 bytes
            rrc_rel = pkt[1]
            earfcn = struct.unpack('<L', pkt[4:8])[0]
            pci = (pkt[8] | pkt[9] << 8) & 0x1ff
            serv_layer_priority = (pkt[8] | pkt[9] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[12:20])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[20:36])
            meas_rsrq = interim_1 & 0x3ff
            avg_rsrq = (interim_1 >> 20) & 0x3ff

            meas_rssi = (interim_2 >> 10) # TODO: get to know exact bit mask

            q_rxlevmin = interim_3 & 0x3f
            p_max = (interim_3 >> 6) & 0x7f
            max_ue_tx_pwr = (interim_3 >> 13) & 0x3f
            s_rxlev = (interim_3 >> 19) & 0x7f
            num_drx_s_fail = (interim_3 >> 26)

            s_intra_search = interim_4 & 0x3f
            s_non_intra_search = (interim_4 >> 6) & 0x3f

            if rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt[36:40])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(rrc_rel))
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('Radio {}: LTE SCell: EARFCN {}, PCI {:3d}, Measured RSRP {:.2f}, Measured RSSI {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), earfcn, pci, real_rsrp, real_rssi))
        elif pkt[0] == 4: # Version 4
            # Version, RRC standard release, EARFCN, PCI - Serving Layer Priority
            # Measured, Average RSRP, Measured, Average RSRQ, Measured RSSI
            # Q_rxlevmin, P_max, Max UE TX Power, S_rxlev, Num DRX S Fail
            # S Intra Searcn, S Non Intra Search, Meas Rules Updated, Meas Rules
            # R9 Info (last 4b) - Q Qual Min, S Qual, S Intra Search Q, S Non Intra Search Q
            # 04 | 01 | 00 00 | 9C 18 | D6 0A | EC C4 4E 00 | E2 24 4E 00 | FF FC E3 0F | FE D8 0A 00 | 47 AD 56 02 | 1D 31 01 00 | A2 62 41 00 
            rrc_rel = pkt[1]
            earfcn = pkt[4] | pkt[5] << 8
            pci = (pkt[6] | pkt[7] << 8) & 0x1ff
            serv_layer_priority = (pkt[6] | pkt[7] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[8:16])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[16:32])
            meas_rsrq = interim_1 & 0x3ff
            avg_rsrq = (interim_1 >> 20) & 0x3ff

            meas_rssi = (interim_2 >> 10) # TODO: get to know exact bit mask

            q_rxlevmin = interim_3 & 0x3f
            p_max = (interim_3 >> 6) & 0x7f
            max_ue_tx_pwr = (interim_3 >> 13) & 0x3f
            s_rxlev = (interim_3 >> 19) & 0x7f
            num_drx_s_fail = (interim_3 >> 26)

            s_intra_search = interim_4 & 0x3f
            s_non_intra_search = (interim_4 >> 6) & 0x3f

            if rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt[32:36])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(rrc_rel))
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('Radio {}: LTE SCell: EARFCN {}, PCI {:3d}, Measured RSRP {:.2f}, Measured RSSI {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), earfcn, pci, real_rsrp, real_rssi))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 Serving Cell Meas packet version {}'.format(pkt[0]))
            return

    def parse_lte_ml1_ncell_meas(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 5: # Version 5
            # EARFCN -> 4 bytes
            rrc_rel = pkt[1]
            earfcn = struct.unpack('<L', pkt[4:8])[0]
            q_rxlevmin = (pkt[8] | pkt[9] << 8) & 0x3f
            n_cells = (pkt[8] | pkt[9] << 8) >> 6
            print('Radio {}: LTE NCell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[12 + 32 * i:12 + 32 * (i + 1)]
                interim = struct.unpack('<LLLLHHLL', n_cell_pkt[0:28])
                n_pci = interim[0] & 0x1ff
                n_meas_rssi = (interim[0] >> 9) & 0x7ff
                n_meas_rsrp = (interim[0] >> 20)
                n_avg_rsrp = (interim[1] >> 12) & 0xfff
                n_meas_rsrq = (interim[2] >> 12) & 0x3ff
                n_avg_rsrq = interim[3] & 0x3ff
                n_s_rxlev = (interim[3] >> 20) & 0x3f
                n_freq_offset = interim[4]
                n_ant0_frame_offset = interim[6] & 0x7ff
                n_ant0_sample_offset = (interim[6] >> 11)
                n_ant1_frame_offset = interim[7] & 0x7ff
                n_ant1_sample_offset = (interim[7] >> 11)

                if rrc_rel == 1: # Rel 9
                    r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                    n_s_qual = r9_info_interim[0]

                n_real_rsrp = -180 + n_meas_rsrp * 0.0625
                n_real_rssi = -110 + n_meas_rssi * 0.0625
                n_real_rsrq = -30 + n_meas_rsrq * 0.0625

                print('Radio {}: Neighbor cell {}: PCI {:3d}, RSRP {:.2f}, RSSI {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_pci, n_real_rsrp, n_real_rssi))
        elif pkt[0] == 4: # Version 4
            # Version, RRC standard release, EARFCN, Q_rxlevmin, Num Cells, Cell Info
            # Cell Info - PCI, Measured RSSI, Measured RSRP, Average RSRP
            #    Measured RSRQ, Average RSRQ, S_rxlev, Freq Offset
            #    Ant0 Frame Offset, Ant0 Sample Offset, Ant1 Frame Offset, Ant1 Sample Offset
            #    S_qual
            # 04 | 01 | 00 00 9C 18 | 47 00 | 83 48 E4 4D | DE A4 4C 00 | CA B4 CC 32 | B6 D8 42 03 | 00 00 | 00 00 | FF 77 33 01 | FF 77 33 01 | 22 02 01 00 
            rrc_rel = pkt[1]
            earfcn = pkt[4] | pkt[5] << 8
            q_rxlevmin = (pkt[6] | pkt[7] << 8) & 0x3f
            n_cells = (pkt[6] | pkt[7] << 8) >> 6
            print('Radio {}: LTE NCell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[8 + 32 * i:8 + 32 * (i + 1)]
                interim = struct.unpack('<LLLLHHLL', n_cell_pkt[0:28])
                n_pci = interim[0] & 0x1ff
                n_meas_rssi = (interim[0] >> 9) & 0x7ff
                n_meas_rsrp = (interim[0] >> 20)
                n_avg_rsrp = (interim[1] >> 12) & 0xfff
                n_meas_rsrq = (interim[2] >> 12) & 0x3ff
                n_avg_rsrq = interim[3] & 0x3ff
                n_s_rxlev = (interim[3] >> 20) & 0x3f
                n_freq_offset = interim[4]
                n_ant0_frame_offset = interim[6] & 0x7ff
                n_ant0_sample_offset = (interim[6] >> 11)
                n_ant1_frame_offset = interim[7] & 0x7ff
                n_ant1_sample_offset = (interim[7] >> 11)

                if rrc_rel == 1: # Rel 9
                    r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                    n_s_qual = r9_info_interim[0]
                n_real_rsrp = -180 + n_meas_rsrp * 0.0625
                n_real_rssi = -110 + n_meas_rssi * 0.0625
                n_real_rsrq = -30 + n_meas_rsrq * 0.0625

                print('Radio {}: Neighbor cell {}: PCI {:3d}, RSRP {:.2f}, RSSI {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_pci, n_real_rsrp, n_real_rssi))
        else:
            self.parent.logger.log(logging.WARNING, 'Radio {}: Unknown LTE ML1 Neighbor Meas packet version {}'.format(self.parent.sanitize_radio_id(radio_id), pkt[0]))

    def parse_lte_ml1_scell_meas_response(self, pkt_ts, pkt, radio_id):
        # First 4b: Version, Number of subpackets, reserved
        # 01 | 01 | 35 0c 
        if pkt[0] == 1: # Version 1
            num_subpkts = pkt[1]
            pos = 4

            for x in range(num_subpkts):
                # 4b: Subpacket ID, Subpacket version, Subpacket size
                # 19 | 30 | 40 02
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0x19:
                    # Serving Cell Measurement Result
                    # EARFCN, num of cell, valid RX data
                    if subpkt_version == 36:
                        # 16 0d 00 00 | 01 00 | 03 00 | d4 10 00 00 9b 24 00 00 fe f0 03 00 7f f8 d9 04 9b 90 0f 00 e4 b3 44 00 4b 04 00 00 00 b0 1c 00 4b 64 46 00 2d b5 94 13 39 01 00 00 39 e5 64 12 77 91 0e 00 00 00 00 00 d2 01 00 00 0d 00 08 00 32 00 31 00 00 00 10 49 a9 3c 04 00 43 85 0d 00 07 75 02 00 00 00 00 00 7d 04 00 00 9b 0c 00 00 0a 6f 02 00 00 00 00 00 a6 00 00 00 39 01 00 00 87 06 00 00 11 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00            
                        earfcn, n_cells, valid_rx = struct.unpack('<LHH', subpkt[0:8])

                        pos_cell = 8
                        for y in range(n_cells):
                            pass
                    elif subpkt_version == 48:
                        # EARFCN, num of cell, valid RX data
                        # 35 0c 01 00 | 01 00 | 03 00 | 00 01 ff ff ee 10 00 00 4c 15 00 00 40 79 02 00 a0 3c 61 0a 4c 21 0f 00 ca 93 44 00 4b 04 00 00 60 09 96 00 00 90 1c 00 49 b4 44 00 de 78 13 0e e1 00 00 00 e1 84 43 0f 96 99 10 00 00 00 00 00 13 02 00 00 0b 00 03 00 00 00 00 00 37 00 3a 00 00 00 00 00 00 00 08 cc 25 f2 00 00 92 0b 01 00 c6 94 01 00 00 00 00 00 d0 00 00 00 e4 00 00 00 bf 86 01 00 00 00 00 00 14 00 00 00 e1 00 00 00 1e ff ff ff 84 ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                        # 35 0c 01 00 | 01 00 | 03 00 | 00 01 ff ff ee 10 00 00 4c 15 00 00 40 79 02 00 a0 3c 61 0a 4c 21 0f 00 ca 93 44 00 4b 04 00 00 60 09 96 00 00 90 1c 00 49 b4 44 00 de 78 13 0e e1 00 00 00 e1 84 43 0f 96 99 10 00 00 00 00 00 13 02 00 00 0b 00 03 00 00 00 00 00 37 00 3a 00 00 00 00 00 00 00 08 cc 25 f2 00 00 92 0b 01 00 c6 94 01 00 00 00 00 00 d0 00 00 00 e4 00 00 00 bf 86 01 00 00 00 00 00 14 00 00 00 e1 00 00 00 1e ff ff ff 84 ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00                                    
                        earfcn, num_cell, valid_rx, rx_map = struct.unpack('<LHHL', subpkt[0:12])
                        interim = struct.unpack('<HHH', subpkt[12:18])
                        pci = interim[0] & 511
                        scell_idx = (interim[0] >> 9) & 7
                        is_scell = (interim[0] >> 12) & 1

                        sfn = interim[2] & 1023
                        subfn = (interim[2] >> 10) & 15

                        interim = struct.unpack('<LLLLLLLLLLLL', subpkt[28:76])
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
                        resid_freq_error = struct.unpack('<H', subpkt[96:98])[0]

                        interim = struct.unpack('<LL', subpkt[104:112])
                        snr0 = (float((interim[0]) & 511)) * 0.1 - 20.0
                        snr1 = (float((interim[0] >> 9) & 511)) * 0.1 - 20.0
                        snr2 = (float((interim[1]) & 511)) * 0.1 - 20.0
                        snr3 = (float((interim[1] >> 9) & 511)) * 0.1 - 20.0

                        interim = struct.unpack('<LLLLLL', subpkt[128:152])
                        prj_sir = interim[0]
                        if prj_sir & (1 << 31):
                            prj_sir = prj_sir - 4294967296
                        prj_sir = prj_sir / 16

                        posticrsrq = (float((interim[1]))) * 0.0625 - 30.0

                        cinr0 = interim[2]
                        if cinr0 & (1 << 31):
                            cinr0 = cinr0 - 4294967296

                        cinr1 = interim[3]
                        if cinr1 & (1 << 31):
                            cinr1 = cinr1 - 4294967296

                        cinr2 = interim[4]
                        if cinr2 & (1 << 31):
                            cinr2 = cinr2 - 4294967296

                        cinr3 = interim[5]
                        if cinr3 & (1 << 31):
                            cinr3 = cinr3 - 4294967296

                        print('Radio {}: LTE ML1 SCell Meas Response: EARFCN {}, Number of cells = {}, Valid RX = {}'.format(self.parent.sanitize_radio_id(radio_id), earfcn, num_cell, valid_rx))
                        print('Radio {}: LTE ML1 SCell Meas Response (Cell 0): PCI {}, Serving cell index {}, is_serving_cell = {}'.format(self.parent.sanitize_radio_id(radio_id), pci, scell_idx, is_scell))

                    else:
                        self.parent.logger.log(logging.WARNING, 'Radio {}: Unknown LTE ML1 Serving Cell Meas Serving Cell Measurement Result subpacket version {}'.format(self.parent.sanitize_radio_id(radio_id), subpkt_version))
                else:
                    self.parent.logger.log(logging.WARNING, 'Radio {}: Unknown LTE ML1 Serving Cell Meas subpacket ID {}'.format(self.parent.sanitize_radio_id(radio_id), subpkt_id))
        else:
            self.parent.logger.log(logging.WARNING, 'Radio {}: Unknown LTE ML1 Serving Cell Meas Response packet version {}'.format(self.parent.sanitize_radio_id(radio_id), pkt[0]))

    def parse_lte_ml1_cell_info(self, pkt_ts, pkt, radio_id):
        mib_payload = bytes([0, 0, 0])

        if pkt[0] == 1: # Version 1
            # Version, DL BW, SFN, EARFCN, (Cell ID, PBCH, PHICH Duration, PHICH Resource), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 01 | 64 | A4 01 | 14 05 | 24 42 | 41 05 00 00 | D3 2D 00 00 | 80 53 3D 00 00 00 00 00 | 00 00 A4 A9 | 1D FF | 01 00 
            pkt_content = struct.unpack('<BHH', pkt[1:6])

            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[0]
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = pkt_content[1]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[2]

            mib_payload = bytes([pkt[27], pkt[26], pkt[25]])
        elif pkt[0] == 2: # Version 2
            # Version, DL BW, SFN, EARFCN, (Cell ID 9, PBCH 1, PHICH Duration 3, PHICH Resource 3), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 02 | 4B | F8 00 | 21 07 00 00 | 03 23 00 00 | 00 00 00 00 | 0F 05 00 00 | 2A BD 0B 17 00 00 00 00 | 00 00 F8 84 | 00 00 | 01 00 
            pkt_content = struct.unpack('<BHL', pkt[1:8])

            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[0]
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = pkt_content[1]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[2]

            mib_payload = bytes([pkt[31], pkt[30], pkt[29]])
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE ML1 cell info packet version {}'.format(pkt[0]))

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)],
            sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + mib_payload, radio_id, pkt_ts)

    def parse_lte_mac_rach_trigger(self, pkt_ts, pkt, radio_id):
        # XXX: Wireshark's GSMTAP dissector does not support PRACH preamble
        self.parent.logger.log(logging.WARNING, "Unhandled XDM Header 0xB061: LTE MAC RACH Trigger")
        return

    def parse_lte_mac_rach_response(self, pkt_ts, pkt, radio_id):
        msg_content = pkt
        mac_header = b''
        mac_body = b''
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] | (1 << 14)

        pkt_version, num_subpacket, reserved = struct.unpack('<BBH', msg_content[0:4])
        pkt_pos = 4

        if pkt_version != 0x01:
            self.parent.logger.log(logging.WARNING, 'Unsupported LTE MAC RACH response packet version 0x%02x' % msg_content[0])
            return

        for i in range(num_subpacket):
            # subpkt_size includes the header size
            if (len(pkt) - pkt_pos) < 4:
                break
            subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', msg_content[pkt_pos:pkt_pos+4])
            subpkt = pkt[pkt_pos+4:pkt_pos+4+subpkt_size]
            pkt_pos += subpkt_size

            if subpkt_id == 0x06: # RACH Attempt
                if subpkt_version == 0x02: # Version 2
                    # [06 | 02 | 24 00] | 01 | 00 | 01 | 07 | [1B | FF | 98 FF] | [00 00 | 01 | 23 1A 04 00] | [18 1C 01 00 | 07 00 | 06 | 00 46 5C 80 BD 06 48 00 00 00]
                    rach_attempt = subpkt[0]
                    rach_result = subpkt[1]
                    rach_msg_bitmask = subpkt[3]
                    rach_msg1 = subpkt[4:8]
                    rach_msg2 = subpkt[8:15]
                    rach_msg3 = subpkt[15:32]
                elif msg_content[5] == 0x03:  # Version 3
                    # [06 | 03 | 28 00] | 01 | 00 | 01 | 00 | 01 | 07 | [18 | FF | 98 FF] | [00 00 | 01 | B9 88 04 00] | [18 18 01 00 | 07 00 | 05 | 00 55 F1 60 A8 1E A6 00 00 00 ] | 00 00
                    # [06 | 03 | 28 00] | 01 | 00 | 01 | 00 | 01 | 07 | [11 | ff | 9c ff] | [00 00 | 01 | f2 cb 05 00] | [b4 de 00 00 | 12 00 | 02 | 20 06 1f 46 8e 47 58 9a a8 00 ] | 11 00
                    rach_attempt = subpkt[2]
                    rach_result = subpkt[3]
                    rach_msg_bitmask = subpkt[5]
                    rach_msg1 = subpkt[6:10]
                    rach_msg2 = subpkt[10:17]
                    rach_msg3 = subpkt[17:34]
                else:
                    self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH Response Subpacket version %s' % subpkt_version)
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
                    continue

                if rach_result != 0x00: # RACH Failure, 0x00 == Success
                    self.parent.logger.log(logging.WARNING, 'RACH result is not success: {}'.format(rach_result))
                    continue
                if rach_msg_bitmask != 0x07: # not all message present
                    self.parent.logger.log(logging.WARNING, 'Not enough message to generate RAR')
                    continue

                rapid = rach_msg1[0]
                backoff, rach_result, tc_rnti, ta = struct.unpack('<HBHH', rach_msg2)
                grant, grant_val, harq_id = struct.unpack('<LHB', rach_msg3[0:7])
                grant = (grant & 0xfffff)
                mac_pdu = rach_msg3[7:] # Contains initial RRC message

                # MAC header required by Wireshark MAC-LTE: radioType, direction, rntiType
                # Additional headers required for each message types
                mac_header_rar = struct.pack('!BBBBBBB',
                    util.mac_lte_radio_types.FDD_RADIO,
                    util.mac_lte_direction_types.DIRECTION_DOWNLINK,
                    util.mac_lte_rnti_types.RA_RNTI,
                    util.mac_lte_tags.MAC_LTE_SEND_PREAMBLE_TAG,
                    rapid,
                    rach_attempt,
                    util.mac_lte_tags.MAC_LTE_PAYLOAD_TAG)

                # RAR payload
                # E = 0, T = 1, RAPID (7b), TA (12b), UL Grant (20b), TC-RNTI (16b)

                rar_body = struct.pack('!BBBHH',
                    (1 << 6) | (rapid & 0x3f),
                    (ta & 0x0ff0) >> 4,
                    ((ta & 0x000f) << 4) | ((grant & 0x0f0000) >> 16),
                    grant & 0x00ffff,
                    tc_rnti)

                mac_header_msg = struct.pack('!BBBBHB',
                    util.mac_lte_radio_types.FDD_RADIO,
                    util.mac_lte_direction_types.DIRECTION_UPLINK,
                    util.mac_lte_rnti_types.C_RNTI,
                    util.mac_lte_tags.MAC_LTE_RNTI_TAG,
                    tc_rnti,
                    util.mac_lte_tags.MAC_LTE_PAYLOAD_TAG)

                self.parent.lte_last_tcrnti[self.parent.sanitize_radio_id(radio_id)] = tc_rnti
                ts_sec = calendar.timegm(pkt_ts.timetuple())
                ts_usec = pkt_ts.microsecond

                gsmtap_hdr = util.create_gsmtap_header(
                    version = 3,
                    payload_type = util.gsmtap_type.LTE_MAC,
                    arfcn = earfcn,
                    device_sec = ts_sec,
                    device_usec = ts_usec)

                self.parent.writer.write_cp(gsmtap_hdr + mac_header_rar + rar_body, self.parent.sanitize_radio_id(radio_id), pkt_ts)
                self.parent.writer.write_cp(gsmtap_hdr + mac_header_msg + mac_pdu, self.parent.sanitize_radio_id(radio_id), pkt_ts)
            else:
                self.parent.logger.log(logging.WARNING, 'Unexpected MAC RACH Response Subpacket ID %s' % subpkt_id)

    def create_lte_mac_gsmtap_packet(self, pkt_ts, is_downlink, header, body, radio_id):
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)]
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
            arfcn = earfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + mac_hdr + body, self.parent.sanitize_radio_id(radio_id), pkt_ts)

    def parse_lte_mac_dl_block(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0x07:
                    if subpkt_version == 0x02:
                        n_samples = subpkt[0]
                        #print("LTE MAC DL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))

                        pos_sample = 1
                        for y in range(n_samples):
                            header = struct.unpack('<HBBHHBHB', subpkt[pos_sample:pos_sample+12])
                            sfn_subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len = header

                            sfn = (sfn_subfn & 0xfff0) >> 4
                            subfn = sfn_subfn & 0xf
                            mac_hdr = subpkt[pos_sample + 12:pos_sample + 12 + header_len]

                            self.create_lte_mac_gsmtap_packet(pkt_ts, True, {'sfn': sfn, 'subfn': subfn,
                                'rnti_type': rnti_type, 'harq_id': harq_id, 'pmch_id': pmch_id,
                                'dl_tbs': dl_tbs, 'rlc_pdus': rlc_pdus, 'padding': padding},
                                mac_hdr,
                                radio_id)
                            pos_sample += (12 + header_len)
                    elif subpkt_version == 0x04:
                        # 01 | 00 | 00 | 09 10 | 02 | 01 | 00 00 | 07 00 | 00 | 00 00 | 07 | 40 0C 0F 0F 8F 2D B0 | 00 00
                        # 01 | 01 | 00 | b9 21 | 02 | 01 | 00 00 | 07 00 | 00 | 00 00 | 07 | 40 06 0f 3d bb 60 b0 | 00 00
                        # 03 | 00 | 00 | 00 2D | 05 | 01 | 00 00 | 1C 00 | 00 | 00 00 | 1C | 00 01 03 27 63 8D DA A5 5C 26 D0 53 90 18 00 00 80 0A 17 55 A2 A8 2F 62 35 F5 06 0C 
                        #    | 00 | 00 | 10 2D | 05 | 01 | 00 00 | 07 00 | 00 | 00 00 | 07 | 00 04 2B 8B 50 6D C4 |
                        #    | 00 | 00 | 20 2D | 05 | 01 | 00 00 | 12 00 | 00 | 00 00 | 12 | 00 0C 56 05 E8 91 AA 61 23 90 58 0E 74 36 A9 84 8C 40
                        n_samples = subpkt[0]
                        #print("LTE MAC DL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))
                        pos_sample = 1
                        for y in range(n_samples):
                            header = struct.unpack('<BBHBBHHBHB', subpkt[pos_sample:pos_sample+14])
                            subid, cid, sfn_subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len = header

                            sfn = (sfn_subfn & 0xfff0) >> 4
                            subfn = sfn_subfn & 0xf
                            mac_hdr = subpkt[pos_sample + 14:pos_sample + 14 + header_len]

                            self.create_lte_mac_gsmtap_packet(pkt_ts, True, {'sfn': sfn, 'subfn': subfn,
                                'rnti_type': rnti_type, 'harq_id': harq_id, 'pmch_id': pmch_id,
                                'dl_tbs': dl_tbs, 'rlc_pdus': rlc_pdus, 'padding': padding},
                                mac_hdr,
                                radio_id)
                            pos_sample += (14 + header_len)
                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected DL MAC Subpacket version {}'.format(subpkt_version))
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC DL packet version {}'.format(pkt[0]))

    def parse_lte_mac_ul_block(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
                subpkt = subpkt[4:]

                pos += subpkt_size

                if subpkt_id == 0x08:
                    if subpkt_version == 0x01:
                        n_samples = subpkt[0]
                        #print("LTE MAC UL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_version, subpkt_size, n_samples))

                        pos_sample = 1
                        for y in range(n_samples):
                            header = struct.unpack('<BBHHBHBBB', subpkt[pos_sample:pos_sample+12])
                            harq_id, rnti_type, sfn_subfn, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len = header

                            # BSR Event: {0: None, 1: Periodic, 2: High Data Arrival}
                            # BSR Trig: {0: No BSR, 3: S-BSR, 4: Pad L-BSR}
                            sfn = (sfn_subfn & 0xfff0) >> 4
                            subfn = sfn_subfn & 0xf
                            mac_hdr = subpkt[pos_sample + 12:pos_sample + 12 + header_len]

                            self.create_lte_mac_gsmtap_packet(pkt_ts, False, {'sfn': sfn, 'subfn': subfn,
                                'rnti_type': rnti_type, 'harq_id': harq_id, 'grant': grant,
                                'rlc_pdus': rlc_pdus, 'padding': padding, 'bsr_event': bsr_event,
                                'bsr_trig': bsr_trig},
                                mac_hdr,
                                radio_id)
                            pos_sample += (12 + header_len)
                    elif subpkt_version == 0x02:
                        n_samples = subpkt[0]
                        #print("LTE MAC UL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_version, subpkt_size, n_samples))

                        pos_sample = 1
                        for y in range(n_samples):
                            header = struct.unpack('<BBBBHHBHBBB', subpkt[pos_sample:pos_sample+14])
                            subid, cid, harq_id, rnti_type, sfn_subfn, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len = header

                            # BSR Event: {0: None, 1: Periodic, 2: High Data Arrival}
                            # BSR Trig: {0: No BSR, 3: S-BSR, 4: Pad L-BSR}
                            sfn = (sfn_subfn & 0xfff0) >> 4
                            subfn = sfn_subfn & 0xf
                            mac_hdr = subpkt[pos_sample + 14:pos_sample + 14 + header_len]

                            self.create_lte_mac_gsmtap_packet(pkt_ts, False, {'sfn': sfn, 'subfn': subfn,
                                'rnti_type': rnti_type, 'harq_id': harq_id, 'grant': grant,
                                'rlc_pdus': rlc_pdus, 'padding': padding, 'bsr_event': bsr_event,
                                'bsr_trig': bsr_trig},
                                mac_hdr,
                                radio_id)
                            pos_sample += (14 + header_len)
                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected LTE MAC UL Subpacket version %s' % subpkt_version)
                        self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE MAC UL packet version %s' % pkt[0])

    def parse_lte_pdcp_dl_cip(self, pkt_ts, pkt, radio_id):
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)]
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
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
                            self.parent.writer.write_up(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id, pkt_ts)
                            pos_sample += (13 + pdu_hdr[2])

                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL Cipher Data Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL Cipher Data packet version %s' % pkt[16])

    def parse_lte_pdcp_ul_cip(self, pkt_ts, pkt, radio_id):
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)]
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
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
                            self.parent.writer.write_up(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id, pkt_ts)
                            pos_sample += (13 + pdu_hdr[2])

                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL Cipher Data Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL Cipher Data packet version %s' % pkt[16])

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

    def parse_lte_pdcp_dl_srb_int(self, pkt_ts, pkt, radio_id):
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)]
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
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
                            self.parent.writer.write_up(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id, pkt_ts)
                            pos_sample += (20 + pdu_hdr[2])

                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP DL SRB Subpacket version %s' % subpkt_ver)
                        pos += subpkt_size
                        continue
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown PDCP DL SRB packet version %s' % pkt[16])

    def parse_lte_pdcp_ul_srb_int(self, pkt_ts, pkt, radio_id):
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] | (1 << 14)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                subpkt_id, subpkt_version, subpkt_size = struct.unpack('<BBH', pkt[pos:pos+4])
                subpkt = pkt[pos:pos+subpkt_size]
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
                            self.parent.writer.write_up(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id, pkt_ts)
                            pos_sample += (16 + pdu_hdr[2])

                    else:
                        self.parent.logger.log(logging.WARNING, 'Unexpected PDCP UL SRB Subpacket version %s' % subpkt_version)
                        pos += subpkt_size
                        continue
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown PDCP UL SRB packet version %s' % pkt[16])

    def parse_lte_mib(self, pkt_ts, pkt, radio_id):
        msg_content = pkt
        # 1.4, 3, 5, 10, 15, 20 MHz - 6, 15, 25, 50, 75, 100 PRBs
        prb_to_bitval = {6: 0, 15: 1, 25: 2, 50: 3, 75: 4, 100: 5}
        mib_payload = [0, 0, 0]

        if pkt[0] == 1:
            if len(msg_content) != 9:
                return 
            msg_content = struct.unpack('<BHHHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 01 | 00 01 | 14 05 | 54 00 | 02 | 64 

            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = msg_content[1]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[2]
            self.parent.lte_last_earfcn_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[2] + 18000
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = msg_content[3]
            self.parent.lte_last_tx_ant[self.parent.sanitize_radio_id(radio_id)] = msg_content[4]
            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]
            self.parent.lte_last_bw_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]
        elif pkt[0] == 2:
            if len(msg_content) != 11:
                return 
            msg_content = struct.unpack('<BHLHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 02 | 03 01 | 21 07 00 00 | F8 00 | 02 | 4B 

            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = msg_content[1]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[2]
            self.parent.lte_last_earfcn_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[2] + 18000
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = msg_content[3]
            self.parent.lte_last_tx_ant[self.parent.sanitize_radio_id(radio_id)] = msg_content[4]
            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]
            self.parent.lte_last_bw_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]
        elif pkt[0] == 17:
            if len(msg_content) != 18:  #Version 17 : MIB-NB (only 1 PRB)
                return
            # 11 | 0b 00 | fa 09 00 00 | b9 03 | 0e 00 | 02 02 | 00 02 02 d0 02 
            # Version, Physical CID, EARFCN, SFN,
            # SFN_MSB 4b, HSFN_LSB2 2b, SIB1_SCH_INFO 4b, SYS_INFO_VALUE_TAG 5b , ACCESS_BARRING 1b, OP_TYPE 2b, OP_INFO 5b, Spare 9b Tx Ant, 
            msg_content = struct.unpack('<BHLHBBBBLB', msg_content)
            #  
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = msg_content[1]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[2]
            self.parent.lte_last_earfcn_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[2] + 18000
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = msg_content[3]
            self.parent.lte_last_tx_ant[self.parent.sanitize_radio_id(radio_id)] = msg_content[9]
            #self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]
            #self.parent.lte_last_bw_ul[self.parent.sanitize_radio_id(radio_id)] = msg_content[5]

            mib_payload[0] = msg_content[5]
            mib_payload[1] = msg_content[4]
            mib_payload[2] = msg_content[7]
            mib_payload.append(msg_content[6])

            ts_sec = calendar.timegm(pkt_ts.timetuple())
            ts_usec = pkt_ts.microsecond
            
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)],
                sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH_NB,
                device_sec = ts_sec,
                device_usec = ts_usec)
            
            mib_payload = bytes(mib_payload)
            self.parent.writer.write_cp(gsmtap_hdr + mib_payload, radio_id, pkt_ts)


        if pkt[0] == 1 or pkt[0] == 2:
            sfn4 = int(self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] / 4)
            # BCCH BCH payload: DL bandwidth 3b, PHICH config (duration 1b, resource 2b), SFN 8b, Spare 10b (all zero)
            if prb_to_bitval.get(self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)]) != None:
                mib_payload[0] = (prb_to_bitval.get(self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)]) << 5) | (2 << 2) | ((sfn4 & 0b11000000) >> 6)
                mib_payload[1] = (sfn4 & 0b111111) << 2

            mib_payload = bytes(mib_payload)

            ts_sec = calendar.timegm(pkt_ts.timetuple())
            ts_usec = pkt_ts.microsecond
        
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)],
                sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
                device_sec = ts_sec,
                device_usec = ts_usec)

            self.parent.writer.write_cp(gsmtap_hdr + mib_payload, radio_id, pkt_ts)

    def parse_lte_rrc_cell_info(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 2:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 02 | 8F 00 | 14 05 | 64 4B | 64 | 64 | 00 74 BC 01 | D6 05 | 03 00 00 00 | 06 01 | 02 01 00 00
            pkt_content = struct.unpack('<HHHBB', pkt[1:9])

            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = pkt_content[0]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[1]
            self.parent.lte_last_earfcn_ul[self.parent.sanitize_radio_id(radio_id)] = pkt_content[2]
            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[3]
            self.parent.lte_last_bw_ul[self.parent.sanitize_radio_id(radio_id)] = pkt_content[4]
        elif pkt[16] == 3 or pkt[0] == 3:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 03 | 4D 00 | 21 07 00 00 | 71 4D 00 00 | 4B | 4B | 33 C8 B0 09 | 15 9B | 03 00 00 00 | CC 01 | 02 0B 00 00
            # 03 | 0b 00 | fa 09 00 00 | 4A 50 00 00 | 00 | 00 | 0b 06 92 00 | 0b 90 | 05 00 00 00 | c2 01 | 02 06 00 00
            pkt_content = struct.unpack('<HLLBB', pkt[1:13])

            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = pkt_content[0]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[1]
            self.parent.lte_last_earfcn_ul[self.parent.sanitize_radio_id(radio_id)] = pkt_content[2]
            self.parent.lte_last_bw_dl[self.parent.sanitize_radio_id(radio_id)] = pkt_content[3]
            self.parent.lte_last_bw_ul[self.parent.sanitize_radio_id(radio_id)] = pkt_content[4]
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown LTE RRC cell info packet version %s' % pkt[0])

    def parse_lte_rrc(self, pkt_ts, pkt, radio_id):
        msg_hdr = b''
        msg_content = b''

        if pkt[0] in (0x19, 0x1a, 0x1b): # Version 25, 26, 27
            # 19 | 0f 30 | 00 00 | 00 | 09 01 | 9c 18 00 00 | 45 51 | 02 | 00 00 00 00 | 33 00 | ...
            # 1a | 0f 40 | 0f 40 | 01 | 0e 01 | 13 07 00 00 | 00 00 | 0b | 00 00 00 00 | 02 00 | 10 15	
            # 1b | 10 10 | 0f 90 | 00 | b1 01 | 86 a0 00 00 | d5 07 | 00 | 00 00 00 07 | 00 05
            msg_hdr = pkt[0:21] # 21 bytes
            msg_content = pkt[21:] # Rest of packet
            if len(msg_hdr) != 21:
                return 
            msg_hdr = struct.unpack('<BHHBHLHBLH', msg_hdr) # Version, RRC Release, NR RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1
            p_cell_id = msg_hdr[4]
            earfcn = msg_hdr[5]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = earfcn
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = p_cell_id
            sfn = (msg_hdr[6] & 0xfff0) >> 4
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = sfn
            subfn = msg_hdr[6] & 0xf
            subtype = msg_hdr[7]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[0] in (0x08, 0x09, 0x0c, 0x0d, 0x0f, 0x10, 0x13, 0x14, 0x16, 0x18): # Version 8, 9, 12, 13, 15, 16, 19, 20, 22, 24
            # 08 | 0a 72 | 01 | 0e 00 | 9c 18 00 00 | a9 33 | 06 | 00 00 00 00 | 02 00 | 2e 02
            # 09 | 0b 70 | 00 | 00 01 | 14 05 00 00 | 09 91 | 0b | 00 00 00 00 | 07 00 | 40 0b ...
            # 0d | 0c 74 | 01 | 32 00 | 38 18 00 00 | 00 00 | 08 | 00 00 00 00 | 02 00 | 2c 00
            # 0f | 0d 21 | 00 | 9e 00 | 14 05 00 00 | 49 8c | 05 | 00 00 00 00 | 07 00 | 40 0c ...
            # 0f | 0d 21 | 01 | 9e 00 | 14 05 00 00 | 00 00 | 09 | 00 00 00 00 | 1c 00 | 08 10 ...
            # 13 | 0e 22 | 00 | 0b 00 | fa 09 00 00 | 00 00 | 32 | 00 00 00 00 | 09 00 | 28 18 ...
            # 14 | 0e 30 | 01 | 09 01 | 9c 18 00 00 | 00 00 | 09 | 00 00 00 00 | 18 00 | 08 10 ...
            # 18 | 0f 22 | 00 | 68 00 | e4 0c 00 00 | 09 dc | 05 | 00 00 00 00 | 0d 00 | 40 85 ...
            msg_hdr = pkt[0:19] # 19 bytes
            msg_content = pkt[19:] # Rest of packet
            if len(msg_hdr) != 19:
                return 
            msg_hdr = struct.unpack('<BHBHLHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1
            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = earfcn
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = p_cell_id
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[0] in (0x06, 0x07): # Version 6 and 7
            # 06 | 09 B1 | 00 | 07 01 | 2C 07 | 25 34 | 02 | 02 00 00 00 | 12 00 | 40 49 88 05 C0 97 02 D3 B0 98 1C 20 A0 81 8C 43 26 D0 
            msg_hdr = pkt[0:17] # 17 bytes
            msg_content = pkt[17:] # Rest of packet
            if len(msg_hdr) != 17:
                return 

            msg_hdr = struct.unpack('<BHBHHHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = earfcn
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = p_cell_id
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[0] in (0x02, 0x03, 0x04): # Version 2, 3, 4
            msg_hdr = pkt[0:13] # 13 bytes
            msg_content = pkt[13:] # Rest of packet
            if len(msg_hdr) != 13:
                return 

            msg_hdr = struct.unpack('<BHBHHHBH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)] = earfcn
            self.parent.lte_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = p_cell_id
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.parent.lte_last_sfn[self.parent.sanitize_radio_id(radio_id)] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)
        else:
            self.parent.logger.log(logging.WARNING, 'Unhandled LTE RRC packet version %s' % pkt[0])
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
            return 

        if pkt[0] in (0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0d, 0x16):
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
        elif pkt[0] in (0x09, 0x0c):
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
        elif pkt[0] in (0x0e,):
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
        elif pkt[0] in (0x0f, 0x10):
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
        elif pkt[0] in (0x13, 0x1a, 0x1b):
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
        elif pkt[0] in (0x14, 0x18, 0x19):
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

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if not (subtype in rrc_subtype_map.keys()):
            self.parent.logger.log(logging.WARNING, "Unknown RRC subtype 0x%02x for RRC packet version 0x%02x" % (subtype, pkt[0]))
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
            return 

        sub_type = rrc_subtype_map[subtype]
        # UL-EARFCN for UL-CCCH/UL-DCCH
        if sub_type == util.gsmtap_lte_rrc_types.UL_CCCH or sub_type == util.gsmtap_lte_rrc_types.UL_DCCH:
            earfcn = util.calculate_ul_earfcn(earfcn)

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = earfcn,
            frame_number = sfn,
            sub_type = sub_type,
            sub_slot = subfn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + msg_content, radio_id, pkt_ts)

    def parse_lte_nas(self, pkt_ts, pkt, radio_id, plain = False):
        # XXX: Qualcomm does not provide RF information on NAS-EPS
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        earfcn = self.parent.lte_last_earfcn_dl[self.parent.sanitize_radio_id(radio_id)]

        msg_content = pkt[4:]
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_NAS,
            arfcn = earfcn,
            sub_type = 0 if plain else 1,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + msg_content, radio_id, pkt_ts)

    def parse_cacombos(self, pkt_ts, pkt, radio_id):
        self.parent.logger.log(logging.WARNING, "0xB0CD " + util.xxd_oneline(pkt))
