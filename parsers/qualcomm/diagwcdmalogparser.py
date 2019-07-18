#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagWcdmaLogParser:
    def __init__(self, parent):
        self.parent = parent
        self.process = {
            # WCDMA (3G RRC)
            0x4005: lambda x, y, z: self.parse_wcdma_search_cell_reselection(x, y, z), # WCDMA Search Cell Reselection Rank
            0x4127: lambda x, y, z: self.parse_wcdma_cell_id(x, y, z), # WCDMA Cell ID
            0x412F: lambda x, y, z: self.parse_wcdma_rrc(x, y, z), # WCDMA Signaling Messages
        }

    # 3G
    def parse_wcdma_search_cell_reselection_v0(self, pkt_ts, pkt, radio_id):
        num_wcdma_cells = pkt[0] & 0x3f # lower 6b
        num_gsm_cells = pkt[1] # TODO: check if num_gsm_cells > 0

        print('Radio {}: 3G Cell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[2 + 10 * i:2 + 10 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt)
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Radio {}: Cell {}: UARFCN {}, PSC {:3d}, RSCP {}, Ec/Io {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))

    def parse_wcdma_search_cell_reselection_v1(self, pkt_ts, pkt, radio_id):
        num_wcdma_cells = pkt[0] & 0x3f # lower 6b
        num_gsm_cells = pkt[1] # TODO: check if num_gsm_cells > 0

        print('Radio {}: 3G Cell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[2 + 11 * i:2 + 11 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt[:10])
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Radio {}: Cell {}: UARFCN {}, PSC {:3d}, RSCP {}, Ec/Io {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))

    def parse_wcdma_search_cell_reselection_v2(self, pkt_ts, pkt, radio_id):
        num_wcdma_cells = pkt[0] & 0x3f # lower 6b
        num_gsm_cells = pkt[1] # TODO: check if num_gsm_cells > 0

        print('Radio {}: 3G Cell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[7 + 16 * i:7 + 16 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt[:10])
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Radio {}: Cell {}: UARFCN {}, PSC {:3d}, RSCP {}, Ec/Io {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))

    def parse_wcdma_search_cell_reselection(self, pkt_ts, pkt, radio_id):
        pkt_version = (pkt[0] >> 6) # upper 2b

        if pkt_version == 0:
            self.parse_wcdma_search_cell_reselection_v0(pkt_ts, pkt, radio_id)
        elif pkt_version == 1:
            self.parse_wcdma_search_cell_reselection_v1(pkt_ts, pkt, radio_id)
        elif pkt_version == 2:
            self.parse_wcdma_search_cell_reselection_v2(pkt_ts, pkt, radio_id)
        else:
            self.parent.logger.log(logging.WARNING, 'Unsupported WCDMA search cell reselection version {}'.format(pkt_version))
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt))

    def parse_wcdma_cell_id(self, pkt_ts, pkt, radio_id):
        result = struct.unpack('<LLLHHHBBBBBBLL', pkt[0:32])
        # UARFCN UL, UARFCN DL, CID, URA_ID, FLAGS, PSC, PLMN_ID, LAC, RAC
        # PSC needs to be >>4'ed
        self.parent.umts_last_uarfcn_ul[self.parent.sanitize_radio_id(radio_id)] = result[0] | (1 << 14)
        self.parent.umts_last_uarfcn_dl[self.parent.sanitize_radio_id(radio_id)] = result[1]
        self.parent.umts_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = result[2] & 0x7fff

    def parse_wcdma_rrc(self, pkt_ts, pkt, radio_id):
        channel_type, rbid, msg_len = struct.unpack('<BBH', pkt[0:4])
        sib_class = -1
        arfcn = 0
        msg_content = b''

        channel_type_map = {
                0: util.gsmtap_umts_rrc_types.UL_CCCH,
                1: util.gsmtap_umts_rrc_types.UL_DCCH,
                2: util.gsmtap_umts_rrc_types.DL_CCCH,
                3: util.gsmtap_umts_rrc_types.DL_DCCH,
                4: util.gsmtap_umts_rrc_types.BCCH_BCH, # Encoded
                5: util.gsmtap_umts_rrc_types.BCCH_FACH, # Encoded
                6: util.gsmtap_umts_rrc_types.PCCH,
                7: util.gsmtap_umts_rrc_types.MCCH,
                8: util.gsmtap_umts_rrc_types.MSCH,
                10: util.gsmtap_umts_rrc_types.System_Information_Container,
        }

        channel_type_map_extended_type = {
                9: util.gsmtap_umts_rrc_types.BCCH_BCH, # Extension SIBs
                0xFE: util.gsmtap_umts_rrc_types.BCCH_BCH, # Decoded
                0xFF: util.gsmtap_umts_rrc_types.BCCH_FACH # Decoded
        }

        sib_type_map = {
                0: util.gsmtap_umts_rrc_types.MasterInformationBlock,
                1: util.gsmtap_umts_rrc_types.SysInfoType1,
                2: util.gsmtap_umts_rrc_types.SysInfoType2,
                3: util.gsmtap_umts_rrc_types.SysInfoType3,
                4: util.gsmtap_umts_rrc_types.SysInfoType4,
                5: util.gsmtap_umts_rrc_types.SysInfoType5,
                6: util.gsmtap_umts_rrc_types.SysInfoType6,
                7: util.gsmtap_umts_rrc_types.SysInfoType7,
                8: util.gsmtap_umts_rrc_types.SysInfoType8,
                9: util.gsmtap_umts_rrc_types.SysInfoType9,
                10: util.gsmtap_umts_rrc_types.SysInfoType10,
                11: util.gsmtap_umts_rrc_types.SysInfoType11,
                12: util.gsmtap_umts_rrc_types.SysInfoType12,
                13: util.gsmtap_umts_rrc_types.SysInfoType13,
                14: util.gsmtap_umts_rrc_types.SysInfoType13_1,
                15: util.gsmtap_umts_rrc_types.SysInfoType13_2,
                16: util.gsmtap_umts_rrc_types.SysInfoType13_3,
                17: util.gsmtap_umts_rrc_types.SysInfoType13_4,
                18: util.gsmtap_umts_rrc_types.SysInfoType14,
                19: util.gsmtap_umts_rrc_types.SysInfoType15,
                20: util.gsmtap_umts_rrc_types.SysInfoType15_1,
                21: util.gsmtap_umts_rrc_types.SysInfoType15_2,
                22: util.gsmtap_umts_rrc_types.SysInfoType15_3,
                23: util.gsmtap_umts_rrc_types.SysInfoType16,
                24: util.gsmtap_umts_rrc_types.SysInfoType17,
                25: util.gsmtap_umts_rrc_types.SysInfoType15_4,
                26: util.gsmtap_umts_rrc_types.SysInfoType18,
                27: util.gsmtap_umts_rrc_types.SysInfoTypeSB1,
                28: util.gsmtap_umts_rrc_types.SysInfoTypeSB2,
                29: util.gsmtap_umts_rrc_types.SysInfoType15_5,
                30: util.gsmtap_umts_rrc_types.SysInfoType5bis,
                31: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                # Extension SIB
                66: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                67: util.gsmtap_umts_rrc_types.SysInfoType19
        }

        channel_type_map_new = {
                0x80: util.gsmtap_umts_rrc_types.UL_CCCH,
                0x81: util.gsmtap_umts_rrc_types.UL_DCCH,
                0x82: util.gsmtap_umts_rrc_types.DL_CCCH,
                0x83: util.gsmtap_umts_rrc_types.DL_DCCH,
                0x84: util.gsmtap_umts_rrc_types.BCCH_BCH, # Encoded
                0x85: util.gsmtap_umts_rrc_types.BCCH_FACH, # Encoded
                0x86: util.gsmtap_umts_rrc_types.PCCH,
                0x87: util.gsmtap_umts_rrc_types.MCCH,
                0x88: util.gsmtap_umts_rrc_types.MSCH,
        }
        channel_type_map_new_extended_type = {
                0x89: util.gsmtap_umts_rrc_types.BCCH_BCH, # Extension SIBs
                0xF0: util.gsmtap_umts_rrc_types.BCCH_BCH, # Decoded
        }
        sib_type_map_new = {
                0: util.gsmtap_umts_rrc_types.MasterInformationBlock,
                1: util.gsmtap_umts_rrc_types.SysInfoType1,
                2: util.gsmtap_umts_rrc_types.SysInfoType2,
                3: util.gsmtap_umts_rrc_types.SysInfoType3,
                4: util.gsmtap_umts_rrc_types.SysInfoType4,
                5: util.gsmtap_umts_rrc_types.SysInfoType5,
                6: util.gsmtap_umts_rrc_types.SysInfoType6,
                7: util.gsmtap_umts_rrc_types.SysInfoType7,
                8: util.gsmtap_umts_rrc_types.SysInfoType8,
                9: util.gsmtap_umts_rrc_types.SysInfoType9,
                10: util.gsmtap_umts_rrc_types.SysInfoType10,
                11: util.gsmtap_umts_rrc_types.SysInfoType11,
                12: util.gsmtap_umts_rrc_types.SysInfoType12,
                13: util.gsmtap_umts_rrc_types.SysInfoType13,
                14: util.gsmtap_umts_rrc_types.SysInfoType13_1,
                15: util.gsmtap_umts_rrc_types.SysInfoType13_2,
                16: util.gsmtap_umts_rrc_types.SysInfoType13_3,
                17: util.gsmtap_umts_rrc_types.SysInfoType13_4,
                18: util.gsmtap_umts_rrc_types.SysInfoType14,
                19: util.gsmtap_umts_rrc_types.SysInfoType15,
                20: util.gsmtap_umts_rrc_types.SysInfoType15_1,
                21: util.gsmtap_umts_rrc_types.SysInfoType15_2,
                22: util.gsmtap_umts_rrc_types.SysInfoType15_3,
                23: util.gsmtap_umts_rrc_types.SysInfoType16,
                24: util.gsmtap_umts_rrc_types.SysInfoType17,
                25: util.gsmtap_umts_rrc_types.SysInfoType15_4,
                26: util.gsmtap_umts_rrc_types.SysInfoType18,
                27: util.gsmtap_umts_rrc_types.SysInfoTypeSB1,
                28: util.gsmtap_umts_rrc_types.SysInfoTypeSB2,
                29: util.gsmtap_umts_rrc_types.SysInfoType15_5,
                30: util.gsmtap_umts_rrc_types.SysInfoType5bis,
                31: util.gsmtap_umts_rrc_types.SysInfoType19,
                # Extension SIB
                66: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                67: util.gsmtap_umts_rrc_types.SysInfoType19
        }

        if channel_type in channel_type_map.keys():
            arfcn = self.parent.umts_last_uarfcn_dl[self.parent.sanitize_radio_id(radio_id)]
            if channel_type == 0 or channel_type == 1:
                arfcn = self.parent.umts_last_uarfcn_ul[self.parent.sanitize_radio_id(radio_id)]

            subtype = channel_type_map[channel_type]
            msg_content = pkt[4:]
        elif channel_type in channel_type_map_extended_type.keys():
            arfcn = self.parent.umts_last_uarfcn_dl[self.parent.sanitize_radio_id(radio_id)]

            # uint8 subtype, uint8 msg[]
            if pkt[4] in sib_type_map.keys():
                subtype = sib_type_map[pkt[4]]
                msg_content = pkt[5:]
            else:
                self.parent.logger.log(logging.WARNING, "Unknown WCDMA SIB Class {}".format(pkt[4]))
                return
        elif channel_type in channel_type_map_new.keys():
            # uint16 uarfcn, uint16 psc, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt[4:8])

            subtype = channel_type_map_new[channel_type]
            msg_content = pkt[8:]
        elif channel_type in channel_type_map_new_extended_type.keys():
            # uint16 uarfcn, uint16 psc, uint8 subtype, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt[4:8])

            if pkt[8] in sib_type_map_new.keys():
                subtype = sib_type_map_new[pkt[8]]
                msg_content = pkt[9:]
            else:
                self.parent.logger.log(logging.WARNING, "Unknown WCDMA new SIB Class {}".format(pkt[8]))
                return
        else:
            self.parent.logger.log(logging.WARNING, "Unknown WCDMA RRC channel type {}".format(pkt[0]))
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
            return

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.UMTS_RRC,
            arfcn = arfcn,
            sub_type = subtype,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + msg_content, radio_id, pkt_ts)
