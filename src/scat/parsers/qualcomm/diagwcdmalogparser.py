#!/usr/bin/env python3

from collections import namedtuple
import binascii
import calendar
import logging
import math
import struct

import scat.parsers.qualcomm.diagcmd as diagcmd
import scat.util as util

class DiagWcdmaLogParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        i = diagcmd.diag_log_get_wcdma_item_id
        c = diagcmd.diag_log_code_wcdma
        self.process = {
            # Layer 1
            i(c.LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C): lambda x, y, z: self.parse_wcdma_search_cell_reselection(x, y, z),

            # Layer 2
            i(c.LOG_WCDMA_RLC_DL_AM_SIGNALING_PDU_C): lambda x, y, z: self.parse_wcdma_rlc_dl_am_signaling_pdu(x, y, z), # WCDMA RLC DL AM Signaling PDU
            i(c.LOG_WCDMA_RLC_UL_AM_SIGNALING_PDU_C): lambda x, y, z: self.parse_wcdma_rlc_ul_am_signaling_pdu(x, y, z), # WCDMA RLC UL AM Signaling PDU
            i(c.LOG_WCDMA_RLC_UL_AM_CONTROL_PDU_LOG_C): lambda x, y, z: self.parse_wcdma_rlc_ul_am_control_pdu_log(x, y, z), # WCDMA RLC UL AM Control PDU Log
            i(c.LOG_WCDMA_RLC_DL_AM_CONTROL_PDU_LOG_C): lambda x, y, z: self.parse_wcdma_rlc_dl_am_control_pdu_log(x, y, z), # WCDMA RLC DL AM Control PDU Log
            i(c.LOG_WCDMA_RLC_DL_PDU_CIPHER_PACKET_C): lambda x, y, z: self.parse_wcdma_rlc_dl_pdu_cipher_packet(x, y, z), # WCDMA RLC DL PDU Cipher Packet
            i(c.LOG_WCDMA_RLC_UL_PDU_CIPHER_PACKET_C): lambda x, y, z: self.parse_wcdma_rlc_ul_pdu_cipher_packet(x, y, z), # WCDMA RLC UL PDU Cipher Packet

            # RRC
            i(c.LOG_WCDMA_CELL_ID_C): lambda x, y, z: self.parse_wcdma_cell_id(x, y, z),
            i(c.LOG_WCDMA_SIGNALING_MSG_C): lambda x, y, z: self.parse_wcdma_rrc(x, y, z),
        }

    def update_parameters(self, display_format: str, gsmtapv3: bool):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def get_real_rscp(self, rscp: int) -> int:
        return rscp - 21

    def get_real_ecio(self, ecio: int) -> float:
        return ecio / 2

    # WCDMA Layer 1
    def parse_wcdma_search_cell_reselection(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_version = (pkt_body[0] >> 6) # upper 2b
        num_wcdma_cells = pkt_body[0] & 0x3f # lower 6b
        num_gsm_cells = pkt_body[1] & 0x3f # lower 6b
        stdout = ''

        cell_search_v0_3g = namedtuple('QcDiagWcdmaSearchCellReselectionV03G',
            'uarfcn psc rscp rank_rscp ecio rank_ecio')
        cell_search_v0_2g = namedtuple('QcDiagWcdmaSearchCellReselectionV02G',
            'arfcn bsic rssi rank')
        cell_search_v1_3g = namedtuple('QcDiagWcdmaSearchCellReselectionV13G',
            'uarfcn psc rscp rank_rscp ecio rank_ecio resel_status')
        cell_search_v1_2g = namedtuple('QcDiagWcdmaSearchCellReselectionV12G',
            'arfcn bsic rssi rank resel_status')
        cell_search_v2_3g = namedtuple('WcdmaSearchCellReselectionV23G',
            'uarfcn psc rscp rank_rscp ecio rank_ecio resel_status hcs_priority h_value hcs_cell_qualify')
        cell_search_v2_2g = namedtuple('WcdmaSearchCellReselectionV22G',
            'arfcn bsic rssi rank resel_status hcs_priority h_value hcs_cell_qualify')

        if pkt_version not in (0, 1, 2):
            self.parent.logger.log(logging.WARNING, 'Unsupported WCDMA search cell reselection version {}'.format(pkt_version))
            self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        stdout += 'WCDMA Search Cell: {} 3G cells, {} 2G cells\n'.format(num_wcdma_cells, num_gsm_cells)
        pos = 2
        if pkt_version == 2:
            pos += 5

        for i in range(num_wcdma_cells):
            if pkt_version == 0:
                cell_3g = cell_search_v0_3g._make(struct.unpack('<HHbhbh', pkt_body[pos:pos+10]))
                pos += 10
            elif pkt_version == 1:
                cell_3g = cell_search_v1_3g._make(struct.unpack('<HHbhbhb', pkt_body[pos:pos+11]))
                pos += 11
            elif pkt_version == 2:
                cell_3g = cell_search_v2_3g._make(struct.unpack('<HHbhbhbhhb', pkt_body[pos:pos+16]))
                pos += 16

            stdout += 'WCDMA Search Cell: 3G Cell {}: UARFCN: {}, PSC: {:3d}, RSCP: {}, Ec/Io: {:.2f}\n'.format(i,
                    cell_3g.uarfcn, cell_3g.psc,
                    self.get_real_rscp(cell_3g.rscp), self.get_real_ecio(cell_3g.ecio))

        for i in range(num_gsm_cells):
            if pkt_version == 0:
                cell_2g = cell_search_v0_2g._make(struct.unpack('<HHbh', pkt_body[pos:pos+7]))
                pos += 7
            elif pkt_version == 1:
                cell_2g = cell_search_v1_2g._make(struct.unpack('<HHbhb', pkt_body[pos:pos+8]))
                pos += 8
            elif pkt_version == 2:
                cell_2g = cell_search_v2_2g._make(struct.unpack('<HHbhbhhb', pkt_body[pos:pos+13]))
                pos += 13

            stdout += 'WCDMA Search Cell: 2G Cell {}: ARFCN: {}, RSSI: {:.2f}, Rank: {}'.format(i,
                    cell_2g.arfcn & 0xfff, cell_2g.rssi, cell_2g.rank)

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    # WCDMA Layer 2
    def parse_wcdma_rlc_dl_am_signaling_pdu(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct = namedtuple('QcDiagWcdmaRlcDlAmSignalingPdu', 'lcid pdu_count pdu_size')
        num_packets = pkt_body[0]
        packets = []

        pos = 1
        for x in range(num_packets):
            item = item_struct._make(struct.unpack('<BHH', pkt_body[pos:pos+5]))
            pos += 5
            actual_pdu_size = min(math.ceil(item.pdu_size / 8), len(pkt_body) - pos)
            rlc_pdu = pkt_body[pos:pos+actual_pdu_size]
            pos += actual_pdu_size

            # Directly pack RLC PDU on UDP packet, see epan/packet-umts_rlc-lte.h of Wireshark
            # Has header on PDU, CP (0x01), no ROHC
            # Direction: Downlink (0x01)
            ws_hdr = struct.pack('!BBBBB',
                util.wcdma_rlc_tags.RLC_MODE_TAG,
                util.wcdma_rlc_mode_types.RLC_AM,
                util.wcdma_rlc_tags.RLC_DIRECTION_TAG,
                util.wcdma_rlc_direction_types.DIRECTION_DOWNLINK,
                util.wcdma_rlc_tags.RLC_PAYLOAD_TAG)

            packets.append(b'umts-rlc' + ws_hdr + rlc_pdu)

        return {'layer': 'rlc', 'up': packets, 'ts': pkt_ts}

    def parse_wcdma_rlc_ul_am_signaling_pdu(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        return {'stdout': 'WCDMARLCAMUL ' + binascii.hexlify(pkt_body).decode(), 'ts': pkt_ts}

    def parse_wcdma_rlc_dl_am_control_pdu_log(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        lcid, pdu_size = struct.unpack('<BH', pkt_body[0:3])
        rlc_pdu = pkt_body[3:3+pdu_size]
        # rlc_pdu = pkt_body[3:]

        # Directly pack RLC PDU on UDP packet, see epan/packet-umts_rlc-lte.h of Wireshark
        # Has header on PDU, CP (0x01), no ROHC
        # Direction: Downlink (0x01)
        ws_hdr = struct.pack('!BBBBB',
            util.wcdma_rlc_tags.RLC_MODE_TAG,
            util.wcdma_rlc_mode_types.RLC_AM,
            util.wcdma_rlc_tags.RLC_DIRECTION_TAG,
            util.wcdma_rlc_direction_types.DIRECTION_DOWNLINK,
            util.wcdma_rlc_tags.RLC_PAYLOAD_TAG)

        return {'layer': 'rlc', 'up': [b'umts-rlc' + ws_hdr + rlc_pdu], 'ts': pkt_ts}

    def parse_wcdma_rlc_ul_am_control_pdu_log(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        lcid, pdu_size = struct.unpack('<BH', pkt_body[0:3])
        rlc_pdu = pkt_body[3:3+pdu_size]
        # rlc_pdu = pkt_body[3:]

        # Directly pack RLC PDU on UDP packet, see epan/packet-umts_rlc-lte.h of Wireshark
        # Has header on PDU, CP (0x01), no ROHC
        # Direction: Downlink (0x01)
        ws_hdr = struct.pack('!BBBBB',
            util.wcdma_rlc_tags.RLC_MODE_TAG,
            util.wcdma_rlc_mode_types.RLC_AM,
            util.wcdma_rlc_tags.RLC_DIRECTION_TAG,
            util.wcdma_rlc_direction_types.DIRECTION_UPLINK,
            util.wcdma_rlc_tags.RLC_PAYLOAD_TAG)

        return {'layer': 'rlc', 'up': [b'umts-rlc' + ws_hdr + rlc_pdu], 'ts': pkt_ts}

    def parse_wcdma_rlc_dl_pdu_cipher_packet(self, pkt_header, pkt_body: bytes, args: dict):
        num_packets = struct.unpack('<H', pkt_body[0:2])[0]
        pos = 2
        stdout = ''
        item_struct = namedtuple('QcDiagWcdmaDlRlcCipherPdu', 'rlc_id ck ciph_alg ciph_msg count_c')

        for x in range(num_packets):
            item = item_struct._make(struct.unpack('<BLBLL', pkt_body[pos:pos+14]))
            pos += 14
            if item.ciph_alg == 0xff:
                continue
            stdout += "WCDMA RLC Cipher DL PDU: LCID: {}, CK: {:#x}, Algorithm: UEA{}, Message: {:#x}, Count C: 0x{:x}\n".format(item.rlc_id,
                item.ck, item.ciph_alg, item.ciph_msg, item.count_c)

        return {'stdout': stdout.rstrip()}

    def parse_wcdma_rlc_ul_pdu_cipher_packet(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        num_packets = struct.unpack('<H', pkt_body[0:2])[0]
        pos = 2
        stdout = ''
        item_struct = namedtuple('QcDiagWcdmaUlRlcCipherPdu', 'rlc_id ck ciph_alg count_c')

        for x in range(num_packets):
            item = item_struct._make(struct.unpack('<BLBL', pkt_body[pos:pos+10]))
            pos += 10
            if item.ciph_alg == 0xff:
                continue
            stdout += "WCDMA RLC Cipher UL PDU: LCID: {}, CK: {:#x}, Algorithm: UEA{}, Count C: 0x{:x}\n".format(item.rlc_id,
                item.ck, item.ciph_alg, item.count_c)

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    # WCDMA RRC
    def parse_wcdma_cell_id(self, pkt_header, pkt_body: bytes, args: dict):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']
        item_struct = namedtuple('QcDiagWcdmaRrcCellId', 'ul_uarfcn dl_uarfcn cell_id ura_id flags access psc mcc mnc lac rac')
        if len(pkt_body) < 32:
            pkt_body += b'\x00' * (32 - len(pkt_body))
        item = item_struct._make(struct.unpack('<LL LH BB H 3s 3s LL', pkt_body[0:32]))

        psc = item.psc >> 4
        # UARFCN UL, UARFCN DL, CID, URA_ID, FLAGS, PSC, PLMN_ID, LAC, RAC
        # PSC needs to be >>4'ed
        if self.parent:
            self.parent.umts_last_uarfcn_ul[radio_id] = item.ul_uarfcn
            self.parent.umts_last_uarfcn_dl[radio_id] = item.dl_uarfcn
            self.parent.umts_last_cell_id[radio_id] = psc

        if self.display_format == 'd':
            lac_rac_cid_str = 'LAC/RAC/CID: {}/{}/{}'.format(item.lac, item.rac, item.cell_id)
        elif self.display_format == 'x':
            lac_rac_cid_str = 'xLAC/xRAC/xCID: {:x}/{:x}/{:x}'.format(item.lac, item.rac, item.cell_id)
        elif self.display_format == 'b':
            lac_rac_cid_str = 'LAC/RAC/CID: {}/{}/{} ({:#x}/{:#x}/{:#x})'.format(item.lac, item.rac, item.cell_id, item.lac, item.rac, item.cell_id)
        else:
            lac_rac_cid_str = 'xLAC/xRAC/xCID: {:x}/{:x}/{:x}'.format(item.lac, item.rac, item.cell_id)

        try:
            mcc_str = util.convert_mcc(item.mcc[0], item.mcc[1], item.mcc[2])
            mnc_str = util.convert_mnc(item.mnc[0], item.mnc[1], item.mnc[2])
        except ValueError:
            mcc_str = 'N/A'
            mnc_str = 'N/A'

        return {'stdout': 'WCDMA Cell ID: UARFCN: {}/{}, PSC: {}, MCC/MNC: {}/{}, {}'.format(item.dl_uarfcn,
            item.ul_uarfcn, psc, mcc_str, mnc_str, lac_rac_cid_str),
            'ts': pkt_ts}

    def parse_wcdma_rrc(self, pkt_header, pkt_body: bytes, args: dict):
        item_struct = namedtuple('QcDiagWcdmaRrcOtaPacket', 'channel_type rbid len')
        item = item_struct._make(struct.unpack('<BBH', pkt_body[0:4]))
        msg_content = b''
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        t_v2 = util.gsmtap_umts_rrc_types
        t_v3 = util.gsmtapv3_umts_rrc_types
        channel_type_map = {
            0:  (t_v2.UL_CCCH,   t_v3.UL_CCCH),
            1:  (t_v2.UL_DCCH,   t_v3.UL_DCCH),
            2:  (t_v2.DL_CCCH,   t_v3.DL_CCCH),
            3:  (t_v2.DL_DCCH,   t_v3.DL_DCCH),
            4:  (t_v2.BCCH_BCH,  t_v3.BCCH_BCH), # Encoded
            5:  (t_v2.BCCH_FACH, t_v3.BCCH_FACH), # Encoded
            6:  (t_v2.PCCH,      t_v3.PCCH),
            7:  (t_v2.MCCH,      t_v3.MCCH),
            8:  (t_v2.MSCH,      t_v3.MSCH),
            10: (t_v2.System_Information_Container, t_v3.System_Information_Container),
        }

        channel_type_map_extended_type = {
            9:    (t_v2.BCCH_BCH,  t_v3.BCCH_BCH), # Extension SIBs
            0xFE: (t_v2.BCCH_BCH,  t_v3.BCCH_BCH), # Decoded
            0xFF: (t_v2.BCCH_FACH, t_v3.BCCH_FACH), # Decoded
        }

        sib_type_map = {
            0:  (t_v2.MasterInformationBlock, t_v3.MasterInformationBlock),
            1:  (t_v2.SysInfoType1,     t_v3.SysInfoType1),
            2:  (t_v2.SysInfoType2,     t_v3.SysInfoType2),
            3:  (t_v2.SysInfoType3,     t_v3.SysInfoType3),
            4:  (t_v2.SysInfoType4,     t_v3.SysInfoType4),
            5:  (t_v2.SysInfoType5,     t_v3.SysInfoType5),
            6:  (t_v2.SysInfoType6,     t_v3.SysInfoType6),
            7:  (t_v2.SysInfoType7,     t_v3.SysInfoType7),
            8:  (t_v2.SysInfoType8,     t_v3.SysInfoType8),
            9:  (t_v2.SysInfoType9,     t_v3.SysInfoType9),
            10: (t_v2.SysInfoType10,    t_v3.SysInfoType10),
            11: (t_v2.SysInfoType11,    t_v3.SysInfoType11),
            12: (t_v2.SysInfoType12,    t_v3.SysInfoType12),
            13: (t_v2.SysInfoType13,    t_v3.SysInfoType13),
            14: (t_v2.SysInfoType13_1,  t_v3.SysInfoType13_1),
            15: (t_v2.SysInfoType13_2,  t_v3.SysInfoType13_2),
            16: (t_v2.SysInfoType13_3,  t_v3.SysInfoType13_3),
            17: (t_v2.SysInfoType13_4,  t_v3.SysInfoType13_4),
            18: (t_v2.SysInfoType14,    t_v3.SysInfoType14),
            19: (t_v2.SysInfoType15,    t_v3.SysInfoType15),
            20: (t_v2.SysInfoType15_1,  t_v3.SysInfoType15_1),
            21: (t_v2.SysInfoType15_2,  t_v3.SysInfoType15_2),
            22: (t_v2.SysInfoType15_3,  t_v3.SysInfoType15_3),
            23: (t_v2.SysInfoType16,    t_v3.SysInfoType16),
            24: (t_v2.SysInfoType17,    t_v3.SysInfoType17),
            25: (t_v2.SysInfoType15_4,  t_v3.SysInfoType15_4),
            26: (t_v2.SysInfoType18,    t_v3.SysInfoType18),
            27: (t_v2.SysInfoTypeSB1,   t_v3.SysInfoTypeSB1),
            28: (t_v2.SysInfoTypeSB2,   t_v3.SysInfoTypeSB2),
            29: (t_v2.SysInfoType15_5,  t_v3.SysInfoType15_5),
            30: (t_v2.SysInfoType5bis,  t_v3.SysInfoType5bis),
            31: (t_v2.SysInfoType11bis, t_v3.SysInfoType11bis),
            # Extension SIB
            66: (t_v2.SysInfoType11bis, t_v3.SysInfoType11bis),
            67: (t_v2.SysInfoType19,    t_v3.SysInfoType19),
        }

        channel_type_map_new = {
            0x80: (t_v2.UL_CCCH,   t_v3.UL_CCCH),
            0x81: (t_v2.UL_DCCH,   t_v3.UL_DCCH),
            0x82: (t_v2.DL_CCCH,   t_v3.DL_CCCH),
            0x83: (t_v2.DL_DCCH,   t_v3.DL_DCCH),
            0x84: (t_v2.BCCH_BCH,  t_v3.BCCH_BCH), # Encoded
            0x85: (t_v2.BCCH_FACH, t_v3.BCCH_FACH), # Encoded
            0x86: (t_v2.PCCH,      t_v3.PCCH),
            0x87: (t_v2.MCCH,      t_v3.MCCH),
            0x88: (t_v2.MSCH,      t_v3.MSCH),
        }
        channel_type_map_new_extended_type = {
            0x89: (t_v2.BCCH_BCH, t_v3.BCCH_BCH), # Extension SIBs
            0xF0: (t_v2.BCCH_BCH, t_v3.BCCH_BCH), # Decoded
        }
        sib_type_map_new = {
             0: (t_v2.MasterInformationBlock, t_v3.MasterInformationBlock),
             1: (t_v2.SysInfoType1,     t_v3.SysInfoType1),
             2: (t_v2.SysInfoType2,     t_v3.SysInfoType2),
             3: (t_v2.SysInfoType3,     t_v3.SysInfoType3),
             4: (t_v2.SysInfoType4,     t_v3.SysInfoType4),
             5: (t_v2.SysInfoType5,     t_v3.SysInfoType5),
             6: (t_v2.SysInfoType6,     t_v3.SysInfoType6),
             7: (t_v2.SysInfoType7,     t_v3.SysInfoType7),
             8: (t_v2.SysInfoType8,     t_v3.SysInfoType8),
             9: (t_v2.SysInfoType9,     t_v3.SysInfoType9),
            10: (t_v2.SysInfoType10,    t_v3.SysInfoType10),
            11: (t_v2.SysInfoType11,    t_v3.SysInfoType11),
            12: (t_v2.SysInfoType12,    t_v3.SysInfoType12),
            13: (t_v2.SysInfoType13,    t_v3.SysInfoType13),
            14: (t_v2.SysInfoType13_1,  t_v3.SysInfoType13_1),
            15: (t_v2.SysInfoType13_2,  t_v3.SysInfoType13_2),
            16: (t_v2.SysInfoType13_3,  t_v3.SysInfoType13_3),
            17: (t_v2.SysInfoType13_4,  t_v3.SysInfoType13_4),
            18: (t_v2.SysInfoType14,    t_v3.SysInfoType14),
            19: (t_v2.SysInfoType15,    t_v3.SysInfoType15),
            20: (t_v2.SysInfoType15_1,  t_v3.SysInfoType15_1),
            21: (t_v2.SysInfoType15_2,  t_v3.SysInfoType15_2),
            22: (t_v2.SysInfoType15_3,  t_v3.SysInfoType15_3),
            23: (t_v2.SysInfoType16,    t_v3.SysInfoType16),
            24: (t_v2.SysInfoType17,    t_v3.SysInfoType17),
            25: (t_v2.SysInfoType15_4,  t_v3.SysInfoType15_4),
            26: (t_v2.SysInfoType18,    t_v3.SysInfoType18),
            27: (t_v2.SysInfoTypeSB1,   t_v3.SysInfoTypeSB1),
            28: (t_v2.SysInfoTypeSB2,   t_v3.SysInfoTypeSB2),
            29: (t_v2.SysInfoType15_5,  t_v3.SysInfoType15_5),
            30: (t_v2.SysInfoType5bis,  t_v3.SysInfoType5bis),
            31: (t_v2.SysInfoType19,    t_v3.SysInfoType19),
            # Extension SIB
            66: (t_v2.SysInfoType11bis, t_v3.SysInfoType11bis),
            67: (t_v2.SysInfoType19,    t_v3.SysInfoType19),
        }

        gsmtapv3_metadata = dict()
        if item.channel_type in channel_type_map.keys():
            arfcn = self.parent.umts_last_uarfcn_dl[radio_id]
            if item.channel_type == 0 or item.channel_type == 1:
                arfcn = self.parent.umts_last_uarfcn_ul[radio_id]

            if self.gsmtapv3:
                subtype = channel_type_map[item.channel_type][1]
            else:
                subtype = channel_type_map[item.channel_type][0]
            msg_content = pkt_body[4:]
        elif item.channel_type in channel_type_map_extended_type.keys():
            arfcn = self.parent.umts_last_uarfcn_dl[radio_id]

            # uint8 subtype, uint8 msg[]
            if pkt_body[4] in sib_type_map.keys():
                if self.gsmtapv3:
                    subtype = sib_type_map[pkt_body[4]][1]
                else:
                    subtype = sib_type_map[pkt_body[4]][0]
                msg_content = pkt_body[5:]
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, "Unknown WCDMA SIB Class {}".format(pkt_body[4]))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                return None
        elif item.channel_type in channel_type_map_new.keys():
            # uint16 uarfcn, uint16 psc, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt_body[4:8])

            if self.gsmtapv3:
                gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = psc
                subtype = channel_type_map_new[item.channel_type][1]
            else:
                subtype = channel_type_map_new[item.channel_type][0]
            msg_content = pkt_body[8:]
        elif item.channel_type in channel_type_map_new_extended_type.keys():
            # uint16 uarfcn, uint16 psc, uint8 subtype, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt_body[4:8])

            if pkt_body[8] in sib_type_map_new.keys():
                if self.gsmtapv3:
                    gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = psc
                    subtype = sib_type_map_new[pkt_body[8]][1]
                else:
                    subtype = sib_type_map_new[pkt_body[8]][0]
                msg_content = pkt_body[9:]
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, "Unknown WCDMA new SIB Class {}".format(pkt_body[8]))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                return None
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Unknown WCDMA RRC channel type {}".format(pkt_body[0]))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if self.gsmtapv3:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.UMTS_RRC,
                arfcn = arfcn,
                sub_type = subtype,
                device_sec = ts_sec,
                device_usec = ts_usec,
                metadata = gsmtapv3_metadata)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UMTS_RRC,
                arfcn = arfcn,
                sub_type = subtype)

        return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}
