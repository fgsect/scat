#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmLteParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_PHY_CELL_INFO: lambda x: self.sdm_lte_phy_cell_info(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_RRC_SERVING_CELL: lambda x: self.sdm_lte_rrc_serving_cell(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_RRC_STATUS: lambda x: self.sdm_lte_rrc_state(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_RRC_OTA_PACKET: lambda x: self.sdm_lte_rrc_ota_packet(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | 0x55: lambda x: self.sdm_lte_0x55(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | 0x57: lambda x: self.sdm_lte_0x57(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_NAS_SIM_DATA: lambda x: self.sdm_lte_nas_sim_data(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_NAS_EMM_MESSAGE: lambda x: self.sdm_lte_nas_msg(x),
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_NAS_ESM_MESSAGE: lambda x: self.sdm_lte_nas_msg(x),
        }

    def sdm_lte_phy_cell_info(self, pkt):
        # 5-7: Current PLMN (BCD or decimal)
        # 8-11: zero
        # 12: cell RAT (0-LTE, 1-3G, 2-2G?)
        # 13-4: EARFCN/UARFCN/ARFCN
        # 15-18: Physical CID
        # 003818 ac000000 70e5d4fe1c250000b004000003
        # 003818 64000000 0019e4250000dc0500000000
        # 003818 7b000000 001910270000dc0500000000
        # 003818 57000000 641910270000080700000000
        sdm_pkt_hdr = parse_sdm_header(pkt[1:11])
        pkt = pkt[11:-1]
        header = namedtuple('SdmLtePhyCellInfo', 'timestamp plmn zero1 arfcn pci zero2')

        if self.model == 'e5123':
            expected_len = 20
        else:
            expected_len = 18
        if len(pkt) < expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), expected_len))
            return None

        if self.model == 'e5123':
            cell_info = header._make(struct.unpack('<IIIIHH', pkt[0:20]))
        else:
            cell_info = header._make(struct.unpack('<IIIHHH', pkt[0:18]))

        if self.parent:
            self.parent.lte_last_earfcn_dl[sdm_pkt_hdr.radio_id] = cell_info.arfcn
            self.parent.lte_last_pci[sdm_pkt_hdr.radio_id] = cell_info.pci
        stdout = 'LTE PHY Cell Info: EARFCN {}, PCI {}, PLMN {}'.format(cell_info.arfcn, cell_info.pci, cell_info.plmn)
        return {'stdout': stdout}

    def sdm_lte_rrc_serving_cell(self, pkt):
        '''
        0x50: 'LteRrcServ?', len:24
            "cid", '<L',  4 bytes, pos:4
            "plmn" '<HB', 3 bytes, pos:16
            "tac", '>H',  2 bytes, pos:20
        '''
        pkt = pkt[11:-1]
        if self.model == 'e5123':
            expected_len = 24
        else:
            expected_len = 22
        if len(pkt) < expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteRrcServingCell', 'timestamp cid zero1 zero2 plmn tac')
        header_e5123 = namedtuple('SdmLteRrcServingCellE5123', 'timestamp cid zero1 zero2 plmn tac band_indicator')
        if self.model == 'e5123':
            cell_info = header_e5123._make(struct.unpack('<IIIIIHH', pkt[0:24]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]
            stdout = 'LTE RRC Serving Cell: xTAC/xCID {:x}/{:x}, PLMN {}, Band {}'.format(tac_real, cell_info.cid, cell_info.plmn, cell_info.band_indicator)
        else:
            # 41 dd fa 05 | 09 23 00 01 | 01 00 00 00 | 00 00 00 00 | d0 af 00 00 | 06 db
            cell_info = header._make(struct.unpack('<IIIIIH', pkt[0:22]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]
            stdout = 'LTE RRC Serving Cell: xTAC/xCID {:x}/{:x}, PLMN {}'.format(tac_real, cell_info.cid, cell_info.plmn)

        return {'stdout': stdout}

    def sdm_lte_rrc_state(self, pkt):
        '''
        0x51: 'LteRrcState' len:5
            "rrc_state", '<B', 1 byte, pos:4  # (00 - IDLE, 01 - CONNECTING, 02 - CONNECTED)
        '''
        pkt = pkt[11:-1]

        if len(pkt) < 5:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (5)'.format(len(pkt)))
            return None

        header = namedtuple('SdmLteRrcState', 'timestamp state')
        rrc_state = header._make(struct.unpack('<IB', pkt[0:5]))
        rrc_state_map = {0: 'IDLE', 1: 'CONNECTING', 2: 'CONNECTED'}
        stdout = 'LTE RRC State: {}'.format(rrc_state_map[rrc_state.state] if rrc_state.state in rrc_state_map else 'UNKNOWN')
        return {'stdout': stdout}

    def sdm_lte_rrc_ota_packet(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:11])
        pkt = pkt[11:-1]

        if len(pkt) < 8:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (8)'.format(len(pkt)))
            return None

        # direction - 0: DL, 1: UL
        header = namedtuple('SdmLteRrcOtaPacket', 'timestamp channel direction length')
        rrc_header = header._make(struct.unpack('<IBBH', pkt[0:8]))
        rrc_msg = pkt[8:]

        rrc_subtype_dl = {
            0: util.gsmtap_lte_rrc_types.DL_CCCH,
            1: util.gsmtap_lte_rrc_types.PCCH,
            2: util.gsmtap_lte_rrc_types.BCCH_BCH,
            3: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
            4: util.gsmtap_lte_rrc_types.DL_DCCH
            }
        rrc_subtype_ul = {
            0: util.gsmtap_lte_rrc_types.UL_CCCH,
            4: util.gsmtap_lte_rrc_types.UL_DCCH
            }

        subtype = 0
        try:
            if rrc_header.direction == 0:
                subtype = rrc_subtype_dl[rrc_header.channel]
            else:
                subtype = rrc_subtype_ul[rrc_header.channel]
        except KeyError:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Unknown LTE RRC channel type 0x{:x}".format(rrc_header.channel))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt))

        if rrc_header.direction == 0:
            if self.parent:
                arfcn = self.parent.lte_last_earfcn_dl[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0
        else:
            if self.parent:
                arfcn = self.parent.lte_last_earfcn_ul[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = arfcn,
            sub_type = subtype)
        return {'cp': [gsmtap_hdr + rrc_msg]}

    def sdm_lte_0x55(self, pkt):
        pkt = pkt[11:-1]
        # TODO: RACH Preamble/Response
        # pkt[1] - pkt[4]: TS
        direction = pkt[5] # 0 - UL, 1 - DL
        rach_vals = struct.unpack('<HIIH', pkt[6:18])

        if direction == 0:
            # UL: RACH cause, Preamble ID, ?, ?
            pass
        elif direction == 1:
            # DL: ?, Preamble ID, TA, T-C-RNTI
            # MAC-LTE: RAR Header, TA, UL Grant, T-C-RNTI
            pass
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Invalid RACH direction 0x{:02x}".format(direction))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt))
        return None

    def sdm_lte_0x57(self, pkt):
        '''
        0x57: '?' len:13
            "earfcn", '<L', 4 bytes, pos:7
            "pci",    '<H', 2 bytes, pos:11
        if pkt[0] == 0x57:
        '''
        pkt = pkt[11:-1]

    def sdm_lte_nas_sim_data(self, pkt):
        '''
        0x58: 'Sim(?)', len:13
            "mcc",  '<2s', 2 bytes, pos:4,   # bcd encoded
            "mnc",  '<1s', 1 bytes, pos:6,   # bcd encoded
            "IMSI", '<9s', 9 bytes, pos:15,  # bcd encoded
        if pkt[0] == 0x58:
        '''
        pkt = pkt[11:-1]

    def sdm_lte_nas_msg(self, pkt):
        pkt = pkt[11:-1]
        # 0x5A: LTE NAS EMM Message
        # 0x5F: LTE NAS ESM Message

        if len(pkt) < 8:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (8)'.format(len(pkt)))
            return

        # direction: 0 - DL, 1 - UL
        header = namedtuple('SdmLteNasMsg', 'timestamp direction length spare')
        nas_header = header._make(struct.unpack('<IBHB', pkt[0:8]))
        nas_msg = pkt[8:]
        if nas_header.length != len(nas_msg):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(nas_msg), nas_header.length))
            return None

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.LTE_NAS,
            arfcn = 0)
        return {'cp': [gsmtap_hdr + nas_msg]}