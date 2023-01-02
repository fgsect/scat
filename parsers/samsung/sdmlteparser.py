#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging
import binascii

class SdmLteParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_LTE_DATA << 8) | sdm_lte_data.LTE_PHY_STATUS: lambda x: self.sdm_lte_phy_status(x),
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

    def sdm_lte_phy_status(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        if len(pkt) != 2:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (2)'.format(len(pkt), 2))
            return None

        header = namedtuple('SdmLtePhyStatus', 'sfn')
        phy_status = header._make(struct.unpack('<H', pkt[0:2]))
        stdout = 'LTE PHY Status: Current SFN {}'.format(phy_status.sfn)
        return {'stdout': stdout}

    def sdm_lte_phy_cell_info(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmLtePhyCellInfo', 'plmn zero1 arfcn pci zero2 reserved1 reserved2 rsrp rsrq num_ncell')
        ncell_header = namedtuple('SdmLtePhyCellInfoNCellMeas', 'type earfcn pci zero1 reserved1 rsrp rsrq reserved2')

        if self.model == 'e5123':
            struct_format = '<IIIHHHHLLB'
        else:
            struct_format = '<IIHHHHHLLB'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), expected_len))
            return None

        cell_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))
        extra = pkt[expected_len:]

        if self.parent:
            self.parent.lte_last_earfcn_dl[sdm_pkt_hdr.radio_id] = cell_info.arfcn
            self.parent.lte_last_pci[sdm_pkt_hdr.radio_id] = cell_info.pci
        stdout = 'LTE PHY Cell Info: EARFCN {}, PCI {}, PLMN {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(cell_info.arfcn, cell_info.pci, cell_info.plmn, cell_info.rsrp / -100.0, cell_info.rsrq / -100.0)

        if cell_info.num_ncell > 0:
            ncell_header_format = '<BHHHHLLH'
            ncell_len = struct.calcsize(ncell_header_format)
            if len(extra) == ncell_len * cell_info.num_ncell:
                for i in range(cell_info.num_ncell):
                    ncell = ncell_header._make(struct.unpack(ncell_header_format, extra[i*ncell_len:(i+1)*ncell_len]))
                    stdout += 'LTE PHY Cell Info: NCell {}: EARFCN {}, PCI {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                        ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Extra data length ({}) does not match with expected ({})'.format(len(extra), ncell_len * cell_info.num_ncell))
        return {'stdout': stdout.rstrip()}

    def sdm_lte_rrc_serving_cell(self, pkt):
        '''
        0x50: 'LteRrcServ?', len:24
            "cid", '<L',  4 bytes, pos:4
            "plmn" '<HB', 3 bytes, pos:16
            "tac", '>H',  2 bytes, pos:20
        '''
        pkt = pkt[15:-1]
        if self.model == 'e5123':
            struct_format = '<IIIIHH'
        else:
            struct_format = '<IIIIH'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteRrcServingCell', 'cid zero1 zero2 plmn tac')
        header_e5123 = namedtuple('SdmLteRrcServingCellE5123', 'cid zero1 zero2 plmn tac band_indicator')
        if self.model == 'e5123':
            cell_info = header_e5123._make(struct.unpack(struct_format, pkt[0:expected_len]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]
            stdout = 'LTE RRC Serving Cell: xTAC/xCID {:x}/{:x}, PLMN {}, Band {}'.format(tac_real, cell_info.cid, cell_info.plmn, cell_info.band_indicator)
        else:
            # 41 dd fa 05 | 09 23 00 01 | 01 00 00 00 | 00 00 00 00 | d0 af 00 00 | 06 db
            cell_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]
            stdout = 'LTE RRC Serving Cell: xTAC/xCID {:x}/{:x}, PLMN {}'.format(tac_real, cell_info.cid, cell_info.plmn)

        return {'stdout': stdout}

    def sdm_lte_rrc_state(self, pkt):
        '''
        0x51: 'LteRrcState' len:5
            "rrc_state", '<B', 1 byte, pos:4  # (00 - IDLE, 01 - CONNECTING, 02 - CONNECTED)
        '''
        pkt = pkt[15:-1]

        if len(pkt) < 1:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (1)'.format(len(pkt)))
            return None

        header = namedtuple('SdmLteRrcState', 'state')
        rrc_state = header._make(struct.unpack('<B', pkt[0:1]))
        rrc_state_map = {0: 'IDLE', 1: 'CONNECTING', 2: 'CONNECTED'}
        stdout = 'LTE RRC State: {}'.format(rrc_state_map[rrc_state.state] if rrc_state.state in rrc_state_map else 'UNKNOWN')
        return {'stdout': stdout}

    def sdm_lte_rrc_ota_packet(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        if len(pkt) < 4:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (4)'.format(len(pkt)))
            return None

        # direction - 0: DL, 1: UL
        header = namedtuple('SdmLteRrcOtaPacket', 'channel direction length')
        rrc_header = header._make(struct.unpack('<BBH', pkt[0:4]))
        rrc_msg = pkt[4:]

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
        pkt = pkt[15:-1]
        # TODO: RACH Preamble/Response
        # pkt[1] - pkt[4]: TS
        direction = pkt[1] # 0 - UL, 1 - DL
        rach_vals = struct.unpack('<HIIH', pkt[2:14])

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
        pkt = pkt[15:-1]

    def sdm_lte_nas_sim_data(self, pkt):
        '''
        0x58: 'Sim(?)', len:13
            "mcc",  '<2s', 2 bytes, pos:4,   # bcd encoded
            "mnc",  '<1s', 1 bytes, pos:6,   # bcd encoded
            "IMSI", '<9s', 9 bytes, pos:15,  # bcd encoded
        if pkt[0] == 0x58:
        '''
        pkt = pkt[15:-1]

    def sdm_lte_nas_msg(self, pkt):
        pkt = pkt[15:-1]
        # 0x5A: LTE NAS EMM Message
        # 0x5F: LTE NAS ESM Message

        if len(pkt) < 4:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (4)'.format(len(pkt)))
            return

        # direction: 0 - DL, 1 - UL
        header = namedtuple('SdmLteNasMsg', 'direction length spare')
        nas_header = header._make(struct.unpack('<BHB', pkt[0:4]))
        nas_msg = pkt[4:]
        if nas_header.length != len(nas_msg):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(nas_msg), nas_header.length))
            return None

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.LTE_NAS,
            arfcn = 0)
        return {'cp': [gsmtap_hdr + nas_msg]}