#!/usr/bin/env python3

from collections import namedtuple
import binascii
import ipaddress
import logging
import struct

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmLteParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver
        self.multi_message_chunk = {}

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_LTE_DATA << 8)
        c = sdmcmd.sdm_lte_data
        self.process = {
            g | c.LTE_PHY_STATUS: lambda x: self.sdm_lte_phy_status(x),
            g | c.LTE_PHY_CELL_SEARCH_MEAS: lambda x: self.sdm_lte_phy_cell_search_meas(x),
            g | c.LTE_PHY_NCELL_INFO: lambda x: self.sdm_lte_phy_cell_info(x),

            g | c.LTE_L1_RF: lambda x: self.sdm_lte_l1_rf_info(x),
            g | c.LTE_L1_RACH_ATTEMPT: lambda x: self.sdm_lte_l1_rach_attempt(x),

            g | c.LTE_L2_RACH_INFO: lambda x: self.sdm_lte_l2_rach_info(x),
            g | c.LTE_L2_RNTI_INFO: lambda x: self.sdm_lte_l2_rnti_info(x),
            g | c.LTE_L2_MAC_CONTROL_ELEMENT: lambda x: self.sdm_lte_l2_mac_ce(x),

            g | c.LTE_RRC_SERVING_CELL: lambda x: self.sdm_lte_rrc_serving_cell(x),
            g | c.LTE_RRC_STATUS: lambda x: self.sdm_lte_rrc_state(x),
            g | c.LTE_RRC_OTA_PACKET: lambda x: self.sdm_lte_rrc_ota_packet(x),
            g | c.LTE_RRC_TIMER: lambda x: self.sdm_lte_rrc_timer(x),
            g | c.LTE_RRC_ASN_VERSION: lambda x: self.sdm_lte_rrc_asn_version(x),
            g | c.LTE_RRC_RACH_MSG: lambda x: self.sdm_lte_rrc_rach_msg(x),
            g | c.LTE_RRC_EVENT: lambda x: self.sdm_lte_dummy(x, 0x57),
            g | c.LTE_NAS_SIM_DATA: lambda x: self.sdm_lte_nas_sim_data(x),
            g | c.LTE_NAS_STATUS_VARIABLE: lambda x: self.sdm_lte_nas_status_variable(x),
            g | c.LTE_NAS_EMM_MESSAGE: lambda x: self.sdm_lte_nas_msg(x),
            g | c.LTE_NAS_PLMN_SELECTION: lambda x: self.sdm_lte_nas_plmn_selection(x),
            g | c.LTE_NAS_SECURITY: lambda x: self.sdm_lte_nas_security(x),
            g | c.LTE_NAS_PDP: lambda x: self.sdm_lte_nas_pdp(x),
            g | c.LTE_NAS_IP: lambda x: self.sdm_lte_nas_ip(x),
            g | c.LTE_NAS_ESM_MESSAGE: lambda x: self.sdm_lte_nas_msg(x),

            g | c.LTE_VOLTE_TX_PACKET_INFO: lambda x: self.sdm_lte_volte_rtp_packet(x, 0x70),
            g | c.LTE_VOLTE_RX_PACKET_INFO: lambda x: self.sdm_lte_volte_rtp_packet(x, 0x71),
            g | c.LTE_VOLTE_TX_OVERALL_STAT_INFO: lambda x: self.sdm_lte_volte_tx_stats(x),
            g | c.LTE_VOLTE_RX_OVERALL_STAT_INFO: lambda x: self.sdm_lte_volte_rx_stats(x),
            g | c.LTE_VOLTE_TX_RTP_STAT_INFO: lambda x: self.sdm_lte_volte_tx_rtp_stats(x),
            g | c.LTE_VOLTE_RX_RTP_STAT_INFO: lambda x: self.sdm_lte_volte_rx_rtp_stats(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def sdm_lte_dummy(self, pkt, cmdid):
        pkt = pkt[15:-1]
        return {'stdout': 'LTE {:#x}: {}'.format(cmdid, binascii.hexlify(pkt).decode())}

    def sdm_lte_phy_status(self, pkt):
        pkt = pkt[15:-1]

        if len(pkt) != 2:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), 2))
            return None

        header = namedtuple('SdmLtePhyStatus', 'sfn')
        phy_status = header._make(struct.unpack('<H', pkt[0:2]))
        stdout = 'LTE PHY Status: Current SFN {}'.format(phy_status.sfn)
        return {'stdout': stdout}

    def sdm_lte_phy_cell_search_meas(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        header = namedtuple('SdmLtePhyCellSearchMeas', 'pci unk rsrp0 rsrq0 rssi0 rsrp1 rsrq1 rssi1 rsrp2 rsrq2 rssi2 rsrp3 rsrq3 rssi3')
        header_fmt = '<HL LLL LLL LLL LLL'
        header_expected_len = struct.calcsize(header_fmt)

        if len(pkt) < header_expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), header_expected_len))
            return None

        scell_meas = header._make(struct.unpack(header_fmt, pkt[0:header_expected_len]))
        stdout = 'LTE PHY Cell Search Measure: SCell: PCI: {}, RSRP/RSRQ/RSSI: ({}, {}, {}), ({}, {}, {}), ({}, {}, {}), ({}, {}, {})\n'.format(
            scell_meas.pci,
            -scell_meas.rsrp0 / 100, -scell_meas.rsrq0 / 100, -scell_meas.rssi0 / 100,
            -scell_meas.rsrp1 / 100, -scell_meas.rsrq1 / 100, -scell_meas.rssi1 / 100,
            -scell_meas.rsrp2 / 100, -scell_meas.rsrq2 / 100, -scell_meas.rssi2 / 100,
            -scell_meas.rsrp3 / 100, -scell_meas.rsrq3 / 100, -scell_meas.rssi3 / 100,
        )

        if len(pkt) > 54:
            pos = 54
            num_ncells = struct.unpack('<L', pkt[pos:pos+4])[0]
            pos += 4
            for i in range(num_ncells):
                ncell_meas = header._make(struct.unpack(header_fmt, pkt[pos:pos+header_expected_len]))
                stdout += 'LTE PHY Cell Search Measure: NCell {}: PCI: {}, RSRP/RSRQ/RSSI: ({}, {}, {}), ({}, {}, {}), ({}, {}, {}), ({}, {}, {})\n'.format(
                    i,
                    ncell_meas.pci,
                    -ncell_meas.rsrp0 / 100, -ncell_meas.rsrq0 / 100, -ncell_meas.rssi0 / 100,
                    -ncell_meas.rsrp1 / 100, -ncell_meas.rsrq1 / 100, -ncell_meas.rssi1 / 100,
                    -ncell_meas.rsrp2 / 100, -ncell_meas.rsrq2 / 100, -ncell_meas.rssi2 / 100,
                    -ncell_meas.rsrp3 / 100, -ncell_meas.rsrq3 / 100, -ncell_meas.rssi3 / 100,
                )
                pos += header_expected_len
            extra = pkt[pos:]

        return {'stdout': stdout.rstrip()}

    def sdm_lte_phy_cell_info(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmLtePhyCellInfo', 'plmn zero1 arfcn pci zero2 reserved1 reserved2 rsrp rsrq num_ncell')
        ncell_header = namedtuple('SdmLtePhyCellInfoNCellMeas', 'type earfcn pci zero1 reserved1 rsrp rsrq reserved2')

        if self.icd_ver >= (5, 40):
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
        stdout = 'LTE PHY Cell Info: EARFCN: {}, PCI: {}, PLMN: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(cell_info.arfcn, cell_info.pci, cell_info.plmn, cell_info.rsrp / -100.0, cell_info.rsrq / -100.0)

        if cell_info.num_ncell > 0:
            if self.icd_ver >= (5, 40):
                ncell_header_format = '<BLHHHLLH'
            else:
                ncell_header_format = '<BHHHHLLH'
            ncell_len = struct.calcsize(ncell_header_format)
            if len(extra) == ncell_len * cell_info.num_ncell:
                for i in range(cell_info.num_ncell):
                    ncell = ncell_header._make(struct.unpack(ncell_header_format, extra[i*ncell_len:(i+1)*ncell_len]))
                    if self.icd_ver >= (9, 0):
                        if ncell.type == 0:
                            stdout += 'LTE PHY Cell Info: NCell {}: EARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 6:
                            stdout += 'LTE PHY Cell Info: NCell {} (NR): NR-ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        else:
                            stdout += 'LTE PHY Cell Info: NCell {} (Type {}): ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.type, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                    elif self.icd_ver >= (7, 2):
                        if ncell.type == 0:
                            stdout += 'LTE PHY Cell Info: NCell {} (GSM): ARFCN: {}, BSIC: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 1:
                            stdout += 'LTE PHY Cell Info: NCell {} (WCDMA): UARFCN: {}, PSC: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 2:
                            stdout += 'LTE PHY Cell Info: NCell {}: EARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 6:
                            stdout += 'LTE PHY Cell Info: NCell {} (NR): NR-ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        else:
                            stdout += 'LTE PHY Cell Info: NCell {} (Type {}): ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.type, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                    else:
                        if ncell.type == 0:
                            stdout += 'LTE PHY Cell Info: NCell {}: EARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 1:
                            stdout += 'LTE PHY Cell Info: NCell {} (WCDMA): UARFCN: {}, PSC: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        elif ncell.type == 3:
                            stdout += 'LTE PHY Cell Info: NCell {} (GSM): ARFCN: {}, BSIC: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, (4294967296 - ncell.rsrq) / -100.0)
                        elif ncell.type == 6:
                            stdout += 'LTE PHY Cell Info: NCell {} (NR): NR-ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
                        else:
                            stdout += 'LTE PHY Cell Info: NCell {} (Type {}): ARFCN: {}, PCI: {}, RSRP: {:.2f}, RSRQ: {:.2f}\n'.format(i, ncell.type, ncell.earfcn,
                                ncell.pci, ncell.rsrp / -100.0, ncell.rsrq / -100.0)
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Extra data length ({}) does not match with expected ({})'.format(len(extra), ncell_len * cell_info.num_ncell))
        return {'stdout': stdout.rstrip()}

    def sdm_lte_l1_rf_info(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<hhhhh'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteL1RfInfo', 'rx0 rx1 rx2 rx3 tx')
        rf_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE L1 RF Info: RX: [{} {} {} {}], TX: {}'.format(
            -rf_info.rx0 / 100, -rf_info.rx1 / 100, -rf_info.rx2 / 100, -rf_info.rx3 / 100, rf_info.tx)

        pos = expected_len
        num_extra_cells = struct.unpack('<L', pkt[expected_len:expected_len+4])[0]
        pos += 4

        if num_extra_cells > 0:
            for i in range(num_extra_cells):
                rf_info = header._make(struct.unpack(struct_format, pkt[pos:pos+expected_len]))
                stdout += '\nLTE L1 RF Info: SCell {}: RX: [{} {} {} {}], TX: {}'.format(
                    i,
                    -rf_info.rx0 / 100, -rf_info.rx1 / 100, -rf_info.rx2 / 100, -rf_info.rx3 / 100, rf_info.tx)
                pos += expected_len

        return {'stdout': stdout}

    def sdm_lte_l1_rach_attempt(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<LHHBBLHHB'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteL1RachAttempt', 'earfcn pci ra_rnti preamble txpwr ul_grant tc_rnti ta unk')
        rach_attempt = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE L1 RACH Attempt: EARFCN/PCI: {}/{}, UL Grant: {:#010x}, TC-RNTI: {}, TA: {}'.format(
            rach_attempt.earfcn, rach_attempt.pci, rach_attempt.ul_grant, rach_attempt.tc_rnti, rach_attempt.ta)

        return {'stdout': stdout}

    def sdm_lte_l2_rach_info(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<HHB'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteL2RachInfo', 'preamble_id preamble_group num_preamble')
        rach_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE L2 RACH Info: Preamble ID: {:#x}, Preamble Group: {:#x}, Num Preamble: {}'.format(
            rach_info.preamble_id, rach_info.preamble_group, rach_info.num_preamble)
        return {'stdout': stdout}

    def sdm_lte_l2_rnti_info(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<HHHHHH'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteL2RntiInfo', 'si_rnti p_rnti tc_rnti c_rnti ra_rnti val6')
        rnti_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE L2 RNTI Info: SI: {:#x} P: {:#x} TC: {:#x} C: {:#x} RA: {:#x} {:#x}'.format(
            rnti_info.si_rnti, rnti_info.p_rnti, rnti_info.tc_rnti,
            rnti_info.c_rnti, rnti_info.ra_rnti, rnti_info.val6)
        return {'stdout': stdout}

    def sdm_lte_l2_mac_ce(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<BLBHB'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteL2MacCe', 'unk1 unk2 ta c_rnti trailer_len')
        ce_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE L2 MAC-CE: PHR: {:#x}, {:#10x}, TA: {}, RNTI: {:#x}, Trailer: {}'.format(
            ce_info.unk1, ce_info.unk2, ce_info.ta, ce_info.c_rnti,
            'None' if ce_info.trailer_len == 0 else '{} {}'.format(pkt[expected_len], binascii.hexlify(pkt[expected_len+1:expected_len+1+ce_info.trailer_len]).decode()))
        return {'stdout': stdout}

    def sdm_lte_rrc_serving_cell(self, pkt):
        '''
        0x50: 'LteRrcServ?', len:24
            "cid", '<L',  4 bytes, pos:4
            "plmn" '<HB', 3 bytes, pos:16
            "tac", '>H',  2 bytes, pos:20
        '''
        pkt = pkt[15:-1]
        if self.icd_ver >= (5, 41):
            struct_format = '<IQIHH'
        else:
            struct_format = '<IQIH'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({})'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteRrcServingCell', 'cid band_bits plmn tac')
        header_v5_41 = namedtuple('SdmLteRrcServingCellE5123', 'cid band_bits plmn tac band_indicator')
        if self.icd_ver >= (5, 41):
            cell_info = header_v5_41._make(struct.unpack(struct_format, pkt[0:expected_len]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]
        else:
            cell_info = header._make(struct.unpack(struct_format, pkt[0:expected_len]))
            tac_real = struct.unpack('<H', struct.pack('>H', cell_info.tac))[0]

        if self.display_format == 'd':
            tac_cid_fmt = 'TAC/CID: {}/{}'.format(tac_real, cell_info.cid)
        elif self.display_format == 'x':
            tac_cid_fmt = 'xTAC/xCID: {:x}/{:x}'.format(tac_real, cell_info.cid)
        elif self.display_format == 'b':
            tac_cid_fmt = 'TAC/CID: {}/{} ({:#x}/{:#x})'.format(tac_real, cell_info.cid, tac_real, cell_info.cid)

        if self.icd_ver >= (5, 41):
            stdout = 'LTE RRC Serving Cell: PLMN: {}, {}, Band: {}'.format(cell_info.plmn, tac_cid_fmt, cell_info.band_indicator)
        else:
            stdout = 'LTE RRC Serving Cell: PLMN: {}, {}'.format(cell_info.plmn, tac_cid_fmt)

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

    def _parse_sdm_lte_rrc_message(self, sdm_pkt_hdr, channel, direction, length, msg):
        t_v2 = util.gsmtap_lte_rrc_types
        t_v3 = util.gsmtapv3_lte_rrc_types
        rrc_subtype_dl = {
            0: (t_v2.DL_CCCH, t_v3.DL_CCCH),
            1: (t_v2.PCCH, t_v3.PCCH),
            2: (t_v2.BCCH_BCH, t_v3.BCCH_BCH),
            3: (t_v2.BCCH_DL_SCH, t_v3.BCCH_DL_SCH),
            4: (t_v2.DL_DCCH, t_v3.DL_DCCH)
        }
        rrc_subtype_ul = {
            0: (t_v2.UL_CCCH, t_v3.UL_CCCH),
            4: (t_v2.UL_DCCH, t_v3.UL_DCCH),
        }

        subtype = 0
        try:
            if direction == 0:
                subtype = rrc_subtype_dl[channel]
            else:
                subtype = rrc_subtype_ul[channel]
        except KeyError:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Unknown LTE RRC channel type 0x{:x}".format(channel))
                self.parent.logger.log(logging.DEBUG, util.xxd(msg))

        if direction == 0:
            if self.parent:
                arfcn = self.parent.lte_last_earfcn_dl[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0
        else:
            if self.parent:
                arfcn = self.parent.lte_last_earfcn_ul[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0

        if self.gsmtapv3:
            gsmtapv3_metadata = dict()
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = self.parent.lte_last_pci[sdm_pkt_hdr.radio_id]
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.LTE_RRC,
                arfcn = arfcn,
                sub_type = subtype[1],
                metadata=gsmtapv3_metadata)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = arfcn,
                sub_type = subtype[0])
        return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg]}

    def sdm_lte_rrc_ota_packet(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        if len(pkt) < 4:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (4)'.format(len(pkt)))
            return None

        # direction - 0: DL, 1: UL
        header = namedtuple('SdmLteRrcOtaPacket', 'channel direction length')
        rrc_header = header._make(struct.unpack('<BBH', pkt[0:4]))
        rrc_msg = pkt[4:]

        return self._parse_sdm_lte_rrc_message(sdm_pkt_hdr, rrc_header.channel, rrc_header.direction, rrc_header.length, rrc_msg)

    def sdm_lte_rrc_timer(self, pkt):
        # [02, 04, 10] 00000000

        pkt = pkt[15:-1]
        return {'stdout': 'LTE RRC Timer: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_rrc_asn_version(self, pkt):
        # Always 01? 1b - only for old revision
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        if len(pkt) < 5:
            return {'stdout': 'LTE RRC ASN Version: {}'.format(binascii.hexlify(pkt).decode())}

        # num_chunk is base 1, should be <= total_chunks
        header = namedtuple('SdmLteRrcMultipleMessage', 'total_chunks num_chunk msgid channel direction length')
        rrc_header = header._make(struct.unpack('<BBBBBH', pkt[0:7]))
        rrc_msg = pkt[7:]

        if rrc_header.msgid not in self.multi_message_chunk:
            # New msgid
            self.multi_message_chunk[rrc_header.msgid] = {'total_chunks': rrc_header.total_chunks}

        if rrc_header.num_chunk in self.multi_message_chunk[rrc_header.msgid]:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Message chunk {} already exists for message id {}".format(
                    rrc_header.num_chunk, rrc_header.msgid))
        self.multi_message_chunk[rrc_header.msgid][rrc_header.num_chunk] = rrc_msg

        is_not_full = False
        for i in range(1, rrc_header.total_chunks+1):
            if not i in self.multi_message_chunk[rrc_header.msgid]:
                is_not_full = True

        if not is_not_full:
            newpkt_body = b''
            for i in range(1, rrc_header.total_chunks+1):
                newpkt_body += self.multi_message_chunk[rrc_header.msgid][i]

            del self.multi_message_chunk[rrc_header.msgid]
            return self._parse_sdm_lte_rrc_message(sdm_pkt_hdr, rrc_header.channel, rrc_header.direction,
                len(newpkt_body), newpkt_body)

    def sdm_lte_rrc_rach_msg(self, pkt):
        pkt = pkt[15:-1]
        struct_format = '<BBBLLL'
        expected_len = struct.calcsize(struct_format)
        if len(pkt) < expected_len:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected ({}))'.format(len(pkt), expected_len))
            return None

        header = namedtuple('SdmLteRrcRachMessage', 'direction cause preamble_group preamble_id ta tc_rnti')
        rach_message = header._make(struct.unpack(struct_format, pkt[0:expected_len]))

        stdout = 'LTE RRC RACH Message: Direction: {}, Cause: {}, Preamble Group: {:#x}, Preamble ID: {:#x}, TA: {}, TC-RNTI: {:#x}'.format(
            rach_message.direction, rach_message.cause, rach_message.preamble_group,
            rach_message.preamble_id, rach_message.ta, rach_message.tc_rnti)
        return {'stdout': stdout}

    def sdm_lte_0x57(self, pkt):
        '''
        0x57: '?' len:13
            "earfcn", '<L', 4 bytes, pos:7
            "pci",    '<H', 2 bytes, pos:11
        if pkt[0] == 0x57:
        '''
        pkt = pkt[15:-1]
        return {'stdout': 'LTE 0x57: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_nas_sim_data(self, pkt):
        '''
        0x58: 'Sim(?)', len:13
            "mcc",  '<2s', 2 bytes, pos:4,   # bcd encoded
            "mnc",  '<1s', 1 bytes, pos:6,   # bcd encoded
            "IMSI", '<9s', 9 bytes, pos:15,  # bcd encoded
        if pkt[0] == 0x58:
        '''
        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS SIM Data: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_nas_status_variable(self, pkt):
        # 3 bytes
        # val1: 1, 2
        # val2: 1, 2, 3, 4, 5
        # val3: 00-ff

        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS Status Variable: {}'.format(binascii.hexlify(pkt).decode())}

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

        if self.gsmtapv3:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NAS_EPS,
                arfcn = 0)
        else:
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_NAS,
                arfcn = 0)
        return {'layer': 'nas', 'cp': [gsmtap_hdr + nas_msg]}

    def sdm_lte_nas_plmn_selection(self, pkt):
        # All zeroes?
        # 00050001
        # 01060002
        # 01060001
        # 02070002
        # 02070001
        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS PLMN Selection: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_nas_security(self, pkt):
        # All zeroes?
        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS Security: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_nas_pdp(self, pkt):
        # 0000ff0000ff0000ff
        # 0001ff0000ff0000ff
        # 0501ff0000ff0000ff
        # Bearer ID, Bearer Type, ? x3

        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS PDP: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_nas_ip(self, pkt):
        # 00000000050000000000000001000000020000000000000000000000
        # 00000000322c0d000000000000000028caa003050000000000000000
        # 00000000000000000000000000000000000000000000000000000000
        # 00000000005ffd75000000000000170035d0a0240000000000000000

        pkt = pkt[15:-1]
        return {'stdout': 'LTE NAS IP: {}'.format(binascii.hexlify(pkt).decode())}

    def sdm_lte_volte_rtp_packet(self, pkt, cmdid):
        # 0x70: TX
        # 0x71: RX
        pkt = pkt[15:-1]

        if len(pkt) < 16:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (16)'.format(len(pkt)))
            return

        header = namedtuple('SdmLteVolteRtpPacket', 'rtp_len dst_port rtp_hdr rtp_payload_type rtp_seq rtp_timestamp rtp_ssrc')
        rtp_info = header._make(struct.unpack('<HHBBHLL', pkt[0:16]))

        stdout = 'LTE VoLTE RTP Packet: Dst Port: {}, Length: {}, Header={}, PT={}, SSRC={:#010x}, Seq={}, Time={}'.format(
            rtp_info.dst_port, rtp_info.rtp_len,
            rtp_info.rtp_hdr,
            rtp_info.rtp_payload_type, rtp_info.rtp_ssrc, rtp_info.rtp_seq, rtp_info.rtp_timestamp
        )

        return {'stdout': stdout}

    def sdm_lte_volte_tx_stats(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmLteVolteTxStats', 'rtp_payload_type rtp_ssrc dst_port ip_type ip_addr time')
        tx_stats = header._make(struct.unpack('<BLHH16sL', pkt[0:58]))

        ip_str = ''

        if tx_stats.ip_type == 0:
            ip_str = str(ipaddress.IPv4Address(tx_stats.ip_addr[0:4]))
        elif tx_stats.ip_type == 1:
            ip_str = str(ipaddress.IPv6Address(tx_stats.ip_addr))
        else:
            ip_str = 'Unknown IP type {}'.format(tx_stats.ip_type)

        stdout = 'LTE VoLTE TX Stats: IP: {}, Dst Port: {}, PT={}, SSRC={:#010x}, {:.2f}s'.format(
            ip_str,
            tx_stats.dst_port,
            tx_stats.rtp_payload_type,
            tx_stats.rtp_ssrc,
            tx_stats.time / 1000
        )

        return {'stdout': stdout}

    def sdm_lte_volte_rx_stats(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmLteVolteRxStats', 'rtp_ssrc dst_port ip_type ip_addr')
        rx_stats = header._make(struct.unpack('<LHH16s', pkt[0:48]))

        if rx_stats.ip_type == 0:
            ip_str = str(ipaddress.IPv4Address(rx_stats.ip_addr[0:4]))
        elif rx_stats.ip_type == 1:
            ip_str = str(ipaddress.IPv6Address(rx_stats.ip_addr))
        else:
            ip_str = 'Unknown IP type {}'.format(rx_stats.ip_type)

        stdout = 'LTE VoLTE RX Stats: IP: {}, Dst Port: {}, SSRC={:#010x}'.format(
            ip_str,
            rx_stats.dst_port, rx_stats.rtp_ssrc
        )

        return {'stdout': stdout}

    def sdm_lte_volte_tx_rtp_stats(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmLteVolteTxRtpStats', 'time pkts bytes')
        tx_stats = header._make(struct.unpack('<LLL', pkt[0:12]))

        stdout = 'LTE VoLTE TX RTP Stats: {:.2f}s, Num Packets: {}, Num Bytes: {}'.format(
            tx_stats.time / 1000,
            tx_stats.pkts,
            tx_stats.bytes
        )

        return {'stdout': stdout}

    def sdm_lte_volte_rx_rtp_stats(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmLteVolteRxRtpStats', 'time pkts bytes')
        rx_stats = header._make(struct.unpack('<LLL', pkt[0:12]))

        stdout = 'LTE VoLTE RX RTP Stats: {:.2f}s, Num Packets: {}, Num Bytes: {}'.format(
            rx_stats.time / 1000,
            rx_stats.pkts,
            rx_stats.bytes
        )

        return {'stdout': stdout}