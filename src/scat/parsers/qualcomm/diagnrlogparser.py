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

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.rrc_segments = dict()
        self.first_segment_item = None

        if self.parent:
            self.display_format = self.parent.display_format
        else:
            self.display_format = 'x'

        i = diagcmd.diag_log_get_lte_item_id
        c = diagcmd.diag_log_code_5gnr
        self.process = {
            # Management Layer 1
            i(c.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE): lambda x, y, z: self.parse_nr_ml1_meas_db_update(x, y, z),

            # MAC

            # RRC
            i(c.LOG_5GNR_RRC_OTA_MESSAGE): lambda x, y, z: self.parse_nr_rrc(x, y, z),
            i(c.LOG_5GNR_RRC_MIB_INFO): lambda x, y, z: self.parse_nr_mib_info(x, y, z),
            i(c.LOG_5GNR_RRC_SERVING_CELL_INFO): lambda x, y, z: self.parse_nr_rrc_scell_info(x, y, z),
            # i(c.LOG_5GNR_RRC_CONFIGURATION_INFO): lambda x, y, z: self.parse_nr_rrc_conf_info(x, y, z),
            i(c.LOG_5GNR_RRC_SUPPORTED_CA_COMBOS): lambda x, y, z: self.parse_nr_cacombos(x, y, z),

            # NAS
            i(c.LOG_5GNR_NAS_5GSM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB800),
            i(c.LOG_5GNR_NAS_5GSM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB801),
            i(c.LOG_5GNR_NAS_5GSM_SEC_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB808),
            i(c.LOG_5GNR_NAS_5GSM_SEC_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB809),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_INCOMING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB80A),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB80B),
            i(c.LOG_5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER_MESSAGE): lambda x, y, z: self.parse_nr_nas(x, y, z, 0xB814),
            i(c.LOG_5GNR_NAS_5GMM_STATE): lambda x, y, z: self.parse_nr_mm_state(x, y, z),
        }

        self.nr_pkt_ver = namedtuple('QcDiagNrPktVer', 'rel_min rel_maj')

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format

    def parse_float_q7(self, data_to_convert):
        if data_to_convert == 0:
            return 0
        integer = (data_to_convert >> 7) & 0xff
        frac = data_to_convert & 0x7f
        sig = (((integer^0xff)+1)* (-1)) + frac * 0.0078125
        return sig

    # ML1
    def parse_nr_ml1_meas_db_update(self, pkt_header, pkt_body, args):
        stdout = ''
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))
        num_layers = 0
        current_offset = 0
        if pkt_ver.rel_maj == 0x02:
            if pkt_ver.rel_min == 0x07:
                ml1_shared_struct = namedtuple('QcDiagNrMl1Packet', 'num_layers ssb_periocity null frequency_offset timing_offset')
                ml1_2_7 = ml1_shared_struct._make(struct.unpack('<BB2sII', pkt_body[4:16]))
                num_layers = ml1_2_7.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_2_7.num_layers, ml1_2_7.ssb_periocity)
                current_offset = 16

            elif pkt_ver.rel_min == 0x09:
                ml1_shared_struct = namedtuple('QcDiagNrMl1Packet', 'unknown num_layers ssb_periocity null frequency_offset timing_offset')
                ml1_2_9 = ml1_shared_struct._make(struct.unpack('<IBBHII', pkt_body[4:20]))
                num_layers = ml1_2_9.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_2_9.num_layers, ml1_2_9.ssb_periocity)
                current_offset = 20
        elif pkt_ver.rel_maj == 0x03:
            if pkt_ver.rel_min == 0x00:
                ml1_shared_struct = namedtuple('QcDiagNrMl1Packet', 'unknown num_layers ssb_periocity null frequency_offset timing_offset')
                ml1_3_0 = ml1_shared_struct._make(struct.unpack('<IBBHII', pkt_body[4:20]))
                num_layers = ml1_3_0.num_layers
                stdout += "NR ML1 Meas Packet: Layers: {}, ssb_periocity: {}\n".format(ml1_3_0.num_layers, ml1_3_0.ssb_periocity)
                current_offset = 20
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR ML1 Information packet, version: {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        for layer in range(num_layers):
            meas_carrier_list_struct = namedtuple('QcDiagNrMl1Packet', 'raster_arfcn num_cells serv_cell_index serv_cell_pci serv_ssb null_0 serv_rsrp_rx_0 serv_rsrp_rx_1 serv_rx_beam_0 serv_rx_beam_1 serv_rfic_id null_1 serv_subarr_0 serv_subarr_1')
            meas_carrier_list_struct_v3 = namedtuple('QcDiagNrMl1PacketV3', 'raster_arfcn cc_id num_cells serv_cell_pci serv_cell_index serv_ssb null_0 serv_rsrp_rx_0 serv_rsrp_rx_1 serv_rsrp_rx_2 serv_rsrp_rx_3 serv_rx_beam_0 serv_rx_beam_1 serv_rfic_id null_1 serv_subarr_0 serv_subarr_1')
            if pkt_ver.rel_maj == 0x02:
                if pkt_ver.rel_min in (0x07, 0x09):
                    meas_carrier_list = meas_carrier_list_struct._make(struct.unpack('<IBBHB3sIIHHH2sHH', pkt_body[current_offset:current_offset+32]))
                    current_offset += 32
            elif pkt_ver.rel_maj == 0x03:
                if pkt_ver.rel_min in (0x00, ):
                    meas_carrier_list = meas_carrier_list_struct_v3._make(struct.unpack('<IBBHBB2sIIIIHHH2sHH', pkt_body[current_offset:current_offset+40]))
                    current_offset += 40

            if pkt_ver.rel_maj == 0x02:
                rsrp_str = 'RSRP: {:.2f}/{:.2f}'.format(
                    self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_0), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_1),
                )
            elif pkt_ver.rel_maj == 0x03:
                rsrp_str = 'RSRP: {:.2f}/{:.2f}/{:.2f}/{:.2f}'.format(
                    self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_0), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_1),
                    self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_2), self.parse_float_q7(meas_carrier_list.serv_rsrp_rx_3),
                )
            stdout += "Layer {}: NR-ARFCN: {}, SCell PCI: {:4d}/SSB: {}, {}, RX beam: {}/{}, Num Cells: {} (S: {})\n".format(
                layer, meas_carrier_list.raster_arfcn, meas_carrier_list.serv_cell_pci, meas_carrier_list.serv_ssb & 0xf,
                rsrp_str,
                meas_carrier_list.serv_rx_beam_0 if meas_carrier_list.serv_rx_beam_0 != 0xffff else 'NA',
                meas_carrier_list.serv_rx_beam_1 if meas_carrier_list.serv_rx_beam_1 != 0xffff else 'NA',
                meas_carrier_list.num_cells, meas_carrier_list.serv_cell_index)

            if meas_carrier_list.num_cells == 0xff or meas_carrier_list.num_cells == 0x00:
                if meas_carrier_list.serv_cell_index > 0x00 and meas_carrier_list.serv_cell_index < 0xff:
                    num_cells = meas_carrier_list.serv_cell_index
                else:
                    num_cells = 0
            else:
                num_cells = meas_carrier_list.num_cells

            for cell in range(num_cells):
                cell_list_struct = namedtuple('QcDiagNrMl1Packet', 'pci pbch_sfn num_beams null_0 cell_quality_rsrp cell_quality_rsrq')
                cell_list = cell_list_struct._make(struct.unpack('<HHB3sII', pkt_body[current_offset:current_offset+16]))
                current_offset += 16
                stdout += "└── Cell {}: PCI: {:4d}, PBCH SFN: {}, RSRP: {:.2f}, RSRQ: {:.2f}, Num Beams: {}\n".format(
                    cell, cell_list.pci, cell_list.pbch_sfn,
                    self.parse_float_q7(cell_list.cell_quality_rsrp), self.parse_float_q7(cell_list.cell_quality_rsrq),
                    cell_list.num_beams)
                for beam in range(cell_list.num_beams):
                    beam_meas_struct = namedtuple('QcDiagNrMl1Packet', 'ssb_index null_0 rx_beam_0 rx_beam_1 null_1 ssb_ref_timing rx_beam_info_rsrp_0 rx_beam_info_rsrp_1 nr2nr_filtered_beam_rsrp_l3 nr2nr_filtered_beam_rsrq_l3 l_2_nr_filtered_tx_beam_rsrp_l3 l_2_nr_filtered_tx_beam_rsrq_l3')
                    beam_meas_struct_v3 = namedtuple('QcDiagNrMl1PacketV3', 'ssb_index null_0 rx_beam_0 rx_beam_1 null_1 ssb_ref_timing rx_beam_info_rsrp_0 rx_beam_info_rsrp_1 unk_0 unk_1 unk_2 unk_3 unk_4 unk_5 unk_6 unk_7 unk_8 unk_9 nr2nr_filtered_beam_rsrp_l3 nr2nr_filtered_beam_rsrq_l3 l_2_nr_filtered_tx_beam_rsrp_l3 l_2_nr_filtered_tx_beam_rsrq_l3')
                    if pkt_ver.rel_maj == 0x02:
                        beam_meas = beam_meas_struct._make(struct.unpack('<HHHHIQIIIIII', pkt_body[current_offset: current_offset+44]))
                        current_offset += 44
                        stdout += "    └── Beam {}: SSB[{}] Beam ID: {}/{}, RSRP: {:.2f}/{:.2f}, Filtered RSRP/RSRQ (Nr2Nr): {:.2f}/{:.2f}, Filtered RSRP/RSRQ (L2Nr): {:.2f}/{:.2f}\n".format(
                            beam, beam_meas.ssb_index,
                            beam_meas.rx_beam_0, beam_meas.rx_beam_1,
                            self.parse_float_q7(beam_meas.rx_beam_info_rsrp_0), self.parse_float_q7(beam_meas.rx_beam_info_rsrp_1),
                            self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrp_l3), self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrq_l3),
                            self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrp_l3), self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrq_l3),
                        )
                    elif pkt_ver.rel_maj == 0x03:
                        beam_meas = beam_meas_struct_v3._make(struct.unpack('<HHHHIQIIIIIIIIIIIIIIII', pkt_body[current_offset: current_offset+84]))
                        current_offset += 84
                        stdout += "    └── Beam {}: SSB[{}] Beam ID: {}/{}, RSRP: {:.2f}/{:.2f}, RSRQ: {:.2f}/{:.2f}, Filtered RSRP/RSRQ (Nr2Nr): {:.2f}/{:.2f}, Filtered RSRP/RSRQ (L2Nr): {:.2f}/{:.2f}\n".format(
                            beam, beam_meas.ssb_index,
                            beam_meas.rx_beam_0, beam_meas.rx_beam_1,
                            self.parse_float_q7(beam_meas.rx_beam_info_rsrp_0), self.parse_float_q7(beam_meas.rx_beam_info_rsrp_1),
                            self.parse_float_q7(beam_meas.unk_0), self.parse_float_q7(beam_meas.unk_1),
                            self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrp_l3), self.parse_float_q7(beam_meas.nr2nr_filtered_beam_rsrq_l3),
                            self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrp_l3), self.parse_float_q7(beam_meas.l_2_nr_filtered_tx_beam_rsrq_l3),
                        )

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    # RRC
    def parse_nr_mib_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        item_struct = namedtuple('QcDiagNrMibInfo', 'pci nrarfcn')
        scs_map = {
            0: 15,
            1: 30,
            2: 60,
            3: 120,
        }

        scs_str = ''
        if pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x03: # Version 3
            item = item_struct._make(struct.unpack('<HI', pkt_body[4:10]))
            props_bits = bitstring.Bits(bytes=reversed(pkt_body[10:14]))
            sfn = props_bits[0:10].uint
            scs = props_bits[30:32].uint
        elif pkt_ver.rel_maj == 0x02 and pkt_ver.rel_min == 0x00: # Version 131072
            item = item_struct._make(struct.unpack('<HI', pkt_body[4:10]))
            props_bits = bitstring.Bits(bytes=reversed(pkt_body[10:15]))
            sfn = props_bits[0:10].uint
            scs = props_bits[31:33].uint
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MIB Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        if scs in scs_map:
            scs_str = '{} kHz'.format(scs_map[scs])

        if len(scs_str) > 0:
            stdout = 'NR MIB: NR-ARFCN: {}, PCI: {:4d}, SFN: {}, SCS: {}'.format(item.nrarfcn, item.pci, sfn, scs_str)
        else:
            stdout = 'NR MIB: NR-ARFCN: {}, PCI: {:4d}, SFN: {}'.format(item.nrarfcn, item.pci, sfn)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_scell_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        item_struct = namedtuple('QcDiagNrScellInfo', 'pci dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        item_struct_v30000 = namedtuple('QcDiagNrScellInfoV30000', 'pci nr_cgi dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        if pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x04:
            # PCI 2b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct._make(struct.unpack('<H LLHH Q H BH B LH', pkt_body[4:38]))
        elif pkt_ver.rel_maj == 0x03:
            if pkt_ver.rel_min == 0x00:
                # PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
                item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[4:46]))
            elif pkt_ver.rel_min in (0x02, 0x03, ):
                # ? 3b, PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
                item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[7:49]))
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR RRC SCell Information packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if self.display_format == 'd':
            tac_cid_fmt = 'TAC/CID: {}/{}'.format(item.tac, item.cell_id)
        elif self.display_format == 'x':
            tac_cid_fmt = 'xTAC/xCID: {:x}/{:x}'.format(item.tac, item.cell_id)
        elif self.display_format == 'b':
            tac_cid_fmt = 'TAC/CID: {}/{} ({:#x}/{:#x})'.format(item.tac, item.cell_id, item.tac, item.cell_id)

        if item.mnc_digit == 2:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {:02}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        elif item.mnc_digit == 3:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {:03}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        else:
            stdout = 'NR RRC SCell Info: NR-ARFCN: {}/{}, Bandwidth: {}/{} MHz, Band: {}, PCI: {:4d}, MCC: {}, MNC: {}, {}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.mcc, item.mnc, tac_cid_fmt)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_conf_info(self, pkt_header, pkt_body, args):
        pass

    def parse_nr_rrc(self, pkt_header, pkt_body, args):
        msg_content = b''
        stdout = ''
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrRrcOtaPacket', 'rrc_rel_maj rrc_rel_min rbid pci nrarfcn sfn_subfn pdu_id sib_mask len')
        item_struct_v17 = namedtuple('QcDiagNrRrcOtaPacketV17', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len')
        item_struct_v19 = namedtuple('QcDiagNrRrcOtaPacketV19', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len unk1')
        item_struct_v23 = namedtuple('QcDiagNrRrcOtaPacketV23', 'rrc_rel_maj rrc_rel_min rbid pci ncgi nrarfcn sfn_subfn pdu_id sib_mask len unk1 unk2 unk3 segment_id')

        if pkt_ver in (0x09, ): # Version 9
            item = item_struct._make(struct.unpack('<BBBHIIBIH', pkt_body[4:24]))
            msg_content = pkt_body[24:]
        elif pkt_ver in (0x0c, 0x0e): # Version 12, 14
            item = item_struct._make(struct.unpack('<BBBHI3sBIH', pkt_body[4:23]))
            msg_content = pkt_body[23:]
        elif pkt_ver in (0x11, ): # Version 17
            item = item_struct_v17._make(struct.unpack('<BBBH Q I3sBIH', pkt_body[4:31]))
            msg_content = pkt_body[31:]
        elif pkt_ver in (0x13, 0x14): # Version 19, 20
            item = item_struct_v19._make(struct.unpack('<BBBH Q I3sBIHB', pkt_body[4:32]))
            msg_content = pkt_body[32:]
        elif pkt_ver in (0x17, 0x1a): # Version 23, 26
            item = item_struct_v23._make(struct.unpack('<BBBH Q I3sBIHBBBB', pkt_body[4:35]))
            msg_content = pkt_body[35:]
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR RRC OTA Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if pkt_ver >= 0x11:
            try:
                ncgi = bitstring.Bits(uint=item.ncgi, length=60)
            except bitstring.exceptions.CreationError:
                # Telit FN990 and others: invalid or logically unfit NR CGI is created, which does not fit in 60 bytes
                ncgi = None
        else:
            ncgi = None

        if pkt_ver >= 0x17:
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

        if pkt_ver in (0x09, 0x0c):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
                28: util.gsmtapv3_nr_rrc_types.UE_MRDC_CAP,
                29: util.gsmtapv3_nr_rrc_types.UE_NR_CAP
            }
            rrc_type_map_stdout = {
                25: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x0e, ):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
                31: util.gsmtapv3_nr_rrc_types.UE_MRDC_CAP,
                32: util.gsmtapv3_nr_rrc_types.UE_NR_CAP,
                33: util.gsmtapv3_nr_rrc_types.UE_NR_CAP
            }
            rrc_type_map_stdout = {
            }
        elif pkt_ver in (0x11, 0x13, ):
            rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.PCCH,
                6: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                8: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                9: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
            }
            rrc_type_map_stdout = {
                29: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x14, 0x17):
           rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.MCCH,
                6: util.gsmtapv3_nr_rrc_types.PCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                8: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                9: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                10: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                11: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
           }
           rrc_type_map_stdout = {
                36: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x1a, ):
           rrc_type_map = {
                1: util.gsmtapv3_nr_rrc_types.BCCH_BCH,
                2: util.gsmtapv3_nr_rrc_types.BCCH_DL_SCH,
                3: util.gsmtapv3_nr_rrc_types.DL_CCCH,
                4: util.gsmtapv3_nr_rrc_types.DL_DCCH,
                5: util.gsmtapv3_nr_rrc_types.MCCH,
                6: util.gsmtapv3_nr_rrc_types.PCCH,
                7: util.gsmtapv3_nr_rrc_types.UL_CCCH,
                8: util.gsmtapv3_nr_rrc_types.UL_CCCH1,
                9: util.gsmtapv3_nr_rrc_types.UL_DCCH,
                11: util.gsmtapv3_nr_rrc_types.RRC_RECONF,
                12: util.gsmtapv3_nr_rrc_types.RRC_RECONF_COMPLETE,
           }
           rrc_type_map_stdout = {
                36: "nr-RadioBearerConfig",
            }

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if item.pdu_id in rrc_type_map.keys():
            type_str = rrc_type_map[item.pdu_id]
            gsmtapv3_metadata = dict()
            gsmtapv3_metadata[util.gsmtapv3_metadata_tags.BSIC_PSC_PCI] = item.pci
            if ncgi:
                mcc_mnc = util.unpack_mcc_mnc(ncgi[36:60].bytes)
                cell_id = ncgi[0:36].uint
                if self.display_format == 'd':
                    stdout += ', NR CGI: {}-{}-{}'.format(mcc_mnc[0], mcc_mnc[1], cell_id)
                elif self.display_format == 'x':
                    stdout += ', NR CGI: {}-{}-{:9x}'.format(mcc_mnc[0], mcc_mnc[1], cell_id)
                elif self.display_format == 'b':
                    stdout += ', NR CGI: {}-{}-{} ({:#9x})'.format(mcc_mnc[0], mcc_mnc[1], cell_id, cell_id)
            nr_pdu_id_gsmtap = rrc_type_map[item.pdu_id]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NR_RRC,
                arfcn = item.nrarfcn,
                sub_type = nr_pdu_id_gsmtap,
                device_sec = ts_sec,
                device_usec = ts_usec,
                metadata = gsmtapv3_metadata)

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts}
        else:
            if item.pdu_id in rrc_type_map_stdout.keys():
                type_str = rrc_type_map_stdout[item.pdu_id]
            else:
                type_str = '{}'.format(item.pdu_id)

            stdout += "NR RRC OTA Packet: NR-ARFCN: {}, PCI: {}, Type: {}\n".format(item.nrarfcn, item.pci, type_str)
            stdout += "NR RRC OTA Packet: Body: {}".format(binascii.hexlify(msg_content).decode())

            return {'layer': 'rrc', 'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_cacombos(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if self.parent:
            if not self.parent.cacombos:
                return None

        return {'stdout': 'NR UE CA Combos Raw: {}'.format(binascii.hexlify(pkt_body).decode()), 'ts': pkt_ts}

    # NAS
    def parse_nr_mm_state(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = self.nr_pkt_ver._make(struct.unpack('<HH', pkt_body[0:4]))

        if (pkt_ver.rel_maj == 0x00 and pkt_ver.rel_min == 0x01) or (pkt_ver.rel_maj == 0x03 and pkt_ver.rel_min == 0x00): # Version 1 and 196608
            item_struct = namedtuple('QcDiagNrNasMmState', 'mm_state mm_substate plmn_id guti_5gs mm_update_status tac')
            item = item_struct._make(struct.unpack('<BH3s12sb3s', pkt_body[4:26]))
            plmn_id = util.unpack_mcc_mnc(item.plmn_id)
            tac = struct.unpack('>L', b'\x00'+item.tac)[0]

            if item.guti_5gs[0] == 0x02:
                # mcc-mcc-amf_rid-amf_sid-amf_ptr-5g_tmsi
                plmn_id_guti = util.unpack_mcc_mnc(item.guti_5gs[1:4])
                amf_sid = struct.unpack('<H', item.guti_5gs[5:7])[0]
                tmsi_5gs = struct.unpack('<L', item.guti_5gs[8:12])[0]
                guti_str = '{}-{}-{:02x}-{:03x}-{:02x}-{:08x}'.format(plmn_id_guti[0], plmn_id_guti[1], item.guti_5gs[4],
                                                              amf_sid, item.guti_5gs[7], tmsi_5gs)
            else:
                guti_str = binascii.hexlify(item.guti_5gs).decode()

            if self.display_format == 'd':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {}, GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
                )
            elif self.display_format == 'x':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {:6x}, GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
                )
            elif self.display_format == 'b':
                stdout = '5GMM State: {}/{}/{}, MCC/MNC: {}/{}, TAC: {} ({:#6x}), GUTI: {}'.format(
                    item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, tac, guti_str
                )
            return {'stdout': stdout, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MM State packet, version {}.{}'.format(pkt_ver.rel_maj, pkt_ver.rel_min))
                self.parent.logger.log(logging.WARNING, "Body: %s" % (util.xxd_oneline(pkt_body[4:])))
            return

    def parse_nr_nas(self, pkt_header, pkt_body, args, cmd_id):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        stdout = ''
        plain = (cmd_id in (0xB800, 0xB801, 0xB80A, 0xB80B, 0xB814))

        # Version 4b, std version maj.min.rev 1b each
        pkt_ver = struct.unpack('<L', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrNasMsg', 'vermaj vermid vermin')
        msg_content = pkt_body[7:]
        if pkt_ver == 0x1:
            item = item_struct._make(struct.unpack('<BBB', pkt_body[4:7]))
            stdout = "NAS-5GS message ({:04X}) version {:x}.{:x}.{:x}".format(cmd_id, item.vermaj, item.vermid, item.vermin)
            msg_content = pkt_body[7:]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 3,
                payload_type = util.gsmtapv3_types.NAS_5GS,
                arfcn = 0,
                sub_type = 0 if plain else 1,
                device_sec = ts_sec,
                device_usec = ts_usec)

            return {'layer': 'nas', 'cp': [gsmtap_hdr + msg_content], 'ts': pkt_ts, 'stdout': stdout}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR NAS Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None
