#!/usr/bin/env python3

import struct
import calendar
import logging
import binascii
from collections import namedtuple

import scat.util as util
import scat.parsers.qualcomm.diagcmd as diagcmd

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        i = diagcmd.diag_log_get_lte_item_id
        c = diagcmd.diag_log_code_5gnr
        self.process = {
            # Management Layer 1
            # i(c.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE): lambda x, y, z: self.parse_nr_ml1_meas_db_update(x, y, z),

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

    # ML1
    def parse_nr_ml1_meas_db_update(self, pkt_header, pkt_body, args):
        # TODO: NR signal strength (rsrp, rsrq, etc.)
        pass

    # RRC
    def parse_nr_rrc(self, pkt_header, pkt_body, args):
        msg_content = b''
        stdout = ''
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrRrcOtaPacket', 'rrc_rel_maj rrc_rel_min rbid pci nrarfcn sfn_subfn pdu_id sib_mask len')
        item_struct_v17 = namedtuple('QcDiagNrRrcOtaPacketV17', 'rrc_rel_maj rrc_rel_min rbid pci unk1 nrarfcn sfn_subfn pdu_id sib_mask len')

        if pkt_ver in (0x09, ): # Version 9
            item = item_struct._make(struct.unpack('<BBBHIIBIH', pkt_body[4:24]))
            msg_content = pkt_body[24:]
        elif pkt_ver in (0x0c, 0x0e): # Version 12, 14
            item = item_struct._make(struct.unpack('<BBBHI3sBIH', pkt_body[4:23]))
            msg_content = pkt_body[23:]
        elif pkt_ver in (0x11, ): # Version 17
            item = item_struct_v17._make(struct.unpack('<BBBH Q I3sBIH', pkt_body[4:31]))
            msg_content = pkt_body[31:]
        elif pkt_ver in (0x13, ): # Version 19
            item = item_struct_v17._make(struct.unpack('<BBBH Q I3sBIHx', pkt_body[4:32]))
            msg_content = pkt_body[32:]
        elif pkt_ver in (0x17, ): # Version 23
            item = item_struct_v17._make(struct.unpack('<BBBH Q I3sBIH4x', pkt_body[4:35]))
            msg_content = pkt_body[35:]
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR RRC OTA Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if pkt_ver in (0x09, 0x0c):
            rrc_type_map = {
                1: "BCCH_BCH",
                2: "BCCH_DL_SCH",
                3: "DL_CCCH",
                4: "DL_DCCH",
                5: "PCCH",
                6: "UL_CCCH",
                7: "UL_CCCH1",
                8: "UL_DCCH",
                9: "RRC_RECONFIGURATION",
                10: "RRC_RECONFIGURATION_COMPLETE",
                25: "nr-RadioBearerConfig",
                28: "UE_MRDC_CAPABILITY",
                29: "UE_NR_CAPABILITY",
            }
        elif pkt_ver in (0x0e, ):
            rrc_type_map = {
                1: "BCCH_BCH",
                2: "BCCH_DL_SCH",
                3: "DL_CCCH",
                4: "DL_DCCH",
                5: "PCCH",
                6: "UL_CCCH",
                7: "UL_CCCH1",
                8: "UL_DCCH",
                9: "RRC_RECONFIGURATION",
                10: "RRC_RECONFIGURATION_COMPLETE",
                31: "UE_MRDC_CAPABILITY",
                32: "UE_NR_CAPABILITY",
                33: "UE_NR_CAPABILITY",
            }
        elif pkt_ver in (0x11, 0x13, ):
            rrc_type_map = {
                1: "BCCH_BCH",
                2: "BCCH_DL_SCH",
                3: "DL_CCCH",
                4: "DL_DCCH",
                5: "PCCH",
                6: "UL_CCCH",
                7: "UL_CCCH1",
                8: "UL_DCCH",
                9: "RRC_RECONFIGURATION",
                10: "RRC_RECONFIGURATION_COMPLETE",
                29: "nr-RadioBearerConfig",
            }
        elif pkt_ver in (0x17, ):
           rrc_type_map = {
                1: "BCCH_BCH",
                2: "BCCH_DL_SCH",
                3: "DL_CCCH",
                4: "DL_DCCH",
                5: "MCCH",
                6: "PCCH",
                7: "UL_CCCH",
                8: "UL_CCCH1",
                9: "UL_DCCH",
                10: "RRC_RECONFIGURATION",
                11: "RRC_RECONFIGURATION_COMPLETE",
                29: "nr-RadioBearerConfig",
            }

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if item.pdu_id in rrc_type_map.keys():
            type_str = rrc_type_map[item.pdu_id]
        else:
            type_str = '{}'.format(item.pdu_id)

        stdout += "NR RRC OTA Packet: NR-ARFCN {}, PCI {}, Type: {}\n".format(item.nrarfcn, item.pci, type_str)
        stdout += "NR RRC OTA Packet: Body: {}".format(binascii.hexlify(msg_content).decode())

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mib_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        item_struct = namedtuple('QcDiagNrMibInfo', 'pci nrarfcn props')
        scs_map = {
            0: 15,
            1: 30,
            2: 60,
            3: 120,
        }

        scs_str = ''
        if pkt_ver == 0x03: # Version 3
            item = item_struct._make(struct.unpack('<HI4s', pkt_body[4:14]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b11000000) >> 6
        elif pkt_ver == 0x20000: # Version 131072
            item = item_struct._make(struct.unpack('<HI5s', pkt_body[4:15]))
            sfn = (item.props[0]) | (((item.props[1] & 0b11000000) >> 6) << 8)
            scs = (item.props[3] & 0b10000000) >> 7 | ((item.props[4] & 0b00000001) << 1)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MIB Information packet version {}'.format(pkt_ver))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return

        if scs in scs_map:
            scs_str = '{} kHz'.format(scs_map[scs])

        if len(scs_str) > 0:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}, SCS: {}'.format(item.nrarfcn, item.pci, sfn, scs_str)
        else:
            stdout = 'NR MIB: NR-ARFCN {}, PCI {:4d}, SFN: {}'.format(item.nrarfcn, item.pci, sfn)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_scell_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        item_struct = namedtuple('QcDiagNrScellInfo', 'pci dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        item_struct_v30000 = namedtuple('QcDiagNrScellInfoV30000', 'pci nr_cgi dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        if pkt_ver == 0x04:
            # PCI 2b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct._make(struct.unpack('<H LLHH Q H BH B LH', pkt_body[4:38]))
        elif pkt_ver == 0x30000:
            # PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[4:46]))
        elif pkt_ver in (0x30002, 0x30003, ):
            # ? 3b, PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[7:49]))
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR SCell Information packet version {:4x}'.format(pkt_ver))
                self.parent.logger.log(logging.WARNING, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        if item.mnc_digit == 2:
            stdout = 'NR RRC SCell Info: NR-ARFCN {}/{}, Bandwidth {}/{} MHz, Band {}, PCI {:4d}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {:02}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        elif item.mnc_digit == 3:
            stdout = 'NR RRC SCell Info: NR-ARFCN {}/{}, Bandwidth {}/{} MHz, Band {}, PCI {:4d}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {:02}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        else:
            stdout = 'NR RRC SCell Info: NR-ARFCN {}/{}, Bandwidth {}/{} MHz, Band {}, PCI {:4d}, xTAC/xCID {:x}/{:x}, MCC {}, MNC {:02}'.format(item.dl_nrarfcn,
                item.ul_nrarfcn, item.dl_bandwidth, item.ul_bandwidth, item.band, item.pci, item.tac, item.cell_id, item.mcc, item.mnc)
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_rrc_conf_info(self, pkt_header, pkt_body, args):
        pass

    def parse_nr_cacombos(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        if self.parent:
            if not self.parent.cacombos:
                return None

        return {'stdout': 'NR UE CA Combos Raw: {}'.format(binascii.hexlify(pkt_body).decode()), 'ts': pkt_ts}

    # NAS
    def parse_nr_nas(self, pkt_header, pkt_body, args, cmd_id):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        stdout = ''

        # Version 4b, std version maj.min.rev 1b each
        pkt_ver = struct.unpack('<L', pkt_body[0:4])[0]
        item_struct = namedtuple('QcDiagNrNasMsg', 'vermaj vermid vermin')
        msg_content = pkt_body[7:]
        if pkt_ver == 0x1:
            item = item_struct._make(struct.unpack('<BBB', pkt_body[4:7]))
            stdout = "NAS-5GS message ({:04X}) version {:x}.{:x}.{:x}: ".format(cmd_id, item.vermaj, item.vermid, item.vermin)
            msg_content = pkt_body[7:]
            stdout += "{}".format(binascii.hexlify(msg_content).decode())
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR NAS Message packet version {:#x}'.format(pkt_ver))
                self.parent.logger.log(logging.DEBUG, "Body: {}".format(util.xxd_oneline(pkt_body)))
            return None

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mm_state(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        if pkt_ver in (0x01, 0x30000, ): # Version 1 and 196608
            item_struct = namedtuple('QcDiagNrNasMmState', 'mm_state mm_substate plmn_id guti_5gs mm_update_status tac')
            item = item_struct._make(struct.unpack('<BH3s12sb3s', pkt_body[4:26]))
            plmn_id = util.unpack_mcc_mnc(item.plmn_id)
            tac = struct.unpack('>L', b'\x00'+item.tac)[0]

            if item.guti_5gs[0] == 0x02:
                # mcc-mcc-amf_rid-amf_sid-amf_ptr-5g_tmsi
                plmn_id_guti = util.unpack_mcc_mnc(item.guti_5gs[1:4])
                amf_sid = struct.unpack('<H', item.guti_5gs[5:7])[0]
                tmsi_5gs = struct.unpack('<L', item.guti_5gs[8:12])[0]
                guti_str = '{:03x}-{:03x}-{:02x}-{:03x}-{:02x}-{:08x}'.format(plmn_id_guti[0], plmn_id_guti[1], item.guti_5gs[4],
                                                              amf_sid, item.guti_5gs[7], tmsi_5gs)
            else:
                guti_str = binascii.hexlify(item.guti_5gs).decode()

            stdout = '5GMM State: {}/{}/{}, PLMN: {:3x}/{:3x}, TAC: {:6x}, GUTI: {}'.format(
                item.mm_state, item.mm_substate, item.mm_update_status, plmn_id[0], plmn_id[1], tac, guti_str
            )
            return {'stdout': stdout, 'ts': pkt_ts}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown NR MM State packet version %s' % pkt_ver)
                self.parent.logger.log(logging.WARNING, "Body: %s" % (util.xxd_oneline(pkt_body[4:])))
            return
