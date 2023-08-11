#!/usr/bin/env python3

from scat.parsers.qualcomm import diagcmd
import scat.util as util

import struct
import calendar
import logging
import binascii
from collections import namedtuple

class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # Management Layer 1
            # 0xB97F: lambda x, y, z: self.parse_nr_ml1_meas_db_update(x, y, z), # NR ML1 Measurement Database Update

            # MAC

            # RRC
            0xB821: lambda x, y, z: self.parse_nr_rrc(x, y, z), # NR RRC OTA
            0xB822: lambda x, y, z: self.parse_nr_mib_info(x, y, z), # NR RRC MIB Info
            0xB823: lambda x, y, z: self.parse_nr_rrc_scell_info(x, y, z), # NR RRC Serving Cell Info
            # 0xB825: lambda x, y, z: self.parse_nr_rrc_conf_info(x, y, z), # NR RRC Configuration Info
            0xB826: lambda x, y, z: self.parse_cacombos(x, y, z), # NR RRC Supported CA Combos

            # NAS
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

        if pkt_ver in (0x09, ): # Version 9
            item = item_struct._make(struct.unpack('<BBBHIIBIH', pkt_body[4:24]))
            msg_content = pkt_body[24:]
        elif pkt_ver in (0x0c, 0x0e): # Version 12, 14
            item = item_struct._make(struct.unpack('<BBBHI3sBIH', pkt_body[4:23]))
            msg_content = pkt_body[23:]
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
                31: "UE_MRDC_CAPABILITY",
                32: "UE_NR_CAPABILITY",
                33: "UE_NR_CAPABILITY",
            }

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if item.pdu_id in rrc_type_map.keys():
            type_str = rrc_type_map[item.pdu_id]
        else:
            type_str = '{}'.format(item.pdu_id)

        stdout += "NR RRC OTA Packet: NR-ARFCN {}, PCI {}, Type: {}\n".format(item.nrarfcn, item.pci, type_str)
        stdout += "NR RRC OTA Packet: Body: {}".format(binascii.hexlify(msg_content).decode('utf-8'))

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_nr_mib_info(self, pkt_header, pkt_body, args):
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
        return {'stdout': stdout}

    def parse_nr_rrc_scell_info(self, pkt_header, pkt_body, args):
        pkt_ver = struct.unpack('<I', pkt_body[0:4])[0]

        item_struct = namedtuple('QcDiagNrScellInfo', 'pci dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        item_struct_v30000 = namedtuple('QcDiagNrScellInfoV30000', 'pci nr_cgi dl_nrarfcn ul_nrarfcn dl_bandwidth ul_bandwidth cell_id mcc mnc_digit mnc allowed_access tac band')
        if pkt_ver == 0x04:
            # PCI 2b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct._make(struct.unpack('<H LLHH Q H BH B LH', pkt_body[4:38]))
        elif pkt_ver == 0x30000:
            # PCI 2b, NR CGI 8b, DL NR-ARFCN 4b, UL NR-ARFCN 4b, DLBW 2b, ULBW 2b, Cell ID 8b, MCC 2b, MCC digit 1b, MNC 2b, MNC digit 1b, TAC 4b, ?
            item = item_struct_v30000._make(struct.unpack('<H Q LLHH Q H BH B LH', pkt_body[4:46]))
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
        return {'stdout': stdout}

    def parse_nr_rrc_conf_info(self, pkt_header, pkt_body, args):
        pass

    def parse_cacombos(self, pkt_header, pkt_body, args):
        self.parent.logger.log(logging.WARNING, "0xB826 " + util.xxd_oneline(pkt_body))
