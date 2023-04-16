#!/usr/bin/env python3

from collections import namedtuple
import util
import binascii

import struct
import logging

class HisiNestedParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            0x00020101: lambda x, y, z: self.hisi_l3_ota(x, y, z),
        }

    def hisi_l3_ota(self, pkt_header, pkt_data, args):
        if pkt_data[0] == 0x22:
            # WCDMA RRC
            header = namedtuple('HisiL3OtaWcdmaRrc', 'unk1 unk2 unk3 unk4 len type')
            wcdma_rrc_header = header._make(struct.unpack('<LBBBLB', pkt_data[1:13]))
            wcdma_rrc_content = pkt_data[13:]
            # print(wcdma_rrc_header)

            # if len(pkt_data) < 20:
            #     util.warning("WCDMA RRC packet shorter than expected")
            #     return None

            # wcdma_rrc_len = struct.unpack('<L', pkt[16:20])[0]
            # if wcdma_rrc_len == 0:
            #     return None

            channel_type_map = {
                0x02: util.gsmtap_umts_rrc_types.DL_CCCH,
                0x03: util.gsmtap_umts_rrc_types.DL_DCCH,
                0x08: util.gsmtap_umts_rrc_types.UL_CCCH,
                0x09: util.gsmtap_umts_rrc_types.UL_DCCH,
                0x0d: util.gsmtap_umts_rrc_types.MasterInformationBlock,
                0x0e: util.gsmtap_umts_rrc_types.SysInfoTypeSB1,
                0x10: util.gsmtap_umts_rrc_types.SysInfoType1,
                0x11: util.gsmtap_umts_rrc_types.SysInfoType2,
                0x12: util.gsmtap_umts_rrc_types.SysInfoType3,
                0x14: util.gsmtap_umts_rrc_types.SysInfoType5,
                0x16: util.gsmtap_umts_rrc_types.SysInfoType7,
                0x1a: util.gsmtap_umts_rrc_types.SysInfoType11,
                0x1c: util.gsmtap_umts_rrc_types.SysInfoType12,
                0x2d: util.gsmtap_umts_rrc_types.SysInfoType19,
            }

            if not (wcdma_rrc_header.type in channel_type_map.keys()):
                if self.parent.logger:
                    self.parent.logger.log(logging.WARNING, "Unknown WCDMA RRC channel type {:#04x}".format(wcdma_rrc_header.type))
                print(binascii.hexlify(pkt_data))
                return None

            #arfcn = umts_last_uarfcn_dl
            #if channel_type == 0 or channel_type == 1:
            #    arfcn = umts_last_uarfcn_ul
            arfcn = 0

            # TODO: parse huawei ts

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UMTS_RRC,
                arfcn = 0,
                sub_type = channel_type_map[wcdma_rrc_header.type])

            return {'cp': [gsmtap_hdr + wcdma_rrc_content]}

        # elif pkt_data[0] == 0x25:
            # GSM?
            # return None
        else:
            # print(binascii.hexlify(pkt_data))
            return None
