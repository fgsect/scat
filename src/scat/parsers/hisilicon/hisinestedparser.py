#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct

import scat.util as util

class HisiNestedParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        self.process = {
            0x00020101: lambda x, y, z: self.hisi_l3_ota(x, y, z),
            0xfd010101: lambda x, y, z: self.hisi_debug_msg(x, y, z),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

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

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + wcdma_rrc_content]}
        elif pkt_data[0] == 0x03:
            # Abis/L3
            header = namedtuple('HisiL3OtaAbis', 'unk1 unk2 seq unk3 unk4 unk5 len1 len2')
            abis_header = header._make(struct.unpack('<HBBBBBLL', pkt_data[1:16]))
            abis_data = pkt_data[16:]

            if abis_header.len2 + 4 != abis_header.len1:
                if self.parent.logger:
                    self.parent.logger.log(logging.WARNING, "Length mismatch: len1={}, len2={}, diff should be 4".format(abis_header.len1, abis_header.len2))

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.ABIS,
                arfcn = 0,
                sub_type = 0)

            return {'layer': 'nas', 'cp': [gsmtap_hdr + abis_data[:abis_header.len2]]}

        elif pkt_data[0] == 0x25:
            # GSM
            header = namedtuple('HisiL3OtaGsm', 'unk1 unk2 msg_type channel direction unk6 len')
            ota_header = header._make(struct.unpack('<HBBBBBL', pkt_data[1:12]))
            ota_data = pkt_data[12:]
            subtype = 0

            if ota_data[0] == 0b0110:
                # GSM RR, regardless of direction
                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.ABIS,
                    arfcn = 0)

                return {'layer': 'rrc', 'cp': [gsmtap_hdr + ota_data[:ota_header.len]]}
            else:
                # 3GPP TS 24.007, Section 11.3 Non standard L3 messages
                if (ota_data[0] & 0b11 == 0b01) and (ota_data[1] == 0b0110):
                    # RR with pseudo length
                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.UM,
                        arfcn = 0,
                        sub_type = util.gsmtap_channel.CCCH)
                else:
                    # 3GPP TS 44.018, Table 10.4.2:
                    if (ota_data[0] & 0b10000000 == 0x0) and (((ota_data[0] & 0b01111100) >> 2) in (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)):
                        # RR with short PD
                        # gsmtap_hdr = util.create_gsmtap_header(
                        #     version = 2,
                        #     payload_type = util.gsmtap_type.UM,
                        #     arfcn = arfcn,
                        #     sub_type = util.gsmtap_channel.SDCCH | 0x80)
                        # ota_data = b'\x00\x00\x01\x03\xf1' + ota_data
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'GSM RR with short PD, decode using "gsm_a_sacch": {}'.format(binascii.hexlify(ota_data).decode()))
                        return None
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Invalid GSM RR message')
                        return None
                return {'layer': 'rrc', 'cp': [gsmtap_hdr + ota_data[:ota_header.len]]}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown L3 OTA message type {:#04x}'.format(pkt_data[0]))
            return None

    def hisi_debug_msg(self, pkt_header, pkt_data, args):
        # TODO decode hisi ts
        if not self.parent.msgs:
            return None

        if pkt_header.cmd == 0xfd010101:
            pkt_info = struct.unpack('<HHLLLLLL', pkt_data[:28])
            print(pkt_info)
            pkt_data = pkt_data[28:]
            log_prefix = b''
            app_name = ''
        else:
            log_prefix = b''
            app_name = ''

        osmocore_log_hdr = util.create_osmocore_logging_header(
            process_name = app_name,
            subsys_name = '',
            filename = '',
            line_number = 0
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        return {'cp': [gsmtap_hdr + osmocore_log_hdr + log_prefix + pkt_data]}