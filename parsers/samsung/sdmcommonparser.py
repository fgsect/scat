#!/usr/bin/env python3

from .sdmcmd import *
from collections import namedtuple
import util
import binascii

import struct
import logging

class SdmCommonParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_BASIC_INFO: lambda x: self.sdm_common_basic_info(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | 0x02: lambda x: self.sdm_common_0x02(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_DATA_SIGNALING_INFO: lambda x: self.sdm_common_signaling(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | 0x04: lambda x: self.sdm_common_0x04(x),
        }

    def sdm_common_basic_info(self, pkt):
        pkt = pkt[11:-1]
        if len(pkt) < 15:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than minimum expected (15)'.format(len(pkt)))
            return

        # cmc221s:
        # 4f 61 01 0f | 17 00 03 | 00 2c ac 6d | 40 96 02 68

        # e303/e333:
        # c3 87 76 05 | 17 04 03 | 00 2c ac 6d | 40 96 02 68 | 41 00 00 00
        # 20 61 bd 37 | 17 00 02 | 80 9d c2 9c | 80 8f 9b 95 | 1f 7e 7f 1a
        # 41 19 01 38 | 17 00 02 | 80 9d c2 9c | 80 8f 9b 95 | 15 7e 7f 1a
        # 8f 19 c0 3d | 17 04 02 | 80 9d c2 9c | 80 8f 9b 95 | 7f 1a 00 00

        # e5123:
        # c6 aa ec 03 | 17 00 03 | 60 76 e1 38 | 20 d1 32 36 | 00 6f 30 c3 | 00 ff ff ff ff ff ff ff
        # e1 aa ec 03 | 19 00 00 | ff ff ff ff | ff ff ff ff | 00 6f 30 c3 | 00 ff ff ff ff ff ff ff
        # c2 31 fd 03 | 20 04 03 | 60 76 e1 38 | 20 d1 32 36 | 00 6f 30 c3 | 00 ff ff ff ff ff ff ff

        # rat: GSM 10, 13 / WCDMA 12, 14 / LTE 17, 19, 20 / 5G TODO
        header = namedtuple('SdmCommonBasicInfo', 'timestamp rat status mimo dlfreq ulfreq')
        common_basic = header._make(struct.unpack('<IBBBLL', pkt[0:15]))

        if len(pkt) > 15:
            extra = pkt[15:]
            print(str(common_basic) + ", Extra: " + binascii.hexlify(extra).decode('utf-8'))
        else:
            print(common_basic)

    def sdm_common_0x02(self, pkt):
        pkt = pkt[11:-1]
        print(util.xxd(pkt))
        # 20 61 bd 37 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff bf 4e 05 00
        # 41 19 01 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff aa 9b 13 00

    def sdm_common_signaling(self, pkt):
        pkt = pkt[11:-1]

        header = namedtuple('SdmCommonSignalingHeader', 'timestamp type subtype direction length')
        pkt_header = header._make(struct.unpack('<LBBBH', pkt[0:9]))
        msg_content = pkt[9:]

        print(pkt_header)

        if pkt_header.type == 0x30: # UMTS RRC
            chan_map_ul = {
                0x30: util.gsmtap_umts_rrc_types.UL_CCCH,
                0x31: util.gsmtap_umts_rrc_types.UL_DCCH
                }
            chan_map_dl = {
                0x30: util.gsmtap_umts_rrc_types.DL_CCCH,
                0x31: util.gsmtap_umts_rrc_types.DL_DCCH,
                0x32: util.gsmtap_umts_rrc_types.BCCH_BCH,
                0x34: util.gsmtap_umts_rrc_types.PCCH
                }

            subtype = 0
            if pkt_header.direction == 2:
                subtype = chan_map_dl[pkt_header.subtype]
                arfcn = self.parent.umts_last_uarfcn_dl[0]
            elif pkt_header.direction == 1:
                subtype = chan_map_ul[pkt_header.subtype]
                arfcn = self.parent.umts_last_uarfcn_ul[0]
            else:
                self.parent.logger.log(logging.WARNING, 'Unknown direction 0x{:02x}'.format(pkt_header.direction))
                return

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UMTS_RRC,
                arfcn = arfcn,
                sub_type = subtype)

            return {'cp': gsmtap_hdr + msg_content}
        elif pkt_header.type == 0x01: # UMTS NAS
            if pkt_header.direction == 2:
                arfcn = self.parent.umts_last_uarfcn_dl[0]
            elif pkt_header.direction == 1:
                arfcn = self.parent.umts_last_uarfcn_ul[0]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.ABIS,
                arfcn = arfcn)

            return {'cp': gsmtap_hdr + msg_content}
        elif pkt_header.type == 0x20: # GSM RR
            # TODO: CCCH and SACCH are not distinguished by headers!
            # Some values are RR message, some are RR_short_PD
            if pkt_header.direction == 2: # RR DL w/ pseudo length
                lapdm_address = b'\x01'
                # Control field
                lapdm_control = b'\x03'
                # length field
                if pkt_header.length > 63:
                    self.parent.logger.log(logging.WARNING, 'message length longer than 63, got {}'.format(pkt_header.length))
                    return
                lapdm_len = bytes([(pkt_header.length << 2) | 0x01])

                #msg_content = lapdm_address + lapdm_control + lapdm_len + msg_content

                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.UM,
                    sub_type = util.gsmtap_channel.CCCH) # Subtype (XXX: All CCCH)

                return {'cp': gsmtap_hdr + msg_content}
            elif pkt_header.direction == 1: # Only RR
                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.ABIS)

                return {'cp': gsmtap_hdr + msg_content}
        elif pkt_header.type == 0x21: # GSM RLC/MAC
            arfcn = 1
            if pkt_header.direction == 1:
                arfcn = arfcn | (1 << 14)
            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UM,
                arfcn = arfcn,
                sub_type = util.gsmtap_channel.PACCH) # Subtype (PACCH dissects as MAC)

            #return gsmtap_hdr + msg_content
            return
        else:
            self.parent.logger.log(logging.WARNING, 'Unknown channel type 0x{:02x}'.format(pkt_header.type))
            return

    def sdm_common_0x04(self, pkt):
        pkt = pkt[11:-1]
        print(util.xxd(pkt))
