#!/usr/bin/env python3

from .sdmcmd import *
from collections import namedtuple
import util
import binascii

import struct
import logging

class SdmCommonParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_BASIC_INFO: lambda x: self.sdm_common_basic_info(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_DATA_INFO: lambda x: self.sdm_common_0x02(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_SIGNALING_INFO: lambda x: self.sdm_common_signaling(x),
            (sdm_command_group.CMD_COMMON_DATA << 8) | 0x04: lambda x: self.sdm_common_0x04(x),
        }

    def set_model(self, model):
        self.model = model

    def sdm_common_basic_info(self, pkt):
        pkt = pkt[15:-1]
        if len(pkt) < 11:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than minimum expected (11)'.format(len(pkt)))
            return

        stdout = ''

        # rat: GSM 10, 13 / WCDMA 12, 14 / LTE 17, 19, 20 / 5G TODO
        header = namedtuple('SdmCommonBasicInfo', 'rat status mimo dlfreq ulfreq')
        common_basic = header._make(struct.unpack('<BBBLL', pkt[0:11]))

        if len(pkt) > 11:
            extra = pkt[11:]
            stdout = 'Common Basic Info: RAT {}, MIMO {}, Frequency {:.2f}/{:.2f} MHz, Extra: {}'.format(common_basic.rat,
                common_basic.mimo,
                0 if common_basic.dlfreq == 4294967295 else common_basic.dlfreq / 1000000,
                0 if common_basic.ulfreq == 4294967295 else common_basic.ulfreq / 1000000,
                binascii.hexlify(extra).decode('utf-8'))
        else:
            stdout = 'Common Basic Info: RAT {}, MIMO {}, Frequency {:.2f}/{:.2f} MHz'.format(common_basic.rat,
                common_basic.mimo,
                0 if common_basic.dlfreq == 4294967295 else common_basic.dlfreq / 1000000,
                0 if common_basic.ulfreq == 4294967295 else common_basic.ulfreq / 1000000)

        return {'stdout': stdout}

    def sdm_common_0x02(self, pkt):
        pkt = pkt[15:-1]
        # print(util.xxd(pkt))
        # 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff bf 4e 05 00
        # 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff aa 9b 13 00

    def sdm_common_signaling(self, pkt):
        pkt = pkt[15:-1]

        header = namedtuple('SdmCommonSignalingHeader', 'type subtype direction length')
        pkt_header = header._make(struct.unpack('<BBBH', pkt[0:5]))
        msg_content = pkt[5:]

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
                if self.parent:
                    arfcn = self.parent.umts_last_uarfcn_dl[0]
                else:
                    arfcn = 0
            elif pkt_header.direction == 1:
                subtype = chan_map_ul[pkt_header.subtype]
                if self.parent:
                    arfcn = self.parent.umts_last_uarfcn_ul[0]
                else:
                    arfcn = 0
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown direction 0x{:02x}'.format(pkt_header.direction))
                return None

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UMTS_RRC,
                arfcn = arfcn,
                sub_type = subtype)

            return {'cp': [gsmtap_hdr + msg_content]}
        elif pkt_header.type == 0x01: # UMTS NAS
            # direction: 1: UL, 2: DL
            arfcn = 0
            if pkt_header.direction == 1:
                arfcn = arfcn | (1 << 14)

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.ABIS,
                arfcn = arfcn)

            return {'cp': [gsmtap_hdr + msg_content]}
        elif pkt_header.type == 0x20: # GSM RR
            # direction: 1: UL, 2: DL
            arfcn = 0
            if pkt_header.direction == 1:
                arfcn = arfcn | (1 << 14)

            if msg_content[0] == 0b0110:
                # GSM RR, regardless of direction
                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    arfcn = arfcn,
                    payload_type = util.gsmtap_type.ABIS)
            else:
                # 3GPP TS 24.007, Section 11.3 Non standard L3 messages
                if (msg_content[0] & 0b11 == 0b01) and (msg_content[1] == 0b0110):
                    # RR with pseudo length
                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.UM,
                        arfcn = arfcn,
                        sub_type = util.gsmtap_channel.CCCH)
                else:
                    # 3GPP TS 44.018, Table 10.4.2:
                    if (msg_content[0] & 0b10000000 == 0x0) and (((msg_content[0] & 0b01111100) >> 2) in (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)):
                        # RR with short PD
                        # gsmtap_hdr = util.create_gsmtap_header(
                        #     version = 2,
                        #     payload_type = util.gsmtap_type.UM,
                        #     arfcn = arfcn,
                        #     sub_type = util.gsmtap_channel.SDCCH | 0x80)
                        # msg_content = b'\x00\x00\x01\x03\xf1' + msg_content
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'GSM RR with short PD, decode using "gsm_a_sacch": {}'.format(binascii.hexlify(msg_content).decode('utf-8')))
                        return None
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Invalid GSM RR message')
                        return None

            return {'cp': [gsmtap_hdr + msg_content]}
        elif pkt_header.type == 0x21: # GSM RLC/MAC
            # direction: 1: UL, 2: DL
            arfcn = 0
            if pkt_header.direction == 1:
                arfcn = arfcn | (1 << 14)

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UM,
                arfcn = arfcn,
                sub_type = util.gsmtap_channel.PACCH) # Subtype (PACCH dissects as MAC)

            return {'cp': [gsmtap_hdr + msg_content]}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown channel type 0x{:02x}'.format(pkt_header.type))
            return None

    def sdm_common_0x04(self, pkt):
        pkt = pkt[15:-1]
        # print(util.xxd(pkt))
