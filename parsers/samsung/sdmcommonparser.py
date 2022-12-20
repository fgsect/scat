#!/usr/bin/env python3

from .sdmcmd import *
from collections import namedtuple
import util

import struct
import logging

class SdmCommonParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            (sdm_command_group.CMD_COMMON_DATA << 8) | sdm_common_data.COMMON_DATA_SIGNALING_INFO: lambda x: self.sdm_common_signaling(x)
        }

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
