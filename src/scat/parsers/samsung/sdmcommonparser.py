#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmCommonParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver
        self.multi_message_chunk = {}
        self.ip_id = 0

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_COMMON_DATA << 8)
        c = sdmcmd.sdm_common_data
        self.process = {
            g | c.COMMON_BASIC_INFO: lambda x: self.sdm_common_basic_info(x),
            # g | 0x01: lambda x: self.sdm_common_dummy(x, 0x01),
            # g | c.COMMON_DATA_INFO: lambda x: self.sdm_common_dummy(x, 0x02),
            g | c.COMMON_SIGNALING_INFO: lambda x: self.sdm_common_signaling(x),
            # g | c.COMMON_SMS_INFO: lambda x: self.sdm_common_dummy(x, 0x04),
            # g | 0x05: lambda x: self.sdm_common_dummy(x, 0x05),
            g | c.COMMON_MULTI_SIGNALING_INFO: lambda x: self.sdm_common_multi_signaling(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def sdm_common_dummy(self, pkt, cmdid):
        pkt = pkt[15:-1]
        return {'stdout': 'COMMON {:#x}: {}'.format(cmdid, binascii.hexlify(pkt).decode('utf-8'))}
        # 0x02
        # 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff bf 4e 05 00
        # 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff aa 9b 13 00

        # 0x04
        # acacac f2f2f2 9f9f9f e5e5e5
        # acacac f2f2f2 9f9f9f e5e5e5
        # 00 00 18 000018 000018 000018
        # 03 00 00 000018 000018 000018
        # 03 01 00 000018 000018 000018

        # 0x05
        # 01 08 07 00 00
        # 03 08 07 00 00
        # 01 08 07 00 00
        # 02 08 07 00 00

        # 03 00 00 00 00
        # 01 00 00 00 00
        # 02 00 00 00 00
        # 01 00 00 00 00

    def sdm_common_basic_info(self, pkt):
        pkt = pkt[15:-1]
        if len(pkt) < 11:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than minimum expected (11)'.format(len(pkt)))
            return

        stdout = ''
        rat_name_map = {
            # 2G
            0x10: 'GSM',
            0x13: 'GPRS',
            # 3G
            0x12: 'WCDMA',
            0x14: 'HSDPA',
            # 4G
            0x17: 'LTE',
            # 0x19: 'LTE+',
            # 5G
            0x20: 'NR NSA',
            0x21: 'NR SA',
        }
        header = namedtuple('SdmCommonBasicInfo', 'rat status mimo dlfreq ulfreq')

        if self.icd_ver >= (9, 0):
            common_basic = header._make(struct.unpack('<BBBLL', pkt[0:11]))
            extra = pkt[11:]
        elif self.icd_ver >= (8, 0):
            common_basic = header._make(struct.unpack('<BBBQQ', pkt[0:19]))
            extra = pkt[19:]
        else:
            common_basic = header._make(struct.unpack('<BBBLL', pkt[0:11]))
            extra = pkt[11:]

        extra_str = ''
        if len(extra) >= 4:
            extra_str += ', Extra: {:#010x}'.format(struct.unpack('<L', extra[0:4])[0])
        if len(extra) >= 5:
            num_cells = extra[4]
            if num_cells <= len(extra[5:]):
                extra_str += ', Num cells: {}'.format(num_cells)
                if num_cells > 0:
                    extra_str += ' ({})'.format(', '.join([str(x) for x in extra[5:5+num_cells]]))

        rat_str = util.map_lookup_value(rat_name_map, common_basic.rat)

        known_bad_freq = (0, 0xffffffff, 0xffffffffffffffff, 1157098112, 1112098112)

        if common_basic.dlfreq in known_bad_freq:
            dlfreq_str = '-'
        else:
            dlfreq_str = 'DL: {:.2f} MHz'.format(common_basic.dlfreq / 1000000)

        if common_basic.ulfreq in known_bad_freq:
            ulfreq_str = '-'
        else:
            if self.icd_ver >= (6, 0) and common_basic.rat in (0x12, 0x14):
                ulfreq_str = 'UL: UARFCN {}'.format(int(common_basic.ulfreq / 100000))
            else:
                ulfreq_str = 'UL: {:.2f} MHz'.format(common_basic.ulfreq / 1000000)


        stdout = 'Common Basic Info: RAT: {}, Status: {}, MIMO: {}, Frequency: {}/{}{}'.format(
            rat_str, common_basic.status, common_basic.mimo, dlfreq_str, ulfreq_str, extra_str)

        return {'stdout': stdout}

    def _parse_sdm_common_signaling(self, sdm_pkt_hdr, type, subtype, direction, length, msg):
        if type == 0x30: # UMTS RRC
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

            gsmtap_subtype = 0
            if direction == 2:
                gsmtap_subtype = chan_map_dl[subtype]
                if self.parent:
                    arfcn = self.parent.umts_last_uarfcn_dl[sdm_pkt_hdr.radio_id]
                else:
                    arfcn = 0
            elif direction == 1:
                gsmtap_subtype = chan_map_ul[subtype]
                if self.parent:
                    arfcn = self.parent.umts_last_uarfcn_ul[sdm_pkt_hdr.radio_id]
                else:
                    arfcn = 0
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown direction 0x{:02x}'.format(direction))
                return None

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UMTS_RRC,
                arfcn = arfcn,
                sub_type = gsmtap_subtype)

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg]}
        elif type == 0x01: # UMTS NAS
            # direction: 1: UL, 2: DL
            arfcn = 0
            if direction == 1:
                arfcn = arfcn | (1 << 14)

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.ABIS,
                arfcn = arfcn)

            return {'layer': 'nas', 'cp': [gsmtap_hdr + msg]}
        elif type == 0x20: # GSM RR
            # direction: 1: UL, 2: DL
            if self.parent:
                arfcn = self.parent.gsm_last_arfcn[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0
            if direction == 1:
                arfcn = arfcn | (1 << 14)

            if msg[0] == 0b0110:
                # GSM RR, regardless of direction
                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    arfcn = arfcn,
                    payload_type = util.gsmtap_type.ABIS)
            else:
                # 3GPP TS 24.007, Section 11.3 Non standard L3 messages
                if (msg[0] & 0b11 == 0b01) and (msg[1] == 0b0110):
                    # RR with pseudo length
                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.UM,
                        arfcn = arfcn,
                        sub_type = util.gsmtap_channel.CCCH)
                else:
                    # 3GPP TS 44.018, Table 10.4.2:
                    if (msg[0] & 0b10000000 == 0x0) and (((msg[0] & 0b01111100) >> 2) in (0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)):
                        # RR with short PD
                        # gsmtap_hdr = util.create_gsmtap_header(
                        #     version = 2,
                        #     payload_type = util.gsmtap_type.UM,
                        #     arfcn = arfcn,
                        #     sub_type = util.gsmtap_channel.SDCCH | 0x80)
                        # msg_content = b'\x00\x00\x01\x03\xf1' + msg_content
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'GSM RR with short PD, decode using "gsm_a_sacch": {}'.format(binascii.hexlify(msg).decode('utf-8')))
                        return None
                    else:
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, 'Invalid GSM RR message')
                        return None

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + msg]}
        elif type == 0x21: # GSM RLC/MAC
            # direction: 1: UL, 2: DL
            if self.parent:
                arfcn = self.parent.gsm_last_arfcn[sdm_pkt_hdr.radio_id]
            else:
                arfcn = 0
            if direction == 1:
                arfcn = arfcn | (1 << 14)

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.UM,
                arfcn = arfcn,
                sub_type = util.gsmtap_channel.PACCH) # Subtype (PACCH dissects as MAC)

            return {'layer': 'mac', 'cp': [gsmtap_hdr + msg]}
        elif type == 0x40: # SIP
            # subtype: 0x40: request, 0x41: response
            # direction: 1: UL, 2: DL
            sip_type = struct.unpack('>H', msg[0:2])[0]
            sip_body = msg[2:]

            # Wrap SIP inside user-plane UDP packet
            if direction == 1:
                udp_hdr = struct.pack('>HHHH', 50600, 5060, len(sip_body)+8, 0)
                ip_hdr = struct.pack('>BBHHBBBBHLL', 0x45, 0x00, len(sip_body)+28,
                    self.ip_id, 0x40, 0x00, 0x40, 0x11, 0x0,
                    0x0a000002, 0x0a000001
                )
            else:
                udp_hdr = struct.pack('>HHHH', 5060, 50600, len(sip_body)+8, 0)
                ip_hdr = struct.pack('>BBHHBBBBHLL', 0x45, 0x00, len(sip_body)+28,
                    self.ip_id, 0x40, 0x00, 0x40, 0x11, 0x0,
                    0x0a000001, 0x0a000002
                )
            self.ip_id += 1

            return {'layer': 'ip', 'up': [ip_hdr+udp_hdr+sip_body]}
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unknown channel type 0x{:02x}'.format(type))
            return None

    def sdm_common_signaling(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        header = namedtuple('SdmCommonSignalingHeader', 'type subtype direction length')
        pkt_header = header._make(struct.unpack('<BBBH', pkt[0:5]))
        msg_content = pkt[5:]

        return self._parse_sdm_common_signaling(sdm_pkt_hdr, pkt_header.type, pkt_header.subtype, pkt_header.direction, pkt_header.length, msg_content)

    def sdm_common_multi_signaling(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        # num_chunk is base 1, should be <= total_chunks
        header = namedtuple('SdmCommonMultiSignalingHeader', 'total_chunks num_chunk msgid type subtype direction length')
        pkt_header = header._make(struct.unpack('<BBBBBBH', pkt[0:8]))
        msg_content = pkt[8:]

        if pkt_header.msgid not in self.multi_message_chunk:
            # New msgid
            self.multi_message_chunk[pkt_header.msgid] = {'total_chunks': pkt_header.total_chunks}

        if pkt_header.num_chunk in self.multi_message_chunk[pkt_header.msgid]:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Message chunk {} already exists for message id {}".format(
                    pkt_header.num_chunk, pkt_header.msgid))
        self.multi_message_chunk[pkt_header.msgid][pkt_header.num_chunk] = msg_content

        is_not_full = False
        for i in range(1, pkt_header.total_chunks+1):
            if not i in self.multi_message_chunk[pkt_header.msgid]:
                is_not_full = True

        if not is_not_full:
            newpkt_body = b''
            for i in range(1, pkt_header.total_chunks+1):
                newpkt_body += self.multi_message_chunk[pkt_header.msgid][i]

            del self.multi_message_chunk[pkt_header.msgid]
            return self._parse_sdm_common_signaling(sdm_pkt_hdr, pkt_header.type, pkt_header.subtype,
                pkt_header.direction, len(newpkt_body), newpkt_body)
