#!/usr/bin/env python3
# coding: utf8

import util
import usb
import struct
import calendar, datetime
import binascii
import logging
from collections import namedtuple
from .sdmcmd import *

sdmheader = namedtuple('SdmHeader', 'length1 zero length2 stamp direction group command')

def content(pkt):
    return pkt[11:-1]

class SamsungParser:
    pkg_header_len = 10

    def __init__(self):
        self.gsm_last_cell_id = [0, 0]
        self.gsm_last_arfcn = [0, 0]

        self.umts_last_cell_id = [0, 0]
        self.umts_last_uarfcn_dl = [0, 0]
        self.umts_last_uarfcn_ul = [0, 0]

        self.lte_last_cell_id = [0, 0]
        self.lte_last_earfcn_dl = [0, 0]
        self.lte_last_earfcn_ul = [0, 0]
        self.lte_last_earfcn_tdd = [0, 0]
        self.lte_last_sfn = [0, 0]
        self.lte_last_tx_ant = [0, 0]
        self.lte_last_bw_dl = [0, 0]
        self.lte_last_bw_ul = [0, 0]
        self.lte_last_band_ind = [0, 0]

        # cmc221s: CMC221S: S3 (SHV-E210SK)
        # e300: Shannon 300: TODO
        # e303: Exynos Modem 303: Note 4 (SM-G910SKL)
        # e333: Exynos Modem 333: S6 (SM-G920F), S6 edge+ (SM-G925F), Note 4 S-LTE (SM-G916SKL)
        # e335: Exynos Modem 335: TODO
        self.model = 'e333'

        self.io_device = None
        self.writer = None

        self.name = 'samsung'
        self.shortname = 'sec'

        self.logger = logging.getLogger('scat.samsungparser')

    def set_io_device(self, io_device):
        self.io_device = io_device

    def set_writer(self, writer):
        self.writer = writer

    def set_parameter(self, params):
        for p in params:
            if p == 'model':
                self.model = params[p]
                if self.model == 'e5123':
                    SamsungParser.pkg_header_len = 11
            elif p == 'log_level':
                self.logger.setLevel(params[p])

    def init_diag_e333(self):
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x00, b'\x00\x00\x00\x00AAAA'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xdc\x05\xdc\x05'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x72, b'\x00\x00\x00\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x06, b'\x00\x00\x00\x00\x05'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x10, b'\x00\x00\x00\x00\x04\x00\x01\x01\x01\x02\x01\x03\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x20, b'\x00\x00\x00\x00\x4a\x00\x01\x01\x01\x02\x01\x04\x01\x05\x01\x06\x01\x07\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x00\x17\x00\x18\x01\x19\x01\x1a\x00\x1b\x00\x1c\x00\x1d\x00\x1e\x00\x1f\x00\x30\x01\x31\x01\x32\x01\x33\x01\x34\x01\x35\x01\x36\x01\x37\x01\x38\x01\x39\x01\x3a\x01\x3b\x00\x3c\x00\x3d\x00\x3e\x00\x3f\x00\x40\x01\x41\x00\x42\x01\x43\x01\x44\x01\x45\x01\x46\x01\x50\x01\x51\x01\x52\x01\x53\x01\x54\x01\x55\x01\x58\x01\x59\x01\x5a\x01\x5b\x01\x5c\x01\x5d\x01\x5e\x01\x5f\x01\x60\x01\x61\x01\x62\x01\x63\x01\x70\x01\x71\x01\x72\x01\x73\x01\x74\x01\x75\x01\x80\x01\x81\x01\x82\x01\x83\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x30, b'\x00\x00\x00\x00\x0f\x00\x01\x01\x01\x03\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x0a\x01\x0b\x01\x0c\x01\x0d\x01\x10\x01\x11\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x40, b'\x00\x00\x00\x00\x24\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x05\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x16\x01\x17\x01\x18\x01\x19\x01\x1a\x01\x1b\x01\x1c\x01\x1d\x01\x20\x01\x21\x01\x22\x01\x28\x01\x29\x01\x2a\x01\x30\x00\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x3a\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xdc\x05\xdc\x05'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x12, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x22, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x32, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x42, b'\x00\x00\x00\x00\xff'))

    def init_diag_e303(self):
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x00, b'\x00\x00\x00\x00AAAA'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xc8\x00\xc8\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x72, b'\x00\x00\x00\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x06, b'\x00\x00\x00\x00\x05'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x10, b'\x00\x00\x00\x00\x05\x00\x01\x01\x01\x02\x01\x03\x01\x04\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x20, b'\x00\x00\x00\x00\x52\x00\x01\x01\x01\x02\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x00\x17\x00\x18\x01\x19\x01\x1a\x00\x1b\x00\x1c\x00\x1d\x00\x1e\x00\x1f\x00\x30\x01\x31\x01\x32\x01\x33\x01\x34\x01\x35\x01\x36\x01\x37\x01\x38\x01\x39\x01\x3a\x01\x3b\x00\x3c\x00\x3d\x00\x3e\x00\x3f\x00\x40\x01\x42\x01\x43\x01\x44\x01\x45\x01\x46\x01\x47\x01\x48\x01\x49\x01\x4a\x01\x4b\x01\x4c\x01\x50\x01\x51\x01\x52\x01\x53\x01\x55\x01\x56\x01\x57\x01\x58\x01\x59\x01\x5a\x01\x5b\x01\x5c\x01\x5d\x01\x5e\x01\x5f\x01\x60\x01\x61\x01\x62\x01\x63\x01\x64\x01\x65\x01\x66\x01\x67\x01\x70\x01\x71\x01\x72\x01\x73\x01\x74\x01\x75\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x30, b'\x00\x00\x00\x00\x0f\x00\x01\x01\x01\x03\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x0a\x01\x0b\x01\x0c\x01\x0d\x01\x10\x01\x11\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x40, b'\x00\x00\x00\x00\x30\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x05\x01\x0d\x01\x0e\x01\x0f\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x01\x17\x01\x18\x01\x19\x01\x1a\x01\x1b\x01\x1c\x01\x1d\x01\x20\x01\x21\x01\x22\x01\x23\x01\x28\x01\x29\x01\x2a\x01\x30\x00\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x3a\x00\x3b\x01\x3c\x01\x50\x01\x51\x01\x52\x01\x60\x01\x61\x01'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xc8\x00\xc8\x00'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x12, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x22, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x32, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x42, b'\x00\x00\x00\x00\xff'))

    def init_diag_cmc221s(self):
        return self.init_diag_e303()

    def init_diag(self):
        self.logger.log(logging.INFO, 'Initialize diag')
        if self.model == 'e333' or self.model == 'e5123':
            self.init_diag_e333()
        elif self.model == 'e303':
            self.init_diag_e303()
        elif self.model == 'cmc221s':
            self.init_diag_cmc221s()
        else:
            assert False, "Invalid model."

    def prepare_diag(self):
        pass

    def parse_diag(self, pkt, hdlc_encoded = True, parse_ts = False, radio_id = 0):
        sock_content = b''
        if self.model == 'e5123':
            self.parse_diag_log_e5123(pkt, radio_id)
        elif self.model == 'e333':
            self.parse_diag_log_e333(pkt, radio_id)
        elif self.model == 'e303':
            self.parse_diag_log_e303(pkt, radio_id)

    def run_diag(self):
        self.logger.log(logging.INFO, 'Starting diag')

        oldbuf = b''
        cur_pos = 0
        try:
            while True:
                buf = self.io_device.read(0x9000)
                #util.xxd(buf, True)
                if len(buf) == 0:
                    continue
                cur_pos = 0
                while cur_pos < len(buf):
                    #print('---- subpacket ----')
                    #print(buf)
                    #assert buf[cur_pos] == 0x7f
                    if buf[cur_pos] != 0x7f:
                        self.logger.log(logging.WARNING, 'Unexpected end of the packet, dropping it')
                        self.logger.log(logging.DEBUG, util.xxd(buf))
                        break
                    len_1 = buf[cur_pos + 1] | (buf[cur_pos + 2] << 8)
                    len_2 = buf[cur_pos + 3] | (buf[cur_pos + 4] << 8)
                    #util.xxd(buf[cur_pos:cur_pos+len_1 + 2])
                    #util.xxd(buf[cur_pos: cur_pos + len_1 + 2], True)
                    self.parse_diag(buf[cur_pos:cur_pos + len_1 + 2])
                    cur_pos += (len_1 + 2)
                    #print('%s/%s' % (cur_pos, len(buf)))
                #print('---- end ----')

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        self.logger.log(logging.INFO, 'Stopping diag')
        # DIAG Disable
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x02, b'\x00\x00\x00\x00'))

    def run_dump(self):
        self.logger.log(logging.INFO, 'Starting diag from dump')

        oldbuf = b''
        cur_pos = 0
        try:
            while True:
                buf = self.io_device.read(0x90000)
                #util.xxd(buf, True)
                if len(buf) == 0:
                    continue
                cur_pos = 0
                first = False
                while cur_pos < len(buf):
                    #print('---- subpacket ----')
                    #print(buf)
                    #assert buf[cur_pos] == 0x7f
                    if buf[cur_pos] != 0x7f:
                        # if first:
                        #     self.logger.log(logging.WARNING, 'Unexpected end of the packet, dropping it')
                        #     self.logger.log(logging.DEBUG, util.xxd(buf))
                        #     break
                        cur_pos += 1
                        continue
                    first = True
                    if cur_pos+SamsungParser.pkg_header_len < len(buf):
                        len_1 = buf[cur_pos + 1] | (buf[cur_pos + 2] << 8)
                        len_2 = buf[cur_pos + 3] | (buf[cur_pos + 4] << 8)
                        #util.xxd(buf[cur_pos:cur_pos+len_1 + 2])
                        #util.xxd(buf[cur_pos: cur_pos + len_1 + 2], True)
                        self.parse_diag(buf[cur_pos:cur_pos + len_1 + 2])
                    # cur_pos += (len_1 + 2)
                    cur_pos += 1
                    #print('%s/%s' % (cur_pos, len(buf)))
                #print('---- end ----')

        except KeyboardInterrupt:
            return

    def read_dump(self):
        if self.io_device.file_available:
            self.logger.log(logging.INFO, 'Unknown baseband dump type, assuming default')
            self.run_dump()

    # Samsung TS format:
    # No Epoch
    # Incremented by 1 000 000 per 1 second
    # Rolled over when TS becomes bigger than 2^32 - 1

    def process_ip_data(self, pkt):
        pkt = content(pkt)
        ip_hdr = struct.unpack('<BLHHHH', pkt[0:13])
        # 00 ts(uint32) stamp(uint16) dir(uint16) ?(uint16) len(uint16)
        # 0: Data type (0x00: IP, 0x10: Unknown)
        # 1: TS
        # 2: Packet #
        # 3: Direction
        # 4: Unknown
        # 5: Length
        ip_payload = pkt[13:]

        if ip_hdr[0] == 0x00:
            if ip_hdr[5] != len(ip_payload):
                self.logger.log(logging.WARNING, 'IP length mismatch, expected %04x, got %04x' % (ip_hdr[5], len(ip_payload)))
            self.writer.write_up(ip_payload, 0)

    def process_control_message(self, pkt):
        pass

    def process_common_data(self, pkt):
        pkt = content(pkt)
        arfcn = 0

        if pkt[0] == 0x03: # Common Signalling Info
            #util.xxd(pkt)
            # pkt[1] - pkt[4] == ts
            chan_type = pkt[5]
            chan_subtype = pkt[6]
            direction = pkt[7] # 2 - DL, 1 - UL
            msg_len = pkt[8] | (pkt[9] << 8)
            msg_content = pkt[10:]

            if chan_type == 0x30: # UMTS RRC
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
                if direction == 2:
                    subtype = chan_map_dl[chan_subtype]
                    arfcn = self.umts_last_uarfcn_dl[0]
                elif direction == 1:
                    subtype = chan_map_ul[chan_subtype]
                    arfcn = self.umts_last_uarfcn_ul[0]
                else:
                    self.logger.log(logging.WARNING, 'Unknown direction %02x' % direction)
                    return

                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.UMTS_RRC,
                    arfcn = arfcn,
                    sub_type = subtype)
                self.writer.write_cp(gsmtap_hdr + msg_content, 0)
            elif chan_type == 0x01: # UMTS NAS
                if direction == 2:
                    arfcn = self.umts_last_uarfcn_dl[0]
                elif direction == 1:
                    arfcn = self.umts_last_uarfcn_ul[0]

                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.ABIS,
                    arfcn = arfcn)
                self.writer.write_cp(gsmtap_hdr + msg_content, 0)
            elif chan_type == 0x20: # GSM RR
                # TODO: CCCH and SACCH are not distinguished by headers!
                # Some values are RR message, some are RR_short_PD
                if direction == 2: # RR DL w/ pseudo length
                    lapdm_address = b'\x01'
                    # Control field
                    lapdm_control = b'\x03'
                    # length field
                    if msg_len > 63:
                        self.logger.log(logging.WARNING, 'message length longer than 63 (%s)' % msg_len)
                        return
                    lapdm_len = bytes([(msg_len << 2) | 0x01])

                    #msg_content = lapdm_address + lapdm_control + lapdm_len + msg_content

                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.UM,
                        sub_type = util.gsmtap_channel.CCCH) # Subtype (XXX: All CCCH)
                    self.writer.write_cp(gsmtap_hdr + msg_content, 0)
                elif direction == 1: # Only RR
                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.ABIS)
                    self.writer.write_cp(gsmtap_hdr + msg_content)
            elif chan_type == 0x21: # GSM RLC/MAC
                arfcn = 1
                if direction == 1:
                    arfcn = arfcn | (1 << 14)
                gsmtap_hdr = util.create_gsmtap_header(
                    version = 2,
                    payload_type = util.gsmtap_type.UM,
                    arfcn = arfcn,
                    sub_type = util.gsmtap_channel.PACCH) # Subtype (PACCH dissects as MAC)
                #return gsmtap_hdr + msg_content
                return
            else:
                self.logger.log(logging.WARNING, 'Unknown channel type %02x for subcommand 0x03' % chan_type)
                return
        else:
            self.logger.log(logging.WARNING, 'Unknown subcommand %02x for command 0x21' % pkt[0])
            #util.xxd(pkt, True)
            return

    def process_common_basic(self, pkt):
        pkt = content(pkt)
        #if not (pkt[0] == 0x00 or pkt[0] == 0x02):
        #if pkt[0] == 0x00:
        #    util.xxd(pkt)
        return

    def process_lte_basic_e333(self, pkt):
        pkt = content(pkt)

        if pkt[0] == 0x02:
            # 5-7: Current PLMN (BCD or decimal)
            # 8-11: zero
            # 12: cell RAT (0-LTE, 1-3G, 2-2G?)
            # 13-4: EARFCN/UARFCN/ARFCN
            # 15-18: Physical CID
            # 003818 ac000000 70e5d4fe1c250000b004000003
            # 003818 64000000 0019e4250000dc0500000000
            # 003818 7b000000 001910270000dc0500000000
            # 003818 57000000 641910270000080700000000
            cell_info = struct.unpack('<BHI', pkt[12:19])

            if cell_info[0] == 0:
                self.lte_last_earfcn_dl[0] = cell_info[1]
                self.lte_last_earfcn_ul[0] = self.lte_last_earfcn_dl[0] | (1 << 14)
                self.lte_last_cell_id[0] = cell_info[2]
            elif cell_info[0] == 1:
                self.umts_last_uarfcn_dl[0] = cell_info[1]
                self.umts_last_cell_id[0] = cell_info[2]
            else:
                self.logger.log(logging.WARNING, 'Unhandled RAT %02x' % cell_info[0])
        else:
            pass
            #print('process_lte_basic')
            #util.xxd(pkt)

        return

        #if pkt[0] == 0x02:
        #    util.xxd(pkt)
        #return b''

    def process_lte_data(self, pkt):
        pkt = content(pkt)
        arfcn = 0

        if len(pkt) == 0:
            return

        '''
        0x50: 'LteRrcServ?', len:24
            "cid", '<L',  4 bytes, pos:4
            "plmn" '<HB', 3 bytes, pos:16
            "tac", '>H',  2 bytes, pos:20
        if pkt[0] == 0x50:
        '''

        '''
        0x51: 'LteRrcState' len:5
            "rrc_state", '<B', 1 byte, pos:4  # (00 - IDLE, 01 - CONNECTING, 02 - CONNECTED)
        if pkt[0] == 0x51:
        '''

        '''
        0x57: '?' len:13
            "earfcn", '<L', 4 bytes, pos:7
            "pci",    '<H', 2 bytes, pos:11
        if pkt[0] == 0x57:
        '''

        '''
        0x58: 'Sim(?)', len:13
            "mcc",  '<2s', 2 bytes, pos:4,   # bcd encoded
            "mnc",  '<1s', 1 bytes, pos:6,   # bcd encoded
            "IMSI", '<9s', 9 bytes, pos:15,  # bcd encoded
        if pkt[0] == 0x58:
        '''
        if pkt[0] == 0x52:
            # 0x52: LTE RRC OTA Packet

            # pkt[1] - pkt[4]: TS
            channel = pkt[5]
            direction = pkt[6] # 0: DL, 1: UL
            rrc_len = pkt[7] | (pkt[8] << 8)
            rrc_msg = pkt[9:]

            rrc_subtype_dl = {
                0: util.gsmtap_lte_rrc_types.DL_CCCH,
                1: util.gsmtap_lte_rrc_types.PCCH,
                2: util.gsmtap_lte_rrc_types.BCCH_BCH,
                3: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                4: util.gsmtap_lte_rrc_types.DL_DCCH
                }
            rrc_subtype_ul = {
                0: util.gsmtap_lte_rrc_types.UL_CCCH,
                4: util.gsmtap_lte_rrc_types.UL_DCCH
                }

            subtype = 0
            try:
                if direction == 0:
                    subtype = rrc_subtype_dl[channel]
                else:
                    subtype = rrc_subtype_ul[channel]
            except KeyError:
                self.logger.log(logging.WARNING, "Unknown LTE RRC channel type %d" % channel)
                self.logger.log(logging.DEBUG, util.xxd(pkt))

            if direction == 0:
                arfcn = self.lte_last_earfcn_dl[0]
            else:
                arfcn = self.lte_last_earfcn_ul[0]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = arfcn,
                sub_type = subtype)
            self.writer.write_cp(gsmtap_hdr + rrc_msg, 0)
        elif pkt[0] == 0x55:
            # TODO: RACH Preamble/Response
            # pkt[1] - pkt[4]: TS
            direction = pkt[5] # 0 - UL, 1 - DL
            rach_vals = struct.unpack('<HIIH', pkt[6:18])

            if direction == 0:
                # UL: RACH cause, Preamble ID, ?, ?
                pass
            elif direction == 1:
                # DL: ?, Preamble ID, TA, T-C-RNTI
                # MAC-LTE: RAR Header, TA, UL Grant, T-C-RNTI
                pass
            else:
                assert False, "Invalid RACH direction"
            return
        elif pkt[0] == 0x5a or pkt[0] == 0x5f:
            # 0x5A: LTE NAS EMM Message
            # 0x5F: LTE NAS ESM Message

            # pkt[1] - pkt[4]: TS?
            direction = pkt[5] # 0 - DL, 1 - UL
            nas_len = pkt[6] | (pkt[7] << 8)
            # pkt[8] - duplicate? - spare!
            nas_msg = pkt[9:]

            if direction == 0:
                arfcn = self.lte_last_earfcn_dl[0]
            else:
                arfcn = self.lte_last_earfcn_ul[0]

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_NAS,
                arfcn = arfcn)
            self.writer.write_cp(gsmtap_hdr + nas_msg, 0)
        else:
            #if len(pkt) < 0x60:
            #    util.xxd(pkt)
            return

    def process_edge_data(self, pkt):
        self.logger.log(logging.WARNING, 'TODO: command 0x23 edge data')
        pkt = content(pkt)

        '''
        0x07: 'GsmServ',
            "bsic",  '>B',  1 bytes, pos:20, # 7bit
            "arfcn", '>H',  2 bytes, pos:26, # 10bit
            "mcc",   '<2s', 2 bytes, pos:39, # bcd encoded
            "mnc",   '<1s', 1 bytes, pos:41, # bcd encoded
            "lac",   '>H',  2 bytes, pos:42,
            "cid",   '>H',  2 bytes, pos:45,
        ], []),
        if pkt[0] == 0x07:
        '''
        if pkt[0] == 0x10:
            # DL?
            pass
        elif pkt[0] == 0x11:
            # UL?
            pass
        else:
            self.logger.log(logging.WARNING, "Unknown packet[0] %02x" % pkt[0])
        return

    def process_hspa_basic(self, pkt):
        pkt = content(pkt)

        if pkt[0] == 0x22:
            self.umts_last_uarfcn_dl[0] = pkt[5] | (pkt[6] << 8)
            self.umts_last_uarfcn_ul[0] = pkt[7] | (pkt[8] << 8)
        else:
            # 0x20 - RRC status
            # uint8: channel, 0x00 - DISCONNECTED, 0x01: CELL_DCH, 0x02: CELL_FACH, 0x03: CELL_PCH, 0x04: URA_PCH
            #if pkt[0] == 0x28:
            #if len(pkt) < 0x40:
                #util.xxd(pkt)
            pass
        return

    def process_hspa_data(self, pkt):
        return

    def process_trace_data(self, pkt):
        return

    def parse_diag_log_e5123(self, pkt, radio_id = 0):
        process = {
            # 0x00 - only used during diag setup
            0x01: lambda x: self.process_common_basic(x),
            0x02: lambda x: self.process_lte_basic_e333(x),
            # 0x03
            0x04: lambda x: self.process_hspa_basic(x),
            0x07: lambda x: self.process_ip_data(x),
            #0x20: lambda x: process_control_message(x),
            0x21: lambda x: self.process_common_data(x),
            0x22: lambda x: self.process_lte_data(x),
            0x23: lambda x: self.process_edge_data(x),
            #0x24: lambda x: process_hspa_data(x),
            #0x25: lambda x: process_trace_data(x),
            # 0x44
        }

        if not (pkt[0] == 0x7f):  # and pkt[-1] == 0x7e):
            self.logger.log(logging.WARNING, 'Invalid packet structure')
            #util.xxd(pkt, True)
            self.logger.log(logging.DEBUG, util.xxd(pkt))
            return

        len_1 = 0x0
        if len(pkt) > 2:
            len_1 = pkt[1] | (pkt[2] << 8)
        if len(pkt) > 5:
            len_2 = pkt[4] | (pkt[5] << 8)
        if len(pkt) > 7:
            stamp = pkt[6] | (pkt[7] << 8)

        main_cmd = 0x0
        sub_cmd = 0x0
        if len(pkt) > 10:
            main_cmd = pkt[9]
            sub_cmd = pkt[10]
        #print('Length %s/%s, Main command %02x, Stamp %04x' % (len_1, len_2, main_cmd, stamp))
        #util.xxd(pkt[0:10])

        if main_cmd == 0xa0 or main_cmd == 0xa1:  # IpcDmCmd
            if sub_cmd in process.keys():
                return process[sub_cmd](pkt)
            else:
                #print('TODO: subcommand %02x' % sub_cmd)
                pass
        elif main_cmd == 0xa1: # IpcCtCmd
            if sub_cmd in process.keys():
                return process[sub_cmd](pkt)
            else:
                #print('TODO: subcommand %02x' % sub_cmd)
                pass
            self.logger.log(logging.WARNING, 'TODO: IpcCtCmd')
            self.logger.log(logging.DEBUG, util.xxd(pkt))
        elif main_cmd == 0xa2: # IpcHimCmd
            self.logger.log(logging.WARNING, 'TODO: IpcHimCmd')
        else:
            self.logger.log(logging.WARNING, 'Invalid main command ID %02x' % main_cmd)

        #print("%s %s %s %s %s %s %s %s" % (binascii.hexlify(pkt[0:1]).decode('ascii'),
        #                                   binascii.hexlify(pkt[1:4]).decode('ascii'),
        #                                   binascii.hexlify(pkt[4:6]).decode('ascii'),
        #                                   binascii.hexlify(pkt[6:8]).decode('ascii'),
        #                                   binascii.hexlify(pkt[8:9]).decode('ascii'),
        #                                   binascii.hexlify(pkt[9:10]).decode('ascii'),
        #                                   binascii.hexlify(pkt[10:-1]).decode('ascii'),
        #                                   binascii.hexlify(pkt[-1:]).decode('ascii')))

        return

    def parse_diag_log_e333(self, pkt, radio_id = 0):
        process = {
            # 0x00 - only used during diag setup
            0x01: lambda x: self.process_common_basic(x),
            0x02: lambda x: self.process_lte_basic_e333(x),
            # 0x03
            0x04: lambda x: self.process_hspa_basic(x),
            0x07: lambda x: self.process_ip_data(x),
            #0x20: lambda x: process_control_message(x),
            0x21: lambda x: self.process_common_data(x),
            0x22: lambda x: self.process_lte_data(x),
            #0x23: lambda x: process_edge_data(x),
            #0x24: lambda x: process_hspa_data(x),
            #0x25: lambda x: process_trace_data(x),
            # 0x44
        }

        if not (pkt[0] == 0x7f):  # and pkt[-1] == 0x7e):
            self.logger.log(logging.WARNING, 'Invalid packet structure')
            #util.xxd(pkt, True)
            self.logger.log(logging.DEBUG, util.xxd(pkt))
            return

        len_1 = 0x0
        if len(pkt) > 2:
            len_1 = pkt[1] | (pkt[2] << 8)
        if len(pkt) > 5:
            len_2 = pkt[4] | (pkt[5] << 8)
        if len(pkt) > 7:
            stamp = pkt[6] | (pkt[7] << 8)

        main_cmd = 0x0
        sub_cmd = 0x0
        if len(pkt) > 10:
            main_cmd = pkt[9]
            sub_cmd = pkt[10]
        #print('Length %s/%s, Main command %02x, Stamp %04x' % (len_1, len_2, main_cmd, stamp))
        #util.xxd(pkt[0:10])

        if main_cmd == sdm_command_type.IPC_DM_CMD or main_cmd == sdm_command_type.IPC_CT_CMD:
            if sub_cmd in process.keys():
                return process[sub_cmd](pkt)
            else:
                #print('TODO: subcommand %02x' % sub_cmd)
                pass
        elif main_cmd == sdm_command_type.IPC_CT_CMD:
            if sub_cmd in process.keys():
                return process[sub_cmd](pkt)
            else:
                #print('TODO: subcommand %02x' % sub_cmd)
                pass
            self.logger.log(logging.WARNING, 'TODO: IpcCtCmd')
            self.logger.log(logging.DEBUG, util.xxd(pkt))
        elif main_cmd == sdm_command_type.IPC_HIM_CMD:
            self.logger.log(logging.WARNING, 'TODO: IpcHimCmd')
        else:
            self.logger.log(logging.WARNING, 'Invalid main command ID %02x' % main_cmd)

        #print("%s %s %s %s %s %s %s %s" % (binascii.hexlify(pkt[0:1]).decode('ascii'),
        #                                   binascii.hexlify(pkt[1:4]).decode('ascii'),
        #                                   binascii.hexlify(pkt[4:6]).decode('ascii'),
        #                                   binascii.hexlify(pkt[6:8]).decode('ascii'),
        #                                   binascii.hexlify(pkt[8:9]).decode('ascii'),
        #                                   binascii.hexlify(pkt[9:10]).decode('ascii'),
        #                                   binascii.hexlify(pkt[10:-1]).decode('ascii'),
        #                                   binascii.hexlify(pkt[-1:]).decode('ascii')))

        return

    def parse_diag_log_e303(self, pkt, radio_id = 0):
        #print('parse_diag_log_e303')
        #util.xxd(pkt)
        process = {
            # 0x00 - only used during diag setup
            0x01: lambda x: self.process_common_data(x),
            0x02: lambda x: self.process_lte_data(x),
            #0x03: lambda x: self.process_common_data(x),
            #0x04: lambda x: self.process_hspa_basic(x),
            0x07: lambda x: self.process_ip_data(x),
            #0x20: lambda x: process_control_message(x),
            #0x21: lambda x: self.process_common_data(x),
            #0x22: lambda x: self.process_lte_data(x),
            #0x23: lambda x: process_edge_data(x),
            #0x24: lambda x: process_hspa_data(x),
            #0x25: lambda x: process_trace_data(x),
            # 0x44
        }

        if not (pkt[0] == 0x7f and pkt[-1] == 0x7e):
            self.logger.log(logging.WARNING, 'Invalid packet structure')
            self.logger.log(logging.DEBUG, util.xxd(pkt))
            return

        len_1 = pkt[1] | (pkt[2] << 8)
        len_2 = pkt[4] | (pkt[5] << 8)
        stamp = pkt[6] | (pkt[7] << 8)

        main_cmd = pkt[8]
        sub_cmd = pkt[9]

        if main_cmd == sdm_command_type.IPC_DM_CMD or main_cmd == sdm_command_type.IPC_CT_CMD:
            if sub_cmd in process.keys():
                return process[sub_cmd](pkt)
            else:
                #print('TODO: subcommand %02x' % sub_cmd)
                pass
        elif main_cmd == sdm_command_type.IPC_CT_CMD:
            self.logger.log(logging.WARNING, 'TODO: IpcCtCmd')
        elif main_cmd == sdm_command_type.IPC_HIM_CMD:
            self.logger.log(logging.WARNING, 'TODO: IpcHimCmd')
        else:
            self.logger.log(logging.WARNING, 'Invalid main command ID %02x' % main_cmd)

        return

__entry__ = SamsungParser

def name():
    return 'samsung'

def shortname():
    return 'sec'

