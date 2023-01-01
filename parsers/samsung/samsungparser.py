#!/usr/bin/env python3
# coding: utf8

import util
import struct
import logging
from .sdmcmd import *
from .sdmcommonparser import SdmCommonParser
from .sdmlteparser import SdmLteParser
from .sdmedgeparser import SdmEdgeParser
from .sdmhspaparser import SdmHspaParser
from .sdmtraceparser import SdmTraceParser
from .sdmipparser import SdmIpParser


def content(pkt):
    return pkt[11:-1]

class SamsungParser:
    pkg_header_len = 10

    def __init__(self):
        self.gsm_last_cell_id = [0, 0]
        self.gsm_last_arfcn = [0, 0]

        self.umts_last_cell_id = [0, 0]
        self.umts_last_psc = [0, 0]
        self.umts_last_uarfcn_dl = [0, 0]
        self.umts_last_uarfcn_ul = [0, 0]

        self.lte_last_cell_id = [0, 0]
        self.lte_last_pci = [0, 0]
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

        self.sdm_parsers = [SdmCommonParser(self),
            SdmLteParser(self), SdmEdgeParser(self),
            SdmHspaParser(self), SdmTraceParser(self), SdmIpParser(self)]
        self.process = { }
        self.no_process = { }

        for p in self.sdm_parsers:
            self.process.update(p.process)
            try:
                self.no_process.update(p.no_process)
            except AttributeError:
                pass

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
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.CONTROL_START, b'\x00\x00\x00\x00AAAA'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xdc\x05\xdc\x05'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x72, b'\x00\x00\x00\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.CHANGE_UPDATE_PERIOD_REQUEST, b'\x00\x00\x00\x00\x05'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.COMMON_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x04\x00\x01\x01\x01\x02\x01\x03\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.LTE_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x4a\x00\x01\x01\x01\x02\x01\x04\x01\x05\x01\x06\x01\x07\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x00\x17\x00\x18\x01\x19\x01\x1a\x00\x1b\x00\x1c\x00\x1d\x00\x1e\x00\x1f\x00\x30\x01\x31\x01\x32\x01\x33\x01\x34\x01\x35\x01\x36\x01\x37\x01\x38\x01\x39\x01\x3a\x01\x3b\x00\x3c\x00\x3d\x00\x3e\x00\x3f\x00\x40\x01\x41\x00\x42\x01\x43\x01\x44\x01\x45\x01\x46\x01\x50\x01\x51\x01\x52\x01\x53\x01\x54\x01\x55\x01\x58\x01\x59\x01\x5a\x01\x5b\x01\x5c\x01\x5d\x01\x5e\x01\x5f\x01\x60\x01\x61\x01\x62\x01\x63\x01\x70\x01\x71\x01\x72\x01\x73\x01\x74\x01\x75\x01\x80\x01\x81\x01\x82\x01\x83\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.EDGE_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x0f\x00\x01\x01\x01\x03\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x0a\x01\x0b\x01\x0c\x01\x0d\x01\x10\x01\x11\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.HSPA_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x24\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x05\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x16\x01\x17\x01\x18\x01\x19\x01\x1a\x01\x1b\x01\x1c\x01\x1d\x01\x20\x01\x21\x01\x22\x01\x28\x01\x29\x01\x2a\x01\x30\x00\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x3a\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xdc\x05\xdc\x05'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.COMMON_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.LTE_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.EDGE_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.HSPA_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))

    def init_diag_e303(self):
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.CONTROL_START, b'\x00\x00\x00\x00AAAA'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xc8\x00\xc8\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x52, b'\x00\x00\x00\x00\x02'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x72, b'\x00\x00\x00\x00'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.CHANGE_UPDATE_PERIOD_REQUEST, b'\x00\x00\x00\x00\x05'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.COMMON_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x05\x00\x01\x01\x01\x02\x01\x03\x01\x04\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.LTE_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x52\x00\x01\x01\x01\x02\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x00\x17\x00\x18\x01\x19\x01\x1a\x00\x1b\x00\x1c\x00\x1d\x00\x1e\x00\x1f\x00\x30\x01\x31\x01\x32\x01\x33\x01\x34\x01\x35\x01\x36\x01\x37\x01\x38\x01\x39\x01\x3a\x01\x3b\x00\x3c\x00\x3d\x00\x3e\x00\x3f\x00\x40\x01\x42\x01\x43\x01\x44\x01\x45\x01\x46\x01\x47\x01\x48\x01\x49\x01\x4a\x01\x4b\x01\x4c\x01\x50\x01\x51\x01\x52\x01\x53\x01\x55\x01\x56\x01\x57\x01\x58\x01\x59\x01\x5a\x01\x5b\x01\x5c\x01\x5d\x01\x5e\x01\x5f\x01\x60\x01\x61\x01\x62\x01\x63\x01\x64\x01\x65\x01\x66\x01\x67\x01\x70\x01\x71\x01\x72\x01\x73\x01\x74\x01\x75\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.EDGE_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x0f\x00\x01\x01\x01\x03\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x0a\x01\x0b\x01\x0c\x01\x0d\x01\x10\x01\x11\x01'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.HSPA_ITEM_SELECT_REQUEST, b'\x00\x00\x00\x00\x30\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x05\x01\x0d\x01\x0e\x01\x0f\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x16\x01\x17\x01\x18\x01\x19\x01\x1a\x01\x1b\x01\x1c\x01\x1d\x01\x20\x01\x21\x01\x22\x01\x23\x01\x28\x01\x29\x01\x2a\x01\x30\x00\x31\x00\x32\x00\x33\x00\x34\x00\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x3a\x00\x3b\x01\x3c\x01\x50\x01\x51\x01\x52\x01\x60\x01\x61\x01'))

        self.io_device.write(generate_sdm_packet(0xa0, 0x00, 0x90, b'\x00\x00\x00\x00\xc8\x00\xc8\x00'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.COMMON_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.LTE_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.EDGE_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.HSPA_ITEM_REFRESH_REQUEST, b'\x00\x00\x00\x00\xff'))

    def init_diag(self):
        self.logger.log(logging.INFO, 'Initialize diag')
        if self.model == 'e333' or self.model == 'e5123':
            self.init_diag_e333()
        elif self.model == 'e303' or self.model == 'cmc221s':
            self.init_diag_e303()
        else:
            assert False, "Invalid model."

    def prepare_diag(self):
        pass

    def parse_diag(self, pkt):
        return self.parse_diag_log(pkt)

    def run_diag(self):
        self.logger.log(logging.INFO, 'Starting diag')

        oldbuf = b''
        loop = True
        cur_pos = 0
        try:
            while loop:
                buf = self.io_device.read(0x1000)
                if len(buf) == 0:
                    if self.io_device.block_until_data:
                        continue
                    else:
                        loop = False
                buf = oldbuf + buf

                cur_pos = 0
                while cur_pos < len(buf):
                    pos = buf.find(b'\x7f', cur_pos)

                    if pos < 0:
                        self.logger.log(logging.WARNING, 'Cannot find the start of packet')
                        oldbuf = buf
                        break

                    if len(buf) < pos + 11:
                        # self.logger.log(logging.WARNING, 'Packet shorter than expected')
                        oldbuf = buf[pos:]
                        break

                    sdm_pkt_hdr = sdmheader._make(struct.unpack('<HBHHBBB', buf[pos+1:pos+11]))

                    # Sanity check
                    if len(buf) < (pos + 2 + sdm_pkt_hdr.length1):
                        # self.logger.log(logging.WARNING, 'Current buffer shorter than the packet, storing it')
                        oldbuf = buf[pos:]
                        break

                    if buf[pos+1+sdm_pkt_hdr.length1] != 0x7e:
                        self.logger.log(logging.WARNING, 'Packet start {:02x} and end {:02x} does not match, dropping'.format(buf[pos], buf[pos+1+sdm_pkt_hdr.length1]))
                        cur_pos = pos + 2
                        continue

                    if sdm_pkt_hdr.length2 + 3 != sdm_pkt_hdr.length1:
                        self.logger.log(logging.WARNING, 'Inner and outer length does not match, dropping')
                        cur_pos = pos + 2
                        continue

                    parse_result = self.parse_diag(buf[pos:pos + sdm_pkt_hdr.length1 + 2])
                    if parse_result is not None:
                        self.postprocess_parse_result(parse_result)

                    cur_pos = (pos + sdm_pkt_hdr.length1 + 2)

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        self.logger.log(logging.INFO, 'Stopping diag')
        # DIAG Disable
        self.io_device.write(generate_sdm_packet(0xa0, 0x00, sdm_control_message.CONTROL_STOP, b'\x00\x00\x00\x00'))

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
        while self.io_device.file_available:
            self.logger.log(logging.INFO, "Reading from {}".format(self.io_device.fname))
            if self.io_device.fname.find('.sdmraw') > 0:
                self.run_diag()
            elif self.io_device.fname.find('.sdm') > 0:
                self.run_dump()
            else:
                self.logger.log(logging.INFO, 'Unknown baseband dump type, assuming raw SDM')
                self.run_diag()
            self.io_device.open_next_file()

    def postprocess_parse_result(self, parse_result):
        if 'radio_id' in parse_result:
            radio_id = parse_result['radio_id']
        else:
            radio_id = 0

        if 'ts' in parse_result:
            ts = parse_result['ts']
        else:
            ts = None

        if 'cp' in parse_result:
            for sock_content in parse_result['cp']:
                self.writer.write_cp(sock_content, radio_id, ts)

        if 'up' in parse_result:
            for sock_content in parse_result['up']:
                self.writer.write_up(sock_content, radio_id, ts)

        if 'stdout' in parse_result:
            if len(parse_result['stdout']) > 0:
                for l in parse_result['stdout'].split('\n'):
                    print('Radio {}: {}'.format(radio_id, l))

    def parse_diag_log(self, pkt):
        if not (pkt[0] == 0x7f and pkt[-1] == 0x7e):
            self.logger.log(logging.WARNING, 'Invalid packet structure')
            self.logger.log(logging.DEBUG, util.xxd(pkt))
            return None

        if len(pkt) < 11:
            self.logger.log(logging.WARNING, 'Packet shorter than expected')
            return None

        sdm_pkt_hdr = parse_sdm_header(pkt[1:11])

        if sdm_pkt_hdr.length2 + 3 != sdm_pkt_hdr.length1:
            self.logger.log(logging.WARNING, 'Inner and outer length does not match, dropping')
            return None

        if len(pkt) != (sdm_pkt_hdr.length1 + 2):
            self.logger.log(logging.WARNING, 'Inner and outer length does not match, dropping')
            return None

        if sdm_pkt_hdr.direction != sdm_command_type.IPC_DM_CMD and sdm_pkt_hdr.direction != sdm_command_type.IPC_CT_CMD:
            self.logger.log(logging.WARNING, 'Unexpected direction ID 0x{:02x}'.format(sdm_pkt_hdr.direction))
            return None

        # print('SDM Header: radio id {}, group 0x{:02x}, command 0x{:02x}'.format(sdm_pkt_hdr.radio_id, sdm_pkt_hdr.group, sdm_pkt_hdr.command))

        cmd_sig = (sdm_pkt_hdr.group << 8) | sdm_pkt_hdr.command
        if cmd_sig in self.process.keys():
            parse_result = self.process[cmd_sig](pkt)
        elif cmd_sig in self.no_process.keys():
            print("Not handling group 0x{:02x} command 0x{:02x}".format(sdm_pkt_hdr.group, sdm_pkt_hdr.command))
            parse_result = None
        else:
            parse_result = None

        if type(parse_result) == dict:
            parse_result['radio_id'] = sdm_pkt_hdr.radio_id
            return parse_result
        else:
            return None

    # Samsung TS format:
    # No Epoch
    # Incremented by 1 000 000 per 1 second
    # Rolled over when TS becomes bigger than 2^32 - 1

__entry__ = SamsungParser

def name():
    return 'samsung'

def shortname():
    return 'sec'

