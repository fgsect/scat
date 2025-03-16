#!/usr/bin/env python3
# coding: utf8

from collections import namedtuple
from inspect import currentframe, getframeinfo
from pathlib import Path
import binascii
import logging
import os, sys
import scat.util as util
import struct

class UnisocParser:
    def __init__(self):
        self.io_device = None
        self.writer = None
        self.combine_stdout = False

        self.display_format = 'x'
        self.gsmtapv3 = False

        self.name = 'unisoc'
        self.shortname = 'sprd'

        self.logger = logging.getLogger('scat.unisocparser')

        self.diag_log_parsers = []
        self.process = { }
        self.no_process = { }
        self.layers = []

        for p in self.diag_log_parsers:
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
            if p == 'log_level':
                self.logger.setLevel(params[p])
            elif p == 'msgs':
                self.msgs = params[p]
            elif p == 'combine-stdout':
                self.combine_stdout = params[p]
            elif p == 'layer':
                self.layers = params[p]
            elif p == 'format':
                self.display_format = params[p]
            elif p == 'gsmtapv3':
                self.gsmtapv3 = params[p]

    def init_diag(self):
        pass

    def prepare_diag(self):
        pass

    def parse_diag(self, pkt):
        pkt = pkt[2:-4]

        # drivers/unisoc_platform/sprdwcn/platform/wcn_txrx.h
        pkt_header_struct = namedtuple('UnisocPktHeader', 'chan_num pkt_type magic csum')
        pkt_tag_header_struct = namedtuple('UnisocPktTagHeader', 'seqnr len type subtype')

        pkt_header = pkt_header_struct._make(struct.unpack('<BBHH', pkt[0:6]))
        assert(pkt_header.magic == 0x5a5a)
        if pkt_header.chan_num == 0x01:
            # pkt_type
            # 0x9c:
            # 0x9d: SMP_DSP_TYPE
            pkt_tag_header = pkt_tag_header_struct._make(struct.unpack('<LHBB', pkt[6:14]))
            print('Chan: {:#04x}, Type: {:#04x}, CSum: {:#06x}, (SeqNr: {:#010x}/{:10d}, Type: {:#04x}, Subtype: {:#04x}): {}'.format(
                pkt_header.chan_num, pkt_header.pkt_type, pkt_header.csum,
                pkt_tag_header.seqnr, pkt_tag_header.seqnr, pkt_tag_header.type, pkt_tag_header.subtype,
                binascii.hexlify(pkt[14:]).decode()
            ))
            if len(pkt[14:]) + 8 != pkt_tag_header.len:
                self.logger.log(logging.WARNING, "Length mismatch: expected {}, got {}".format(pkt_tag_header.len, len(pkt[14:]) + 8))

            if pkt_tag_header.type == 0xf8:
                pkt_0xf8_struct = namedtuple('Unisoc0xf8Header', 'zero type len')
                pkt_0xf8 = pkt_0xf8_struct._make(struct.unpack('>HHH', pkt[14:20]))
                assert(pkt_0xf8.zero == 0)
                assert(pkt_0xf8.len == len(pkt[20:]))

                if pkt_0xf8.type == 0x1200:
                    pkt_0xf8_0x1200 = struct.unpack('>LL', pkt[20:28])
                    pkt_0xf8_0x1200_rest = pkt[28:]
                    assert(len(pkt_0xf8_0x1200_rest) == pkt_0xf8_0x1200[1])
                    print('Log ID: {:#010x}, Args: {} {}'.format(pkt_0xf8_0x1200[0], pkt_0xf8_0x1200[1], binascii.hexlify(pkt_0xf8_0x1200_rest).decode()))
            elif pkt_tag_header.type == 0x98:
                pkt_0x98_struct = namedtuple('Unisoc0x98Header', 'zero type len')
                pkt_0x98 = pkt_0x98_struct._make(struct.unpack('<HHH', pkt[14:20]))
                assert(pkt_0x98.zero == 0)
                assert(pkt_0x98.len == len(pkt[20:]) + 4)
                if pkt_0x98.type == 0x9104:
                    print('Log 0x9104: {}'.format(pkt[20:].decode(errors='replacebackslash')))
        else:
            self.logger.log(logging.WARNING, "Unknown channel number {:#04x}".format(pkt_header.chan_num))
            return

    def run_diag(self):
        pass

    def stop_diag(self):
        pass

    def run_dump(self):
        self.logger.log(logging.INFO, 'Starting diag from dump')

        usoc_header_struct = namedtuple('UnisocDumpHeader', 'magic unk1 unk2 unk3')
        sync_word = b'~~~~'

        oldbuf = b''
        loop = True
        cur_pos = 0
        try:
            header_buf = self.io_device.read(0x10)
            usoc_header = usoc_header_struct._make(struct.unpack('<4L', header_buf))
            print(usoc_header)
            if usoc_header.magic != 0x12345678:
                self.logger.log(logging.WARNING, "Not processing due to magic mismatch: expected {:#10x}, got {:#10x}".format(0x12345678, usoc_header.magic))
                return

            buf = self.io_device.read(0x04)
            if buf != sync_word:
                self.logger.log(logging.WARNING, "End-of-packet indicator not found")
                return

            while loop:
                buf = self.io_device.read(0x90000)
                if len(buf) == 0:
                    if self.io_device.block_until_data:
                        continue
                    else:
                        loop = False
                buf = oldbuf + buf

                cur_pos = 0
                while cur_pos < len(buf):
                    if cur_pos + 2 > len(buf):
                        oldbuf = buf[cur_pos:]
                        break
                    pkt_len = struct.unpack('<H', buf[cur_pos:cur_pos+2])[0]
                    if cur_pos + pkt_len > len(buf):
                        oldbuf = buf[cur_pos:]
                        break
                    pkt = buf[cur_pos:cur_pos+pkt_len+4]
                    if len(pkt) < (pkt_len+4):
                        oldbuf = buf[cur_pos:]
                        break

                    parse_result = self.parse_diag(pkt)
                    if parse_result is not None:
                        self.postprocess_parse_result(parse_result)

                    cur_pos += (pkt_len + 4)

                if cur_pos == len(buf):
                    oldbuf = b''

        except KeyboardInterrupt:
            return

    def read_dump(self):
        while self.io_device.file_available:
            self.logger.log(logging.INFO, "Reading from {}".format(self.io_device.fname))
            self.run_dump()
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
            if 'layer' in parse_result:
                if parse_result['layer'] in self.layers:
                    for sock_content in parse_result['cp']:
                        self.writer.write_cp(sock_content, radio_id, ts)
            else:
                for sock_content in parse_result['cp']:
                    self.writer.write_cp(sock_content, radio_id, ts)

        if 'up' in parse_result:
            if 'layer' in parse_result:
                if parse_result['layer'] in self.layers:
                    for sock_content in parse_result['up']:
                        self.writer.write_up(sock_content, radio_id, ts)
            else:
                for sock_content in parse_result['up']:
                    self.writer.write_up(sock_content, radio_id, ts)

        if 'stdout' in parse_result:
            if len(parse_result['stdout']) > 0:
                if self.combine_stdout:
                    for l in parse_result['stdout'].split('\n'):
                        osmocore_log_hdr = util.create_osmocore_logging_header(
                            timestamp = ts,
                            process_name = Path(sys.argv[0]).name,
                            pid = os.getpid(),
                            level = 3,
                            subsys_name = self.__class__.__name__,
                            filename = Path(__file__).name,
                            line_number = getframeinfo(currentframe()).lineno
                        )
                        gsmtap_hdr = util.create_gsmtap_header(
                            version = 2,
                            payload_type = util.gsmtap_type.OSMOCORE_LOG)
                        self.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + l.encode('utf-8'), radio_id, ts)
                else:
                    for l in parse_result['stdout'].split('\n'):
                        print('Radio {}: {}'.format(radio_id, l))

    def parse_diag_log(self, pkt, args=None):
        pass

__entry__ = UnisocParser

def name():
    return 'unisoc'

def shortname():
    return 'sprd'
