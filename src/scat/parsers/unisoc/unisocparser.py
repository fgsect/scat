#!/usr/bin/env python3
# coding: utf8

import scat.util as util
import struct
import logging
from collections import namedtuple
from inspect import currentframe, getframeinfo
from pathlib import Path
import os, sys
import binascii

class UnisocParser:
    def __init__(self):
        self.io_device = None
        self.writer = None
        self.combine_stdout = False

        self.name = 'unisoc'
        self.shortname = 'sprd'

        self.logger = logging.getLogger('scat.unisocparser')

        self.diag_log_parsers = []
        self.process = { }
        self.no_process = { }

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

    def init_diag(self):
        pass

    def prepare_diag(self):
        pass

    def parse_diag(self, pkt):
        pkt = pkt[2:-4]

        pkt_9c01_header_Struct = namedtuple('Unisoc9c01Header', 'id magic cmdid seqnr len')

        if pkt[0:2] == b'\x01\x9c':
            pkt_019c_header = pkt_9c01_header_Struct._make(struct.unpack('<HHH LH', pkt[0:12]))
            pkt_rest = pkt[12:]
            # print("SeqNr: {:#010x}, CMD_ID: {:#06x}, Len: {:3}, Body: {}".format(pkt_019c_header.seqnr, pkt_019c_header.cmdid, pkt_019c_header.len, binascii.hexlify(pkt_rest).decode()))

            if len(pkt_rest) + 6 != pkt_019c_header[4]:
                self.logger.log(logging.WARNING, "Length mismatch: expected {}, got {}".format(pkt_019c_header[4], len(pkt_rest) + 6))

            body_cmdid = struct.unpack('<L', pkt_rest[0:4])[0]
            if body_cmdid == 0x0198:
                log_header_struct = namedtuple('UnisocLogHeader', 'cmdid cmd_subid len')
                log_header = log_header_struct._make(struct.unpack('<LHH', pkt_rest[0:8]))

                if len(pkt_rest[8:]) + 4 != log_header.len:
                    self.logger.log(logging.WARNING, "Length mismatch: expected {}, got {}".format(log_header.len, len(pkt_rest[8:]) + 4))

                if log_header.cmd_subid == 0x9104:
                    print('Log 0x9104: {}'.format(pkt_rest[8:].decode()))
                # 9100, 9101, 910e
                # elif log_header.cmd_subid == 0x910e:
                #     # print('Log 0x910e: {}'.format(pkt_rest[8:]))
                #     pass
                # elif log_header.cmd_subid == 0x9100:
                #     pass
                else:
                    print('Unknown cmd_subid {:#x}, body: {}'.format(log_header.cmd_subid, binascii.hexlify(pkt_rest[8:]).decode()))
                pass
            elif body_cmdid == 0x01f8:
                pass
            else:
                pass

        elif pkt[0:2] == b'\x01\x9d':
            pkt_019c_header = pkt_9c01_header_Struct._make(struct.unpack('<HHH LL', pkt[0:14]))
            # print(pkt_019c_header)
            pkt_rest = pkt[14:]

            # if pkt_019c_header.cmdid != 196:
                # print(binascii.hexlify(pkt))
            # if len(pkt_rest) + 8 != pkt_019c_header[4]:
            #     self.logger.log(logging.WARNING, "Length mismatch: expected {}, got {}".format(pkt_019c_header[4], len(pkt_rest) + 8))
        else:
            self.logger.log(logging.WARNING, "Unknown command type {:#06x}".format(struct.unpack('<H', pkt[0:2])[0]))
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
            for sock_content in parse_result['cp']:
                self.writer.write_cp(sock_content, radio_id, ts)

        if 'up' in parse_result:
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
        if pkt[0] == 0x00:
            if len(pkt) < 25:
                return
            pkt_header = self.log_header._make(struct.unpack('<LQLLL', pkt[1:25]))
            pkt_data = pkt[25:]

            if pkt_header.len != len(pkt_data):
                if self.logger:
                    self.logger.log(logging.WARNING, "Packet length mismatch: expected {}, got {}".format(pkt_header.len, len(pkt_data)))

            if pkt_header.cmd in self.process.keys():
                return self.process[pkt_header.cmd](pkt_header, pkt_data, args)
            else:
                # print(binascii.hexlify(pkt_data))
                return None
        elif pkt[0] == 0x01:
            if len(pkt) < 29:
                return
            pkt_header = self.type_0x01_header._make(struct.unpack('<LLLHLHQ', pkt[1:29]))
            pkt_data = pkt[29:-4]
            magic_2 = struct.unpack('<L', pkt[-4:])[0]

            if not (pkt_header.magic == 0xaaaa5555 and magic_2 == 0x5555aaaa):
                if self.logger:
                    self.logger.log(logging.WARNING, "Packet magic mismatch: expected wrapping of 0x5555aaaa and aaaa5555")

            if pkt_header.nested_len1 != pkt_header.nested_len2 + 8:
                if self.logger:
                    self.logger.log(logging.WARNING, "Packet length mismatch: {} and {}".format(pkt_header.nested_len1, pkt_header.nested_len2))

            if pkt_header.cmd in self.process_nested.keys():
                return self.process_nested[pkt_header.cmd](pkt_header, pkt_data, args)
            else:
                # print(binascii.hexlify(pkt_data))
                return None
        else:
            self.logger.log(logging.INFO, 'Unknown packet type {:#04x}'.format(pkt[0]))
            # print(binascii.hexlify(pkt))
            return None

__entry__ = UnisocParser

def name():
    return 'unisoc'

def shortname():
    return 'sprd'
