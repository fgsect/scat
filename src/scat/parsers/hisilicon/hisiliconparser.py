#!/usr/bin/env python3
# coding: utf8

from collections import namedtuple
from inspect import currentframe, getframeinfo
from pathlib import Path
import logging
import os, sys
import struct

import scat.util as util
from scat.parsers.hisilicon.hisilogparser import HisiLogParser
from scat.parsers.hisilicon.hisinestedparser import HisiNestedParser

class HisiliconParser:

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

        self.io_device = None
        self.writer = None
        self.combine_stdout = False
        self.check_crc = True
        self.layers = []
        self.display_format = 'x'
        self.gsmtapv3 = False

        self.name = 'hisilicon'
        self.shortname = 'hisi'

        self.logger = logging.getLogger('scat.hisiliconparser')

        self.diag_log_parsers = [HisiLogParser(self)]
        self.process = { }
        self.no_process = { }

        for p in self.diag_log_parsers:
            self.process.update(p.process)
            try:
                self.no_process.update(p.no_process)
            except AttributeError:
                pass

        self.diag_nested_parsers = [HisiNestedParser(self)]
        self.process_nested = { }
        self.no_process_nested = { }

        for p in self.diag_nested_parsers:
            self.process_nested.update(p.process)
            try:
                self.no_process_nested.update(p.no_process)
            except AttributeError:
                pass

        self.msgs = False

    def set_io_device(self, io_device):
        self.io_device = io_device

    def set_writer(self, writer):
        self.writer = writer

    def update_parameters(self, display_format, gsmtapv3):
        for p in self.diag_log_parsers:
            p.update_parameters(display_format, gsmtapv3)

        for p in self.diag_nested_parsers:
            p.update_parameters(display_format, gsmtapv3)

    def set_parameter(self, params):
        for p in params:
            if p == 'log_level':
                self.logger.setLevel(params[p])
            elif p == 'msgs':
                self.msgs = params[p]
            elif p == 'combine-stdout':
                self.combine_stdout = params[p]
            elif p == 'disable-crc-check':
                self.check_crc = not params[p]
            elif p == 'layer':
                self.layers = params[p]
            elif p == 'format':
                self.display_format = params[p]
            elif p == 'gsmtapv3':
                self.gsmtapv3 = params[p]

        self.update_parameters(self.display_format, self.gsmtapv3)

    def init_diag(self):
        pass

    def prepare_diag(self):
        pass

    def parse_diag(self, pkt, hdlc_encoded = True, has_crc = True, args = None):
        if len(pkt) < 3:
            return

        if hdlc_encoded:
            pkt = util.unwrap(pkt)

        if has_crc:
            # Check CRC only if check_crc is enabled
            if self.check_crc:
                crc = util.dm_crc16(pkt[:-2])
                crc_pkt = (pkt[-1] << 8) | pkt[-2]
                if crc != crc_pkt:
                    self.logger.log(logging.WARNING, "CRC mismatch: expected 0x{:04x}, got 0x{:04x}".format(crc, crc_pkt))
                    self.logger.log(logging.DEBUG, util.xxd(pkt))
            pkt = pkt[:-2]

        return self.parse_diag_log(pkt)

    def run_diag(self):
        pass

    def stop_diag(self):
        pass

    def run_dump(self):
        self.logger.log(logging.INFO, 'Starting diag from dump')

        oldbuf = b''
        loop = True
        cur_pos = 0
        try:
            while loop:
                buf = self.io_device.read(0x90000)
                if len(buf) == 0:
                    if self.io_device.block_until_data:
                        continue
                    else:
                        loop = False

                last_pkt_pos = buf.rfind(b'\x7e')
                if last_pkt_pos > 0:
                    buf_t = oldbuf + buf[0:last_pkt_pos]
                    oldbuf = buf[last_pkt_pos:]
                    buf = buf_t
                else:
                    buf = oldbuf + buf

                buf_atom = buf.split(b'\x7e')

                for pkt in buf_atom:
                    if len(pkt) == 0:
                        continue
                    parse_result = self.parse_diag(pkt)

                    if parse_result is not None:
                        self.postprocess_parse_result(parse_result)

        except KeyboardInterrupt:
            return

    def read_dump(self):
        while self.io_device.file_available:
            self.logger.log(logging.INFO, "Reading from {}".format(self.io_device.fname))
            if self.io_device.fname.find('.lpd') > 0:
                self.run_dump()
            else:
                self.logger.log(logging.INFO, 'Unknown baseband dump type, assuming LPD')
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

    log_header = namedtuple('HisiLogHeader', 'unk2 ts unk3 cmd len')
    type_0x01_header = namedtuple('Hisi0x01Header', 'unk1 unk2 magic nested_len1 cmd nested_len2 ts')

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

__entry__ = HisiliconParser

def name():
    return 'hisilicon'

def shortname():
    return 'hisi'
