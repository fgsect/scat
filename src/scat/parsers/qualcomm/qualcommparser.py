#!/usr/bin/env python3
# coding: utf8
# SPDX-License-Identifier: GPL-2.0-or-later

# Part of the source code:
# (C) 2013-2016 by Harald Welte <laforge@gnumonks.org>

from collections import namedtuple
from inspect import currentframe, getframeinfo
from packaging import version
from pathlib import Path
import binascii
import bitstring
import datetime
import io
import logging
import os, sys
import re
import scat.util as util
import struct
import uuid
import zlib

from scat.parsers.qualcomm import diagcmd
from scat.parsers.qualcomm.diaggsmlogparser import DiagGsmLogParser
from scat.parsers.qualcomm.diagwcdmalogparser import DiagWcdmaLogParser
from scat.parsers.qualcomm.diagumtslogparser import DiagUmtsLogParser
from scat.parsers.qualcomm.diagltelogparser import DiagLteLogParser
from scat.parsers.qualcomm.diag1xlogparser import Diag1xLogParser
from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser

from scat.parsers.qualcomm.diagcommoneventparser import DiagCommonEventParser
from scat.parsers.qualcomm.diaglteeventparser import DiagLteEventParser
from scat.parsers.qualcomm.diaggsmeventparser import DiagGsmEventParser
from scat.parsers.qualcomm.diagfallbackeventparser import DiagFallbackEventParser

bitstring_ver = version.parse(bitstring.__version__)
if bitstring_ver >= version.parse('4.2.0'):
    bitstring.options.lsb0 = True
elif bitstring_ver >= version.parse('4.0.0'):
    bitstring.lsb0 = True
elif bitstring_ver >= version.parse('3.1.7'):
    bitstring.set_lsb0(True)
else:
    raise Exception("SCAT requires bitstring>=3.1.7, recommends bitstring>=4.0.0")

class QualcommParser:
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
        self.lte_last_tcrnti = [1, 1]

        self.io_device = None
        self.writer = None
        self.parse_msgs = False
        self.parse_events = False
        self.qsr_hash_filename = ''
        self.qsr4_hash_filename = ''
        self.emr_id_range = []
        self.log_id_range = {}
        self.cacombos = False
        self.combine_stdout = False
        self.check_crc = True
        self.layers = []
        self.display_format = 'x'
        self.gsmtapv3 = False

        self.qsr4_content = {}
        self.qsr4_mtrace_content = {}
        self.qsr4_qtrace_str_content = {}

        self.name = 'qualcomm'
        self.shortname = 'qc'

        self.logger = logging.getLogger('scat.qualcommparser')

        self.diag_log_parsers = [DiagGsmLogParser(self),
            DiagWcdmaLogParser(self), DiagUmtsLogParser(self),
            DiagLteLogParser(self), Diag1xLogParser(self), DiagNrLogParser(self)]
        self.process = { }
        self.no_process = { }

        for p in self.diag_log_parsers:
            self.process.update(p.process)
            try:
                self.no_process.update(p.no_process)
            except AttributeError:
                pass

        self.diag_event_parsers = [DiagCommonEventParser(self),
            DiagGsmEventParser(self), DiagLteEventParser(self)]
        self.diag_fallback_event_parser = DiagFallbackEventParser(self)

        self.process_event = { }
        self.no_process_event = { }

        for p in self.diag_event_parsers:
            self.process_event.update(p.process)
            try:
                self.no_process_event.update(p.no_process)
            except AttributeError:
                pass

    def set_io_device(self, io_device):
        self.io_device = io_device

    def set_writer(self, writer):
        self.writer = writer

    def update_parameters(self, display_format, gsmtapv3):
        for p in self.diag_event_parsers:
            p.update_parameters(display_format, gsmtapv3)

        for p in self.diag_log_parsers:
            p.update_parameters(display_format, gsmtapv3)

    def load_qsr4_hash(self, filename):
        zlib_content = b''
        content = b''
        with open(filename, 'rb') as qsr4_file:
            header = qsr4_file.read(64)
            if header[0:4] != b'\x7fQDB':
                self.logger.log(logging.ERROR, '{} is not a valid QSR4 hash file: magic does not match'.format(filename))
                return False
            qsr4_uuid = uuid.UUID(bytes=header[4:20])
            self.logger.log(logging.INFO, 'Loading QSR4 hash file with UUID {}'.format(qsr4_uuid))
            zlib_content = qsr4_file.read()

        try:
            content = zlib.decompress(zlib_content)
        except zlib.error as e:
            self.logger.log(logging.ERROR, 'Error while decompressing zlib content: {}'.format(e))
            return False

        mode = 0
        tag_oneline_re = re.compile(r'\<(\w*)\>\s*([\w\-=.]*)\s*\<\\(\w*)\>')
        tag_open_re = re.compile(r'^\<(\w*)\>$')
        tag_close_re = re.compile(r'^\<\\(\w*)\>$')

        txt_qsr4_uuid = ''
        txt_qsr4_version = ''
        txt_qsr4_baseline = ''

        content_t = namedtuple('Qsr4Content', 'subsys_mask ssid line file string')
        mtrace_t = namedtuple('Qsr4MtraceContent', 'line level client file tag string')
        for l in io.BytesIO(content):
            l = l.decode(errors='backslashreplace').strip()

            if l[0] == '#':
                continue
            is_tag_oneline = tag_oneline_re.match(l)
            if is_tag_oneline:
                g = is_tag_oneline.groups()
                if g[0] == g[2] == 'GUID':
                    txt_qsr4_uuid = uuid.UUID(g[1])
                elif g[0] == g[2] == 'Version':
                    txt_qsr4_version = g[1]
                elif g[0] == g[2] == 'Baseline':
                    txt_qsr4_baseline = g[1]
            else:
                is_tag_open = tag_open_re.match(l)
                is_tag_close = tag_close_re.match(l)
                if is_tag_open:
                    tag = is_tag_open.groups()[0]
                    if tag == 'Content':
                        mode = 1
                    elif tag == 'MtraceContent':
                        mode = 2
                    elif tag == 'QtraceStrContent':
                        mode = 3
                    else:
                        raise ValueError('Tag should be one of Content, MtraceContent, QtraceStrContent')
                elif is_tag_close:
                    tag = is_tag_close.groups()[0]
                    if tag == 'Content':
                        if mode != 1:
                            raise ValueError('Open and close tag mismatch')
                    elif tag == 'MtraceContent':
                        if mode != 2:
                            raise ValueError('Open and close tag mismatch')
                    elif tag == 'QtraceStrContent':
                        if mode != 3:
                            raise ValueError('Open and close tag mismatch')
                    mode = 0
                else:
                    if mode == 1:
                        content_str = l.split(':', 5)
                        content_str[1] = int(content_str[1])
                        content_str[2] = int(content_str[2])
                        content_str[3] = int(content_str[3])
                        x = content_t._make(content_str[1:])
                        # print('{:08x} {}'.format(int(content_str[0]), x))
                        self.qsr4_content[int(content_str[0])] = x
                    elif mode == 2:
                        mtrace_str = l.split(':', 6)
                        x = mtrace_t._make(mtrace_str[1:])
                        # print('{:08x} {}'.format(int(mtrace_str[0]), x))
                        self.qsr4_mtrace_content[int(mtrace_str[0])] = x
                        # line: pure int, "int|hex", "|hex"
                        # tag: pure str, "str|hex", "str|"
                    elif mode == 3:
                        qtrace_str = l.split(':', 1)
                        # print('{:08x} {}'.format(int(qtrace_str[0]), qtrace_str[1]))
                        self.qsr4_qtrace_str_content[int(qtrace_str[0])] = qtrace_str[1]

        if len(self.qsr4_content) > 0:
            return True

    def set_parameter(self, params):
        qsr_hash_loaded = False
        for p in params:
            if p == 'log_level':
                self.logger.setLevel(params[p])
            elif p == 'qsr-hash':
                self.qsr_hash_filename = params[p]
                if not self.qsr4_hash_filename:
                    continue
                self.parse_msgs = True
            elif p == 'qsr4-hash':
                self.qsr4_hash_filename = params[p]
                if not self.qsr4_hash_filename:
                    continue
                try:
                    qsr_hash_loaded = self.load_qsr4_hash(self.qsr4_hash_filename)
                except ValueError as e:
                    self.logger.log(logging.INFO, 'Error parsing QSR4 hash table: {}'.format(e))
            elif p == 'events':
                self.parse_events = params[p]
            elif p == 'msgs':
                self.parse_msgs = params[p]
            elif p == 'cacombos':
                self.cacombos = params[p]
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

        if qsr_hash_loaded:
            self.parse_msgs = True
        self.update_parameters(self.display_format, self.gsmtapv3)

    def sanitize_radio_id(self, radio_id):
        if radio_id <= 0:
            return 0
        elif radio_id > 2:
            return 1
        else:
            return (radio_id - 1)

    def init_diag(self):
        self.logger.log(logging.INFO, 'Initializing diag')
        # Disable static event reporting
        self.io_device.read(0x1000)

        self.io_device.write(util.generate_packet(struct.pack('<B', diagcmd.DIAG_VERNO_F)), False)
        ver_buf = self.io_device.read(0x1000)
        result = self.parse_diag(ver_buf[:-1])
        if result:
            self.postprocess_parse_result(result)

        self.io_device.write(util.generate_packet(struct.pack('<B', diagcmd.DIAG_EXT_BUILD_ID_F)), False)
        build_id_buf = self.io_device.read(0x1000)
        result = self.parse_diag(build_id_buf[:-1])
        if result:
            self.postprocess_parse_result(result)

        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00)), 0x1000, False)

        self.io_device.write(util.generate_packet(struct.pack('<LL', diagcmd.DIAG_LOG_CONFIG_F, diagcmd.LOG_CONFIG_RETRIEVE_ID_RANGES_OP)), False)
        log_config_buf = self.io_device.read(0x1000)
        result = self.parse_diag(log_config_buf[:-1])
        if result:
            self.postprocess_parse_result(result)

        # Send empty masks
        if diagcmd.DIAG_SUBSYS_ID_1X in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_1x(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_1X])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_1x()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_WCDMA in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_wcdma(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_WCDMA])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_wcdma()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_GSM in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_gsm(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_GSM])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_gsm()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_UMTS in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_umts(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_UMTS])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_umts()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_DTV in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_dtv(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_DTV])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_dtv()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_LTE in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_lte(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_LTE])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_lte()), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_TDSCDMA in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_tdscdma(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_TDSCDMA])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_tdscdma()), 0x1000, False)

        self.io_device.write(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EXT_MSG_CONFIG_F, 0x01)), False)
        ext_msg_buf = self.io_device.read(0x1000)
        result = self.parse_diag(ext_msg_buf[:-1])
        if result:
            self.postprocess_parse_result(result)

        emr = lambda x, y: diagcmd.create_extended_message_config_set_mask(x, y)
        if result and 'id_range' in result:
            self.emr_id_range = result['id_range']
            for x in result['id_range']:
                self.io_device.write_then_read_discard(util.generate_packet(emr(x[0], x[1])), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x0000, 0x0065)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x01f4, 0x01fa)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x03e8, 0x033f)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x07d0, 0x07d8)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x0bb8, 0x0bc6)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x0fa0, 0x0faa)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1194, 0x11ae)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x11f8, 0x1206)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1388, 0x13a6)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x157c, 0x158c)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1770, 0x17c0)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1964, 0x1979)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1b58, 0x1b5b)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1bbc, 0x1bc7)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1c20, 0x1c21)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x1f40, 0x1f40)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x2134, 0x214c)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x2328, 0x2330)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x251c, 0x2525)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x27d8, 0x27e2)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x280b, 0x280f)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x283c, 0x283c)), 0x1000, False)
            self.io_device.write_then_read_discard(util.generate_packet(emr(0x286e, 0x2886)), 0x1000, False)

    def prepare_diag(self):
        self.logger.log(logging.INFO, 'Starting diag')

        emr_level_range = []
        if self.parse_msgs:
            if len(self.emr_id_range) > 0:
                for x in self.emr_id_range:
                    self.io_device.write(util.generate_packet(struct.pack('<BBHH', diagcmd.DIAG_EXT_MSG_CONFIG_F, 0x02, x[0], x[1])), False)
                    ext_msg_level_buf = self.io_device.read(0x1000)
                    result = self.parse_diag(ext_msg_level_buf[:-1])
                    if result:
                        self.postprocess_parse_result(result)
                    emr_level_range.append((result['start'], result['end'], result['level']))

            if len(emr_level_range) > 0:
                for x in emr_level_range:
                    self.io_device.write_then_read_discard(util.generate_packet(diagcmd.create_extended_message_config_set_mask(x[0], x[1], *x[2])), 0x1000, False)

        # Static event reporting Enable
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x01)), 0x1000, False)

        if diagcmd.DIAG_SUBSYS_ID_1X in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_1x(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_1X], self.layers)), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_1x(layers=self.layers)), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_WCDMA in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_wcdma(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_WCDMA], self.layers)), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_wcdma(layers=self.layers)), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_GSM in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_gsm(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_GSM], self.layers)), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_gsm(layers=self.layers)), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_UMTS in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_umts(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_UMTS], self.layers)), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_umts(layers=self.layers)), 0x1000, False)
        if diagcmd.DIAG_SUBSYS_ID_LTE in self.log_id_range:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_lte(self.log_id_range[diagcmd.DIAG_SUBSYS_ID_LTE], self.layers)), 0x1000, False)
        else:
            self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_lte(layers=self.layers)), 0x1000, False)

    def parse_diag(self, pkt, hdlc_encoded = True, has_crc = True, args = None):
        # Should contain DIAG command and CRC16
        # pkt should not contain trailing 0x7E, and either HDLC encoded or not
        # When the pkt is not HDLC encoded, hdlc_encoded should be set to True
        # radio_id = 0 for default, larger than 1 for SIM 1 and such

        if len(pkt) < 3:
            return

        if hdlc_encoded:
            pkt = util.unwrap(pkt)

        # Check and strip CRC if existing
        if has_crc:
            # Check CRC only if check_crc is enabled
            if self.check_crc:
                crc = util.dm_crc16(pkt[:-2])
                crc_pkt = (pkt[-1] << 8) | pkt[-2]
                if crc != crc_pkt:
                    self.logger.log(logging.WARNING, "CRC mismatch: expected 0x{:04x}, got 0x{:04x}".format(crc, crc_pkt))
                    self.logger.log(logging.DEBUG, util.xxd(pkt))
            pkt = pkt[:-2]

        if pkt[0] == diagcmd.DIAG_VERNO_F:
            return self.parse_diag_version(pkt)
        elif pkt[0] == diagcmd.DIAG_LOG_F:
            return self.parse_diag_log(pkt, args)
        elif pkt[0] == diagcmd.DIAG_EVENT_REPORT_F and self.parse_events:
            return self.parse_diag_event(pkt)
        elif pkt[0] == diagcmd.DIAG_LOG_CONFIG_F:
            return self.parse_diag_log_config(pkt)
        elif pkt[0] == diagcmd.DIAG_EXT_MSG_F and self.parse_msgs:
            return self.parse_diag_ext_msg(pkt)
        elif pkt[0] == diagcmd.DIAG_EXT_BUILD_ID_F:
            return self.parse_diag_ext_build_id(pkt)
        elif pkt[0] == diagcmd.DIAG_EXT_MSG_CONFIG_F:
            return self.parse_diag_ext_msg_config(pkt)
        elif pkt[0] == diagcmd.DIAG_QSR_EXT_MSG_TERSE_F and self.parse_msgs:
            return self.parse_diag_qsr_ext_msg(pkt)
        elif pkt[0] == diagcmd.DIAG_MULTI_RADIO_CMD_F:
            return self.parse_diag_multisim(pkt)
        elif pkt[0] == diagcmd.DIAG_QSR4_EXT_MSG_TERSE_F and self.parse_msgs:
            return self.parse_diag_qsr4_ext_msg(pkt)
        elif pkt[0] == diagcmd.DIAG_QSH_TRACE_PAYLOAD_F and self.parse_msgs:
            return self.parse_diag_qsh_trace_msg(pkt)
        else:
            self.logger.log(logging.DEBUG, 'Not parsing DIAG command {:#02x}'.format(pkt[0]))
            self.logger.log(logging.DEBUG, util.xxd(pkt))
            return None

    def run_diag(self, writer_qmdl = None):
        oldbuf = b''
        loop = True
        try:
            while loop:
                buf = self.io_device.read(0x1000)
                if len(buf) == 0:
                    if self.io_device.block_until_data:
                        continue
                    else:
                        loop = False
                buf = oldbuf + buf
                buf_atom = buf.split(b'\x7e')

                if len(buf) < 1 or buf[-1] != 0x7e:
                    oldbuf = buf_atom.pop()
                else:
                    oldbuf = b''

                for pkt in buf_atom:
                    if len(pkt) == 0:
                        continue
                    parse_result = self.parse_diag(pkt)

                    if writer_qmdl:
                        writer_qmdl.write_cp(pkt + b'\x7e')

                    if parse_result is not None:
                        self.postprocess_parse_result(parse_result)

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        self.io_device.read(0x1000)
        self.logger.log(logging.INFO, 'Stopping diag')
        # Static event reporting Disable
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00)), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<LL', diagcmd.DIAG_LOG_CONFIG_F, diagcmd.LOG_CONFIG_DISABLE_OP)), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BBHHH', diagcmd.DIAG_EXT_MSG_CONFIG_F, 0x05, 0x0000, 0x0000, 0x0000)), 0x1000, False)

    def parse_dlf(self):
        oldbuf = b''
        while True:
            buf = self.io_device.read(0x100000)
            #print("%d"% len(buf))
            if len(buf) == 0:
                break
            buf = oldbuf + buf

            while True:
                # DLF lacks CRC16/other fancy stuff
                if len(buf) < 2:
                    break
                pkt_len = struct.unpack('<H', buf[0:2])[0]
                if pkt_len < 2:
                    buf = buf[2:]
                    continue
                pkt = buf[0:pkt_len]
                pkt = b'\x10\x00' + pkt[0:2] + pkt
                parse_result = self.parse_diag(pkt, has_crc=False, hdlc_encoded=False)

                if parse_result is not None:
                    self.postprocess_parse_result(parse_result)

                buf = buf[pkt_len:]

            oldbuf = buf

    # Experimental HDF parser.
    # It scans the file for packets in the format "0x10 0x00 packet_length body"
    # Ignoring any additional fields that the file might contain
    def parse_hdf(self):
        while True:
            header = self.io_device.read(1)

            # EOF check
            if len(header) == 0:
                break

            # First byte must be 0x10
            if header != b'\x10':
                continue

            # Second byte must be 0x00
            header += self.io_device.read(1)
            if header != b'\x10\x00':
                continue

            # pkt length from header and pkt length from body must be equal
            header += self.io_device.read(2)
            body = self.io_device.read(2)
            if header[2:4] != body[0:2]:
                continue

            # Convert pkt length to int
            pkt_len = struct.unpack('<H', header[2:4])[0]

            body_len = pkt_len - 2

            if (body_len < 1):
                continue

            # Read full body
            body += self.io_device.read(body_len)
            pkt = header + body

            parse_result = self.parse_diag(pkt, has_crc=False, hdlc_encoded=False)
            if parse_result is not None:
                self.postprocess_parse_result(parse_result)

    def read_dump(self):
        while self.io_device.file_available:
            self.logger.log(logging.INFO, "Reading from {}".format(self.io_device.fname))
            if self.io_device.fname.find('.qmdl') > 0:
                self.run_diag()
            elif self.io_device.fname.find('.dlf') > 0:
                self.parse_dlf()
            elif self.io_device.fname.find('.hdf') > 0:
                self.parse_hdf()
            else:
                self.logger.log(logging.INFO, 'Unknown baseband dump type, assuming QMDL')
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
            ts = datetime.datetime.now()

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

    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    def _snprintf(self, fmtstr, fmtargs):
        # Observed fmt string: {'%02x', '%03d', '%04d', '%04x', '%08x', '%X', '%d', '%ld', '%llx', '%lu', '%u', '%x', '%p'}
        cfmt = re.compile(r'(%(?:(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|l|ll|w|I|I32|I64)?[duxXp])|%%)')
        cfmt_nums = re.compile(r'%((?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?)(?:h|l|ll|w|I|I32|I64)?[duxXp]')
        fmt_strs = cfmt.findall(fmtstr)
        formatted_strs = []
        log_content_pyfmt = cfmt.sub('{}', fmtstr)

        i = 0
        if len(fmtargs) != len(fmt_strs):
            log_content_formatted = fmtstr
        else:
            for fmt_str in fmt_strs:
                fmt_num = ''
                x = cfmt_nums.match(fmt_str)
                if x:
                    fmt_num = x.group(1)
                if fmt_str == '%%':
                    formatted_strs.append('%')
                else:
                    if fmt_str[-1] in ('x', 'X', 'p'):
                        if fmt_str[-1] == 'p':
                            pyfmt_str = '{:' + fmt_num + 'x' + '}'
                        else:
                            pyfmt_str = '{:' + fmt_num + fmt_str[-1] + '}'
                        formatted_strs.append(pyfmt_str.format(fmtargs[i]))
                    elif fmt_str[-1] in ('d'):
                        pyfmt_str = '{:' + fmt_num + '}'
                        if fmtargs[i] > 2147483648:
                            formatted_strs.append(pyfmt_str.format(-(4294967296 - fmtargs[i])))
                        else:
                            formatted_strs.append(pyfmt_str.format(fmtargs[i]))
                    else:
                        pyfmt_str = '{:' + fmt_num + '}'
                        formatted_strs.append(pyfmt_str.format(fmtargs[i]))
                i += 1
            try:
                log_content_formatted = log_content_pyfmt.format(*formatted_strs)
            except:
                log_content_formatted = fmtstr
                if len(fmtargs) > 0:
                    log_content_formatted += ", args="
                    log_content_formatted += ', '.join(['0x{:x}'.format(x) for x in fmtargs])

        return log_content_formatted

    def parse_diag_version(self, pkt):
        header = namedtuple('QcDiagVersion', 'compile_date compile_time release_date release_time chipset')
        if len(pkt) < 47:
            return None
        ver_info = header._make(struct.unpack('<11s 8s 11s 8s 8s', pkt[1:47]))

        stdout = 'Compile: {}/{}, Release: {}/{}, Chipset: {}'.format(
            ver_info.compile_date.decode(errors="backslashreplace"),
            ver_info.compile_time.decode(errors="backslashreplace"),
            ver_info.release_date.decode(errors="backslashreplace"),
            ver_info.release_time.decode(errors="backslashreplace"),
            ver_info.chipset.decode(errors="backslashreplace"))

        return {'stdout': stdout}

    def parse_diag_log(self, pkt, args=None):
        """Parses the DIAG_LOG_F packet.

        Parameters:
        pkt (bytes): DIAG_LOG_F data without trailing CRC
        args (dict): 'radio_id' (int): used SIM or subscription ID on multi-SIM devices
        """
        if len(pkt) < 16:
            return

        pkt_header = self.log_header._make(struct.unpack('<BBHHHQ', pkt[0:16]))
        pkt_body = pkt[16:]

        if len(pkt_body) != (pkt_header.length2 - 12):
            self.logger.log(logging.WARNING, "Packet length mismatch: expected {}, got {}".format(pkt_header.length2, len(pkt_body)+12))

        if pkt_header.log_id in self.process.keys():
            return self.process[pkt_header.log_id](pkt_header, pkt_body, args)
        elif pkt_header.log_id in self.no_process.keys():
            #print("Not handling XDM Header 0x%04x (%s)" % (xdm_hdr[1], self.no_process[xdm_hdr[1]]))
            return None
        else:
            #print("Unhandled XDM Header 0x%04x" % xdm_hdr[1])
            #util.xxd(pkt)
            return None

    event_header = namedtuple('QcDiagEventHeader', 'cmd_code msg_len')

    def parse_diag_event(self, pkt):
        """Parses the DIAG_EVENT_REPORT_F packet.

        Parameters:
        pkt (bytes): DIAG_EVENT_REPORT_F data without trailing CRC
        """
        pkt_header = self.event_header._make(struct.unpack('<BH', pkt[0:3]))

        pos = 3
        event_pkts = []
        ts = datetime.datetime.now()
        while pos < len(pkt):
            # id 12b, _pad 1b, payload_len 2b, ts_trunc 1b
            _eid = struct.unpack('<H', pkt[pos:pos+2])[0]
            event_id = _eid & 0xfff
            payload_len = (_eid & 0x6000) >> 13
            ts_trunc = (_eid & 0x8000) >> 15 # 0: 64bit, 1: 16bit TS
            if ts_trunc == 0:
                ts = struct.unpack('<Q', pkt[pos+2:pos+10])[0]
                ts = util.parse_qxdm_ts(ts)
                pos += 10
            else:
                #ts = struct.unpack('<H', pkt[pos+2:pos+4])[0]
                # TODO: correctly parse ts
                ts = datetime.datetime.now()
                pos += 4

            assert (payload_len >= 0) and (payload_len <= 3)
            if payload_len == 0:
                # No payload
                if event_id in self.process_event.keys():
                    event_pkts.append(self.process_event[event_id][0](ts, event_id))
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    event_pkts.append(self.diag_fallback_event_parser.parse_event_fallback(ts, event_id))
            elif payload_len == 1:
                # 1x uint8
                arg1 = pkt[pos]

                if event_id in self.process_event.keys():
                    event_pkts.append(self.process_event[event_id][0](ts, event_id, arg1))
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    event_pkts.append(self.diag_fallback_event_parser.parse_event_fallback(ts, event_id, arg1))
                pos += 1
            elif payload_len == 2:
                # 2x uint8
                arg1 = pkt[pos]
                arg2 = pkt[pos+1]

                if event_id in self.process_event.keys():
                    event_pkts.append(self.process_event[event_id][0](ts, event_id, arg1, arg2))
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    event_pkts.append(self.diag_fallback_event_parser.parse_event_fallback(ts, event_id, arg1, arg2))
                pos += 2
            elif payload_len == 3:
                # Pascal string
                bin_len = pkt[pos]
                arg_bin = pkt[pos+1:pos+1+bin_len]

                if event_id in self.process_event.keys():
                    event_pkts.append(self.process_event[event_id][0](ts, event_id, arg_bin))
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    event_pkts.append(self.diag_fallback_event_parser.parse_event_fallback(ts, event_id, arg_bin))
                pos += (1 + pkt[pos])

        return {'cp': event_pkts, 'ts': ts}

    def parse_diag_log_config(self, pkt):
        if len(pkt) < 8:
            return None
        header = namedtuple('QcDiagLogConfig', 'pkt_id cmd_id')
        header_val = header._make(struct.unpack('<LL', pkt[0:8]))
        payload = pkt[8:]
        stdout = 'Log Config: '

        if header_val.cmd_id == diagcmd.LOG_CONFIG_DISABLE_OP:
            stdout += 'Disable'
            stdout += ', Extra: {}'.format(binascii.hexlify(payload).decode())
        elif header_val.cmd_id == diagcmd.LOG_CONFIG_RETRIEVE_ID_RANGES_OP:
            stdout += 'Retrieve ID ranges: '
            ranges = payload[4:]
            num_ranges = int(len(ranges)/4)
            for i in range(num_ranges):
                val = struct.unpack('<L', ranges[4*i:4*(i+1)])[0]
                if val > 0:
                    stdout += '{}: {}, '.format(i, val)
                    self.log_id_range[i] = val
        elif header_val.cmd_id == diagcmd.LOG_CONFIG_RETRIEVE_VALID_MASK_OP:
            stdout += 'Retrieve valid mask'
            stdout += ', Extra: {}'.format(binascii.hexlify(payload).decode())
        elif header_val.cmd_id == diagcmd.LOG_CONFIG_SET_MASK_OP:
            stdout += 'Set mask'
            stdout += ', Extra: {}'.format(binascii.hexlify(payload).decode())
        elif header_val.cmd_id == diagcmd.LOG_CONFIG_GET_LOGMASK_OP:
            stdout += 'Get mask'
            stdout += ', Extra: {}'.format(binascii.hexlify(payload).decode())

        return {'stdout': stdout}

    ext_msg_header = namedtuple('QcDiagExtMsgHeader', 'cmd_code ts_type num_args drop_cnt timestamp line_no message_subsys_id reserved1')

    def parse_diag_ext_msg(self, pkt):
        """Parses the DIAG_EXT_MSG_F packet.

        Parameters:
        pkt (bytes): DIAG_EXT_MSG_F data without trailing CRC
        """
        # 79 | 00 | 00 | 00 | 00 00 1c fc 0f 16 e4 00 | e6 04 | 94 13 | 02 00 00 00
        # cmd_code, ts_type, num_args, drop_cnt, TS, Line number, Message subsystem ID, ?
        # Message: two null-terminated strings, one for log and another for filename
        pkt_header = self.ext_msg_header._make(struct.unpack('<BBBBQHHL', pkt[0:20]))
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        pkt_args = list(struct.unpack('<{}L'.format(pkt_header.num_args), pkt[20:20+4*pkt_header.num_args]))
        pkt_body = pkt[20 + 4 * pkt_header.num_args:]
        pkt_body = pkt_body.rstrip(b'\0').rsplit(b'\0', maxsplit=1)

        if len(pkt_body) == 2:
            src_fname = pkt_body[1]
            log_content = pkt_body[0].decode(errors='backslashreplace')
        else:
            src_fname = b''
            log_content = pkt_body[0].decode(errors='backslashreplace')

        log_content_formatted = self._snprintf(log_content, pkt_args)

        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = pkt_ts,
            subsys_name = str(pkt_header.message_subsys_id).encode('utf-8'),
            filename = src_fname,
            line_number = pkt_header.line_no
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        return {'cp': [gsmtap_hdr + osmocore_log_hdr + log_content_formatted.encode('utf-8')], 'ts': pkt_ts}

    def parse_diag_ext_build_id(self, pkt):
        if len(pkt) < 12:
            return None

        stdout = 'Build ID: {}'.format(pkt[12:-2].decode(errors='backslashreplace'))
        return {'stdout': stdout}

    def parse_diag_ext_msg_config(self, pkt):
        if len(pkt) < 2:
            return None

        if pkt[1] == 0x01:
            # Ranges
            ext_msg_range_header = namedtuple('QcDiagExtMsgRange', 'cmd_code ts_type unk1 num_ranges unk2')
            if len(pkt) < 8:
                return None
            pkt_header = ext_msg_range_header._make(struct.unpack('<BBHHH', pkt[0:8]))
            stdout = 'Extended message range: '
            id_ranges = []

            pos = 8
            if len(pkt) < (8 + 4 * (pkt_header.num_ranges)):
                return None
            for i in range(pkt_header.num_ranges):
                id_range = struct.unpack('<HH', pkt[pos:pos+4])
                stdout += '{}-{}, '.format(id_range[0], id_range[1])
                id_ranges.append((id_range[0], id_range[1]))
                pos += 4

            return {'stdout': stdout, 'id_range': id_ranges}
        elif pkt[1] == 0x02:
            # Levels
            ext_msg_level_header = namedtuple('QcDiagExtMsgLevel', 'cmd_code ts_type start_id end_id unk1')
            if len(pkt) < 8:
                return None
            pkt_header = ext_msg_level_header._make(struct.unpack('<BBHHH', pkt[0:8]))
            stdout = 'Extended message level: \n'
            levels = []

            pos = 8
            if len(pkt) < (8 + 4 * (pkt_header.end_id - pkt_header.start_id + 1)):
                return None
            for i in range(pkt_header.end_id - pkt_header.start_id + 1):
                level = struct.unpack('<L', pkt[pos:pos+4])[0]
                stdout += 'Message ID {}: {:#x}\n'.format(pkt_header.start_id + i, level)
                levels.append((pkt_header.start_id + i, level))
                pos += 4

            return {'stdout': stdout, 'start': pkt_header.start_id, 'end': pkt_header.end_id, 'level': levels}

    def parse_diag_qsr_ext_msg(self, pkt):
        return None

    multisim_header = namedtuple('QcDiagMultiSimHeader', 'cmd_code reserved1 reserved2 radio_id')

    def parse_diag_multisim(self, pkt):
        """Parses the DIAG_MULTI_RADIO_CMD_F packet. This function calls nexted DIAG log packet with correct radio ID attached.

        Parameters:
        pkt (bytes): DIAG_MULTI_RADIO_CMD_F data without trailing CRC
        """
        # 98 | 01 | 00 00 | 01 00 00 00 -> Subscription ID=1
        # 98 | 01 | 00 00 | 02 00 00 00 -> Subscription ID=2
        # Subscription ID is base 1, 0 or -1 is also observed (we treat it as 1)
        if len(pkt) < 8:
            return

        pkt_header = self.multisim_header._make(struct.unpack('<BBHL', pkt[0:8]))
        pkt_body = pkt[8:]

        ret = self.parse_diag(pkt_body, hdlc_encoded=False, has_crc=False, args={'radio_id': self.sanitize_radio_id(pkt_header.radio_id)})
        if type(ret) == dict:
            ret['radio_id'] = self.sanitize_radio_id(pkt_header.radio_id)
        return ret

    qsr4_ext_msg_terse = namedtuple('QcDiagQsr4ExtMsgTerse', 'cmd_code ts_type num_size_args drop_cnt timestamp hash unk')
    def parse_diag_qsr4_ext_msg(self, pkt):
        if len(pkt) < 18:
            return None
        terse = self.qsr4_ext_msg_terse._make(struct.unpack('<BBBBQLH', pkt[0:18]))
        pkt_ts = util.parse_qxdm_ts(terse.timestamp)
        extra = pkt[18:]
        arg_num_size = bitstring.Bits(uint=terse.num_size_args, length=8)
        arg_num = arg_num_size[0:4].uint
        arg_size = arg_num_size[4:8].uint
        args = []

        if len(extra) != arg_num * arg_size:
            self.logger.log(logging.ERROR, 'Argument data size mismatch: expected {}, got {}'.format(arg_num * arg_size, len(extra)))
            return None
        if arg_size == 1:
            args = list(struct.unpack('<' + 'B' * arg_num, extra))
        elif arg_size == 2:
            args = list(struct.unpack('<' + 'H' * arg_num, extra))
        elif arg_size == 3:
            tmp_args = struct.unpack('3s' * arg_num, extra)
            args = [bitstring.Bits(bytes=reversed(x)).uint for x in tmp_args]
        elif arg_size == 4:
            args = list(struct.unpack('<' + 'L' * arg_num, extra))
        else:
            if arg_size != 0:
                self.logger.log(logging.ERROR, 'Argument data size mismatch: expected {}, got {}'.format(arg_num * arg_size, len(extra)))
                return None

        if terse.hash in self.qsr4_content:
            q = self.qsr4_content[terse.hash]

            osmocore_log_hdr = util.create_osmocore_logging_header(
                timestamp = pkt_ts,
                subsys_name = '{}/{:x}'.format(q.ssid, q.subsys_mask),
                filename = q.file,
                line_number = q.line
            )

            log_content_formatted = self._snprintf(q.string, args)

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.OSMOCORE_LOG)

            return {'cp': [gsmtap_hdr + osmocore_log_hdr + log_content_formatted.encode('utf-8')], 'ts': pkt_ts}

    qsh_trace_msg_terse = namedtuple('QcDiagQshTraceMsgTerse', 'cmd_code unk1 client_id unk3 arg_count unk5 unk6 unk7 unk_inc hash')
    def parse_diag_qsh_trace_msg(self, pkt):
        if len(pkt) < 16:
            return None
        terse = self.qsh_trace_msg_terse._make(struct.unpack('<B BBBBBBB L L', pkt[0:16]))
        num_args = terse.arg_count - 0x13

        if terse.hash in self.qsr4_mtrace_content:
            extra = pkt[16:]
            assert len(extra)//4 == num_args
            if num_args > 0:
                args = list(struct.unpack('<' + 'L' * num_args, extra))
            else:
                args = []

            q = self.qsr4_mtrace_content[terse.hash]
            if q.line.find('|') >= 0:
                line_num = 0
                level = 0
                log_content_formatted = q.line
            else:
                line_num = int(q.line)
                level = int(q.level)
                log_content_formatted = self._snprintf(q.string, args)

            osmocore_log_hdr = util.create_osmocore_logging_header(
                level = level,
                process_name = q.tag,
                subsys_name = q.client,
                filename = q.file,
                line_number = line_num
            )

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.OSMOCORE_LOG)

            return {'cp': [gsmtap_hdr + osmocore_log_hdr + log_content_formatted.encode('utf-8')]}
        return None

__entry__ = QualcommParser

def name():
    return 'qualcomm'

def shortname():
    return 'qc'
