#!/usr/bin/env python3
# coding: utf8
# SPDX-License-Identifier: GPL-2.0-or-later

# Part of the source code:
# (C) 2013-2016 by Harald Welte <laforge@gnumonks.org>

from . import diagcmd
from .diaggsmlogparser import DiagGsmLogParser
from .diagwcdmalogparser import DiagWcdmaLogParser
from .diagumtslogparser import DiagUmtsLogParser
from .diagltelogparser import DiagLteLogParser
from .diag1xlogparser import Diag1xLogParser

from .diagcommoneventparser import DiagCommonEventParser
from .diaglteeventparser import DiagLteEventParser

import util
import usb
import struct
import calendar, datetime
import logging

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

        self.name = 'qualcomm'
        self.shortname = 'qc'

        self.logger = logging.getLogger('scat.qualcommparser')

        self.diag_log_parsers = [DiagGsmLogParser(self),
            DiagWcdmaLogParser(self), DiagUmtsLogParser(self),
            DiagLteLogParser(self), Diag1xLogParser(self)]

        self.process = { }
        self.no_process = { }

        for p in self.diag_log_parsers:
            self.process.update(p.process)
            try:
                self.no_process.update(p.no_process)
            except AttributeError:
                pass

        self.diag_event_parsers = [DiagCommonEventParser(self),
            DiagLteEventParser(self)]

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

    def set_parameter(self, params):
        for p in params:
            if p == 'log_level':
                self.logger.setLevel(params[p])
            elif p == 'qsr-hash':
                self.qsr_hash_filename = params[p]
                self.parse_msgs = True
            elif p == 'qsr4-hash':
                self.qsr4_hash_filename = params[p]
                self.parse_msgs = True
            elif p == 'events':
                self.parse_events = params[p]
            elif p == 'msgs':
                self.parse_msgs = params[p]

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
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00)), 0x1000, False)

        # Send empty masks
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_1x()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_wcdma()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_gsm()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_umts()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_dtv()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_lte()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_empty_tdscdma()), 0x1000, False)

        emr = lambda x, y: diagcmd.create_extended_message_config_set_mask(x, y)
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
        # Static event reporting Enable
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x01)), 0x1000, False)

        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_1x()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_wcdma()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_gsm()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_umts()), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(diagcmd.log_mask_scat_lte()), 0x1000, False)

    def parse_diag(self, pkt, hdlc_encoded = True, check_crc = True, radio_id = 0):
        # Should contain DIAG command and CRC16
        # pkt should not contain trailing 0x7E, and either HDLC encoded or not
        # When the pkt is not HDLC encoded, hdlc_encoded should be set to True
        # radio_id = 0 for default, larger than 1 for SIM 1 and such

        if len(pkt) < 3:
            return

        if hdlc_encoded:
            pkt = util.unwrap(pkt)

        # Check and strip CRC if existing
        if check_crc:
            crc = util.dm_crc16(pkt[:-2])
            crc_pkt = (pkt[-1] << 8) | pkt[-2]
            if crc != crc_pkt:
                self.logger.log(logging.WARNING, "CRC mismatch: expected 0x{:04x}, got 0x{:04x}".format(crc, crc_pkt))
                self.logger.log(logging.DEBUG, util.xxd(pkt))
            pkt = pkt[:-2]

        if pkt[0] == diagcmd.DIAG_LOG_F:
            self.parse_diag_log(pkt, radio_id)
        elif pkt[0] == diagcmd.DIAG_EVENT_REPORT_F and self.parse_events:
            self.parse_diag_event(pkt, radio_id)
        elif pkt[0] == diagcmd.DIAG_EXT_MSG_F and self.parse_msgs:
            self.parse_diag_ext_msg(pkt, radio_id)
        elif pkt[0] == diagcmd.DIAG_QSR_EXT_MSG_TERSE_F and self.parse_msgs:
            #self.parse_diag_qsr_ext_msg(pkt, radio_id)
            pass
        elif pkt[0] == diagcmd.DIAG_QSR4_EXT_MSG_TERSE_F and self.parse_msgs:
            #self.parse_diag_qsr4_ext_msg(pkt, radio_id)
            pass
        elif pkt[0] == diagcmd.DIAG_MULTI_RADIO_CMD_F:
            self.parse_diag_multisim(pkt)
        else:
            #print("Not parsing non-Log packet %02x" % pkt[0])
            #util.xxd(pkt)
            return

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
                    self.parse_diag(pkt)
                    if writer_qmdl:
                        writer_qmdl.write_cp(pkt + b'\x7e')

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        self.io_device.read(0x1000)
        self.logger.log(logging.INFO, 'Stopping diag')
        # Static event reporting Disable
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00)), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(struct.pack('<LL', diagcmd.DIAG_LOG_CONFIG_F, diagcmd.LOG_CONFIG_DISABLE_OP)), 0x1000, False)
        self.io_device.write_then_read_discard(util.generate_packet(b'\x7d\x05\x00\x00\x00\x00\x00\x00'), 0x1000, False)

    def parse_dlf(self):
        oldbuf = b''
        while True:
            buf = self.io_device.read(0x100000)
            #print("%d"% len(buf))
            if len(buf) == 0:
                break
            buf = oldbuf + buf

            pkt_len = struct.unpack('<H', buf[0:2])[0]
            while len(buf) >= pkt_len:
                # DLF lacks CRC16/other fancy stuff
                pkt = buf[0:pkt_len]
                pkt = b'\x10\x00' + pkt[0:2] + pkt
                calculated_crc = util.dm_crc16(pkt)
                pkt = pkt + struct.pack('<H', calculated_crc)

                #print("%02x %02x" % (pkt_len, len(buf)))
                self.parse_diag(pkt, hdlc_encoded = False)
                buf = buf[pkt_len:]

                if len(buf) < 2:
                    break
                pkt_len = struct.unpack('<H', buf[0:2])[0]

            oldbuf = buf

    def read_dump(self):
        while self.io_device.file_available:
            self.logger.log(logging.INFO, "Reading from {}".format(self.io_device.fname))
            if self.io_device.fname.find('.qmdl') > 0:
                self.run_diag()
            elif self.io_device.fname.find('.dlf') > 0:
                self.parse_dlf()
            else:
                self.logger.log(logging.INFO, 'Unknown baseband dump type, assuming QMDL')
                self.run_diag()
            self.io_device.open_next_file()

    def parse_diag_log(self, pkt: "DIAG_LOG_F data without trailing CRC", radio_id = 0):
        if len(pkt) < 16:
            return

        xdm_hdr = pkt[4:16]
        xdm_hdr = struct.unpack('<HHQ', xdm_hdr) # len, ID, TS
        pkt_ts = util.parse_qxdm_ts(xdm_hdr[2])
        pkt_body = pkt[16:]

        if len(pkt_body) != (xdm_hdr[0] - 12):
            self.logger.log(logging.WARNING, "Packet length mismatch: expected {}, got {}".format(xdm_hdr[0], len(pkt_body)))

        if xdm_hdr[1] in self.process.keys():
            self.process[xdm_hdr[1]](pkt_ts, pkt_body, radio_id)
        elif xdm_hdr[1] in self.no_process.keys():
            #print("Not handling XDM Header 0x%04x (%s)" % (xdm_hdr[1], self.no_process[xdm_hdr[1]]))
            return
        else:
            #print("Unhandled XDM Header 0x%04x" % xdm_hdr[1])
            #util.xxd(pkt)
            return

    def parse_diag_ext_msg(self, pkt, radio_id):
        # 79 | 00 | 00 | 00 | 00 00 1c fc 0f 16 e4 00 | e6 04 | 94 13 | 02 00 00 00 
        # cmd_code, ts_type, num_args, drop_cnt, TS, Line number, Message subsystem ID, ?
        # Message: two null-terminated strings, one for log and another for filename
        xdm_hdr = pkt[0:20]
        xdm_hdr = struct.unpack('<BBBBQHHL', xdm_hdr)
        pkt_ts = util.parse_qxdm_ts(xdm_hdr[4])
        pkt_body = pkt[20 + 4 * xdm_hdr[2]:]
        pkt_body = pkt_body.rstrip(b'\0').rsplit(b'\0', maxsplit=1)

        if len(pkt_body) == 2:
            src_fname = pkt_body[1]
            log_content = pkt_body[0]
        else:
            src_fname = b''
            log_content = pkt_body[0]

        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = pkt_ts,
            subsys_name = str(xdm_hdr[6]).encode('utf-8'),
            filename = src_fname,
            line_number = xdm_hdr[5]
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        self.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, pkt_ts)

    def parse_diag_multisim(self, pkt):
        # 98 01 00 00 | 01 00 00 00 -> Subscription ID=1
        # 98 01 00 00 | 02 00 00 00 -> Subscription ID=2
        # Subscription ID is base 1, 0 or -1 is also observed (we treat it as 1)
        if len(pkt) < 8:
            return

        xdm_hdr = pkt[0:8]
        xdm_hdr = struct.unpack('<BBHL', xdm_hdr) # cmd_id, unknown, dummy, subscription_id
        pkt_body = pkt[8:]

        self.parse_diag(pkt_body, hdlc_encoded=False, check_crc=False, radio_id = (xdm_hdr[3]))

    def parse_diag_event(self, pkt, radio_id):
        cmd_code, len_msg = struct.unpack('<BH', pkt[0:3])

        pos = 3
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
                    self.process_event[event_id](radio_id, ts)
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    print("Event: {} {}".format(event_id, ts))
            elif payload_len == 1:
                # 1x uint8
                arg1 = pkt[pos]

                if event_id in self.process_event.keys():
                    self.process_event[event_id](radio_id, ts, arg1)
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    print("Event: {} {}: 0x{:02x}".format(event_id, ts, arg1))
                pos += 1
            elif payload_len == 2:
                # 2x uint8
                arg1 = pkt[pos]
                arg2 = pkt[pos+1]

                if event_id in self.process_event.keys():
                    self.process_event[event_id](radio_id, ts, arg1, arg2)
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    print("Event: {} {}: 0x{:02x} 0x{:02x}".format(event_id, ts, arg1, arg2))
                pos += 2
            elif payload_len == 3:
                # Pascal string
                bin_len = pkt[pos]
                arg_bin = pkt[pos+1:pos+1+bin_len]

                if event_id in self.process_event.keys():
                    self.process_event[event_id](radio_id, ts, arg_bin)
                elif event_id in self.no_process_event.keys():
                    pass
                else:
                    print("Event {}: {}: Binary(len=0x{:02x}) = {}"
                    .format(event_id, ts, bin_len, ' '.join('{:02x}'.format(x) for x in arg_bin)))
                pos += (1 + pkt[pos])

    def parse_diag_qsr_ext_msg(self, pkt, radio_id):
        pass

    def parse_diag_qsr4_ext_msg(self, pkt, radio_id):
        pass

__entry__ = QualcommParser

def name():
    return 'qualcomm'

def shortname():
    return 'qc'

