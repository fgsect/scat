#!/usr/bin/env python3

from collections import namedtuple
import calendar
import logging
import struct

import scat.parsers.qualcomm.diagcmd as diagcmd
import scat.util as util

class DiagUmtsLogParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        i = diagcmd.diag_log_get_umts_item_id
        c = diagcmd.diag_log_code_umts
        self.process = {
            # UMTS (3G NAS)
            i(c.LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C): lambda x, y, z: self.parse_umts_ue_ota(x, y, z),
            i(c.LOG_UMTS_DSDS_NAS_SIGNALING_MESSAGE): lambda x, y, z: self.parse_umts_ue_ota_dsds(x, y, z),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def parse_umts_ue_ota(self, pkt_header, pkt_body, args):
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagUmtsUeOta', 'direction length')
        item = item_struct._make(struct.unpack('<BL', pkt_body[0:5]))
        msg_content = pkt_body[5:]

        if item.length != len(msg_content):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(msg_content), item.length))
            return None

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        # msg_hdr[1] == L3 message length
        # Rest of content: L3 message
        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = 0,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'layer': 'nas', 'cp': [gsmtap_hdr + msg_content], 'radio_id': radio_id, 'ts': pkt_ts}

    def parse_umts_ue_ota_dsds(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_umts_ue_ota(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})
