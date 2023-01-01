#!/usr/bin/env python3

import util

import struct
import calendar
import logging
from collections import namedtuple

class DiagUmtsLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # UMTS (3G NAS)
            0x713A: lambda x, y, z: self.parse_umts_ue_ota(x, y, z), # UMTS UE OTA
            0x7B3A: lambda x, y, z: self.parse_umts_ue_ota_dsds(x, y, z), # UMTS DSDS NAS Signaling Messages
        }

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
            version = 3,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = 0,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'cp': [gsmtap_hdr + msg_content], 'radio_id': radio_id, 'ts': pkt_ts}

    def parse_umts_ue_ota_dsds(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_umts_ue_ota(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})
