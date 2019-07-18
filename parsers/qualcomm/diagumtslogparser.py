#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagUmtsLogParser:
    def __init__(self, parent):
        self.parent = parent
        
        self.process = {
            # UMTS (3G NAS)
            0x713A: lambda x, y, z: self.parse_umts_ue_ota(x, y, z), # UMTS UE OTA
            0x7B3A: lambda x, y, z: self.parse_umts_ue_ota_dsds(x, y, z), # UMTS DSDS NAS Signaling Messages
        }

    def parse_umts_ue_ota(self, pkt_ts, pkt, radio_id):
        msg_hdr = pkt[0:5]
        msg_content = pkt[5:]

        msg_hdr = struct.unpack('<BL', msg_hdr) # 1b direction, 4b length
        arfcn = self.parent.umts_last_uarfcn_dl[self.parent.sanitize_radio_id(radio_id)]
        if msg_hdr[0] == 1:
            # Uplink
            arfcn = self.parent.umts_last_uarfcn_ul[self.parent.sanitize_radio_id(radio_id)]

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        # msg_hdr[1] == L3 message length
        # Rest of content: L3 message
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = arfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + msg_content, radio_id, pkt_ts)

    def parse_umts_ue_ota_dsds(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_umts_ue_ota(pkt_ts, pkt[1:], radio_id_pkt)
