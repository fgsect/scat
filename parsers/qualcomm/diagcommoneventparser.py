#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging
import uuid

class DiagCommonEventParser:
    def __init__(self, parent):
        self.parent = parent

        # Event IDs are available at:
        # https://source.codeaurora.org/quic/la/platform/vendor/qcom-opensource/wlan/qcacld-2.0/tree/CORE/VOSS/inc/event_defs.h
        # https://android.googlesource.com/kernel/msm/+/android-7.1.0_r0.2/drivers/staging/qcacld-2.0/CORE/VOSS/inc/event_defs.h
        self.process = {
            #621: self.parse_event_sd_event_action,
            #1682: self.parse_event_ipv6_sm_event,
            #1742: self.parse_event_cm_ds_call_event_orig_thr,
            2865: self.parse_event_diag_qshrink_id,
            2866: self.parse_event_diag_process_name_id,
        }

    def parse_event_diag_qshrink_id(self, radio_id, ts, arg_bin):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 2865,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        diag_id = arg_bin[0]
        diag_uuid = arg_bin[1:]
        diag_uuid_real = uuid.UUID(bytes_le=b'\x00'*16)

        if len(diag_uuid) == 16:
            diag_uuid_real = uuid.UUID(bytes_le=diag_uuid)

        log_content = "DIAG_QSHRINK_ID: diag_id={}, diag_uuid={}".format(diag_id, diag_uuid_real).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_diag_process_name_id(self, radio_id, ts, arg_bin):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 2866,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        diag_id = arg_bin[0]
        diag_process_name = arg_bin[1:].decode('utf-8')

        log_content = "DIAG_PROCESS_NAME: diag_id={}, diag_process_name={}".format(diag_id, diag_process_name).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

