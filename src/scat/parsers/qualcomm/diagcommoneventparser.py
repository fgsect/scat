#!/usr/bin/env python3

from functools import wraps
import calendar, datetime
import logging
import struct
import uuid

from scat.parsers.qualcomm import diagcmd
import scat.util as util

class DiagCommonEventParser:
    def __init__(self, parent):
        self.parent = parent
        self.header = b''

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        # Event IDs are available at:
        # https://source.codeaurora.org/quic/la/platform/vendor/qcom-opensource/wlan/qcacld-2.0/tree/CORE/VOSS/inc/event_defs.h
        # https://android.googlesource.com/kernel/msm/+/android-7.1.0_r0.2/drivers/staging/qcacld-2.0/CORE/VOSS/inc/event_defs.h
        self.process = {
            #621: self.parse_event_sd_event_action,
            1682: (self.parse_event_ipv6_sm_event, 'IPV6_SM_EVENT'),
            1684: (self.parse_event_ipv6_prefix_update, 'IPV6_PREFIX_UPDATE'),
            #1742: self.parse_event_cm_ds_call_event_orig_thr,
            2865: (self.parse_event_diag_qshrink_id, 'DIAG_QSHRINK_ID'),
            2866: (self.parse_event_diag_process_name_id, 'DIAG_PROCESS_NAME'),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def build_header(func):
        @wraps(func)
        def wrapped_function(self, *args, **kwargs):
            osmocore_log_hdr = util.create_osmocore_logging_header(
                timestamp = args[0],
                process_name = b'Event',
                pid = args[1],
            )

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.OSMOCORE_LOG)

            log_precontent = "{}: ".format(self.process[args[1]][1]).encode('utf-8')

            self.header = gsmtap_hdr + osmocore_log_hdr + log_precontent
            return func(self, *args, **kwargs)
        return wrapped_function

    @build_header
    def parse_event_ipv6_sm_event(self, ts, event_id, arg_bin):
        # Event 1682: 2023-01-01 15:02:20.275880: Binary(len=0x04) = 04 80 02 03
        log_content = "{}".format(' '.join('{:02x}'.format(x) for x in arg_bin)).encode('utf-8')

        return self.header + log_content

    @build_header
    def parse_event_ipv6_prefix_update(self, ts, event_id, arg_bin):
        # Event 1684: 2018-10-25 18:40:03.870095: Binary(len=0x18) = 04 80 02 03 | 00 00 00 00 | 2a 02 30 3e 28 02 48 9c | 40 00 00 00 | 00 00 00 00
        log_content = "{}".format(' '.join('{:02x}'.format(x) for x in arg_bin)).encode('utf-8')

        return self.header + log_content


    @build_header
    def parse_event_diag_qshrink_id(self, ts, event_id, arg_bin):
        diag_id = arg_bin[0]
        diag_uuid = arg_bin[1:]
        diag_uuid_real = uuid.UUID(bytes_le=b'\x00'*16)

        if len(diag_uuid) == 16:
            diag_uuid_real = uuid.UUID(bytes_le=diag_uuid)

        log_content = "diag_id={}, diag_uuid={}".format(diag_id, diag_uuid_real).encode('utf-8')

        return self.header + log_content

    @build_header
    def parse_event_diag_process_name_id(self, ts, event_id, arg_bin):
        diag_id = arg_bin[0]
        diag_process_name = arg_bin[1:].decode(errors='backslashreplace')

        log_content = "diag_id={}, diag_process_name={}".format(diag_id, diag_process_name).encode('utf-8')

        return self.header + log_content

