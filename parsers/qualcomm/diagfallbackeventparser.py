#!/usr/bin/env python3

from functools import wraps
import util
import logging

class DiagFallbackEventParser:
    def __init__(self, parent):
        self.parent = parent
        self.header = b''

        # Event IDs are available at:
        # https://source.codeaurora.org/quic/la/platform/vendor/qcom-opensource/wlan/qcacld-2.0/tree/CORE/VOSS/inc/event_defs.h
        # https://android.googlesource.com/kernel/msm/+/android-7.1.0_r0.2/drivers/staging/qcacld-2.0/CORE/VOSS/inc/event_defs.h
        self.event_names = {
            # event ID, event name
        }

    def parse_event_fallback(self, ts, event_id, *args):
        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = event_id,
        )
        if event_id in self.event_names:
            log_precontent = '{}: '.format(self.event_names[event_id]).encode('utf-8')
        else:
            log_precontent = 'Event {}: '.format(event_id).encode('utf-8')

        header = gsmtap_hdr + osmocore_log_hdr + log_precontent
        log_content = b''

        if len(args) == 2:
            # arg1, arg2 -> 2x uint8
            log_content = '{:#02x} {:#02x}'.format(args[0], args[1]).encode('utf-8')
        elif len(args) == 1:
            if type(args[0]) == int:
                log_content = '{:#02x}'.format(args[0]).encode('utf-8')
            elif type(args[0]) == bytes:
                log_content = '{}'.format(' '.join('{:02x}'.format(x) for x in args[0])).encode('utf-8')
            else:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unexpected type of arguments ({}) passed to event'.format(type(args[0])))
        elif len(args) == 0:
            pass
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unexpected number of arguments ({}) passed to event'.format(len(args)))

        return header + log_content