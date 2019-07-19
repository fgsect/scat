#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagLteEventParser:
    def __init__(self, parent):
        self.parent = parent

        # Event IDs are available at:
        # https://android.googlesource.com/kernel/msm/+/android-7.1.0_r0.2/drivers/staging/qcacld-2.0/CORE/VOSS/inc/event_defs.h
        self.process = {
            1609: self.parse_event_lte_rrc_dl_msg,
            1610: self.parse_event_lte_rrc_ul_msg,
        }

    def parse_event_lte_rrc_dl_msg(self, radio_id, ts, arg1, arg2):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1609,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        channel_dl_map = {
            1: "BCCH",
            2: "PCCH",
            3: "CCCH",
            4: "DCCH"
        }

        message_type_map = {
            0x00: "MasterInformationBlock",
            0x01: "SystemInformationBlockType1",
            0x02: "SystemInformationBlockType2",
            0x03: "SystemInformationBlockType3",
            0x04: "SystemInformationBlockType4",
            0x05: "SystemInformationBlockType5",
            0x06: "SystemInformationBlockType6",
            0x07: "SystemInformationBlockType7",
            0x40: "Paging",
            0x4b: "RRCConnectionSetup",
            0x81: "DLInformationTransfer",
            0x85: "RRCConnectionRelease",
        }

        if arg1 in channel_dl_map.keys():
            channel = channel_dl_map[arg1]
        else:
            channel = "Unknown"

        if arg2 in message_type_map.keys():
            message_type = message_type_map[arg2]
        else:
            message_type = "Unknown ({:2x})".format(arg2)

        log_content = "LTE_RRC_DL_MSG: channel={}, message_type={}".format(channel, message_type).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_rrc_ul_msg(self, radio_id, ts, arg1, arg2):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1610,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        channel_ul_map = {
            5: "CCCH",
            6: "DCCH"
        }

        message_type_map = {
            0x01: "RRCConnectionRequest",
            0x84: "RRCConnectionSetupComplete",
            0x89: "ULInformationTransfer",
        }

        if arg1 in channel_ul_map.keys():
            channel = channel_ul_map[arg1]
        else:
            channel = "Unknown"

        if arg2 in message_type_map.keys():
            message_type = message_type_map[arg2]
        else:
            message_type = "Unknown ({:2x})".format(arg2)

        log_content = "LTE_RRC_UL_MSG: channel={}, message_type={}".format(channel, message_type).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

