#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging
import binascii

class DiagLteEventParser:
    def __init__(self, parent):
        self.parent = parent

        # Event IDs are available at:
        # https://source.codeaurora.org/quic/la/platform/vendor/qcom-opensource/wlan/qcacld-2.0/tree/CORE/VOSS/inc/event_defs.h
        # https://android.googlesource.com/kernel/msm/+/android-7.1.0_r0.2/drivers/staging/qcacld-2.0/CORE/VOSS/inc/event_defs.h
        self.process = {
            1605: self.parse_event_lte_rrc_timer_status,
            1606: self.parse_event_lte_rrc_state_change,
            1609: self.parse_event_lte_rrc_dl_msg,
            1610: self.parse_event_lte_rrc_ul_msg,
            #1611: self.parse_evnet_lte_rrc_new_cell_ind,
            1614: self.parse_event_lte_rrc_paging_drx_cycle,

            #1627: self.parse_event_lte_cm_incoming_msg,
            #1628: self.parse_event_lte_cm_outgoing_msg,
            1629: self.parse_event_lte_emm_incoming_msg,
            1630: self.parse_event_lte_emm_outgoing_msg,
            1631: self.parse_event_lte_emm_timer_start,
            1632: self.parse_event_lte_emm_timer_expiry,

            #1633: self.parse_event_lte_reg_incoming_msg,
            #1634: self.parse_event_lte_reg_outgoing_msg,
            #1635: self.parse_event_lte_esm_incoming_msg,
            #1636: self.parse_event_lte_esm_outgoing_msg,
            #1637: self.parse_event_lte_esm_timer_start,
            #1638: self.parse_event_lte_esm_timer_expiry,

            1938: self.parse_event_lte_ml1_phr_report,
            1994: self.parse_event_lte_rrc_state_change_trigger,
        }

    def parse_event_lte_rrc_timer_status(self, radio_id, ts, arg_bin):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1605,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_TIMER_STATUS: {}".format(' '.join('{:02x}'.format(x) for x in arg_bin)).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_rrc_state_change(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1606,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        rrc_state_map = {
            1: "RRC_IDLE_NOT_CAMPED",
            2: "RRC_IDLE_CAMPED",
            3: "RRC_CONNECTING",
            4: "RRC_CONNECTED",
            7: "RRC_CLOSING",
        }
        if arg1 in rrc_state_map.keys():
            rrc_state = rrc_state_map[arg1]
        else:
            rrc_state = "{:02x}".format(arg1)

        log_content = "LTE_RRC_STATE_CHANGE: rrc_state={}".format(rrc_state).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

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


    def parse_event_lte_rrc_paging_drx_cycle(self, radio_id, ts, arg1, arg2):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1614,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_PAGING_DRX_CYCLE: {:02x} {:02x}".format(arg1, arg2).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_emm_incoming_msg(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1629,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        if type(arg1) == bytes:
            log_content = "LTE_RRC_EMM_INCOMING_MSG: {}".format(binascii.hexlify(arg1)).encode('utf-8')
        else:
            log_content = "LTE_RRC_EMM_INCOMING_MSG: {:02x}".format(arg1).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_emm_outgoing_msg(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1630,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_EMM_OUTGOING_MSG: {}".format(arg1).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_emm_timer_start(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1631,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_EMM_TIMER_START: {:02x}".format(arg1).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_emm_timer_expiry(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1632,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_EMM_TIMER_EXPIRY: {:02x}".format(arg1).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_ml1_phr_report(self, radio_id, ts, arg1, arg2):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1938,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_ML1_PHR_REPORT: {:02x} {:02x}".format(arg1, arg2).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)

    def parse_event_lte_rrc_state_change_trigger(self, radio_id, ts, arg1):
        osmocore_log_hdr = util.create_osmocore_logging_header(
            timestamp = ts,
            process_name = b'Event',
            pid = 1994,
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        log_content = "LTE_RRC_STATE_CHANGE_TRIGGER: {:02x}".format(arg1).encode('utf-8')

        self.parent.writer.write_cp(gsmtap_hdr + osmocore_log_hdr + log_content, radio_id, ts)
