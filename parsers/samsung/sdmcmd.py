#!/usr/bin/env python3
from enum import IntEnum, unique
from collections import namedtuple
import struct

@unique
class sdm_command_type(IntEnum):
    IPC_DM_CMD = 0xa0
    IPC_CT_CMD = 0xa1
    IPC_HIM_CMD = 0xa2

@unique
class sdm_command_group(IntEnum):
    CMD_CONTROL_MESSAGE = 0x00
    CMD_COMMON_DATA     = 0x01
    CMD_LTE_DATA        = 0x02
    CMD_EDGE_DATA       = 0x03
    CMD_HSPA_DATA       = 0x04
    CMD_TRACE_DATA      = 0x05
    CMD_IP_DATA         = 0x07

# Part of constants obtained from:
# https://github.com/P1sec/LTE_monitor_c2xx/blob/master/wireshark/epan/dissectors/packet-c2xx.c
@unique
class sdm_control_message(IntEnum):
    CONTROL_START                 = 0x00
    CONTROL_START_RESPONSE        = 0x01
    CONTROL_STOP                  = 0x02
    CONTROL_STOP_RESPONSE         = 0x03
    RESET_REQUEST                 = 0x04
    RESET_RESPONSE                = 0x05
    CHANGE_UPDATE_PERIOD_REQUEST  = 0x06
    CHANGE_UPDATE_PERIOD_RESPONSE = 0x07
    SLEEP_REQUEST                 = 0x08
    WAKEUP_REQUEST                = 0x09

    COMMON_ITEM_SELECT_REQUEST    = 0x10
    COMMON_ITEM_SELECT_RESPONSE   = 0x11
    COMMON_ITEM_REFRESH_REQUEST   = 0x12
    COMMON_ITEM_REFRESH_RESPONSE  = 0x13

    LTE_ITEM_SELECT_REQUEST       = 0x20
    LTE_ITEM_SELECT_RESPONSE      = 0x21
    LTE_ITEM_REFRESH_REQUEST      = 0x22
    LTE_ITEM_REFRESH_RESPONSE     = 0x23

    EDGE_ITEM_SELECT_REQUEST      = 0x30
    EDGE_ITEM_SELECT_RESPONSE     = 0x31
    EDGE_ITEM_REFRESH_REQUEST     = 0x32
    EDGE_ITEM_REFRESH_RESPONSE    = 0x33

    HSPA_ITEM_SELECT_REQUEST      = 0x40
    HSPA_ITEM_SELECT_RESPONSE     = 0x41
    HSPA_ITEM_REFRESH_REQUEST     = 0x42
    HSPA_ITEM_REFRESH_RESPONSE    = 0x43

    TRACE_ITEM_SELECT_REQUEST     = 0x50
    TRACE_ITEM_SELECT_RESPONSE    = 0x51

@unique
class sdm_common_data(IntEnum):
    COMMON_BASIC_INFO             = 0x00
    COMMON_DATA_SIGNALING_INFO    = 0x03

@unique
class sdm_lte_data(IntEnum):
    LTE_PHY_STATUS                  = 0x00
    LTE_PHY_CELL_SEARCH_MEASUREMENT = 0x01
    LTE_PHY_CELL_INFO               = 0x02
    LTE_PHY_SYSTEM_INFO             = 0x04
    LTE_PHY_CHANNEL_QUALITY_INFO    = 0x05
    LTE_PHY_PARAMETER               = 0x06
    LTE_PHY_PHICH_INFO              = 0x07

    LTE_L1_RF          = 0x10
    LTE_L1_SYNC        = 0x11
    LTE_L1_DOWNLINK    = 0x12
    LTE_L1_UPLINK      = 0x13
    LTE_L1_MEAS_CONFIG = 0x18

    LTE_L2_UL_SPECIFIC_PARAM    = 0x30
    LTE_L2_DL_SCH_CONFIG        = 0x31
    LTE_L2_UL_SCH_CONFIG        = 0x32
    LTE_L2_TIME_ALIGNMENT_TIMER = 0x33 # (N_TA uint16 / FFFF == invalid?)
    LTE_L2_PHR_CONFIG           = 0x34 # (periodicPHR-Timer uint16, prohibitPHR-Timer uint16, dl-PathlossChange uint16) RRCConnectionSetup
    LTE_L2_PREAMBLE_INFO        = 0x35 # (numberOfRA-Preambles uint16, sizeofRA-PreamblesGroupA uint16) SIB2
    LTE_L2_POWER_RAMPING_STEP   = 0x36 # (powerRampingStep uint8, preambleInitialRXTargetPower int8) SIB2
    LTE_L2_RA_SUPERVISION_INFO  = 0x37 # (preambleTransMax uint8, ra-ResponseWindowSize uint8, mac-ContentionResolutionTimer uint8) SIB2
    LTE_L2_MAX_HARQ_MSG3_TX     = 0x38 # (maxHARQ-Msg3Tx uint8) SIB2
    LTE_L2_RACH_INFO            = 0x39
    LTE_L2_RNTI_INFO            = 0x3A
    LTE_L2_UL_SYNC_STAT_INFO    = 0x3C
    LTE_L2_RB_INFO              = 0x40
    LTE_L2_RLS_STATUS_INFO      = 0x41
    LTE_L2_PDCP_UL_INFO         = 0x42
    LTE_L2_PDCP_DL_INFO         = 0x43
    LTE_L2_MAC_CONTROL_ELEMENT  = 0x48
    LTE_L2_BSR_STATISTICS       = 0x4A
    LTE_L2_RLC_STATISTICS       = 0x4B
    LTE_L2_PDCP_STATISTICS      = 0x4C

    LTE_RRC_SERVING_CELL    = 0x50
    LTE_RRC_STATUS          = 0x51 # (00 - IDLE, 01 - CONNECTING, 02 - CONNECTED)
    LTE_RRC_OTA_PACKET      = 0x52
    LTE_RRC_TIMER           = 0x53
    LTE_RRC_ASN_VERSION     = 0x54
    LTE_NAS_SIM_DATA        = 0x58
    LTE_NAS_STATUS_VARIABLE = 0x59
    LTE_NAS_EMM_MESSAGE     = 0x5A
    LTE_NAS_PLMN_SELECTION  = 0x5B
    LTE_NAS_SECURITY        = 0x5C
    LTE_NAS_PDP             = 0x5D
    LTE_NAS_IP              = 0x5E
    LTE_NAS_ESM_MESSAGE     = 0x5F

    LTE_DATA_THROUGHPUT_INFO = 0x60
    LTE_DATA_TIMING_INFO     = 0x61

@unique
class sdm_edge_data(IntEnum):
    EDGE_GSM_SERVING_CELL = 0x07

@unique
class sdm_hspa_data(IntEnum):
    HSPA_WCDMA_RRC_STATUS   = 0x20
    HSPA_WCDMA_SERVING_CELL = 0x22

sdmheader = namedtuple('SdmHeader', 'length1 zero length2 stamp direction group command timestamp')
sdmheader_ext = namedtuple('SdmHeaderExt', 'length1 zero length2 stamp direction radio_id group command timestamp')

def generate_sdm_packet(direction, group, command, payload, timestamp=0):
    pkt_len = 2 + 3 + 4 + len(payload) + 2
    pkt_header = struct.pack('<HBHHBBBL', pkt_len + 3, 0, pkt_len, 0, direction, group, command, timestamp)
    return b'\x7f' + pkt_header + payload + b'\x7e'

def parse_sdm_header(hdr):
    tmp_hdr = sdmheader._make(struct.unpack('<HBHHBBBL', hdr))
    radio_id = (tmp_hdr.group) >> 5
    group_real = tmp_hdr.group & 0x1F
    if radio_id <= 0:
        radio_id = 0
    elif radio_id > 2:
        radio_id = 1
    else:
        radio_id -= 1

    return sdmheader_ext(tmp_hdr.length1, tmp_hdr.zero, tmp_hdr.length2,
        tmp_hdr.stamp, tmp_hdr.direction, radio_id, group_real, tmp_hdr.command, tmp_hdr.timestamp)