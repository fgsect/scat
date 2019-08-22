#!/usr/bin/env python3
from enum import IntEnum, unique
import struct

# Diag command constants
# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diagcmd.h

DIAG_LOG_F = 0x10            # Log packet Request/Reponse
DIAG_DIAG_VER_F = 0x1c       # Version response
DIAG_EVENT_REPORT_F = 0x60   # Static Event reporting
DIAG_LOG_CONFIG_F = 0x73     # Logging configuration packet
DIAG_EXT_MSG_F = 0x79        # Request for extended message report
DIAG_EXT_MSG_CONFIG_F = 0x7d # Request for Extended message report
DIAG_QSR_EXT_MSG_TERSE_F = 0x92  # QSR extended messages
DIAG_QSR4_EXT_MSG_TERSE_F = 0x99 # QSR4 extended messages
DIAG_MULTI_RADIO_CMD_F = 0x98    # Found on newer dual SIMs

DIAG_SUBSYS_ID_1X = 0x01
DIAG_SUBSYS_ID_WCDMA = 0x04
DIAG_SUBSYS_ID_GSM = 0x05
DIAG_SUBSYS_ID_UMTS = 0x07
DIAG_SUBSYS_ID_DTV = 0x0A
DIAG_SUBSYS_ID_APPS = 0x0B
DIAG_SUBSYS_ID_LTE = 0x0B
DIAG_SUBSYS_ID_TDSCDMA = 0x0D

# Log configuration operations
# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log.c
LOG_CONFIG_DISABLE_OP = 0
LOG_CONFIG_RETRIEVE_ID_RANGES_OP = 1
LOG_CONFIG_RETRIEVE_VALID_MASK_OP = 2
LOG_CONFIG_SET_MASK_OP = 3
LOG_CONFIG_GET_LOGMASK_OP = 4

# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log_1x.h
def diag_log_get_1x_item_id(x):
    return 0x1000 + x

@unique
class diag_log_code_1x(IntEnum):
    LOG_UIM_DATA_C = 0x98                                         # 0x1098 RUIM Debug
    LOG_INTERNAL_CORE_DUMP_C = 0x158                              # 0x1158 Internal - Core Dump
    LOG_DATA_PROTOCOL_LOGGING_C = 0x1eb                           # 0x11EB Protocol Services Data
    LOG_GENERIC_SIM_TOOLKIT_TASK_C = 0x272                        # 0x1272 Generic SIM Toolkit Task
    LOG_UIM_DS_DATA_C = 0x4ce                                     # 0x14CE UIM DS Data
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_TX_80_BYTES_C = 0x572 # 0x1572 Network IP Rm Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_RX_80_BYTES_C = 0x573 # 0x1573 Network IP Rm Rx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_TX_FULL_C = 0x574     # 0x1574 Network IP Rm Tx Full
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_RX_FULL_C = 0x575     # 0x1575 Network IP Rm Rx Full
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_TX_80_BYTES_C = 0x576 # 0x1576 Network IP Um Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_RX_80_BYTES_C = 0x577 # 0x1577 Network IP Um Rx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_TX_FULL_C = 0x578     # 0x1578 Network IP Um Tx Full
    LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_RX_FULL_C = 0x579     # 0x1579 Network IP Um Rx Full
    LOG_DATA_PROTOCOL_LOGGING_LINK_RM_TX_80_BYTES_C = 0x57a       # 0x157A Link Rm Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_LINK_RM_RX_80_BYTES_C = 0x57b       # 0x157B Link Rm Rx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_LINK_RM_TX_FULL_C = 0x57c           # 0x157C Link Rm Tx Full
    LOG_DATA_PROTOCOL_LOGGING_LINK_RM_RX_FULL_C = 0x57d           # 0x157D Link Rm Rx Full
    LOG_DATA_PROTOCOL_LOGGING_LINK_UM_TX_80_BYTES_C = 0x57e       # 0x157E Link Um Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_LINK_UM_RX_80_BYTES_C = 0x57f       # 0x157F Link Um Rx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_LINK_UM_TX_FULL_C = 0x580           # 0x1580 Link Um Tx Full
    LOG_DATA_PROTOCOL_LOGGING_LINK_UM_RX_FULL_C = 0x581           # 0x1581 Link Um Rx Full
    LOG_DATA_PROTOCOL_LOGGING_FLOW_RM_TX_80_BYTES_C = 0x582       # 0x1582 Flow Rm Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_FLOW_RM_TX_FULL_C = 0x583           # 0x1583 Flow Rm Tx Full
    LOG_DATA_PROTOCOL_LOGGING_FLOW_UM_TX_80_BYTES_C = 0x584       # 0x1584 Flow Um Tx 80 Bytes
    LOG_DATA_PROTOCOL_LOGGING_FLOW_UM_TX_FULL_C = 0x585           # 0x1585 Flow Um Tx Full

# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log_wcdma.h
def diag_log_get_wcdma_item_id(x):
    return 0x4000 + x

@unique
class diag_log_code_wcdma(IntEnum):
    LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C = 0x5 # 0x4005 WCDMA Search Cell Reselection Rank
    LOG_WCDMA_CELL_ID_C = 0x127                    # 0x4127 WCDMA Cell ID
    LOG_WCDMA_SIB_C = 0x12b                        # 0x412B WCDMA SIB
    LOG_WCDMA_SIGNALING_MSG_C = 0x12f              # 0x412F WCDMA Signaling Messages

# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log_gsm.h
def diag_log_get_gsm_item_id(x):
    return 0x5000 + x

@unique
class diag_log_code_gsm(IntEnum):
    # Layer 1
    LOG_GSM_L1_FCCH_ACQUISITION_C = 0x65       # 0x5065 GSM L1 FCCH Acquisition
    LOG_GSM_L1_SCH_ACQUISITION_C = 0x66        # 0x5066 GSM L1 SCH Acquisition
    LOG_GSM_L1_NEW_BURST_METRICS_C = 0x6a      # 0x506A GSM L1 New Burst Metrics
    LOG_GSM_L1_BURST_METRICS_C = 0x6c          # 0x506C GSM L1 Burst Metrics
    LOG_GSM_L1_SCELL_BA_LIST_C = 0x71          # 0x5071 GSM Surround Cell BA List
    LOG_GSM_L1_SCELL_AUX_MEASUREMENTS_C = 0x7a # 0x507A GSM L1 Serving Auxiliary Measurments
    LOG_GSM_L1_NCELL_AUX_MEASUREMENTS_C = 0x7b # 0x507B GSM L1 Neighbor Cell Auxiliary Measurments

    # Layer 3
    LOG_GSM_RR_SIGNALING_MESSAGE_C = 0x12f # 0x512F GSM RR Signaling Message
    LOG_GSM_RR_CELL_INFORMATION_C = 0x134  # 0x5134 GSM RR Cell Information

    # GPRS, Layer 3
    LOG_GPRS_RR_PACKET_SI_1_C = 0x1fd               # 0x51FD GPRS RR Packet System Information 1
    LOG_GPRS_RR_PACKET_SI_2_C = 0x1fe               # 0x51FE GPRS RR Packet System Information 2
    LOG_GPRS_RR_PACKET_SI_3_C = 0x1ff               # 0x51FF GPRS RR Packet System Information 3
    LOG_GPRS_MAC_SIGNALING_MESSACE_C = 0x226        # 0x5226 GPRS MAC Signaling Message
    LOG_GPRS_SM_GMM_OTA_SIGNALING_MESSAGE_C = 0x230 # 0x5230 GPRS SM/GMM OTA Signaling Message

    # DSDS, Layer 1
    LOG_GSM_DSDS_L1_FCCH_ACQUISITION_C = 0xa65       # 0x5A65 GSM DSDS L1 FCCH Acquisition
    LOG_GSM_DSDS_L1_SCH_ACQUISITION_C = 0xa66        # 0x5A66 GSM DSDS L1 SCH Acquisition
    LOG_GSM_DSDS_L1_BURST_METRICS_C = 0xa6c          # 0x5A6C GSM DSDS L1 Burst Metrics
    LOG_GSM_DSDS_L1_SCELL_BA_LIST_C = 0xa71          # 0x5A71 GSM DSDS Surround Cell BA List
    LOG_GSM_DSDS_L1_SCELL_AUX_MEASUREMENTS_C = 0xa7a # 0x5A7A GSM DSDS L1 Serving Auxiliary Measurments
    LOG_GSM_DSDS_L1_NCELL_AUX_MEASUREMENTS_C = 0xa7b # 0x5A7B GSM DSDS L1 Neighbor Cell Auxiliary Measurments

    # DSDS, Layer 3
    LOG_GSM_DSDS_RR_SIGNALING_MESSAGE_C = 0xb2f # 0x5B2F GSM DSDS RR Signaling Message
    LOG_GSM_DSDS_RR_CELL_INFORMATION_C = 0xb34  # 0x5B34 GSM DSDS RR Cell Information

    # DSDS GPRS, Layer 3
    LOG_GPRS_DSDS_RR_PACKET_SI_1_C = 0xbfd # 0x5BFD GPRS DSDS RR Packet System Information 1
    LOG_GPRS_DSDS_RR_PACKET_SI_2_C = 0xbfe # 0x5BFE GPRS DSDS RR Packet System Information 2
    LOG_GPRS_DSDS_RR_PACKET_SI_3_C = 0xbff # 0x5BFF GPRS DSDS RR Packet System Information 3

# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log_umts.h
def diag_log_get_umts_item_id(x):
    return 0x7000 + x

@unique
class diag_log_code_umts(IntEnum):
    LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C = 0x13a # 0x713A UMTS UE OTA
    LOG_UMTS_DSDS_NAS_SIGNALING_MESSAGE = 0xb3a   # 0x7B3A UMTS DSDS NAS Signaling Messages

# https://osmocom.org/projects/quectel-modems/wiki/Diag
def diag_log_get_lte_item_id(x):
    return 0xB000 + x

@unique
class diag_log_code_lte(IntEnum):
    # Management Layer 1
    LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL = 0x17F # 0xB17F LTE ML1 Serving Cell Meas and Eval
    LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS = 0x180      # 0xB180 LTE ML1 Neighbor Measurements
    LOG_LTE_ML1_SERVING_CELL_INFO = 0x197          # 0xB197 LTE ML1 Serving Cell Information

    # MAC
    LOG_LTE_MAC_RACH_TRIGGER = 0x61       # 0xB061 LTE MAC RACH Trigger
    LOG_LTE_MAC_RACH_RESPONSE = 0x62      # 0xB062 LTE MAC Rach Attempt
    LOG_LTE_MAC_DL_TRANSPORT_BLOCK = 0x63 # 0xB063 LTE MAC DL Transport Block
    LOG_LTE_MAC_UL_TRANSPORT_BLOCK = 0x64 # 0xB064 LTE MAC UL Transport Block

    # RRC
    LOG_LTE_RRC_OTA_MESSAGE = 0xC0 # 0xB0C0 LTE RRC OTA Packet
    LOG_LTE_RRC_MIB_MESSAGE = 0xC1 # 0xB0C1 LTE RRC MIB Message Log Packet
    LOG_LTE_RRC_SERVING_CELL_INFO = 0xC2 # 0xB0C2 LTE RRC Serving Cell Info Log Pkt

    # NAS
    LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE   = 0xE0 # 0xB0E0 LTE NAS EMM Security Protected Incoming Msg
    LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE   = 0xE1 # 0xB0E1 LTE NAS EMM Security Protected Outgoing Msg
    LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE = 0xE2 # 0xB0E2 LTE NAS EMM Plain OTA Incoming Message
    LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE = 0xE3 # 0xB0E3 LTE NAS EMM Plain OTA Outgoing Message
    LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE   = 0xEA # 0xB0EA LTE NAS EMM Security Protected Incoming Msg
    LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE   = 0xEB # 0xB0EB LTE NAS EMM Security Protected Outgoing Msg
    LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE = 0xEC # 0xB0EC LTE NAS EMM Plain OTA Incoming Message
    LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE = 0xED # 0xB0ED LTE NAS EMM Plain OTA Outgoing Message

def bytes_reqd_for_bit(bit):
    if bit % 8 > 0:
        return int(bit / 8) + 1
    else:
        return int(bit / 8)

def create_log_config_set_mask(equip_id, last_item, *bits):
    # Command ID, Operation | equip_id, last_item, bitfields
    diag_log_config_mask_header = struct.pack('<LLLL',
        DIAG_LOG_CONFIG_F, LOG_CONFIG_SET_MASK_OP,
        equip_id, last_item)
    diag_log_config_mask_payload = bytearray(b'\x00' * bytes_reqd_for_bit(last_item))

    for bit in bits:
        if bit > last_item:
            print("Bit 0x%d is outside of maximal items" % (bit))
            continue

        pos_byte = int(bit / 8)
        pos_bit = bit % 8
        diag_log_config_mask_payload[pos_byte] |= (1 << pos_bit)

    return diag_log_config_mask_header + bytes(diag_log_config_mask_payload)

# Preferred log masks used by SCAT
def log_mask_empty_1x():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_1X, 0x0fff)

def log_mask_scat_1x():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_1X, 0x0847,
        diag_log_code_1x.LOG_UIM_DATA_C,
        diag_log_code_1x.LOG_INTERNAL_CORE_DUMP_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_C,
        diag_log_code_1x.LOG_GENERIC_SIM_TOOLKIT_TASK_C,
        diag_log_code_1x.LOG_UIM_DS_DATA_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_RX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_TX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_RM_RX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_RX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_TX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_NETWORK_IP_UM_RX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_RM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_RM_RX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_RM_TX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_RM_RX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_UM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_UM_RX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_UM_TX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_LINK_UM_RX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_FLOW_RM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_FLOW_RM_TX_FULL_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_FLOW_UM_TX_80_BYTES_C,
        diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_FLOW_UM_TX_FULL_C,
        0x648, # 0x1648   Indoor Info
        0x649, # 0x1649   Indoor RTS CTS Scan
        0x650, # 0x1650   Indoor Active Scan
        0x651, # 0x1651   Unrecognized
        0x652, # 0x1652   Unrecognized
        0x653, # 0x1653   Unrecognized
        0x654, # 0x1654   Unrecognized
        )

def log_mask_empty_wcdma():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_WCDMA, 0x0ff7)

def log_mask_scat_wcdma():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_WCDMA, 0x0ff7,
        diag_log_code_wcdma.LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C,
        diag_log_code_wcdma.LOG_WCDMA_CELL_ID_C,
        diag_log_code_wcdma.LOG_WCDMA_SIB_C,
        diag_log_code_wcdma.LOG_WCDMA_SIGNALING_MSG_C
        )

def log_mask_empty_gsm():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_GSM, 0x0ff7)

def log_mask_scat_gsm():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_GSM, 0x0ff7,
        diag_log_code_gsm.LOG_GSM_L1_FCCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_L1_SCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_L1_NEW_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_L1_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_L1_SCELL_BA_LIST_C,
        diag_log_code_gsm.LOG_GSM_L1_SCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_L1_NCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_RR_SIGNALING_MESSAGE_C,
        diag_log_code_gsm.LOG_GSM_RR_CELL_INFORMATION_C,
        diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_1_C,
        diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_2_C,
        diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_3_C,
        diag_log_code_gsm.LOG_GPRS_MAC_SIGNALING_MESSACE_C,
        diag_log_code_gsm.LOG_GPRS_SM_GMM_OTA_SIGNALING_MESSAGE_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_FCCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCELL_BA_LIST_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_NCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_RR_SIGNALING_MESSAGE_C,
        diag_log_code_gsm.LOG_GSM_DSDS_RR_CELL_INFORMATION_C,
        diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_1_C,
        diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_2_C,
        diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_3_C,
    )

def log_mask_empty_umts():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_UMTS, 0x0b5e)

def log_mask_scat_umts():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_UMTS, 0x0b5e,
        diag_log_code_umts.LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
        diag_log_code_umts.LOG_UMTS_DSDS_NAS_SIGNALING_MESSAGE,
    )

def log_mask_empty_dtv():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_DTV, 0x0392)

def log_mask_empty_lte():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, 0x0209)

def log_mask_scat_lte():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, 0x0209,
        diag_log_code_lte.LOG_LTE_MAC_RACH_RESPONSE,
        diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL,
        diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS,
        diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_INFO,
        diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE,
        diag_log_code_lte.LOG_LTE_RRC_MIB_MESSAGE,
        diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO,
        diag_log_code_lte.LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE,
        diag_log_code_lte.LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE
    )

def log_mask_empty_tdscdma():
    return create_log_config_set_mask(DIAG_SUBSYS_ID_TDSCDMA, 0x0207)

def create_extended_message_config_set_mask(first_ssid, last_ssid, *masks):
    # Command ID, Operation | first_ssid, last_ssid, runtime_masks
    diag_log_config_mask_header = struct.pack('<BBHHH',
        DIAG_EXT_MSG_CONFIG_F, 0x04,
        first_ssid, last_ssid, 0x00)
    ext_msg_config_mask_payload = bytearray(b'\x00\x00\x00\x00' * (last_ssid - first_ssid + 1))

    # Each subsystem ID has own log level
    # Currently Extended messages are not parsed so do nothing
    for mask in masks:
        pass

    return diag_log_config_mask_header + bytes(ext_msg_config_mask_payload)
