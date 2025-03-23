#!/usr/bin/env python3
from enum import IntEnum, unique
import struct

# Diag command constants
# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diagcmd.h

DIAG_VERNO_F              = 0x00
DIAG_STATUS_F             = 0x0c
DIAG_LOG_F                = 0x10 # Log packet Request/Reponse
DIAG_BAD_CMD_F            = 0x13
DIAG_DIAG_VER_F           = 0x1c # Version response
DIAG_TS_F                 = 0x1d
DIAG_SUBSYS_CMD_F         = 0x4b
DIAG_EVENT_REPORT_F       = 0x60 # Static Event reporting
DIAG_STATUS_SNAPSHOT_F    = 0x63
DIAG_LOG_CONFIG_F         = 0x73 # Logging configuration packet
DIAG_EXT_MSG_F            = 0x79 # Request for extended message report
DIAG_EXT_BUILD_ID_F       = 0x7c
DIAG_EXT_MSG_CONFIG_F     = 0x7d # Request for Extended message report
DIAG_SUBSYS_CMD_VER_2_F   = 0x80
DIAG_EVENT_MASK_GET_F     = 0x81
DIAG_EVENT_MASK_SET_F     = 0x82
DIAG_QSR_EXT_MSG_TERSE_F  = 0x92 # QSR extended messages
DIAG_MULTI_RADIO_CMD_F    = 0x98 # Found on newer dual SIMs
DIAG_QSR4_EXT_MSG_TERSE_F = 0x99 # QSR4 extended messages
DIAG_MSG_SMALL_F          = 0x9c
DIAG_QSH_TRACE_PAYLOAD_F  = 0x9d

DIAG_SUBSYS_ID_1X = 0x01
DIAG_SUBSYS_ID_WCDMA = 0x04
DIAG_SUBSYS_ID_GSM = 0x05
DIAG_SUBSYS_ID_UMTS = 0x07
DIAG_SUBSYS_ID_DTV = 0x0A
DIAG_SUBSYS_ID_APPS = 0x0B
DIAG_SUBSYS_ID_LTE = 0x0B # Also shared by NR
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
    # SIM
    LOG_UIM_DATA_C = 0x98                                         # 0x1098 RUIM Debug
    LOG_GENERIC_SIM_TOOLKIT_TASK_C = 0x272                        # 0x1272 Generic SIM Toolkit Task
    LOG_UIM_DS_DATA_C = 0x4ce                                     # 0x14CE UIM DS Data

    # IP
    LOG_DATA_PROTOCOL_LOGGING_C = 0x1eb                           # 0x11EB Protocol Services Data
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

    # IMS
    LOG_IMS_RTP_SN_PAYLOAD = 0x568                                # 0x1568 IMS RTP SN and Payload
    LOG_IMS_RTP_PACKET_LOSS = 0x569                               # 0x1569 IMS RTP Packet Loss
    LOG_IMS_RTCP = 0x56A                                          # 0x156A IMS RTCP
    LOG_IMS_SIP_MESSAGE = 0x56E                                   # 0x156E IMS SIP Message
    LOG_IMS_VOICE_CALL_STATS = 0x7F2                              # 0x17F2 IMS Voice Call Statistics
    LOG_IMS_VOLTE_SESSION_SETUP = 0x830                           # 0x1830 IMS VoLTE Session Setup
    LOG_IMS_VOLTE_SESSION_END = 0x831                             # 0x1831 IMS VoLTE Session End
    LOG_IMS_REGISTRATION = 0x832                                  # 0x1832 IMS Registration

    # QMI
    LOG_QMI_LINK_01_RX_MSG_C = 0x38e                              # 0x138E QMI Link 1 RX Message
    LOG_QMI_LINK_01_TX_MSG_C = 0x38f                              # 0x138E QMI Link 1 TX Message
    LOG_QMI_LINK_02_RX_MSG_C = 0x390                              # 0x138E QMI Link 2 RX Message
    LOG_QMI_LINK_02_TX_MSG_C = 0x391                              # 0x138E QMI Link 2 TX Message
    LOG_QMI_LINK_03_RX_MSG_C = 0x392                              # 0x138E QMI Link 3 RX Message
    LOG_QMI_LINK_03_TX_MSG_C = 0x393                              # 0x138E QMI Link 3 TX Message
    LOG_QMI_LINK_04_RX_MSG_C = 0x394                              # 0x138E QMI Link 4 RX Message
    LOG_QMI_LINK_04_TX_MSG_C = 0x395                              # 0x138E QMI Link 4 TX Message
    LOG_QMI_LINK_05_RX_MSG_C = 0x396                              # 0x138E QMI Link 5 RX Message
    LOG_QMI_LINK_05_TX_MSG_C = 0x397                              # 0x138E QMI Link 5 TX Message
    LOG_QMI_LINK_06_RX_MSG_C = 0x398                              # 0x138E QMI Link 6 RX Message
    LOG_QMI_LINK_06_TX_MSG_C = 0x399                              # 0x138E QMI Link 6 TX Message
    LOG_QMI_LINK_07_RX_MSG_C = 0x39a                              # 0x138E QMI Link 7 RX Message
    LOG_QMI_LINK_07_TX_MSG_C = 0x39b                              # 0x138E QMI Link 7 TX Message
    LOG_QMI_LINK_08_RX_MSG_C = 0x39c                              # 0x138E QMI Link 8 RX Message
    LOG_QMI_LINK_08_TX_MSG_C = 0x39d                              # 0x138E QMI Link 8 TX Message
    LOG_QMI_LINK_09_RX_MSG_C = 0x39e                              # 0x138E QMI Link 9 RX Message
    LOG_QMI_LINK_09_TX_MSG_C = 0x39f                              # 0x138E QMI Link 9 TX Message
    LOG_QMI_LINK_10_RX_MSG_C = 0x3a0                              # 0x138E QMI Link 10 RX Message
    LOG_QMI_LINK_10_TX_MSG_C = 0x3a1                              # 0x138E QMI Link 10 TX Message
    LOG_QMI_LINK_11_RX_MSG_C = 0x3a2                              # 0x138E QMI Link 11 RX Message
    LOG_QMI_LINK_11_TX_MSG_C = 0x3a3                              # 0x138E QMI Link 11 TX Message
    LOG_QMI_LINK_12_RX_MSG_C = 0x3a4                              # 0x138E QMI Link 12 RX Message
    LOG_QMI_LINK_12_TX_MSG_C = 0x3a5                              # 0x138E QMI Link 12 TX Message
    LOG_QMI_LINK_13_RX_MSG_C = 0x3a6                              # 0x138E QMI Link 13 RX Message
    LOG_QMI_LINK_13_TX_MSG_C = 0x3a7                              # 0x138E QMI Link 13 TX Message
    LOG_QMI_LINK_14_RX_MSG_C = 0x3a8                              # 0x138E QMI Link 14 RX Message
    LOG_QMI_LINK_14_TX_MSG_C = 0x3a9                              # 0x138E QMI Link 14 TX Message
    LOG_QMI_LINK_15_RX_MSG_C = 0x3aa                              # 0x138E QMI Link 15 RX Message
    LOG_QMI_LINK_15_TX_MSG_C = 0x3ab                              # 0x138E QMI Link 15 TX Message
    LOG_QMI_LINK_16_RX_MSG_C = 0x3ac                              # 0x138E QMI Link 16 RX Message
    LOG_QMI_LINK_16_TX_MSG_C = 0x3ad                              # 0x138E QMI Link 16 TX Message
    LOG_QMI_LINK_17_RX_MSG_C = 0x80b                              # 0x138E QMI Link 17 RX Message
    LOG_QMI_LINK_17_TX_MSG_C = 0x80c                              # 0x138E QMI Link 17 TX Message
    LOG_QMI_LINK_18_RX_MSG_C = 0x80d                              # 0x138E QMI Link 18 RX Message
    LOG_QMI_LINK_18_TX_MSG_C = 0x80e                              # 0x138E QMI Link 18 TX Message
    LOG_QMI_LINK_19_RX_MSG_C = 0x80f                              # 0x138E QMI Link 19 RX Message
    LOG_QMI_LINK_19_TX_MSG_C = 0x810                              # 0x138E QMI Link 19 TX Message
    LOG_QMI_LINK_20_RX_MSG_C = 0x811                              # 0x138E QMI Link 20 RX Message
    LOG_QMI_LINK_20_TX_MSG_C = 0x812                              # 0x138E QMI Link 20 TX Message
    LOG_QMI_LINK_21_RX_MSG_C = 0x92b                              # 0x138E QMI Link 21 RX Message
    LOG_QMI_LINK_21_TX_MSG_C = 0x02c                              # 0x138E QMI Link 21 TX Message
    LOG_QMI_CALL_FLOW_C = 0x4cf                                   # 0x14CF QMI Call Flow
    LOG_QMI_SUPPORTED_INTERFACES_C = 0x588                        # 0x1588 QMI Supported Interfaces

    # General
    LOG_INTERNAL_CORE_DUMP_C = 0x158                              # 0x1158 Internal - Core Dump

# Origin: http://cgit.osmocom.org/osmo-qcdiag/tree/src/protocol/diag_log_wcdma.h
def diag_log_get_wcdma_item_id(x):
    return 0x4000 + x

@unique
class diag_log_code_wcdma(IntEnum):
    # Layer 1
    LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C = 0x5 # 0x4005 WCDMA Search Cell Reselection Rank
    LOG_WCDMA_PN_SEARCH_EDITION_2_C          = 0x179 # 0x4179 WCDMA PN Search Edition 2
    LOG_WCDMA_FREQ_SCAN_C                    = 0x1b0 # 0x41B0 WCDMA Freq Scan

    # Layer 2
    LOG_WCDMA_RLC_DL_AM_SIGNALING_PDU_C   = 0x135 # 0x4135 WCDMA RLC DL AM Signaling PDU
    LOG_WCDMA_RLC_UL_AM_SIGNALING_PDU_C   = 0x13c # 0x413C WCDMA RLC UL AM Signaling PDU
    LOG_WCDMA_RLC_UL_AM_CONTROL_PDU_LOG_C = 0x145 # 0x4145 WCDMA RLC UL AM Control PDU Log
    LOG_WCDMA_RLC_DL_AM_CONTROL_PDU_LOG_C = 0x146 # 0x4146 WCDMA RLC DL AM Control PDU Log
    LOG_WCDMA_RLC_DL_PDU_CIPHER_PACKET_C  = 0x168 # 0x4168 WCDMA RLC DL PDU Cipher Packet
    LOG_WCDMA_RLC_UL_PDU_CIPHER_PACKET_C  = 0x169 # 0x4169 WCDMA RLC DL PDU Cipher Packet

    # RRC
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
    LOG_LTE_ML1_MAC_RAR_MSG1_REPORT    = 0x167 # 0xB167 LTE MAC RAR (Msg1) Report
    LOG_LTE_ML1_MAC_RAR_MSG2_REPORT    = 0x168 # 0xB168 LTE MAC RAR (Msg2) Report
    LOG_LTE_ML1_MAC_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT     = 0x169 # 0xB169 LTE MAC RAR (Msg3) Report
    LOG_LTE_ML1_MAC_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT = 0x16A # 0xB16A LTE MAC RAR (Msg4) Report
    LOG_LTE_ML1_CONNECTED_MODE_INTRA_FREQ_MEAS  = 0x179 # 0xB179 LTE ML1 Connected Mode LTE Intra-Freq Measurements
    LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL      = 0x17f # 0xB17F LTE ML1 Serving Cell Meas and Eval
    LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS           = 0x180 # 0xB180 LTE ML1 Neighbor Measurements
    LOG_LTE_ML1_INTRA_FREQ_CELL_RESELECTION     = 0x181 # 0xB181 LTE ML1 Intra Frequency Cell Reselection
    LOG_LTE_ML1_NEIGHBOR_CELL_MEAS_REQ_RESPONSE = 0x192 # B192 LTE ML1 Neighbor Cell Meas Request/Response
    LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE      = 0x193 # 0xB193 LTE ML1 Serving Cell Meas Response
    LOG_LTE_ML1_SEARCH_REQ_RESPONSE             = 0x194 # 0xB194 LTE ML1 Search Request/Response
    LOG_LTE_ML1_CONNECTED_MODE_NEIGHBOR_MEAS_REQ_RESPONSE = 0x195 # 0xB195 LTE ML1 Connected Neighbor Meas Request/Response
    LOG_LTE_ML1_SERVING_CELL_INFO               = 0x197 # 0xB197 LTE ML1 Serving Cell Information

    # MAC
    LOG_LTE_MAC_RACH_TRIGGER       = 0x61 # 0xB061 LTE MAC RACH Trigger
    LOG_LTE_MAC_RACH_RESPONSE      = 0x62 # 0xB062 LTE MAC Rach Attempt
    LOG_LTE_MAC_DL_TRANSPORT_BLOCK = 0x63 # 0xB063 LTE MAC DL Transport Block
    LOG_LTE_MAC_UL_TRANSPORT_BLOCK = 0x64 # 0xB064 LTE MAC UL Transport Block

    # PDCP
    LOG_LTE_PDCP_DL_CONFIG                 = 0xa0 # 0xB0A0 LTE PDCP DL Config
    LOG_LTE_PDCP_UL_CONFIG                 = 0xb0 # 0xB0B0 LTE PDCP UL Config
    LOG_LTE_PDCP_DL_DATA_PDU               = 0xa1 # 0xB0A1 LTE PDCP DL Data PDU
    LOG_LTE_PDCP_UL_DATA_PDU               = 0xb1 # 0xB0B1 LTE PDCP UL Data PDU
    LOG_LTE_PDCP_DL_CONTROL_PDU            = 0xa2 # 0xB0A2 LTE PDCP DL Ctrl PDU
    LOG_LTE_PDCP_UL_CONTROL_PDU            = 0xb2 # 0xB0B2 LTE PDCP UL Ctrl PDU
    LOG_LTE_PDCP_DL_CIPHER_DATA_PDU        = 0xa3 # 0xB0A3 LTE PDCP DL Cipher Data PDU
    LOG_LTE_PDCP_UL_CIPHER_DATA_PDU        = 0xb3 # 0xB0B3 LTE PDCP UL Cipher Data PDU
    LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU = 0xa5 # 0xB0A5 LTE PDCP DL SRB Integrity Data PDU
    LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU = 0xb5 # 0xB0B5 LTE PDCP UL SRB Integrity Data PDU

    # RRC
    LOG_LTE_RRC_OTA_MESSAGE         = 0xc0 # 0xB0C0 LTE RRC OTA Packet
    LOG_LTE_RRC_MIB_MESSAGE         = 0xc1 # 0xB0C1 LTE RRC MIB Message Log Packet
    LOG_LTE_RRC_SERVING_CELL_INFO   = 0xc2 # 0xB0C2 LTE RRC Serving Cell Info Log Pkt
    LOG_LTE_RRC_SUPPORTED_CA_COMBOS = 0xcd # 0xB0CD LTE RRC Supported CA Combos

    # NAS
    LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE   = 0xe0 # 0xB0E0 LTE NAS EMM Security Protected Incoming Msg
    LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE   = 0xe1 # 0xB0E1 LTE NAS EMM Security Protected Outgoing Msg
    LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE = 0xe2 # 0xB0E2 LTE NAS EMM Plain OTA Incoming Message
    LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE = 0xe3 # 0xB0E3 LTE NAS EMM Plain OTA Outgoing Message
    LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE   = 0xea # 0xB0EA LTE NAS EMM Security Protected Incoming Msg
    LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE   = 0xeb # 0xB0EB LTE NAS EMM Security Protected Outgoing Msg
    LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE = 0xec # 0xB0EC LTE NAS EMM Plain OTA Incoming Message
    LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE = 0xed # 0xB0ED LTE NAS EMM Plain OTA Outgoing Message

@unique
class diag_log_code_5gnr(IntEnum):
    # Management Layer 1
    LOG_5GNR_ML1_MEAS_DATABASE_UPDATE  = 0x97F # 0xB97F NR ML1 Measurement Database Update

    # MAC
    LOG_5GNR_MAC_RACH_ATTEMPT          = 0x88A # 0xB88A NR MAC RACH Attempt

    # RRC
    LOG_5GNR_RRC_OTA_MESSAGE           = 0x821 # 0xB821 NR RRC OTA
    LOG_5GNR_RRC_MIB_INFO              = 0x822 # 0xB822 NR RRC MIB Info
    LOG_5GNR_RRC_SERVING_CELL_INFO     = 0x823 # 0xB823 NR RRC Serving Cell Info
    LOG_5GNR_RRC_CONFIGURATION_INFO    = 0x825 # 0xB825 NR RRC Configuration Info
    LOG_5GNR_RRC_SUPPORTED_CA_COMBOS   = 0x826 # 0xB826 NR RRC Supported CA Combinations

    # NAS
    LOG_5GNR_NAS_5GSM_PLAIN_OTA_INCOMING_MESSAGE = 0x800 # NR NAS 5GSM Plain OTA Incoming Message
    LOG_5GNR_NAS_5GSM_PLAIN_OTA_OUTGOING_MESSAGE = 0x801 # NR NAS 5GSM Plain OTA Outgoing Message
    LOG_5GNR_NAS_5GSM_SEC_OTA_INCOMING_MESSAGE   = 0x808 # NR NAS 5GMM Security Protected OTA Incoming Message
    LOG_5GNR_NAS_5GSM_SEC_OTA_OUTGOING_MESSAGE   = 0x809 # NR NAS 5GMM Security Protected OTA Outgoing Message
    LOG_5GNR_NAS_5GMM_PLAIN_OTA_INCOMING_MESSAGE = 0x80A # NR NAS 5GMM Plain OTA Incoming Message
    LOG_5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MESSAGE = 0x80B # NR NAS 5GMM Plain OTA Outgoing Message
    LOG_5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER_MESSAGE= 0x814 # NR NAS 5GMM Plain OTA Container Message
    LOG_5GNR_NAS_5GMM_STATE                      = 0x80C # NR NAS 5GMM State - According to MobileInsight

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
            continue

        pos_byte = int(bit / 8)
        pos_bit = bit % 8
        diag_log_config_mask_payload[pos_byte] |= (1 << pos_bit)

    return diag_log_config_mask_header + bytes(diag_log_config_mask_payload)

# Preferred log masks used by SCAT
def log_mask_empty_1x(num_max_items=0x0fff):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_1X, num_max_items)

def log_mask_scat_1x(num_max_items=0x0847, layers=[]):
    log_items = [
        diag_log_code_1x.LOG_UIM_DATA_C,
        diag_log_code_1x.LOG_INTERNAL_CORE_DUMP_C,
        diag_log_code_1x.LOG_GENERIC_SIM_TOOLKIT_TASK_C,
        diag_log_code_1x.LOG_UIM_DS_DATA_C,
        0x648, # 0x1648   Indoor Info
        0x649, # 0x1649   Indoor RTS CTS Scan
        0x650, # 0x1650   Indoor Active Scan
        0x651, # 0x1651   Unrecognized
        0x652, # 0x1652   Unrecognized
        0x653, # 0x1653   Unrecognized
        0x654, # 0x1654   Unrecognized
    ]

    if 'ip' in layers:
        log_items += [
            diag_log_code_1x.LOG_DATA_PROTOCOL_LOGGING_C,
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
            diag_log_code_1x.LOG_IMS_SIP_MESSAGE,
        ]

    if 'qmi' in layers:
        log_items += [
            diag_log_code_1x.LOG_QMI_CALL_FLOW_C,
            diag_log_code_1x.LOG_QMI_SUPPORTED_INTERFACES_C,
            diag_log_code_1x.LOG_QMI_LINK_01_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_01_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_02_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_02_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_03_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_03_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_04_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_04_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_05_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_05_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_06_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_06_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_07_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_07_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_08_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_08_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_09_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_09_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_10_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_10_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_11_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_11_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_12_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_12_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_13_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_13_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_14_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_14_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_15_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_15_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_16_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_16_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_17_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_17_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_18_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_18_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_19_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_19_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_20_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_20_TX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_21_RX_MSG_C,
            diag_log_code_1x.LOG_QMI_LINK_21_TX_MSG_C,
        ]

    return create_log_config_set_mask(DIAG_SUBSYS_ID_1X, num_max_items, *log_items)

def log_mask_empty_wcdma(num_max_items=0x0ff7):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_WCDMA, num_max_items)

def log_mask_scat_wcdma(num_max_items=0x0ff7, layers=[]):
    log_items = [
        diag_log_code_wcdma.LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C,
        diag_log_code_wcdma.LOG_WCDMA_CELL_ID_C,
    ]

    if 'rlc' in layers:
        log_items += [
            diag_log_code_wcdma.LOG_WCDMA_RLC_DL_AM_SIGNALING_PDU_C,
            diag_log_code_wcdma.LOG_WCDMA_RLC_UL_AM_SIGNALING_PDU_C,
            diag_log_code_wcdma.LOG_WCDMA_RLC_UL_AM_CONTROL_PDU_LOG_C,
            diag_log_code_wcdma.LOG_WCDMA_RLC_DL_AM_CONTROL_PDU_LOG_C,
            diag_log_code_wcdma.LOG_WCDMA_RLC_DL_PDU_CIPHER_PACKET_C,
            diag_log_code_wcdma.LOG_WCDMA_RLC_UL_PDU_CIPHER_PACKET_C,
        ]
    if 'rrc' in layers:
        log_items += [
            diag_log_code_wcdma.LOG_WCDMA_SIB_C,
            diag_log_code_wcdma.LOG_WCDMA_SIGNALING_MSG_C,
        ]

    return create_log_config_set_mask(DIAG_SUBSYS_ID_WCDMA, num_max_items, *log_items)

def log_mask_empty_gsm(num_max_items=0x0ff7):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_GSM, num_max_items)

def log_mask_scat_gsm(num_max_items=0x0ff7, layers=[]):
    log_items = [
        diag_log_code_gsm.LOG_GSM_L1_FCCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_L1_SCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_L1_NEW_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_L1_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_L1_SCELL_BA_LIST_C,
        diag_log_code_gsm.LOG_GSM_L1_SCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_L1_NCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_RR_CELL_INFORMATION_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_FCCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCH_ACQUISITION_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_BURST_METRICS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCELL_BA_LIST_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_SCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_L1_NCELL_AUX_MEASUREMENTS_C,
        diag_log_code_gsm.LOG_GSM_DSDS_RR_CELL_INFORMATION_C,
    ]

    if 'mac' in layers:
        log_items += [
            diag_log_code_gsm.LOG_GPRS_MAC_SIGNALING_MESSACE_C,
        ]
    if 'rrc' in layers:
        log_items += [
            diag_log_code_gsm.LOG_GSM_RR_SIGNALING_MESSAGE_C,
            diag_log_code_gsm.LOG_GSM_DSDS_RR_SIGNALING_MESSAGE_C,
            diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_1_C,
            diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_2_C,
            diag_log_code_gsm.LOG_GPRS_RR_PACKET_SI_3_C,
            diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_1_C,
            diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_2_C,
            diag_log_code_gsm.LOG_GPRS_DSDS_RR_PACKET_SI_3_C,
        ]
    if 'nas' in layers:
        log_items += [
            diag_log_code_gsm.LOG_GPRS_SM_GMM_OTA_SIGNALING_MESSAGE_C,
        ]

    return create_log_config_set_mask(DIAG_SUBSYS_ID_GSM, num_max_items, *log_items)

def log_mask_empty_umts(num_max_items=0x0b5e):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_UMTS, num_max_items)

def log_mask_scat_umts(num_max_items=0x0b5e, layers=[]):
    log_items = []

    if 'nas' in layers:
        log_items += [
            diag_log_code_umts.LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
            diag_log_code_umts.LOG_UMTS_DSDS_NAS_SIGNALING_MESSAGE,
        ]

    return create_log_config_set_mask(DIAG_SUBSYS_ID_UMTS, num_max_items, *log_items)

def log_mask_empty_dtv(num_max_items=0x0392):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_DTV, num_max_items)

def log_mask_empty_lte(num_max_items=0x0209):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, num_max_items)

def log_mask_scat_lte(num_max_items=0x09ff, layers=[]):
    items_lte = [
        diag_log_code_lte.LOG_LTE_ML1_MAC_RAR_MSG1_REPORT,
        diag_log_code_lte.LOG_LTE_ML1_MAC_RAR_MSG2_REPORT,
        diag_log_code_lte.LOG_LTE_ML1_MAC_UE_IDENTIFICATION_MESSAGE_MSG3_REPORT,
        diag_log_code_lte.LOG_LTE_ML1_MAC_CONTENTION_RESOLUTION_MESSAGE_MSG4_REPORT,
        diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL,
        diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS,
        # diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE,
        diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_INFO,
        diag_log_code_lte.LOG_LTE_RRC_MIB_MESSAGE,
        diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO,
        diag_log_code_lte.LOG_LTE_RRC_SUPPORTED_CA_COMBOS,
    ]

    items_nr = [
        diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_CONFIGURATION_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_SUPPORTED_CA_COMBOS,
        diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE,
        diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE,
    ]

    if 'mac' in layers:
        items_lte += [
            diag_log_code_lte.LOG_LTE_MAC_RACH_TRIGGER,
            diag_log_code_lte.LOG_LTE_MAC_RACH_RESPONSE,
            diag_log_code_lte.LOG_LTE_MAC_DL_TRANSPORT_BLOCK,
            diag_log_code_lte.LOG_LTE_MAC_UL_TRANSPORT_BLOCK,
        ]
    if 'pdcp' in layers:
        items_lte += [
            diag_log_code_lte.LOG_LTE_PDCP_DL_CONFIG,
            diag_log_code_lte.LOG_LTE_PDCP_UL_CONFIG,
            diag_log_code_lte.LOG_LTE_PDCP_DL_DATA_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_UL_DATA_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_DL_CONTROL_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_UL_CONTROL_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_DL_CIPHER_DATA_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_UL_CIPHER_DATA_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_DL_SRB_INTEGRITY_DATA_PDU,
            diag_log_code_lte.LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU,
        ]
    if 'rrc' in layers:
        items_lte += [
            diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE,
        ]
        items_nr += [
            diag_log_code_5gnr.LOG_5GNR_RRC_OTA_MESSAGE,
        ]
    if 'nas' in layers:
        items_lte += [
            diag_log_code_lte.LOG_LTE_NAS_ESM_SEC_OTA_INCOMING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_ESM_SEC_OTA_OUTGOING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_ESM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_ESM_PLAIN_OTA_OUTGOING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_EMM_SEC_OTA_INCOMING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_EMM_SEC_OTA_OUTGOING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_EMM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_lte.LOG_LTE_NAS_EMM_PLAIN_OTA_OUTGOING_MESSAGE,
        ]
        items_nr += [
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_PLAIN_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_SEC_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_SEC_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER_MESSAGE,
        ]

    if num_max_items < 0x0800:
        return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, num_max_items,
            *items_lte
        )
    else:
        return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, num_max_items,
            *(items_lte + items_nr)
        )

def log_mask_empty_nr(num_max_items=0x09ff):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, num_max_items)

def log_mask_scat_nr(num_max_items=0x09ff, layers=[]):
    log_items = [
        diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_CONFIGURATION_INFO,
        diag_log_code_5gnr.LOG_5GNR_RRC_SUPPORTED_CA_COMBOS,
        diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE,
        diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE,
    ]

    if 'rrc' in layers:
        log_items += [
            diag_log_code_5gnr.LOG_5GNR_RRC_OTA_MESSAGE,
        ]
    if 'nas' in layers:
        log_items += [
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_PLAIN_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_SEC_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GSM_SEC_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_INCOMING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_OUTGOING_MESSAGE,
            diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_PLAIN_OTA_CONTAINER_MESSAGE,
        ]

    return create_log_config_set_mask(DIAG_SUBSYS_ID_LTE, num_max_items, *log_items)

def log_mask_empty_tdscdma(num_max_items=0x0207):
    return create_log_config_set_mask(DIAG_SUBSYS_ID_TDSCDMA, num_max_items)

def create_extended_message_config_set_mask(first_ssid, last_ssid, *masks):
    # Command ID, Operation | first_ssid, last_ssid, runtime_masks
    diag_log_config_mask_header = struct.pack('<BBHHH',
        DIAG_EXT_MSG_CONFIG_F, 0x04,
        first_ssid, last_ssid, 0x00)
    ext_msg_config_levels = [0] * (last_ssid - first_ssid + 1)
    ext_msg_config_mask_payload = b''

    # Each subsystem ID has own log level
    for mask in masks:
        subsys_id = mask[0]
        if subsys_id < first_ssid or subsys_id > last_ssid:
            continue
        rel_subsys_id = subsys_id - first_ssid
        log_level = mask[1]
        ext_msg_config_levels[rel_subsys_id] = log_level

    for x in ext_msg_config_levels:
        ext_msg_config_mask_payload += struct.pack('<L', x)

    return diag_log_config_mask_header + ext_msg_config_mask_payload
