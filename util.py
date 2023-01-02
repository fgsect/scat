#!/usr/bin/python3
# coding: utf8

import struct
import datetime
import sys
import string
from enum import IntEnum, unique

XXD_SET = string.ascii_letters + string.digits + string.punctuation

crc_table = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
    ]

def dm_crc16(arr):
    ret = 0xffff
    for b in arr:
        ret = (ret >> 8) ^ crc_table[(ret ^ b) & 0xff]
    return ret ^ 0xffff

def wrap(arr):
    t = arr.replace(b'\x7d', b'\x7d\x5d')
    t = t.replace(b'\x7e', b'\x7d\x5e')
    return t

def unwrap(arr):
    t = arr.replace(b'\x7d\x5e', b'\x7e')
    t = t.replace(b'\x7d\x5d', b'\x7d')
    return t

def generate_packet(arr):
    crc = struct.pack('<H', dm_crc16(arr))
    arr += crc
    arr = wrap(arr)
    arr += b'\x7e'
    return arr

def parse_qxdm_ts(ts):
    # Upper 48 bits: epoch at 1980-01-06 00:00:00, incremented by 1 for 1/800s
    # Lower 16 bits: time since last 1/800s tick in 1/32 chip units

    ts_upper = (ts >> 16)
    ts_lower = ts & 0xffff

    epoch = datetime.datetime(1980, 1, 6, 0, 0, 0)

    try:
        ts_delta = datetime.timedelta(0, 0, 0, ts_upper * 1.25 + ts_lower * (1 / 40960), 0, 0, 0)
        date = epoch + ts_delta
    except OverflowError:
        date = epoch + datetime.timedelta(seconds=0)
    return date

def xxd(buf, stdout = False):
    xxd_str = ''
    i = 0
    while i < len(buf):
        if (i + 16) < len(buf):
            xxd_str += (' '.join(('%02x' % x) for x in buf[i:i+16])) + '\t' + (''.join((chr(x) if chr(x) in XXD_SET else '.') for x in buf[i:i+16]))
        else:
            xxd_str += (' '.join(('%02x' % x) for x in buf[i:len(buf)])) + '   ' * (16 - (len(buf) - i)) + '\t' + (''.join((chr(x) if chr(x) in XXD_SET else '.') for x in buf[i:len(buf)]))
        xxd_str += '\n'
        i += 16
    xxd_str += '-------- end --------'

    if stdout:
        print(xxd_str)
    else:
        return 'Hexdump: \n' + xxd_str

def xxd_oneline(buf, stdout = False):
    xxd_str = ''
    xxd_str += ' '.join(('%02x' % x) for x in buf)
    xxd_str += '\n'
    xxd_str += '-------- end --------'

    if stdout:
        print(xxd_str)
    else:
        return 'Hexdump: \n' + xxd_str

# Definition copied from libosmocore's include/osmocom/core/gsmtap.h

@unique
class gsmtap_type(IntEnum):
    UM = 0x01
    ABIS = 0x02
    UM_BURST = 0x03
    SIM = 0x04
    GB_LLC = 0x08
    GB_SNDCP = 0x09
    UMTS_RRC = 0x0c
    LTE_RRC = 0x0d
    LTE_MAC = 0x0e
    LTE_MAC_FRAMED = 0x0f
    OSMOCORE_LOG = 0x10
    QC_DIAG = 0x11
    LTE_NAS = 0x12

@unique
class gsmtap_channel(IntEnum):
    UNKNOWN = 0x00
    BCCH = 0x01
    CCCH = 0x02
    RACH = 0x03
    AGCH = 0x04
    PCH = 0x05
    SDCCH = 0x06
    SDCCH4 = 0x07
    SDCCH8 = 0x08
    TCH_F = 0x09
    TCH_H = 0x0a
    PACCH = 0x0b
    CBCH52 = 0x0c
    PDCH = 0x0d
    PTCCH = 0x0e
    CBCH51 = 0x0f

@unique
class gsmtap_umts_rrc_types(IntEnum):
    DL_DCCH = 0
    UL_DCCH = 1
    DL_CCCH = 2
    UL_CCCH = 3
    PCCH = 4
    DL_SHCCH = 5
    UL_SHCCH = 6
    BCCH_FACH = 7
    BCCH_BCH = 8
    MCCH = 9
    MSCH = 10
    HandoverToUTRANCommand = 11
    InterRATHandoverInfo = 12
    SystemInformation_BCH = 13
    System_Information_Container = 14
    UE_RadioAccessCapabilityInfo = 15
    MasterInformationBlock = 16
    SysInfoType1 = 17
    SysInfoType2 = 18
    SysInfoType3 = 19
    SysInfoType4 = 20
    SysInfoType5 = 21
    SysInfoType5bis = 22
    SysInfoType6 = 23
    SysInfoType7 = 24
    SysInfoType8 = 25
    SysInfoType9 = 26
    SysInfoType10 = 27
    SysInfoType11 = 28
    SysInfoType11bis = 29
    SysInfoType12 = 30
    SysInfoType13 = 31
    SysInfoType13_1 = 32
    SysInfoType13_2 = 33
    SysInfoType13_3 = 34
    SysInfoType13_4 = 35
    SysInfoType14 = 36
    SysInfoType15 = 37
    SysInfoType15bis = 38
    SysInfoType15_1 = 39
    SysInfoType15_1bis = 40
    SysInfoType15_2 = 41
    SysInfoType15_2bis = 42
    SysInfoType15_2ter = 43
    SysInfoType15_3 = 44
    SysInfoType15_3bis = 45
    SysInfoType15_4 = 46
    SysInfoType15_5 = 47
    SysInfoType15_6 = 48
    SysInfoType15_7 = 49
    SysInfoType15_8 = 50
    SysInfoType16 = 51
    SysInfoType17 = 52
    SysInfoType18 = 53
    SysInfoType19 = 54
    SysInfoType20 = 55
    SysInfoType21 = 56
    SysInfoType22 = 57
    SysInfoTypeSB1 = 58
    SysInfoTypeSB2 = 59
    ToTargetRNC_Container = 60
    TargetRNC_ToSourceRNC_Container = 61

@unique
class gsmtap_lte_rrc_types(IntEnum):
    DL_CCCH = 0
    DL_DCCH = 1
    UL_CCCH = 2
    UL_DCCH = 3
    BCCH_BCH = 4
    BCCH_DL_SCH = 5
    PCCH = 6
    MCCH = 7
    BCCH_BCH_MBMS = 8
    BCCH_DL_SCH_BR = 9
    BCCH_DL_SCH_MBMS = 10
    SC_MCCH = 11
    SBCCH_SL_BCH = 12
    SBCCH_SL_BCH_V2X = 13
    DL_CCCH_NB = 14
    DL_DCCH_NB = 15
    UL_CCCH_NB = 16
    UL_DCCH_NB = 17
    BCCH_BCH_NB = 18
    BCCH_BCH_TDD_NB = 19
    BCCH_DL_SCH_NB = 20
    PCCH_NB = 21
    SC_MCCH_NB = 22

def create_gsmtap_header(version = 2, payload_type = 0, timeslot = 0,
    arfcn = 0, signal_dbm = 0, snr_db = 0, frame_number = 0,
    sub_type = 0, antenna_nr = 0, sub_slot = 0,
    device_sec = 0, device_usec = 0):

    gsmtap_v2_hdr_def = '!BBBBHBBLBBBB'
    gsmtap_v3_hdr_def = '!BBBBHBBLBBBBQL'
    gsmtap_hdr = b''

    # Sanity check - Wireshark GSMTAP dissector accepts only 14 bits of ARFCN
    if arfcn < 0 or arfcn > (2 ** 14 - 1):
        arfcn = 0

    if version == 2:
        gsmtap_hdr = struct.pack(gsmtap_v2_hdr_def,
            2,                           # Version
            4,                           # Header Length
            payload_type,                # Type
            timeslot,                    # GSM Timeslot
            arfcn,                       # ARFCN
            signal_dbm,                  # Signal dBm
            snr_db,                      # SNR dB
            frame_number,                # Frame Number
            sub_type,                    # Subtype
            antenna_nr,                  # Antenna Number
            sub_slot,                    # Subslot
            0                            # Reserved
            )
    elif version == 3:
        gsmtap_hdr = struct.pack(gsmtap_v3_hdr_def,
            3,                           # Version
            7,                           # Header Length
            payload_type,                # Type
            timeslot,                    # GSM Timeslot
            arfcn,                       # ARFCN
            signal_dbm,                  # Signal dBm
            snr_db,                      # SNR dB
            frame_number,                # Frame Number
            sub_type,                    # Subtype
            antenna_nr,                  # Antenna Number
            sub_slot,                    # Subslot
            0,                           # Reserved
            device_sec,
            device_usec)
    else:
        assert (version == 2) or (version == 3), "GSMTAP version should be either 2 or 3"

    return gsmtap_hdr

def create_osmocore_logging_header(timestamp = datetime.datetime.now(),
        process_name = '', pid = 0, level = 0,
        subsys_name = '', filename = '', line_number = 0):

    if type(process_name) == str:
        process_name = process_name.encode('utf-8')
    if type(subsys_name) == str:
        subsys_name = subsys_name.encode('utf-8')
    if type(filename) == str:
        filename = filename.encode('utf-8')

    logging_hdr = struct.pack('!LL16sLB3x16s32sL',
        int(timestamp.timestamp()), # uint32_t sec
        timestamp.microsecond, # uint32_t usec
        process_name, # uint8_t proc_name[16]
        pid, # uint32_t pid
        level, # uint8_t level
        subsys_name, # uint8_t subsys[16]
        filename, # uint8_t filename[32]
        line_number # uint32_t line_nr
    )

    return logging_hdr

@unique
class mac_lte_rnti_types(IntEnum):
    NO_RNTI = 0
    P_RNTI = 1
    RA_RNTI = 2
    C_RNTI = 3
    SI_RNTI = 4
    SPS_RNTI = 5
    M_RNTI = 6
    SL_BCH_RNTI = 7
    SL_RNTI = 8
    SC_RNTI = 9
    G_RNTI = 10

@unique
class mac_lte_radio_types(IntEnum):
    FDD_RADIO = 1
    TDD_RADIO = 2

@unique
class mac_lte_direction_types(IntEnum):
    DIRECTION_UPLINK = 0
    DIRECTION_DOWNLINK = 1

@unique
class mac_lte_tags(IntEnum):
    MAC_LTE_PAYLOAD_TAG  = 0x01
    MAC_LTE_RNTI_TAG = 0x02 # 2 bytes, network order
    MAC_LTE_UEID_TAG = 0x03 # 2 bytes, network order
    MAC_LTE_FRAME_SUBFRAME_TAG = 0x04 # 2 bytes, network order, SFN is stored in 12 MSB and SF in 4 LSB
    MAC_LTE_PREDEFINED_DATA_TAG = 0x05 # 1 byte
    MAC_LTE_RETX_TAG = 0x06 # 1 byte
    MAC_LTE_CRC_STATUS_TAG = 0x07 # 1 byte
    MAC_LTE_EXT_BSR_SIZES_TAG = 0x08 # 0 byte
    MAC_LTE_SEND_PREAMBLE_TAG = 0x09 # 2 bytes, RAPID value (1 byte) followed by RACH attempt number (1 byte)
    MAC_LTE_CARRIER_ID_TAG = 0x0A # 1 byte
    MAC_LTE_PHY_TAG = 0x0B # variable length, length (1 byte) then depending on direction
    # in UL: modulation type (1 byte), TBS index (1 byte), RB length (1 byte),
    #        RB start (1 byte), HARQ id (1 byte), NDI (1 byte)
    # in DL: DCI format (1 byte), resource allocation type (1 byte), aggregation level (1 byte),
    #        MCS index (1 byte), redundancy version (1 byte), resource block length (1 byte),
    #        HARQ id (1 byte), NDI (1 byte), TB (1 byte), DL reTx (1 byte)
    MAC_LTE_SIMULT_PUCCH_PUSCH_PCELL_TAG = 0x0C # 0 byte
    MAC_LTE_SIMULT_PUCCH_PUSCH_PSCELL_TAG = 0x0D # 0 byte
    MAC_LTE_CE_MODE_TAG = 0x0E # 1 byte containing mac_lte_ce_mode enum value
    MAC_LTE_NB_MODE_TAG = 0x0F # 1 byte containing mac_lte_nb_mode enum value
    MAC_LTE_N_UL_RB_TAG = 0x10 # 1 byte containing the number of UL resource blocks: 6, 15, 25, 50, 75 or 100
    MAC_LTE_SR_TAG = 0x11 # 2 bytes for the number of items, followed by that number of ueid, rnti (2 bytes each)

@unique
class pdcp_lte_direction_types(IntEnum):
    DIRECTION_UPLINK = 0
    DIRECTION_DOWNLINK = 1

@unique
class pdcp_plane_types(IntEnum):
    SIGNALING_PLANE = 1
    USER_PLANE = 2

@unique
class pdcp_logical_channel_types(IntEnum):
    Channel_DCCH=1,
    Channel_BCCH=2,
    Channel_CCCH=3,
    Channel_PCCH=4,
    Channel_DCCH_NB=5,
    Channel_BCCH_NB=6,
    Channel_CCCH_NB=7,
    Channel_PCCH_NB=8

@unique
class pdcp_bcch_transport_types(IntEnum):
    BCH_TRANSPORT=1,
    DLSCH_TRANSPORT=2

@unique
class pdcp_sn_length_types(IntEnum):
    PDCP_SN_LENGTH_5_BITS = 5
    PDCP_SN_LENGTH_7_BITS = 7
    PDCP_SN_LENGTH_12_BITS = 12
    PDCP_SN_LENGTH_15_BITS = 15
    PDCP_SN_LENGTH_18_BITS = 18

@unique
class pdcp_lte_tags(IntEnum):
    PDCP_LTE_PAYLOAD_TAG = 0x01
    PDCP_LTE_SEQNUM_LENGTH_TAG = 0x02 # 1 byte
    PDCP_LTE_DIRECTION_TAG = 0x03 # 1 byte
    PDCP_LTE_LOG_CHAN_TYPE_TAG = 0x04 # 1 byte
    PDCP_LTE_BCCH_TRANSPORT_TYPE_TAG = 0x05 # 1 byte
    PDCP_LTE_ROHC_IP_VERSION_TAG = 0x06 # 2 bytes
    PDCP_LTE_ROHC_CID_INC_INFO_TAG = 0x07 # 1 byte
    PDCP_LTE_ROHC_LARGE_CID_PRES_TAG = 0x08 # 1 byte
    PDCP_LTE_ROHC_MODE_TAG = 0x09 # 1 byte
    PDCP_LTE_ROHC_RND_TAG = 0x0A # 1 byte
    PDCP_LTE_ROHC_UDP_CHECKSUM_PRES_TAG = 0x0B # 1 byte
    PDCP_LTE_ROHC_PROFILE_TAG = 0x0C # 2 bytes, network order
    PDCP_LTE_CHANNEL_ID_TAG = 0x0D # 2 bytes, network order
    PDCP_LTE_UEID_TAG = 0x0E # 2 bytes, network order

@unique
class wcdma_rlc_channel_types(IntEnum):
    UMTS_CHANNEL_TYPE_UNSPECIFIED = 0
    UMTS_CHANNEL_TYPE_PCCH = 1
    UMTS_CHANNEL_TYPE_CCCH = 2
    UMTS_CHANNEL_TYPE_DCCH = 3
    UMTS_CHANNEL_TYPE_PS_DTCH = 4
    UMTS_CHANNEL_TYPE_CTCH = 5
    UMTS_CHANNEL_TYPE_BCCH = 6

@unique
class wcdma_rlc_mode_types(IntEnum):
    RLC_TM = 0
    RLC_UM = 1
    RLC_AM = 2

@unique
class wcdma_li_size_types(IntEnum):
    RLC_LI_VARIABLE = 0
    RLC_LI_7BITS = 1
    RLC_LI_15BITS = 2

@unique
class wcdma_rlc_direction_types(IntEnum):
    DIRECTION_UPLINK = 0
    DIRECTION_DOWNLINK = 1

@unique
class wcdma_rlc_tags(IntEnum):
    RLC_PAYLOAD_TAG = 0x01
    RLC_CHANNEL_TYPE_TAG = 0x02 # 1 byte
    RLC_MODE_TAG = 0x03 # 1 byte, enum rlc_mode value
    RLC_DIRECTION_TAG = 0x04 # 1 byte
    RLC_URNTI_TAG = 0x05 # 4 bytes, network order
    RLC_RADIO_BEARER_ID_TAG = 0x06 # 1 byte
    RLC_LI_SIZE_TAG = 0x07 # 1 byte, enum rlc_li_size value

# Calculates the equivalent UL-EARFCN of a given DL-EARFCN,
# if the input is an SDL or unknown EARFCN the output will be equal to the input
# Based on 3GPP TS 36.101 V16.6.0 Table 5.7.3-1
def calculate_ul_earfcn(dl_earfcn):
    if 0 <= dl_earfcn < 9660:        # B1-B28
        offset = 18000
    elif 9769 < dl_earfcn < 9920:    # B30-31
        offset = 17890
    elif 65535 < dl_earfcn < 67136:  # B65-66
        offset = 65536
    elif 67535 < dl_earfcn < 67836:  # B68
        offset = 65136
    elif 68335 < dl_earfcn < 68486:  # B70
        offset = 64636
    elif 68585 < dl_earfcn < 69466:  # B71-74
        offset = 64536
    elif 70365 < dl_earfcn < 70596:  # B85-87
        offset = 63636
    elif 70595 < dl_earfcn < 70646:  # B88
        offset = 63635
    else:
        offset = 0
    return dl_earfcn + offset

def unpack_mcc_mnc(mcc_mnc_bin):
    mcc = 0
    mnc = 0

    mcc = ((mcc_mnc_bin[0] & 0xf) << 8) | (((mcc_mnc_bin[0] & 0xf0) >> 4) << 4) | (mcc_mnc_bin[1] & 0xf)
    mnc = ((mcc_mnc_bin[2] & 0xf) << 8) | (((mcc_mnc_bin[2] & 0xf0) >> 4) << 4) | ((mcc_mnc_bin[1] & 0xf0) >> 4)

    if mnc & 0xf == 0xf:
        mnc = (mnc >> 4)

    return (mcc, mnc)
