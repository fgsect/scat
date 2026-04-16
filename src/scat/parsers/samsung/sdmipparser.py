#!/usr/bin/env python3

from enum import IntEnum, unique
from collections import namedtuple
import binascii
import logging
import struct

import scat.parsers.samsung.sdmcmd as sdmcmd

# Constants obtained from:
# https://github.com/morphis/libsamsung-ipc
@unique
class samsung_ipc_type_ap2cp(IntEnum):
    EXEC  = 0x01
    GET   = 0x02
    SET   = 0x03
    CFRM  = 0x04
    EVENT = 0x05

@unique
class samsung_ipc_type_cp2ap(IntEnum):
    INDI = 0x01
    RESP = 0x02
    NOTI = 0x03

@unique
class samsung_ipc_group(IntEnum):
    GROUP_PWR  = 0x01
    GROUP_CALL = 0x02
    GROUP_SMS  = 0x04
    GROUP_SEC  = 0x05
    GROUP_PB   = 0x06
    GROUP_DISP = 0x07
    GROUP_NET  = 0x08
    GROUP_SND  = 0x09
    GROUP_MISC = 0x0A
    GROUP_SVC  = 0x0B
    GROUP_SS   = 0x0C
    GROUP_GPRS = 0x0D
    GROUP_SAT  = 0x0E
    GROUP_CFG  = 0x0F
    GROUP_IMEI = 0x10
    GROUP_GPS  = 0x11
    GROUP_SAP  = 0x12
    GROUP_RFS  = 0x42
    GROUP_GEN  = 0x80

@unique
class samsung_ipc_pwr_types(IntEnum):
    PWR_PHONE_PWR_UP  = 0x01
    PWR_PHONE_PWR_OFF = 0x02
    PWR_PHONE_RESET   = 0x03
    PWR_BATT_STATUS   = 0x04
    PWR_BATT_TYPE     = 0x05
    PWR_BATT_COMP     = 0x06
    PWR_PHONE_STATE   = 0x07

@unique
class samsung_ipc_call_types(IntEnum):
    CALL_OUTGOING   = 0x01
    CALL_INCOMING   = 0x02
    CALL_RELEASE    = 0x03
    CALL_ANSWER     = 0x04
    CALL_STATUS     = 0x05
    CALL_LIST       = 0x06
    CALL_BURST_DTMF = 0x07
    CALL_CONT_DTMF  = 0x08
    CALL_WAITING    = 0x09
    CALL_LINE_ID    = 0x0A

@unique
class samsung_ipc_sms_types(IntEnum):
    SMS_SEND_MSG         = 0x01
    SMS_INCOMING_MSG     = 0x02
    SMS_READ_MSG         = 0x03
    SMS_SAVE_MSG         = 0x04
    SMS_DEL_MSG          = 0x05
    SMS_DELIVER_REPORT   = 0x06
    SMS_DEVICE_READY     = 0x07
    SMS_SEL_MEM          = 0x08
    SMS_STORED_MSG_COUNT = 0x09
    SMS_SVC_CENTER_ADDR  = 0x0A
    SMS_SVC_OPTION       = 0x0B
    SMS_MEM_STATUS       = 0x0C
    SMS_CBS_MSG          = 0x0D
    SMS_CBS_CONFIG       = 0x0E
    SMS_STORED_MSG_STATUS= 0x0F
    SMS_PARAM_COUNT      = 0x10
    SMS_PARAM            = 0x11

@unique
class samsung_ipc_sec_types(IntEnum):
    SEC_SIM_STATUS        = 0x01
    SEC_PHONE_LOCK        = 0x02
    SEC_CHANGE_LOCKING_PW = 0x03
    SEC_SIM_LANG          = 0x04
    SEC_RSIM_ACCESS       = 0x05
    SEC_GSIM_ACCESS       = 0x06
    SEC_SIM_ICC_TYPE      = 0x07
    SEC_LOCK_INFO         = 0x08
    SEC_ISIM_AUTH         = 0x09

@unique
class samsung_ipc_pb_types(IntEnum):
    PB_ACCESS          = 0x01
    PB_STORAGE         = 0x02
    PB_STORAGE_LIST    = 0x03
    PB_ENTRY_INFO      = 0x04
    PB_CAPABILITY_INFO = 0x05

@unique
class samsung_ipc_disp_types(IntEnum):
    DISP_ICON_INFO     = 0x01
    DISP_HOMEZONE_INFO = 0x02
    DISP_RSSI_INFO     = 0x06

@unique
class samsung_ipc_net_types(IntEnum):
    NET_PREF_PLMN             = 0x01
    NET_PLMN_SEL              = 0x02
    NET_CURRENT_PLMN          = 0x03
    NET_PLMN_LIST             = 0x04
    NET_REGIST                = 0x05
    NET_SUBSCRIBER_NUM        = 0x06
    NET_BAND_SEL              = 0x07
    NET_SERVICE_DOMAIN_CONFIG = 0x08
    NET_POWERON_ATTACH        = 0x09
    NET_MODE_SEL              = 0x0A
    NET_ACQ_ORDER             = 0x0B
    NET_IDENTITY              = 0x0C
    NET_CURRENT_RRC_STATUS    = 0x0D

@unique
class samsung_ipc_misc_types(IntEnum):
    MISC_ME_VERSION  = 0x01
    MISC_ME_IMSI     = 0x02
    MISC_ME_SN       = 0x03
    MISC_TIME_INFO   = 0x05
    MISC_DEBUG_LEVEL = 0x0C

@unique
class samsung_ipc_gprs_types(IntEnum):
    GPRS_DEFINE_PDP_CONTEXT         = 0x01
    GPRS_QOS                        = 0x02
    GPRS_PS                         = 0x03
    GPRS_PDP_CONTEXT                = 0x04
    GPRS_ENTER_DATA                 = 0x05
    GPRS_SHOW_PDP_ADDR              = 0x06
    GPRS_MS_CLASS                   = 0x07
    GPRS_3G_QUAL_SERVICE_PROFILE    = 0x08
    GPRS_IP_CONFIGURATION           = 0x09
    GPRS_DEFINE_SEC_PDP_CONTEXT     = 0x0A
    GPRS_TFT                        = 0x0B
    GPRS_HSDPA_STATUS               = 0x0C
    GPRS_CURRENT_SESSION_DATA_COUNT = 0x0D
    GPRS_DATA_DORMANT               = 0x0E
    GPRS_DUN_PIN_CTRL               = 0x0F
    GPRS_CALL_STATUS                = 0x10
    GPRS_PORT_LIST                  = 0x11

@unique
class samsung_ipc_gen_types(IntEnum):
    GEN_PHONE_RES = 0x01

class SdmIpParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_IP_DATA << 8)
        self.process = {
            g | 0x00: lambda x: self.sdm_ip_data(x),
            g | 0x10: lambda x: self.sdm_samsung_ipc_data(x),
        }


    def set_icd_ver(self, version: tuple):
        self.icd_ver = version

    def update_parameters(self, display_format: str, gsmtapv3: bool):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def sdm_ip_data(self, pkt: bytes):
        pkt = pkt[15:-1]

        header_struct = namedtuple('SdmIpData', 'seq_num direction ethertype length')
        header = header_struct._make(struct.unpack('<HHHH', pkt[0:8]))
        payload = pkt[8:]

        if header.length != len(payload):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'IP length mismatch, expected 0x{:04x}, got 0x{:04x}'.format(header.length, len(payload)))
        else:
            return {'layer': 'ip', 'up': [payload]}

    def sdm_samsung_ipc_data(self, pkt: bytes):
        pkt = pkt[15:-1]

        header_struct = namedtuple('SdmSamsungIpcData', 'seq_num direction')
        ipc_hdr_struct = namedtuple('SamsungIpcHeader', 'length mseq aseq group index type')
        header = header_struct._make(struct.unpack('<HH', pkt[0:4]))
        payload = pkt[4:]
        stdout = ''
        if header.direction == 0:
            ipc_hdr = struct.unpack('<L', payload[0:4])
            ipc_data = payload[4:]
            stdout += 'SDM IPC Data (AP2CP): seq_num={}, {:#x}, {}'.format(header.seq_num, ipc_hdr[0], binascii.hexlify(ipc_data).decode())
        else:
            ipc_hdr = ipc_hdr_struct._make(struct.unpack('<HBBBBB', payload[0:7]))
            ipc_data = payload[7:]

            if ipc_hdr.length != len(ipc_data) + 7:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'IPC data length mismatch, expected 0x{:04x}, got 0x{:04x}'.format(ipc_hdr.length - 7, len(ipc_data)))
            else:
                group_str = ''
                cmd_str = '{}'.format(ipc_hdr.index)
                if ipc_hdr.group in samsung_ipc_group:
                    g = samsung_ipc_group(ipc_hdr.group)
                    group_str = g.name

                    if g == samsung_ipc_group.GROUP_PWR:
                        if ipc_hdr.index in samsung_ipc_pwr_types:
                            cmd_str = samsung_ipc_pwr_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_CALL:
                        if ipc_hdr.index in samsung_ipc_call_types:
                            cmd_str = samsung_ipc_call_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_SMS:
                        if ipc_hdr.index in samsung_ipc_sms_types:
                            cmd_str = samsung_ipc_sms_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_SEC:
                        if ipc_hdr.index in samsung_ipc_sec_types:
                            cmd_str = samsung_ipc_sec_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_PB:
                        if ipc_hdr.index in samsung_ipc_pb_types:
                            cmd_str = samsung_ipc_pb_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_DISP:
                        if ipc_hdr.index in samsung_ipc_disp_types:
                            cmd_str = samsung_ipc_disp_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_NET:
                        if ipc_hdr.index in samsung_ipc_net_types:
                            cmd_str = samsung_ipc_net_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_MISC:
                        if ipc_hdr.index in samsung_ipc_misc_types:
                            cmd_str = samsung_ipc_misc_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_GPRS:
                        if ipc_hdr.index in samsung_ipc_gprs_types:
                            cmd_str = samsung_ipc_gprs_types(ipc_hdr.index).name
                    elif g == samsung_ipc_group.GROUP_GEN:
                        if ipc_hdr.index in samsung_ipc_gen_types:
                            cmd_str = samsung_ipc_gen_types(ipc_hdr.index).name
                else:
                    group_str = '{}'.format(ipc_hdr.group)
                if ipc_hdr.type in samsung_ipc_type_cp2ap:
                    type_str = samsung_ipc_type_cp2ap(ipc_hdr.type).name
                else:
                    type_str = '{}'.format(ipc_hdr.type)

                stdout += 'SDM IPC Data (CP2AP): seq_num={}, mseq={}, aseq={}, Group: {}, Command: {}, Type: {}, Data: {}'.format(
                    header.seq_num,
                    ipc_hdr.mseq, ipc_hdr.aseq, group_str, cmd_str, type_str,
                    binascii.hexlify(ipc_data).decode()
                )

        return {'stdout': stdout}
