#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging
import binascii

class SdmControlParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.trace_group = {}

        self.process = {
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CONTROL_START_RESPONSE: lambda x: self.sdm_control_start_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CHANGE_UPDATE_PERIOD_RESPONSE: lambda x: self.sdm_control_change_update_period_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.COMMON_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x10),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.LTE_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x20),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.EDGE_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x30),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.HSPA_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x40),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CDMA_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x44),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.TRACE_TABLE_GET_RESPONSE: lambda x: self.sdm_dm_trace_table_get_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.TCPIP_DUMP_RESPONSE: lambda x: self.sdm_control_tcpip_dump_response(x),
        }

    def set_model(self, model):
        self.model = model

    def sdm_control_start_response(self, pkt):
        pkt = pkt[15:-1]

        version_str = pkt[2:27]
        if version_str[0:6] == b'LibVer':
            version_str = "LibVer: {}, ASN: {}".format(
                binascii.hexlify(version_str[6:12]).decode('utf-8'),
                binascii.hexlify(version_str[15:25]).decode('utf-8'),
            )
        else:
            version_str = version_str.decode('utf-8').split('\x00',1)[0]
        date_str = pkt[27:52].decode('utf-8').split('\x00',1)[0]
        extra_str_len = pkt[54]
        extra_str = pkt[57:]
        rest_str = b''
        if len(extra_str) > extra_str_len:
            rest_str = extra_str[extra_str_len:]
            extra_str = extra_str[:extra_str_len]
        extra_str = extra_str.decode('utf-8').split('\x00',1)[0]

        stdout = "SDM Start Response: Version: {}, Date: {}{}".format(
            version_str, date_str,
            ', Extra: ' + extra_str if len(extra_str) > 0 else ''
        )
        return {'stdout': stdout}

    def sdm_control_change_update_period_response(self, pkt):
        pkt = pkt[15:-1]
        if len(pkt) < 2:
            return None
        item_struct = namedtuple('SdmControlChangeUpdatePeriodResponse', 'val1 val2')
        item = item_struct._make(struct.unpack('<BB', pkt[0:2]))

        stdout = 'Change Update Period Response: {} {}'.format(item.val1, item.val2)
        return {'stdout': stdout}

    def sdm_control_item_select_response(self, pkt, group):
        pkt = pkt[15:-1]
        group_name_map = {0x10: 'Common', 0x20: 'LTE', 0x30: 'EDGE', 0x40: 'HSPA', 0x44: 'CDMA'}
        group_text = group_name_map[group] if group in group_name_map else 'Unknown'

        stdout = 'Item Select Response for {}{}:\n'.format(group_text, '' if len(pkt) == (pkt[0]+1) else ' (length mismatch)')

        index = 0
        for i in pkt[1:]:
            item_name = ''
            try:
                if group == 0x10:
                    item_name = '{:#04x} {}'.format(index, sdm_common_data(index).name)
                elif group == 0x20:
                    item_name = '{:#04x} {}'.format(index, sdm_lte_data(index).name)
                elif group == 0x30:
                    item_name = '{:#04x} {}'.format(index, sdm_edge_data(index).name)
                elif group == 0x40:
                    item_name = '{:#04x} {}'.format(index, sdm_hspa_data(index).name)
            except ValueError:
                item_name = '{:#04x} ITEM_{:02x}'.format(index, index)
            if i == 1:
                stdout += ' * {}: set\n'.format(item_name)
            index += 1

        return {'stdout': stdout.rstrip()}

    def sdm_dm_trace_table_get_response(self, pkt):
        pkt = pkt[15:-1]

        item_struct = namedtuple('SdmDmTraceTableGetResponse', 'is_end two trace_group_id')
        item = item_struct._make(struct.unpack('<BBH', pkt[0:4]))
        content = pkt[4:]
        trace_items_list = []
        stdout = ''

        pos = 0
        while pos < len(content) and content[pos] != 0x00:
            strlen = content[pos]
            itemstr = content[pos+1:pos+1+strlen]
            trace_items_list.append(itemstr.decode('utf-8'))
            pos += (1+strlen)
        self.trace_group[item.trace_group_id] = trace_items_list

        if item.is_end == 1:
            stdout += 'SDM Trace Table:\n'
            for x in self.trace_group:
                stdout += 'Group ID {:#06x}, Items: {}\n'.format(x, ', '.join(self.trace_group[x]))

        return {'stdout': stdout}

    def sdm_control_tcpip_dump_response(self, pkt):
        pkt = pkt[15:-1]
        item_struct = namedtuple('SdmControlTcpipDumpResponse', 'dl_size ul_size')
        item = item_struct._make(struct.unpack('<HH', pkt[0:4]))

        stdout = 'TCP/IP Dump Response: DL max {} bytes, UL max {} bytes'.format(item.dl_size, item.ul_size)
        return {'stdout': stdout}
