#!/usr/bin/env python3

from scat.parsers.samsung.sdmcmd import *
import scat.util as util

import struct
import logging
import binascii

class SdmControlParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver
        self.trace_group = {}
        self.ilm_group = {}
        self.ilm_total_count = 0
        self.ilm_cur_count = 0
        self.trigger_group = {}

        self.process = {
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CONTROL_START_RESPONSE: lambda x: self.sdm_control_start_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CHANGE_UPDATE_PERIOD_RESPONSE: lambda x: self.sdm_control_change_update_period_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.COMMON_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x10),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.LTE_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x20),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.EDGE_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x30),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.HSPA_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x40),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CDMA_ITEM_SELECT_RESPONSE: lambda x: self.sdm_control_item_select_response(x, 0x44),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.TRACE_TABLE_GET_RESPONSE: lambda x: self.sdm_dm_trace_table_get_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.ILM_ENTITY_TAGLE_GET_RESPONSE: lambda x: self.sdm_dm_ilm_table_get_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.TCPIP_DUMP_RESPONSE: lambda x: self.sdm_control_tcpip_dump_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.TRIGGER_TABLE_RESPONSE: lambda x: self.sdm_dm_trigger_table_response(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def sdm_control_start_response(self, pkt):
        pkt = pkt[15:-1]

        version_str = pkt[2:27]
        if version_str[0:6] == b'LibVer':
            version_str = "LibVer: {}, ASN: {}".format(
                binascii.hexlify(version_str[6:12]).decode(errors='backslashreplace'),
                binascii.hexlify(version_str[15:25]).decode(errors='backslashreplace'),
            )
        else:
            version_str = version_str.decode(errors='backslashreplace').split('\x00',1)[0]
        date_str = pkt[27:52].decode(errors='backslashreplace').split('\x00',1)[0]
        extra_str_len = pkt[54]
        extra_str = pkt[57:]
        rest_str = b''
        if len(extra_str) > extra_str_len:
            rest_str = extra_str[extra_str_len:]
            extra_str = extra_str[:extra_str_len]
        extra_str = extra_str.decode(errors='backslashreplace').split('\x00',1)[0]
        chip_id = 0
        if len(rest_str) == 4:
            chip_id = struct.unpack('<L', rest_str)[0]
        elif len(rest_str) == 2:
            chip_id = struct.unpack('<H', rest_str)[0]

        icd_ver_min = pkt[55]
        icd_ver_maj = pkt[56]

        if icd_ver_maj > 0:
            if self.parent:
                self.parent.update_icd_ver((icd_ver_maj, icd_ver_min))
            else:
                self.set_icd_ver((icd_ver_maj, icd_ver_min))

        stdout = "SDM Start Response: Version: {}, ICD: {}.{}, Date: {}{}{}".format(
            version_str, icd_ver_maj, icd_ver_min, date_str,
            ', Extra: ' + extra_str if len(extra_str) > 0 else '',
            ', ID: ' + hex(chip_id) if len(rest_str) > 0 else ''
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
                elif group == 0x44:
                    item_name = '{:#04x} ITEM_{:02x}'.format(index, index)
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
            trace_items_list.append(itemstr.decode(errors='backslashreplace'))
            pos += (1+strlen)
        self.trace_group[item.trace_group_id] = trace_items_list

        if item.is_end == 1:
            stdout += 'SDM Trace Table:\n'
            for x in self.trace_group:
                stdout += 'Group ID {:#06x}, Items: {}\n'.format(x, ', '.join(self.trace_group[x]))

        return {'stdout': stdout}

    def sdm_dm_ilm_table_get_response(self, pkt):
        pkt = pkt[15:-1]

        item_struct = namedtuple('SdmIlmTableGetResponse', 'is_end unk total_item_count packet_item_count')
        subitem_struct = namedtuple('SdmIlmTableIlmItem', 'id unk1 unk2 unk3 text_len')
        item = item_struct._make(struct.unpack('<BBBB', pkt[0:4]))
        content = pkt[4:]
        stdout = ''
        if self.ilm_total_count != 0:
            if self.ilm_total_count != item.total_item_count:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, "ILM item total count changed: {} -> {}".format(self.ilm_total_count, item.total_item_count))
        else:
            self.ilm_total_count = item.total_item_count

        for i in range(item.packet_item_count):
            subitem = content[33*i:33*(i+1)]
            item_hdr = subitem_struct._make(struct.unpack('<BLBBB', subitem[0:8]))
            if item_hdr.text_len > 25:
                item_str = subitem[8:].decode(errors='backslashreplace')
            else:
                item_str = subitem[8:8+item_hdr.text_len].decode(errors='backslashreplace')
            self.ilm_group[item_hdr.id] = (item_hdr.unk1, item_hdr.unk2, item_hdr.unk3, item_str)
            self.ilm_cur_count += 1

        if item.is_end == 1:
            if self.ilm_total_count != self.ilm_cur_count:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, "ILM item count mismatch: {} != {}".format(self.ilm_total_count, self.ilm_cur_count))
            stdout += 'SDM ILM Table:\n'
            for x in self.ilm_group:
                stdout += 'Item ID {:#06x}, Args: {:#10x}, {:#04x}, {:#04x}, Text: {}\n'.format(x,
                    self.ilm_group[x][0], self.ilm_group[x][1], self.ilm_group[x][2],
                    self.ilm_group[x][3])

        return {'stdout': stdout}

    def sdm_control_tcpip_dump_response(self, pkt):
        pkt = pkt[15:-1]
        item_struct = namedtuple('SdmControlTcpipDumpResponse', 'dl_size ul_size')
        item = item_struct._make(struct.unpack('<HH', pkt[0:4]))

        stdout = 'TCP/IP Dump Response: DL max {} bytes, UL max {} bytes'.format(item.dl_size, item.ul_size)
        return {'stdout': stdout}

    def sdm_dm_trigger_table_response(self, pkt):
        pkt = pkt[15:-1]

        item_struct = namedtuple('SdmTriggerTableResponse', 'num_items1 num_items2')
        subitem_struct = namedtuple('SdmTriggerTableItem', 'id text_len')
        item = item_struct._make(struct.unpack('<LL', pkt[0:8]))
        content = pkt[8:]

        pos = 0
        stdout = ''

        for i in range(item.num_items1):
            subitem = subitem_struct._make(struct.unpack('<LL', content[pos:pos+8]))
            subitem_text = content[pos+8:pos+8+subitem.text_len].decode(errors='backslashreplace')
            self.trigger_group[subitem.id] = subitem_text
            pos += (8 + subitem.text_len)

        stdout += 'SDM Trigger Table:\n'
        for x in self.trigger_group:
            stdout += 'Item ID {:#06x}, Text: {}\n'.format(x, self.trigger_group[x])

        return {'stdout': stdout}
