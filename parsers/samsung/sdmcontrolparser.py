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

        self.process = {
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | sdm_control_message.CONTROL_START_RESPONSE: lambda x: self.sdm_control_start_response(x),
            (sdm_command_group.CMD_CONTROL_MESSAGE << 8) | 0x57: lambda x: self.sdm_dm_trace_table_get_response(x),
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

    def sdm_dm_trace_table_get_response(self, pkt):
        pkt = pkt[11:-1]

        item_struct = namedtuple('SdmDmTraceTableGetResponse', 'timestamp trace_item_id')
        item = item_struct._make(struct.unpack('<LL', pkt[0:8]))
        content = pkt[8:]
        trace_items = {'item_id': item.trace_item_id, 'string': []}

        pos = 0
        while pos < len(content) and content[pos] != 0x00:
            strlen = content[pos]
            itemstr = content[pos+1:pos+1+strlen]
            trace_items['string'].append(itemstr.decode('utf-8'))
            pos += (1+strlen)

        stdout = "SDM Trace Table Get Response: ID {:#08x}, Items: {}".format(trace_items['item_id'],
            ', '.join(trace_items['string']))

        return {'stdout': stdout}
