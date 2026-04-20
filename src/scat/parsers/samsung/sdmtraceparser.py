#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct
import os

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmTraceParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_TRACE_DATA << 8)
        self.process = {
            g | 0x90: lambda x: self.sdm_trace_dbt(x),
        }

        self.mmap_region_debug_symbol = []
        self.modem_bin_available = False
        self.dbt_struct = namedtuple('SdmTraceDBTStruct', 'magic_1 group item magic_2 message_ptr line_num file_ptr')

    def set_icd_ver(self, version: tuple):
        self.icd_ver = version

    def update_parameters(self, display_format: str, gsmtapv3: bool):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def check_range(self, base: int, len: int, addr: int) -> bool:
        if addr >= base and addr < (base + len):
            return True
        else:
            return False

    def _sdm_get_dbt(self, dbt_addr: int, dbt_args: list[int]) -> dict:
        ret = {}
        if not self.parent:
            return ret

        for region in self.mmap_region_debug_symbol:
            if self.check_range(region.start_addr, region.length, dbt_addr):
                pos = dbt_addr - region.start_addr + region.mmap_offset
                dbt = self.dbt_struct._make(struct.unpack('<LLLLLLL', region.mmap_object[pos:pos+28]))

                if dbt.magic_1 == 0x3a544244 and dbt.magic_2 == 0xfecdba98:
                    msg_str = ''
                    fname_str = ''
                    for region1 in self.mmap_region_debug_symbol:
                        if self.check_range(region1.start_addr, region1.length, dbt.message_ptr):
                            file_pos = dbt.message_ptr - region1.start_addr + region1.mmap_offset
                            msg_pos = region1.mmap_object.find(b'\x00', file_pos)
                            if msg_pos > file_pos:
                                msg_str = region1.mmap_object[file_pos:msg_pos].decode()
                                break

                    for region1 in self.mmap_region_debug_symbol:
                        if self.check_range(region1.start_addr, region1.length, dbt.file_ptr):
                            file_pos = dbt.file_ptr - region1.start_addr + region1.mmap_offset
                            msg_pos = region1.mmap_object.find(b'\x00', file_pos)
                            if msg_pos > file_pos:
                                fname_str = region1.mmap_object[file_pos:msg_pos].decode()
                                break

                    ret['group'] = dbt.group
                    ret['item'] = dbt.item
                    ret['filename'] = fname_str
                    ret['line'] = dbt.line_num
                    ret['msg'] = msg_str
                    break

        if 'msg' in ret:
            formatted = util.snprintf(ret['msg'], dbt_args)
            ret['msg'] = formatted
        return ret

    def sdm_trace_dbt(self, pkt: bytes):
        pkt = pkt[15:-1]
        ret = []

        if self.parent:
            if not self.parent.trace_loaded:
                return None

        item_struct = namedtuple('SdmTraceDBTItem', 'trace_item_id trace_item_level')
        dbt_ptr_struct = namedtuple('SdmTraceDBTPointer', 'dbt_addr zero num_args')
        item = item_struct._make(struct.unpack('<HH', pkt[0:4]))
        content = pkt[4:]

        stdout = 'ID: {}, Level: {:#x}\n'.format(item.trace_item_id, item.trace_item_level)
        pos = 0
        while pos < len(content):
            try:
                # Something we don't want
                if content[pos:pos+5] == b'[MIF]':
                    pos += 5
                    pos += 14
                    continue
                if content[pos:pos+6] == b'LTE_PS':
                    pos += 5
                    pos += 14
                    continue

                dbt_ptr = dbt_ptr_struct._make(struct.unpack('<LHB', content[pos:pos+7]))
                if dbt_ptr.zero != 0x0000 or dbt_ptr.num_args > 0x20:
                    # Invalid read
                    pos += 1
                    continue
                pos += 7
                if (pos + 4 * (dbt_ptr.num_args+1)) >= len(content):
                    num_args_real = (len(content) - pos) // 4
                    dbt_args = struct.unpack('<' + 'L' * num_args_real, content[pos:pos+4*(num_args_real)])
                    pos = len(content)
                else:
                    dbt_args = struct.unpack('<' + 'L' * (dbt_ptr.num_args+1), content[pos:pos+4*(dbt_ptr.num_args+1)])
                    pos += (4 * (dbt_ptr.num_args + 1))

                dbt_obj = self._sdm_get_dbt(dbt_ptr.dbt_addr, dbt_args)

                if 'filename' in dbt_obj:
                    try:
                        fname_str = os.path.basename(dbt_obj['filename'])[-32:]
                    except:
                        fname_str = dbt_obj['filename'][-32:]

                    osmocore_log_hdr = util.create_osmocore_logging_header(
                        filename = fname_str,
                        subsys_name = '{}/{}'.format(dbt_obj['group'], dbt_obj['item']),
                        line_number = dbt_obj['line']
                    )
                    gsmtap_hdr = util.create_gsmtap_header(
                        version = 2,
                        payload_type = util.gsmtap_type.OSMOCORE_LOG)

                    final_msg = '{}:{} {}'.format(dbt_obj['filename'], dbt_obj['line'], dbt_obj['msg']).encode('utf-8')
                    payload = (gsmtap_hdr + osmocore_log_hdr + final_msg)
                    ret.append(payload)
                else:
                    if self.parent:
                        self.parent.logger.log(logging.WARNING, "DBT item address {:#x} does not exist in the modem image or debug symbol. Check whether modem firmware version of the image matches with the device/SDM file.".format(dbt_ptr.dbt_addr))
            except:
                break

        return {'cp': ret, 'stdout': stdout.rstrip()}
