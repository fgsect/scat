#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct

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

    def sdm_trace_dbt(self, pkt: bytes):
        pkt = pkt[15:-1]

        if self.parent:
            if not self.parent.trace:
                return None

        item_struct = namedtuple('SdmTraceDBTItem', 'trace_item_id trace_item_level')
        dbt_ptr_struct = namedtuple('SdmTraceDBTPointer', 'dbt_addr zero num_args')
        dbt_struct = namedtuple('SdmTraceDBTStruct', 'magic_1 group item magic_2 message_ptr line_num file_ptr')
        item = item_struct._make(struct.unpack('<HH', pkt[0:4]))
        content = pkt[4:]
        if self.parent:
            mmap_region_debug_symbol = [
                util.mmap_memory_pos._make((self.parent.trace_bin_addr, 0, self.parent.trace_bin_size, self.parent.trace_bin_mmap)),
                util.mmap_memory_pos._make((self.parent.const_bin_addr, 0, self.parent.const_bin_size, self.parent.const_bin_mmap)),
            ]
        else:
            mmap_region_debug_symbol = []

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

                if self.check_range(self.parent.trace_bin_addr, self.parent.trace_bin_size, dbt_ptr.dbt_addr):
                    pos = dbt_ptr.dbt_addr - self.parent.trace_bin_addr
                    dbt = dbt_struct._make(struct.unpack('<LLLLLLL', self.parent.trace_bin_mmap[pos:pos+28]))
                    if dbt.magic_1 == 0x3a544244 and dbt.magic_2 == 0xfecdba98:
                        msg_str = util.snprintf('%s', [dbt.message_ptr], mmap_region_debug_symbol)
                        fname_str = util.snprintf('%s', [dbt.file_ptr], mmap_region_debug_symbol)

                        stdout += 'Group: {}, Item: {}, {}:{} - {}, args: {}\n'.format(
                            dbt.group, dbt.item,
                            fname_str, dbt.line_num, msg_str,
                            ', '.join([hex(x) for x in dbt_args])
                        )
            except:
                break

        return {'stdout': stdout.rstrip()}
