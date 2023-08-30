#!/usr/bin/env python3

from scat.parsers.samsung.sdmcmd import *
import scat.util as util

import struct
import logging

class SdmTraceParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        self.process = {
            # 0x0103: lambda x, y: self.process_common_signaling(x, y)
        }

    def set_icd_ver(self, version):
        self.icd_ver = version