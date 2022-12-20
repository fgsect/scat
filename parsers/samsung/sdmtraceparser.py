#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmTraceParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # 0x0103: lambda x, y: self.process_common_signaling(x, y)
        }
