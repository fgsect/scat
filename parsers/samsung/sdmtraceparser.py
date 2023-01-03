#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmTraceParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            # 0x0103: lambda x, y: self.process_common_signaling(x, y)
        }
