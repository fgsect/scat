#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging


class DiagNrLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            # NR
            # NR RRC COMBOS
            0xB826: lambda x, y, z: self.parse_cacombos(x, y, z),
        }
    def parse_cacombos(self, pkt_ts, pkt, radio_id):
        self.parent.logger.log(logging.WARNING, "0xB826 " + util.xxd_oneline(pkt))
