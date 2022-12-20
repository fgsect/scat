#!/usr/bin/env python3

from .sdmcmd import *
import util

import struct
import logging

class SdmHspaParser:
    def __init__(self, parent):
        self.parent = parent

        self.process = {
            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_WCDMA_RRC_STATUS: lambda x: self.sdm_hspa_wcdma_rrc_status(x),
            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_WCDMA_SERVING_CELL: lambda x: self.sdm_hspa_wcdma_serving_cell(x),
        }

    def sdm_hspa_wcdma_rrc_status(self, pkt):
        # 0x20 - RRC status
        # uint8: channel, 0x00 - DISCONNECTED, 0x01: CELL_DCH, 0x02: CELL_FACH, 0x03: CELL_PCH, 0x04: URA_PCH
        #if pkt[0] == 0x28:
        #if len(pkt) < 0x40:
            #util.xxd(pkt)
        pkt = pkt[11:-1]

    def sdm_hspa_wcdma_serving_cell(self, pkt):
        pkt = pkt[11:-1]

        self.parent.umts_last_uarfcn_dl[0] = pkt[5] | (pkt[6] << 8)
        self.parent.umts_last_uarfcn_ul[0] = pkt[7] | (pkt[8] << 8)