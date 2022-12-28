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
        # uint8: channel
        # 0x00 - DISCONNECTED, 0x01: CELL_DCH, 0x02: CELL_FACH, 0x03: CELL_PCH, 0x04: URA_PCH
        pkt = pkt[11:-1]

        if len(pkt) < 9:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (9)'.format(len(pkt)))
            return

        header = namedtuple('SdmHspaWcdmaRrcState', 'timestamp val1 val2 val3 val4 val5')
        rrc_state = header._make(struct.unpack('<IBBBBB', pkt[0:9]))
        print(rrc_state)

    def sdm_hspa_wcdma_serving_cell(self, pkt):
        pkt = pkt[11:-1]

        if len(pkt) < 12:
            self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (12)'.format(len(pkt)))
            return

        header = namedtuple('SdmHspaWcdmaServingCell', 'timestamp ul_uarfcn dl_uarfcn mcc mnc')
        scell_info = header._make(struct.unpack('<IHHHH', pkt[0:12]))
        print(scell_info)

        self.parent.umts_last_uarfcn_dl[0] = scell_info.dl_uarfcn
        self.parent.umts_last_uarfcn_ul[0] = scell_info.ul_uarfcn