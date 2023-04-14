#!/usr/bin/env python3

from .sdmcmd import *
import util
import binascii

import struct
import logging
from collections import namedtuple

class SdmHspaParser:
    def __init__(self, parent, model=None):
        self.parent = parent
        if model:
            self.model = model
        else:
            self.model = self.parent.model

        self.process = {
            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO: lambda x: self.sdm_hspa_ul1_rf_info(x),
            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_UL1_SERV_CELL: lambda x: self.sdm_hspa_ul1_serving_cell(x),

            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_URRC_RRC_STATUS: lambda x: self.sdm_hspa_wcdma_rrc_status(x),
            (sdm_command_group.CMD_HSPA_DATA << 8) | sdm_hspa_data.HSPA_URRC_NETWORK_INFO: lambda x: self.sdm_hspa_wcdma_serving_cell(x),
        }

    def set_model(self, model):
        self.model = model

    def sdm_hspa_ul1_rf_info_old(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1RfInfoOld', 'uarfcn zero rssi txpwr')

        ul1_rf_info = header._make(struct.unpack('<HHhh', pkt[0:12]))
        extra = pkt[12:]

        stdout = 'HSPA UL1 RF Info: DL UARFCN {}, RSSI {:.2f}, TxPwr {:.2f}'.format(
            ul1_rf_info.uarfcn,
            ul1_rf_info.rssi,
            ul1_rf_info.txpwr / 100
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode('utf-8'))

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_rf_info_e355(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1RfInfo', 'uarfcn psc rssi ecno rscp txpwr')

        ul1_rf_info = header._make(struct.unpack('<HHBBBB', pkt[0:12]))
        extra = pkt[12:]

        stdout = 'HSPA UL1 RF Info: DL UARFCN {}, PSC {}, RSSI {:.2f}, Ec/No {:.2f}, RSCP {:.2f}, TxPwr {:.2f}'.format(
            ul1_rf_info.uarfcn, ul1_rf_info.psc,
            ul1_rf_info.rssi - 101,
            (ul1_rf_info.ecno / 2) - 24.5,
            ul1_rf_info.rscp - 116,
            ul1_rf_info.txpwr - 71
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode('utf-8'))

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_rf_info(self, pkt):
        if self.model == 'cmc221s' or self.model == 'e333':
            return self.sdm_hspa_ul1_rf_info_old(pkt)
        else:
            return self.sdm_hspa_ul1_rf_info_e355(pkt)

    def sdm_hspa_ul1_serving_cell(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1ServingCell', 'psc cpich_rscp cpich_delta_rscp cpich_ecno drx_cycle')

        ul1_meas = header._make(struct.unpack('<HhhhH', pkt[0:10]))
        extra = pkt[10:]

        stdout = 'HSPA UL1 Serving Cell: PSC {}, CPICH RSCP {:.2f}, Delta RSCP {:.2f}, Ec/No {:.2f}, DRX {} ms'.format(
            ul1_meas.psc,
            ul1_meas.cpich_rscp,
            ul1_meas.cpich_delta_rscp,
            ul1_meas.cpich_ecno,
            ul1_meas.drx_cycle
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode('utf-8'))

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_wcdma_rrc_status(self, pkt):
        # uint8: channel
        # 0x00 - DISCONNECTED, 0x01: CELL_DCH, 0x02: CELL_FACH, 0x03: CELL_PCH, 0x04: URA_PCH
        pkt = pkt[15:-1]

        if len(pkt) < 5:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (5)'.format(len(pkt)))
            return None

        header = namedtuple('SdmHspaWcdmaRrcState', 'val1 val2 val3 val4 val5')
        rrc_state = header._make(struct.unpack('<BBBBB', pkt[0:5]))
        # print(rrc_state)

    def sdm_hspa_wcdma_serving_cell(self, pkt):
        sdm_pkt_hdr = parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        if len(pkt) < 8:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (8)'.format(len(pkt)))
            return None

        header = namedtuple('SdmHspaWcdmaServingCell', 'ul_uarfcn dl_uarfcn mcc mnc')
        scell_info = header._make(struct.unpack('<HHHH', pkt[0:8]))
        if scell_info.dl_uarfcn == 0:
            return None
        stdout = 'WCDMA Serving Cell: UARFCN {}/{}, MCC {:x}, MNC {:x}'.format(scell_info.dl_uarfcn,
            scell_info.ul_uarfcn, scell_info.mcc, scell_info.mnc)

        if self.parent:
            self.parent.umts_last_uarfcn_dl[sdm_pkt_hdr.radio_id] = scell_info.dl_uarfcn
            self.parent.umts_last_uarfcn_ul[sdm_pkt_hdr.radio_id] = scell_info.ul_uarfcn

        return {'stdout': stdout}
