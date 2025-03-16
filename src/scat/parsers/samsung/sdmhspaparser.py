#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct

import scat.parsers.samsung.sdmcmd as sdmcmd
import scat.util as util

class SdmHspaParser:
    def __init__(self, parent, icd_ver=(0, 0)):
        self.parent = parent
        self.icd_ver = icd_ver

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        g = (sdmcmd.sdm_command_group.CMD_HSPA_DATA << 8)
        c = sdmcmd.sdm_hspa_data
        self.process = {
            g | c.HSPA_UL1_UMTS_RF_INFO: lambda x: self.sdm_hspa_ul1_rf_info(x),
            g | c.HSPA_UL1_SERV_CELL: lambda x: self.sdm_hspa_ul1_serving_cell(x),
            g | c.HSPA_UL1_INTRA_FREQ_RESEL: lambda x: self.sdm_hspa_ul1_intra_freq_resel(x),
            g | c.HSPA_UL1_INTER_FREQ_RESEL: lambda x: self.sdm_hspa_ul1_inter_freq_resel(x),

            g | c.HSPA_URRC_RRC_STATUS: lambda x: self.sdm_hspa_wcdma_rrc_status(x),
            g | c.HSPA_URRC_NETWORK_INFO: lambda x: self.sdm_hspa_wcdma_serving_cell(x),
        }

    def set_icd_ver(self, version):
        self.icd_ver = version

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def sdm_hspa_ul1_rf_info_icd_4(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1RfInfoOld', 'uarfcn zero rssi txpwr')

        ul1_rf_info = header._make(struct.unpack('<HHhh', pkt[0:12]))
        extra = pkt[12:]

        stdout = 'HSPA UL1 RF Info: DL UARFCN: {}, RSSI: {:.2f}, TxPwr: {:.2f}'.format(
            ul1_rf_info.uarfcn,
            ul1_rf_info.rssi,
            ul1_rf_info.txpwr / 100
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_rf_info_icd_5(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1RfInfo', 'uarfcn psc rssi ecno rscp txpwr')

        ul1_rf_info = header._make(struct.unpack('<HHBBBB', pkt[0:12]))
        extra = pkt[12:]

        stdout = 'HSPA UL1 RF Info: DL UARFCN: {}, PSC: {}, RSSI: {:.2f}, Ec/No: {:.2f}, RSCP: {:.2f}, TxPwr: {:.2f}'.format(
            ul1_rf_info.uarfcn, ul1_rf_info.psc,
            ul1_rf_info.rssi - 101,
            (ul1_rf_info.ecno / 2) - 24.5,
            ul1_rf_info.rscp - 116,
            ul1_rf_info.txpwr - 71
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_rf_info(self, pkt):
        if self.icd_ver >= (5, 0):
            return self.sdm_hspa_ul1_rf_info_icd_5(pkt)
        else:
            return self.sdm_hspa_ul1_rf_info_icd_4(pkt)

    def sdm_hspa_ul1_serving_cell(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1ServingCell', 'psc cpich_rscp cpich_delta_rscp cpich_ecno drx_cycle')

        ul1_meas = header._make(struct.unpack('<HhhhH', pkt[0:10]))
        extra = pkt[10:]

        stdout = 'HSPA UL1 Serving Cell: PSC: {}, CPICH RSCP: {:.2f}, Delta RSCP: {:.2f}, Ec/No: {:.2f}, DRX: {} ms'.format(
            ul1_meas.psc,
            ul1_meas.cpich_rscp,
            ul1_meas.cpich_delta_rscp,
            ul1_meas.cpich_ecno,
            ul1_meas.drx_cycle
        )
        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_intra_freq_resel(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1IntraFreqResel', 'psc cpich_rscp cpich_ecno')

        num_meas = struct.unpack('<H', pkt[0:2])[0]
        stdout = ''

        stdout += 'HSPA UL1 Intra Frequency Reselection:\n'
        pos = 2
        for i in range(num_meas):
            intra_meas = header._make(struct.unpack('<Hhh', pkt[pos:pos+6]))
            stdout += 'Measurement {}: PSC: {}, CPICH RSCP: {}, CPICH Ec/No: {}\n'.format(
                i,
                intra_meas.psc,
                intra_meas.cpich_rscp,
                intra_meas.cpich_ecno,
            )
            pos += 6

        extra = pkt[pos:]

        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_ul1_inter_freq_resel(self, pkt):
        pkt = pkt[15:-1]
        header = namedtuple('SdmHspaUL1InterFreqResel', 'uarfcn psc cpich_rscp cpich_ecno')
        num_meas = struct.unpack('<H', pkt[0:2])[0]
        stdout = ''

        stdout += 'HSPA UL1 Inter Frequency Reselection:\n'
        pos = 2
        for i in range(num_meas):
            inter_meas = header._make(struct.unpack('<HHhh', pkt[pos:pos+8]))
            stdout += 'Measurement {}: UARFCN: {}, PSC: {}, CPICH RSCP: {}, CPICH Ec/No: {}\n'.format(
                i,
                inter_meas.uarfcn,
                inter_meas.psc,
                inter_meas.cpich_rscp,
                inter_meas.cpich_ecno,
            )
            pos += 8

        extra = pkt[pos:]

        if len(extra) > 0:
            stdout += "Extra: {}\n".format(binascii.hexlify(extra).decode())

        return {'stdout': stdout.rstrip()}

    def sdm_hspa_wcdma_rrc_status(self, pkt):
        # uint8: channel
        # 0x00 - DISCONNECTED, 0x01: CELL_DCH, 0x02: CELL_FACH, 0x03: CELL_PCH, 0x04: URA_PCH
        pkt = pkt[15:-1]
        stdout = ''
        rrc_state_map = {
            0: 'DISCONNECTED',
            1: 'CELL_DCH',
            2: 'CELL_FACH',
            3: 'CELL_PCH',
            4: 'URA_PCH',
        }

        rrc_domain_map = {
            0: 'IDLE',
            1: 'CS',
            2: 'PS',
            3: 'CS_PS',
        }

        rrc_rel_map = {
            0: 'UNKNOWN',
            1: 'R99',
            2: 'R4',
            3: 'R5',
            4: 'R6',
            5: 'R7',
        }

        if len(pkt) < 5:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (5)'.format(len(pkt)))
            return None

        header = namedtuple('SdmHspaWcdmaRrcState', 'rrc_state domain rrc_rel has_hs_dsch has_e_dch')
        rrc_state = header._make(struct.unpack('<BBBBB', pkt[0:5]))

        stdout += 'WCDMA RRC State: RRC Release: {}, RRC Status: {}, Domain: {}'.format(
            util.map_lookup_value(rrc_rel_map, rrc_state.rrc_rel),
            util.map_lookup_value(rrc_state_map, rrc_state.rrc_state),
            util.map_lookup_value(rrc_domain_map, rrc_state.domain),
        )
        return {'stdout': stdout}

    def sdm_hspa_wcdma_serving_cell(self, pkt):
        sdm_pkt_hdr = sdmcmd.parse_sdm_header(pkt[1:15])
        pkt = pkt[15:-1]

        if len(pkt) < 8:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Packet length ({}) shorter than expected (8)'.format(len(pkt)))
            return None

        header = namedtuple('SdmHspaWcdmaServingCell', 'ul_uarfcn dl_uarfcn mcc mnc')
        scell_info = header._make(struct.unpack('<HHHH', pkt[0:8]))
        if scell_info.dl_uarfcn == 0:
            return None
        stdout = 'WCDMA Serving Cell: UARFCN: {}/{}, MCC: {:x}, MNC: {:x}'.format(scell_info.dl_uarfcn,
            scell_info.ul_uarfcn, scell_info.mcc, scell_info.mnc)

        if self.parent:
            self.parent.umts_last_uarfcn_dl[sdm_pkt_hdr.radio_id] = scell_info.dl_uarfcn
            self.parent.umts_last_uarfcn_ul[sdm_pkt_hdr.radio_id] = scell_info.ul_uarfcn

        return {'stdout': stdout}
