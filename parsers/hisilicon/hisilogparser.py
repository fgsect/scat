#!/usr/bin/env python3

from collections import namedtuple
import util
import binascii

import struct
import logging

class HisiLogParser:
    def __init__(self, parent, model=None):
        self.parent = parent

        self.process = {
            0x10051082: lambda x, y, z: self.hisi_lte_current_cell_info(x, y, z),
            0x20010000: lambda x, y, z: self.hisi_lte_ota_msg(x, y, z),
        }

    def hisi_lte_ota_msg(self, pkt_header, pkt_data, args):
        # Direction: 1: DL, 2: UL
        header = namedtuple('HisiLteOtaMessage', 'chan_type direction unk2 unk3')
        if len(pkt_data) < 16:
            return None

        ota_hdr = header._make(struct.unpack('<LLLL', pkt_data[0:16]))
        ota_content = pkt_data[16:]

        pkt_content = b''
        if ota_hdr.chan_type == 0xab:
            # LTE RRC
            rrc_chan_type = ota_content[0]
            pkt_content = ota_content[1:]

            # 01: DL DCCH 02: UL DCCH 03: DL CCCH 04: UL CCCH
            # 05: PCCH 06: BCCH DL-SCH 07: BCCH BCH
            # 08: UECapabilityInfoEUTRA - GSMTAP cannot encapsulate it

            rrc_subtype_map = {
                0x01: util.gsmtap_lte_rrc_types.DL_DCCH,
                0x02: util.gsmtap_lte_rrc_types.UL_DCCH,
                0x03: util.gsmtap_lte_rrc_types.DL_CCCH,
                0x04: util.gsmtap_lte_rrc_types.UL_CCCH,
                0x05: util.gsmtap_lte_rrc_types.PCCH,
                0x06: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                0x07: util.gsmtap_lte_rrc_types.BCCH_BCH,
            }

            if rrc_chan_type == 8:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Ignoring EUTRA UECapability as GSMTAP cannot encapsulate it')
                return None

            if not (rrc_chan_type in rrc_subtype_map):
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'Unknown LTE RRC channel type {:#x}'.format(rrc_chan_type))
                return None

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_RRC,
                arfcn = self.parent.lte_last_earfcn_dl[0] if self.parent else 0,
                sub_type = rrc_subtype_map[rrc_chan_type])

            return {'cp': [gsmtap_hdr + pkt_content]}

        elif ota_hdr.chan_type == 0xad or ota_hdr[0] == 0xae:
            # NAS-EPS EMM, ESM
            pkt_content = ota_content

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_NAS,
                arfcn = 0,
                sub_type = 0)

            return {'cp': [gsmtap_hdr + pkt_content]}

        else:
            if self.parent:
                self.parent.log(logging.WARNING, 'Unknown LTE OTA message type {:#x}'.format(ota_hdr.chan_type))
            return None

    def hisi_lte_current_cell_info(self, pkt_header, pkt_data, args):
        # TODO: Frequency to EARFCN fallback

        header = namedtuple('HisiLteCurrentCellInfo', 'ul_earfcn dl_earfcn ul_freq dl_freq ul_bw dl_bw band_ind')

        cell_info = header._make(struct.unpack('<HHHHHHH', pkt_data[-32:-18]))
        nrb_to_bw = {
                0: 0,
                6: 1.4,
                15: 3,
                25: 5,
                50: 10,
                75: 15,
                100: 20 }

        if self.parent:
            self.parent.lte_last_earfcn_ul[0] = cell_info.ul_earfcn
            self.parent.lte_last_earfcn_dl[0] = cell_info.dl_earfcn

            if cell_info.ul_bw in nrb_to_bw:
                self.parent.lte_last_bw_ul[0] = nrb_to_bw[cell_info.ul_bw]
            else:
                self.parent.lte_last_bw_ul[0] = 0

            if cell_info.dl_bw in nrb_to_bw:
                self.parent.lte_last_bw_dl[0] = nrb_to_bw[cell_info.dl_bw]
            else:
                self.parent.lte_last_bw_dl[0] = 0

            self.parent.lte_last_band_ind[0] = cell_info.band_ind

        stdout = 'LTE Current Cell Info: EARFCN {}/{} ({:.1f}/{:.1f} MHz), Bandwidth {}/{} MHz, Band {}'.format(
            cell_info.dl_earfcn, cell_info.ul_earfcn, cell_info.dl_freq / 10, cell_info.ul_freq / 10,
            nrb_to_bw[cell_info.dl_bw], nrb_to_bw[cell_info.ul_bw], cell_info.band_ind
        )
        return {'stdout': stdout}
