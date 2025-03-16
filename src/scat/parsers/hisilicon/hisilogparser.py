#!/usr/bin/env python3

from collections import namedtuple
import binascii
import logging
import struct

import scat.util as util

class HisiLogParser:
    def __init__(self, parent, model=None):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        self.process = {
            0x10051082: lambda x, y, z: self.hisi_lte_current_cell_info(x, y, z),
            0x20010000: lambda x, y, z: self.hisi_lte_ota_msg(x, y, z),
            0x30940001: lambda x, y, z: self.hisi_debug_msg(x, y, z),
            0x20030000: lambda x, y, z: self.hisi_debug_msg(x, y, z),
            0x20020000: lambda x, y, z: self.hisi_0x20020000(x, y, z),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

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

            return {'layer': 'rrc', 'cp': [gsmtap_hdr + pkt_content]}

        elif ota_hdr.chan_type == 0xad or ota_hdr[0] == 0xae:
            # NAS-EPS EMM, ESM
            pkt_content = ota_content

            gsmtap_hdr = util.create_gsmtap_header(
                version = 2,
                payload_type = util.gsmtap_type.LTE_NAS,
                arfcn = 0,
                sub_type = 0)

            return {'layer': 'nas', 'cp': [gsmtap_hdr + pkt_content]}

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

        stdout = 'LTE Current Cell Info: EARFCN: {}/{} ({:.1f}/{:.1f} MHz), Bandwidth: {}/{} MHz, Band: {}'.format(
            cell_info.dl_earfcn, cell_info.ul_earfcn, cell_info.dl_freq / 10, cell_info.ul_freq / 10,
            nrb_to_bw[cell_info.dl_bw], nrb_to_bw[cell_info.ul_bw], cell_info.band_ind
        )
        return {'stdout': stdout}

    def hisi_debug_msg(self, pkt_header, pkt_data, args):
        # TODO decode hisi ts
        if not self.parent.msgs:
            return None

        if pkt_header.cmd == 0x30940001:
            log_prefix = b'[NORM] '
            app_name = '[NORM]'
        elif pkt_header.cmd == 0x20030000:
            log_prefix = b'[SSRC] '
            app_name = '[SSRC]'
            # ?, ?, seq_nr
            # pkt_info = struct.unpack('<LLL', pkt_data[:12])
            # print(pkt_info)
            pkt_data = pkt_data[12:]
        else:
            log_prefix = b''
            app_name = ''

        osmocore_log_hdr = util.create_osmocore_logging_header(
            process_name = app_name,
            subsys_name = '',
            filename = '',
            line_number = 0
        )

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.OSMOCORE_LOG)

        return {'cp': [gsmtap_hdr + osmocore_log_hdr + log_prefix + pkt_data]}

    def hisi_0x20020000(self, pkt_header, pkt_data, args):
        stdout = ''
        header = namedtuple('Hisi0x20020000', 'cmdid1 unk2 seq_nr msgid cmdid2 unk6 unk7 unk8 inner_len')

        info = header._make(struct.unpack('<LLLLLLLLL', pkt_data[0:36]))
        info_data = pkt_data[36:]
        # print('1: ' + str(info))
        # print('Data: ' + binascii.hexlify(pkt_data[36:]).decode('utf-8'))
        if info.msgid == 0x0986:
            inner_header = namedtuple('Hisi0x20020000_0x0986', 'msgid opid cmd')
            inner_header_data = inner_header._make(struct.unpack('<LHH', info_data[0:8]))
            if inner_header_data.cmd == 0x1f:
                # Idle measurement, Serving cell
                scell_header = namedtuple('HisiSCellHeader', 'freq band')
                scell_meas = namedtuple('HisiSCellMeas', 'pci rsrp rsrq unk')
                scell_header_data = scell_header._make(struct.unpack('<HH', info_data[8:12]))

                stdout += 'Idle mode serving cell measurement: {:.1f} MHz (Band {}), '.format(
                    scell_header_data.freq / 10, scell_header_data.band
                )
                scell_meas_data = scell_meas._make(struct.unpack('<Hhhh', info_data[12:20]))
                stdout += 'PCI: {}, RSRP: {:.1f}, RSRQ: {:.1f}\n'.format(
                    scell_meas_data.pci,
                    scell_meas_data.rsrp / 10, scell_meas_data.rsrq / 10
                )
            elif inner_header_data.cmd == 0x20:
                # Idle measurement, Intra frequency cell
                intra_freq_header = namedtuple('HisiIntraFreqHeader', 'freq band total_cell detected_cell')
                intra_freq_meas = namedtuple('HisiIntraFreqMeas', 'pci rsrp rsrq unk')
                intra_freq_header_data = intra_freq_header._make(struct.unpack('<HHHH', info_data[8:16]))

                stdout += 'Idle mode intra frequency cell measurement: {:.1f} MHz (Band {}), Total/Detected: {}/{}\n'.format(
                    intra_freq_header_data.freq / 10, intra_freq_header_data.band,
                    intra_freq_header_data.total_cell, intra_freq_header_data.detected_cell
                )
                for i in range(intra_freq_header_data.total_cell):
                    intra_freq_meas_data = intra_freq_meas._make(struct.unpack('<Hhhh', info_data[8*(i+2):8*(i+3)]))
                    stdout += 'Cell {}: PCI: {}, RSRP: {:.1f}, RSRQ: {:.1f}\n'.format(i,
                        intra_freq_meas_data.pci,
                        intra_freq_meas_data.rsrp / 10, intra_freq_meas_data.rsrq / 10,
                    )
            elif inner_header_data.cmd == 0x21:
                # Idle measurement, Inter frequency cell
                num_freqs = struct.unpack('<H', info_data[8:10])[0]
                inter_freq_header = namedtuple('HisiInterFreqHeader', 'cur_band freq band total_cell detected_cell')
                inter_freq_meas = namedtuple('HisiInterFreqMeas', 'pci rsrp rsrq unk')
                pos = 10
                for i in range(num_freqs):
                    inter_freq_header_data = inter_freq_header._make(struct.unpack('<HHHHH', info_data[pos:pos+10]))
                    pos += 10

                    stdout += 'Idle mode inter frequency cell measurement: {:.1f} MHz (Band {}), Total/Detected: {}/{}\n'.format(
                        inter_freq_header_data.freq / 10, inter_freq_header_data.band,
                        inter_freq_header_data.total_cell, inter_freq_header_data.detected_cell
                    )
                    for j in range(inter_freq_header_data.total_cell):
                        inter_freq_meas_data = inter_freq_meas._make(struct.unpack('<Hhhh', info_data[pos:pos+8]))
                        stdout += 'Cell {}: PCI: {}, RSRP: {:.1f}, RSRQ: {:.1f}\n'.format(j,
                            inter_freq_meas_data.pci,
                            inter_freq_meas_data.rsrp / 10, inter_freq_meas_data.rsrq / 10,
                        )
                        pos += 8
            else:
                # print(inner_header_data)
                return None

        elif info.msgid == 0x0988:
            inner_header = namedtuple('Hisi0x20020000_0x0988', 'msgid opid cmd')
            inner_header_data = inner_header._make(struct.unpack('<LHH', info_data[0:8]))

            if inner_header_data.cmd == 0x33:
                # Connected mode measurement, Intra frequency cell
                intra_freq_header = namedtuple('HisiIntraFreqHeader', 'freq band total_cell detected_cell')
                intra_freq_meas = namedtuple('HisiIntraFreqMeas', 'pci rsrp rsrq unk')
                intra_freq_header_data = intra_freq_header._make(struct.unpack('<HHHH', info_data[8:16]))

                stdout += 'Connected mode intra frequency cell measurement: {:.1f} MHz (Band {}), Total/Detected: {}/{}\n'.format(
                    intra_freq_header_data.freq / 10, intra_freq_header_data.band,
                    intra_freq_header_data.total_cell, intra_freq_header_data.detected_cell
                )
                for i in range(intra_freq_header_data.total_cell):
                    intra_freq_meas_data = intra_freq_meas._make(struct.unpack('<Hhhh', info_data[8*(i+2):8*(i+3)]))
                    stdout += 'Cell {}: PCI: {}, RSRP: {:.1f}, RSRQ: {:.1f}\n'.format(i,
                        intra_freq_meas_data.pci,
                        intra_freq_meas_data.rsrp / 10, intra_freq_meas_data.rsrq / 10,
                    )
            else:
                # print(inner_header_data)
                return None
        else:
            # print(info)
            return None

        return {'stdout': stdout.rstrip()}