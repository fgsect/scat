#!/usr/bin/env python3

from collections import namedtuple
from packaging import version
import binascii
import bitstring
import calendar
import logging
import struct

import scat.util as util
import scat.parsers.qualcomm.diagcmd as diagcmd

bitstring_ver = version.parse(bitstring.__version__)
if bitstring_ver >= version.parse('4.2.0'):
    bitstring.options.lsb0 = True
elif bitstring_ver >= version.parse('4.0.0'):
    bitstring.lsb0 = True
elif bitstring_ver >= version.parse('3.1.7'):
    bitstring.set_lsb0(True)
else:
    raise Exception("SCAT requires bitstring>=3.1.7, recommends bitstring>=4.0.0")

class DiagGsmLogParser:
    def __init__(self, parent):
        self.parent = parent

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        self.no_process = {
            0x5226: 'GPRS MAC Signaling Message',
        }

        i = diagcmd.diag_log_get_gsm_item_id
        c = diagcmd.diag_log_code_gsm
        self.process = {
            # L1
            i(c.LOG_GSM_L1_FCCH_ACQUISITION_C): lambda x, y, z: self.parse_gsm_fcch(x, y, z),
            i(c.LOG_GSM_L1_SCH_ACQUISITION_C): lambda x, y, z: self.parse_gsm_sch(x, y, z),
            i(c.LOG_GSM_L1_NEW_BURST_METRICS_C): lambda x, y, z: self.parse_gsm_l1_new_burst_metric(x, y, z),
            i(c.LOG_GSM_L1_BURST_METRICS_C): lambda x, y, z: self.parse_gsm_l1_burst_metric(x, y, z),
            i(c.LOG_GSM_L1_SCELL_BA_LIST_C): lambda x, y, z: self.parse_gsm_l1_surround_cell_ba(x, y, z),
            i(c.LOG_GSM_L1_SCELL_AUX_MEASUREMENTS_C): lambda x, y, z: self.parse_gsm_l1_serv_aux_meas(x, y, z),
            i(c.LOG_GSM_L1_NCELL_AUX_MEASUREMENTS_C): lambda x, y, z: self.parse_gsm_l1_neig_aux_meas(x, y, z),

            # RR
            i(c.LOG_GSM_RR_SIGNALING_MESSAGE_C): lambda x, y, z: self.parse_gsm_rr(x, y, z),
            i(c.LOG_GSM_RR_CELL_INFORMATION_C): lambda x, y, z: self.parse_gsm_cell_info(x, y, z),

            # GPRS
            i(c.LOG_GPRS_MAC_SIGNALING_MESSACE_C): lambda x, y, z: self.parse_gprs_mac(x, y, z),
            i(c.LOG_GPRS_SM_GMM_OTA_SIGNALING_MESSAGE_C): lambda x, y, z: self.parse_gprs_ota(x, y, z),

            # DSDS L1
            i(c.LOG_GSM_DSDS_L1_FCCH_ACQUISITION_C): lambda x, y, z: self.parse_gsm_dsds_fcch(x, y, z),
            i(c.LOG_GSM_DSDS_L1_SCH_ACQUISITION_C): lambda x, y, z: self.parse_gsm_dsds_sch(x, y, z),
            i(c.LOG_GSM_DSDS_L1_BURST_METRICS_C): lambda x, y, z: self.parse_gsm_dsds_l1_burst_metric(x, y, z),
            i(c.LOG_GSM_DSDS_L1_SCELL_BA_LIST_C): lambda x, y, z: self.parse_gsm_dsds_l1_surround_cell_ba(x, y, z),
            i(c.LOG_GSM_DSDS_L1_SCELL_AUX_MEASUREMENTS_C): lambda x, y, z: self.parse_gsm_dsds_l1_serv_aux_meas(x, y, z),
            i(c.LOG_GSM_DSDS_L1_NCELL_AUX_MEASUREMENTS_C): lambda x, y, z: self.parse_gsm_dsds_l1_neig_aux_meas(x, y, z),

            # DSDS RR
            i(c.LOG_GSM_DSDS_RR_SIGNALING_MESSAGE_C): lambda x, y, z: self.parse_gsm_dsds_rr(x, y, z),
            i(c.LOG_GSM_DSDS_RR_CELL_INFORMATION_C): lambda x, y, z: self.parse_gsm_dsds_cell_info(x, y, z),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    # GSM

    def parse_gsm_fcch(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagGsmL1Fcch', 'arfcn_band tone_id msw lsw coarse_freq_offset fine_freq_offset afc_freq snr')
        item = item_struct._make(struct.unpack('<HHHHhhhH', pkt_body[0:16]))

        band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
        arfcn = band_arfcn_bits[0:12].uint
        band = band_arfcn_bits[12:16].uint

        if self.parent:
            self.parent.gsm_last_arfcn[radio_id] = arfcn
        return {'stdout': 'GSM FCCH acquistion: ARFCN: {}/Band: {}'.format(arfcn, band), 'radio_id': radio_id, 'ts': pkt_ts}

    def parse_gsm_dsds_fcch(self, pkt_header, pkt_body, args):
        radio_id_pkt = pkt_body[0]
        return self.parse_gsm_fcch(pkt_header, pkt_body[1:], {'radio_id': self.parent.sanitize_radio_id(radio_id_pkt)})

    def parse_gsm_sch(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagGsmL1Sch', 'arfcn_band tone_id crc_pass dsp_rx bad_frame decoded_data_len decoded_data msw lsw peak_corr_energy freq_offset')
        item = item_struct._make(struct.unpack('<HHHHHHLHHHH', pkt_body[0:24]))

        band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
        arfcn = band_arfcn_bits[0:12].uint
        band = band_arfcn_bits[12:16].uint
        sch_data = struct.unpack('>L', struct.pack('<L', item.decoded_data))[0]
        # SCH data 25bits: 19b reduced frame number, 6b BSIC

        if self.parent:
            self.parent.gsm_last_arfcn[radio_id] = arfcn
        return {'stdout': 'GSM SCH acquistion: ARFCN: {}/Band: {}, Data: {:025b}'.format(arfcn, band, sch_data), 'radio_id': radio_id, 'ts': pkt_ts}

    def parse_gsm_dsds_sch(self, pkt_header, pkt_body, args):
        radio_id_pkt = pkt_body[0]
        return self.parse_gsm_sch(pkt_header, pkt_body[1:], {'radio_id': self.parent.sanitize_radio_id(radio_id_pkt)})

    def parse_gsm_l1_new_burst_metric(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct_v4 = namedtuple('QcDiagGsmL1NewBurstMetricV4', 'sfn arfcn_band rssi rxpwr dcoff_i dcoff_q freq_offset time_offset snr_est gain_state aci q16 aqpsk timeslot jdet_reading_divrx wb_power ll_hl_state')
        stdout = ''

        pkt_version = pkt_body[0]
        if pkt_version == 4: # Version 4
            chan = pkt_body[1]
            for i in range(4):
                cell_pkt = pkt_body[2+37*i:2+37*(i+1)]
                item = item_struct_v4._make(struct.unpack('<LHLhhhhhhbbLBBHLB', cell_pkt))
                c_band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
                c_arfcn = c_band_arfcn_bits[0:12].uint
                c_band = c_band_arfcn_bits[12:16].uint
                if item.rxpwr != 0:
                    c_rxpwr_real = item.rxpwr * 0.0625
                    stdout += 'GSM Serving Cell New Burst Metric: ARFCN: {}/BC: {}, RSSI: {}, RxPwr: {:.2f}\n'.format(c_arfcn, c_band, item.rssi, c_rxpwr_real)
        else:
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Unsupported GSM Serving Cell L1 New Burst Metric version {}'.format(pkt_version))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def parse_gsm_l1_burst_metric(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        channel = pkt_body[0]
        # for each 23 bytes
        item_struct = namedtuple('QcDiagGsmL1BurstMetric', 'sfn arfcn_band rssi rxpwr dcoff_i dcoff_q freq_offset time_offset snr_est gain_state')
        stdout = ''

        for i in range(4):
            cell_pkt = pkt_body[1+23*i:1+23*(i+1)]
            item = item_struct._make(struct.unpack('<LHLhhhhhhb', cell_pkt))
            c_band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
            c_arfcn = c_band_arfcn_bits[0:12].uint
            c_band = c_band_arfcn_bits[12:16].uint
            if item.rxpwr != 0:
                c_rxpwr_real = item.rxpwr * 0.0625
                stdout += 'GSM Serving Cell Burst Metric: ARFCN: {}/BC: {}, RSSI: {}, RxPwr: {:.2f}\n'.format(c_arfcn, c_band, item.rssi, c_rxpwr_real)

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def parse_gsm_dsds_l1_burst_metric(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_l1_burst_metric(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gsm_l1_surround_cell_ba(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct = namedtuple('QcDiagGsmL1SurroundCellBa', 'arfcn_band rxpwr bsic_valid bsic fn_offset time_offset')
        stdout = ''
        num_cells = pkt_body[0]
        stdout += 'GSM Surround Cell BA: {} cells\n'.format(num_cells)
        for i in range(num_cells):
            cell_pkt = pkt_body[1 + 12 * i:1 + 12 * (i + 1)]
            item = item_struct._make(struct.unpack('<HhBBLH', cell_pkt))
            s_band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
            s_arfcn = s_band_arfcn_bits[0:12].uint
            s_band = s_band_arfcn_bits[12:16].uint
            s_rxpwr_real = item.rxpwr * 0.0625
            if item.bsic_valid == 1:
                stdout += 'GSM Surround Cell BA: Cell {}: ARFCN: {}/BC: {}/BSIC: {}, RxPwr: {:.2f}\n'.format(i, s_arfcn, s_band, item.bsic, s_rxpwr_real)
            else:
                stdout += 'GSM Surround Cell BA: Cell {}: ARFCN: {}/BC: {}/BSIC: N/A, RxPwr: {:.2f}\n'.format(i, s_arfcn, s_band, item.bsic, s_rxpwr_real)

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def parse_gsm_dsds_l1_surround_cell_ba(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_l1_surround_cell_ba(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gsm_l1_serv_aux_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct = namedtuple('QcDiagGsmL1ServAuxMeas', 'rxpwr snr_is_bad')
        item = item_struct._make(struct.unpack('<hB', pkt_body[0:3]))
        rxpwr_real = item.rxpwr * 0.0625
        return {'stdout': 'GSM Serving Cell Aux Measurement: RxPwr: {:.2f}'.format(rxpwr_real), 'ts': pkt_ts}

    def parse_gsm_dsds_l1_serv_aux_meas(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_l1_serv_aux_meas(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gsm_l1_neig_aux_meas(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        stdout = ''
        item_struct = namedtuple('QcDiagGsmL1NeigAuxMeas', 'arfcn_band rxpwr')

        num_cells = pkt_body[0]
        stdout += 'GSM Neighbor Cell Aux: {} cells\n'.format(num_cells)
        for i in range(num_cells):
            item = item_struct._make(struct.unpack('<Hh', pkt_body[1+4*i:1+4*(i+1)]))
            n_band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
            n_arfcn = n_band_arfcn_bits[0:12].uint
            n_band = n_band_arfcn_bits[12:16].uint
            n_rxpwr_real = item.rxpwr * 0.0625
            stdout += 'GSM Neighbor Cell Aux {}: ARFCN: {}/BC: {}, RxPwr: {:.2f}\n'.format(i, n_arfcn, n_band, n_rxpwr_real)

        return {'stdout': stdout.rstrip(), 'ts': pkt_ts}

    def parse_gsm_dsds_l1_neig_aux_meas(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_l1_neig_aux_meas(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gsm_cell_info(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagGsmRrCellInfo', 'arfcn_band bcc ncc cid lai priority ncc_permitted')
        item = item_struct._make(struct.unpack('<HBBH5sBB', pkt_body[0:13]))

        band_arfcn_bits = bitstring.Bits(uint=item.arfcn_band, length=16)
        arfcn = band_arfcn_bits[0:12].uint
        band = band_arfcn_bits[12:16].uint

        if self.parent:
            self.parent.gsm_last_arfcn[radio_id] = arfcn
            self.parent.gsm_last_cell_id[radio_id] = item.cid

        mcc_mnc_lac = util.unpack_lai(item.lai)
        if self.display_format == 'd':
            cid_str = 'MCC/MNC: {}/{}, LAC/CID: {}{}'.format(*mcc_mnc_lac, item.cid)
        elif self.display_format == 'x':
            cid_str = 'MCC/MNC: {}/{}, xLAC/xCID: {:x}/{:x}'.format(*mcc_mnc_lac, item.cid)
        elif self.display_format == 'b':
            cid_str = 'MCC/MNC: {}/{}, LAC/CID: {}/{} ({:#x}/{:#x})'.format(*mcc_mnc_lac, item.cid, mcc_mnc_lac[2], item.cid)

        return {'stdout': 'GSM RR Cell Info: ARFCN: {}/Band: {}, BCC: {}, NCC: {}, {}'.format(arfcn, band, item.bcc, item.ncc, cid_str),
                'ts': pkt_ts}

    def parse_gsm_dsds_cell_info(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_cell_info(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gsm_rr(self, pkt_header, pkt_body, args):
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']
        item_struct = namedtuple('QcDiagGsmRrSignalingMessage', 'channel_type_dir message_type message_len')
        item = item_struct._make(struct.unpack('<BBB', pkt_body[0:3]))
        l3_message = pkt_body[3:]

        if item.message_len != len(l3_message):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(l3_message), item.message_len))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        if self.parent:
            arfcn = self.parent.gsm_last_arfcn[radio_id]
        else:
            arfcn = 0
        # 0x80: downlink
        if (item.channel_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = item.channel_type_dir & 0x7F

        # 0: DCCH, 1: BCCH, 2: RACH, 3: CCCH, 4: SACCH, 5: SDCCH, 6: FACCH
        # DCCH, SACCH requires pseudo length
        rr_channel_map = [8, util.gsmtap_channel.BCCH, util.gsmtap_channel.RACH, util.gsmtap_channel.CCCH, 0x88]
        channel_type = rr_channel_map[chan]

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        # Attach L2 pseudo length
        #if chan == 0 or chan == 4:
        #    l3_message = bytes([(msg_len << 2) | 0x01]) +  l3_message

        if chan == 0:
            # SDCCH/8 expects LAPDm header
            # Address field
            lapdm_address = b'\x01'
            # Control field
            lapdm_control = b'\x03'
            # length field
            if item.message_len > 63:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'message length longer than 63 ({})'.format(item.message_len))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                return None
            lapdm_len = bytes([(item.message_len << 2) | 0x01])

            l3_message = lapdm_address + lapdm_control + lapdm_len + l3_message
        elif chan == 4:
            # SACCH/8 expects SACCH L1/LAPDm header
            # SACCH L1 header
            sacch_l1 = b'\x00\x00'
            # Address field
            lapdm_address = b'\x01'
            # Control field
            lapdm_control = b'\x03'
            # length field
            if item.message_len > 63:
                if self.parent:
                    self.parent.logger.log(logging.WARNING, 'message length longer than 63 ({})'.format(item.message_len))
                    self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
                return None
            lapdm_len = bytes([(item.message_len << 2) | 0x01])

            l3_message = sacch_l1 + lapdm_address + lapdm_control + lapdm_len + l3_message

        # SACCH DL/Measurement Information: Short PD format

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.UM,
            arfcn = arfcn,
            sub_type = channel_type,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'layer': 'rrc', 'cp': [gsmtap_hdr + l3_message], 'ts': pkt_ts, 'radio_id': radio_id}

    def parse_gsm_dsds_rr(self, pkt_header, pkt_body, args):
        radio_id_pkt = self.parent.sanitize_radio_id(pkt_body[0])
        return self.parse_gsm_rr(pkt_header, pkt_body[1:], {'radio_id': radio_id_pkt})

    def parse_gprs_mac(self, pkt_header, pkt_body, args):
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagGsmGprsMac', 'chan_type_dir message_type message_len')
        item = item_struct._make(struct.unpack('<BBB', pkt_body[0:3]))
        l3_message = pkt_body[3:]

        payload_type = util.gsmtap_type.UM

        if item.message_len != len(l3_message):
            if self.parent:
                self.parent.logger.log(logging.WARNING, 'Payload length ({}) does not match with expected ({})'.format(len(l3_message), item.message_len))
                self.parent.logger.log(logging.DEBUG, util.xxd(pkt_body))
            return None

        arfcn = self.parent.gsm_last_arfcn[radio_id]
        # 0x80: downlink
        if (item.chan_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = item.chan_type_dir & 0x7F

        # 3: PACCH, 4: Unknown
        channel_type = chan

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = payload_type,
            arfcn = arfcn,
            sub_type = channel_type,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'layer': 'mac', 'cp': [gsmtap_hdr + l3_message], 'ts': pkt_ts, 'radio_id': radio_id}

    def parse_gprs_ota(self, pkt_header, pkt_body, args):
        radio_id = 0
        if args is not None and 'radio_id' in args:
            radio_id = args['radio_id']

        item_struct = namedtuple('QcDiagGsmGprsOta', 'msg_dir message_type message_len')
        item = item_struct._make(struct.unpack('<BBH', pkt_body[0:4]))
        l3_message = pkt_body[4:]

        arfcn = self.parent.gsm_last_arfcn[radio_id]
        # 0: uplink, 1: downlink
        if (item.msg_dir) == 0x00:
            arfcn = arfcn | (1 << 14)

        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = arfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        return {'layer': 'rrc', 'cp': [gsmtap_hdr + l3_message], 'ts': pkt_ts, 'radio_id': radio_id}
