#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class DiagGsmLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.no_process = {
            0x5226: 'GPRS MAC Signaling Message',
        }

        self.process = {
            # GSM
            0x5065: lambda x, y, z: self.parse_gsm_fcch(x, y, z), # GSM L1 FCCH Acquisition
            0x5066: lambda x, y, z: self.parse_gsm_sch(x, y, z), # GSM L1 SCH Acquisition
            0x506C: lambda x, y, z: self.parse_gsm_l1_burst_metric(x, y, z), # GSM L1 Burst Metrics
            0x506A: lambda x, y, z: self.parse_gsm_l1_new_burst_metric(x, y, z), # GSM L1 New Burst Metrics
            0x5071: lambda x, y, z: self.parse_gsm_l1_surround_cell_ba(x, y, z), # GSM Surround Cell BA List
            0x507A: lambda x, y, z: self.parse_gsm_l1_serv_aux_meas(x, y, z), # GSM L1 Serving Auxiliary Measurments
            0x507B: lambda x, y, z: self.parse_gsm_l1_neig_aux_meas(x, y, z), # GSM L1 Neighbor Cell Auxiliary Measurments
            0x5134: lambda x, y, z: self.parse_gsm_cell_info(x, y, z), # GSM RR Cell Information
            0x512F: lambda x, y, z: self.parse_gsm_rr(x, y, z), # GSM RR Signaling Message
            #0x5226: lambda x, y, z: parse_gprs_mac(x, y, z), # GPRS MAC Signaling Message
            0x5230: lambda x, y, z: self.parse_gprs_ota(x, y, z), # GPRS SM/GMM OTA Signaling Message

            # GSM DSDS
            0x5A65: lambda x, y, z: self.parse_gsm_dsds_fcch(x, y, z), # GSM DSDS L1 FCCH Acquisition
            0x5A66: lambda x, y, z: self.parse_gsm_dsds_sch(x, y, z), # GSM DSDS L1 SCH Acquisition
            0x5A6C: lambda x, y, z: self.parse_gsm_dsds_l1_burst_metric(x, y, z), # GSM DSDS L1 Burst Metrics
            0x5A71: lambda x, y, z: self.parse_gsm_dsds_l1_surround_cell_ba(x, y, z), # GSM DSDS Surround Cell BA List
            0x5A7A: lambda x, y, z: self.parse_gsm_dsds_l1_serv_aux_meas(x, y, z), # GSM DSDS L1 Serving Auxiliary Measurments
            0x5A7B: lambda x, y, z: self.parse_gsm_dsds_l1_neig_aux_meas(x, y, z), # GSM DSDS L1 Neighbor Cell Auxiliary Measurments
            0x5B34: lambda x, y, z: self.parse_gsm_dsds_cell_info(x, y, z), # GSM DSDS RR Cell Information
            0x5B2F: lambda x, y, z: self.parse_gsm_dsds_rr(x, y, z), # GSM DSDS RR Signaling Message
        }

    # GSM

    def parse_gsm_fcch(self, pkt_ts, pkt, radio_id):
        arfcn_band = (pkt[1] << 8) | pkt[0]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        self.parent.gsm_last_arfcn[self.parent.sanitize_radio_id(radio_id)] = arfcn

    def parse_gsm_dsds_fcch(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_fcch(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_sch(self, pkt_ts, pkt, radio_id):
        self.parse_gsm_fcch(pkt_ts, pkt, radio_id)

    def parse_gsm_dsds_sch(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_sch(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_l1_new_burst_metric(self, pkt_ts, pkt, radio_id):
        version = pkt[0]
        if pkt[0] == 4: # Version 4
            chan = pkt[1]
            i = 0
            while (2 + 37 * i) < len(pkt):
                cell_pkt = pkt[2 + 37 * i:2 + 37 * (i + 1)]
                if len(cell_pkt) < 37:
                    break
                interim = struct.unpack('<LHLhhhhhhbbLBBHLB', cell_pkt)
                c_fn = interim[0]
                c_arfcn = interim[1] & 0xfff
                c_band = (interim[1] >> 12)
                c_rssi = interim[2]
                c_rxpwr = interim[3]
                c_dcoff_i = interim[4]
                c_dcoff_q = interim[5]
                c_freq_offset = interim[6]
                c_time_offset = interim[7]
                c_snr_est = interim[8]
                c_gain_state = interim[9]
                c_aci = interim[10]
                c_q16 = interim[11]
                c_aqpsk = interim[12]
                c_timeslot = interim[13]
                c_jdet_reading_divrx = interim[14]
                c_wb_power = interim[15]
                c_ll_hl_state = interim[16]

                c_rxpwr_real = c_rxpwr * 0.0625
                if c_rxpwr < 0:
                    print('Radio {}: 2G Serving Cell New: ARFCN {}/BC {}, RxPwr {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), c_arfcn, c_band, c_rxpwr_real))
                i += 1
        else:
            self.parent.logger.log(logging.WARNING, 'Unsupported GSM L1 New Burst Metric version {}'.format(pkt[0]))

    def parse_gsm_l1_burst_metric(self, pkt_ts, pkt, radio_id):
        chan = pkt[0]
        # for each 23 bytes
        i = 0
        while (1 + 23 * i) < len(pkt):
            cell_pkt = pkt[1 + 23 * i:1 + 23 * (i + 1)]
            if len(cell_pkt) < 23:
                break
            interim = struct.unpack('<LHLhhhhhhb', cell_pkt)
            c_fn = interim[0]
            c_arfcn = interim[1] & 0xfff
            c_band = (interim[1] >> 12)
            c_rssi = interim[2]
            c_rxpwr = interim[3]
            c_dcoff_i = interim[4]
            c_dcoff_q = interim[5]
            c_freq_offset = interim[6]
            c_time_offset = interim[7]
            c_snr_est = interim[8]
            c_gain_state = interim[9]

            c_rxpwr_real = c_rxpwr * 0.0625
            if c_rxpwr < 0:
                print('Radio {}: 2G Serving Cell: ARFCN {}/BC {}, RxPwr {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), c_arfcn, c_band, c_rxpwr_real))
            i += 1

    def parse_gsm_dsds_l1_burst_metric(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_l1_burst_metric(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_l1_surround_cell_ba(self, pkt_ts, pkt, radio_id):
        num_cells = pkt[0]
        print('Radio {}: 2G Cell: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), num_cells))
        for i in range(num_cells):
            cell_pkt = pkt[1 + 12 * i:1 + 12 * (i + 1)]
            interim = struct.unpack('<HhHLH', cell_pkt)
            s_arfcn = interim[0] & 0xfff
            s_band = (interim[0] >> 12)
            s_rxpwr = interim[1]
            s_bsic = interim[2] # TODO: correctly parse data
            s_fn_offset = interim[3]
            s_time_offset = interim[4]

            s_rxpwr_real = s_rxpwr * 0.0625
            print('Radio {}: 2G Cell {}: ARFCN {}/BC {}, RxPwr {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, s_arfcn, s_band, s_rxpwr_real))

    def parse_gsm_dsds_l1_surround_cell_ba(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_l1_surround_cell_ba(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_l1_serv_aux_meas(self, pkt_ts, pkt, radio_id):
        interim = struct.unpack('<hB', pkt[0:3])
        rxpwr = interim[0]
        snr_is_bad = interim[1]
        rxpwr_real = rxpwr * 0.0625
        print('Radio {}: 2G Serving Cell Aux: RxPwr {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), rxpwr_real))

    def parse_gsm_dsds_l1_serv_aux_meas(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_l1_serv_aux_meas(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_l1_neig_aux_meas(self, pkt_ts, pkt, radio_id):
        num_cells = pkt[0]
        print('Radio {}: 2G Cell Aux: # cells {}'.format(self.parent.sanitize_radio_id(radio_id), num_cells))
        for i in range(num_cells):
            cell_pkt = pkt[1 + 4 * i:1 + 4 * (i + 1)]
            interim = struct.unpack('<Hh', cell_pkt)
            n_arfcn = interim[0] & 0xfff
            n_band = (interim[0] >> 12)
            n_rxpwr = interim[1]

            n_rxpwr_real = n_rxpwr * 0.0625
            print('Radio {}: Cell {}: ARFCN {}/BC {}, RxPwr {:.2f}'.format(self.parent.sanitize_radio_id(radio_id), i, n_arfcn, n_band, n_rxpwr_real))

    def parse_gsm_dsds_l1_neig_aux_meas(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_l1_neig_aux_meas(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_cell_info(self, pkt_ts, pkt, radio_id):
        arfcn_band = (pkt[1] << 8) | pkt[0]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        cell_id = (pkt[5] << 8) | pkt[4]

        self.parent.gsm_last_arfcn[self.parent.sanitize_radio_id(radio_id)] = arfcn
        self.parent.gsm_last_cell_id[self.parent.sanitize_radio_id(radio_id)] = cell_id

    def parse_gsm_dsds_cell_info(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_cell_info(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gsm_rr(self, pkt_ts, pkt, radio_id):
        chan_type_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = pkt[2]
        l3_message = pkt[3:]

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.parent.gsm_last_arfcn[self.parent.sanitize_radio_id(radio_id)]
        # 0x80: downlink
        if (chan_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = chan_type_dir & 0x7F

        # 0: DCCH, 1: BCCH, 3: CCCH, 4: SACCH
        # DCCH, SACCH requires pseudo length
        rr_channel_map = [8, util.gsmtap_channel.BCCH, 0, util.gsmtap_channel.CCCH, 0x88]
        channel_type = rr_channel_map[chan]

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
            if msg_len > 63:
                self.parent.logger.log(logging.WARNING, 'message length longer than 63 ({})'.format(msg_len))
                return 
            lapdm_len = bytes([(msg_len << 2) | 0x01])

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
            if msg_len > 63:
                self.parent.logger.log(logging.WARNING, 'message length longer than 63 ({})'.format(msg_len))
                return
            lapdm_len = bytes([(msg_len << 2) | 0x01])

            l3_message = sacch_l1 + lapdm_address + lapdm_control + lapdm_len + l3_message

        # SACCH DL/Measurement Information: Short PD format
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.UM,
            arfcn = arfcn,
            sub_type = channel_type,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + l3_message, radio_id, pkt_ts)

    def parse_gsm_dsds_rr(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        self.parse_gsm_rr(pkt_ts, pkt[1:], radio_id_pkt)

    def parse_gprs_mac(self, pkt_ts, pkt, radio_id):
        self.parent.logger.log(logging.WARNING, "Unhandled XDM Header 0x5226: GPRS MAC Packet")

        chan_type_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = pkt[2]
        l3_message = pkt[3:]

        payload_type = util.gsmtap_type.UM

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.parent.gsm_last_arfcn[self.parent.sanitize_radio_id(radio_id)]
        # 0x80: downlink
        if (chan_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = chan_type_dir & 0x7F

        # 3: PACCH, 4: Unknown
        channel_type = chan

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = payload_type,
            arfcn = arfcn,
            sub_type = channel_type,
            device_sec = ts_sec,
            device_usec = ts_usec)

        #self.parent.writer.write_cp(gsmtap_hdr + l3_message, radio_id, pkt_ts)

    def parse_gprs_ota(self, pkt_ts, pkt, radio_id):
        msg_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = (pkt[3] << 8) | pkt[2]
        l3_message = pkt[4:]

        arfcn = self.parent.gsm_last_arfcn[self.parent.sanitize_radio_id(radio_id)]
        # 0: uplink, 1: downlink
        if (msg_dir) == 0x00:
            arfcn = arfcn | (1 << 14)

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = arfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.parent.writer.write_cp(gsmtap_hdr + l3_message, radio_id, pkt_ts)

