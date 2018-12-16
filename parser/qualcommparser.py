#!/usr/bin/python3
# coding: utf8
import util
import usb
import struct
import calendar, datetime
import parser.qualcomm_diagcmd as diagcmd

class QualcommParser:
    def __init__(self):
        self.gsm_last_cell_id = [0, 0]
        self.gsm_last_arfcn = [0, 0]

        self.umts_last_cell_id = [0, 0]
        self.umts_last_uarfcn_dl = [0, 0]
        self.umts_last_uarfcn_ul = [0, 0]

        self.lte_last_cell_id = [0, 0]
        self.lte_last_earfcn_dl = [0, 0]
        self.lte_last_earfcn_ul = [0, 0]
        self.lte_last_earfcn_tdd = [0, 0]
        self.lte_last_sfn = [0, 0]
        self.lte_last_tx_ant = [0, 0]
        self.lte_last_bw_dl = [0, 0]
        self.lte_last_bw_ul = [0, 0]
        self.lte_last_band_ind = [0, 0]
        self.lte_last_tcrnti = [1, 1]

        self.handler = None
        self.writerSIM1 = None
        self.writerSIM2 = None

        self.pending_pkts = dict()

        self.last_tx = [b'', b'']
        self.last_rx = [b'', b'']

        self.name = 'qualcomm'
        self.shortname = 'qc'

    def setHandler(self, handler):
        self.handler = handler

    def setWriter(self, writerSIM1, writerSIM2):
        self.writerSIM1 = writerSIM1
        self.writerSIM2 = writerSIM2

    def writeCP(self, pkt_content, radio_id):
        if radio_id == 0:
            self.writerSIM1.write_cp(pkt_content)
        elif radio_id == 1:
            self.writerSIM2.write_cp(pkt_content)
        else:
            util.warning("Unknown radio_id {}".format(radio_id))

    def writeUP(self, pkt_content, radio_id):
        if radio_id == 0:
            self.writerSIM1.write_up(pkt_content)
        elif radio_id == 1:
            self.writerSIM2.write_up(pkt_content)
        else:
            util.warning("Unknown radio_id {}".format(radio_id))

    def setParameter(self, params):
        pass

    def _write_then_read_discard(self, buf, hdlc_encoded = False, xxd = False):
        if not hdlc_encoded:
            buf = util.generate_packet(buf)
        self.handler.write(buf)

        rbuf = self.handler.read(0x1000)
        if xxd:
            rbuf = util.unwrap(rbuf)
            util.xxd(rbuf)

    def init_diag(self):
        print('-------- initialize diag --------')
        # Disable static event reporting
        self._write_then_read_discard(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00))

        # Send empty masks
        self._write_then_read_discard(diagcmd.log_mask_empty_1x(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_wcdma(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_gsm(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_umts(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_dtv(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_lte(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_empty_tdscdma(), False, True)

        emr = lambda x, y: diagcmd.create_extended_message_config_set_mask(x, y)
        self._write_then_read_discard(emr(0x0000, 0x0065), False, True)
        self._write_then_read_discard(emr(0x01f4, 0x01fa), False, True)
        self._write_then_read_discard(emr(0x03e8, 0x033f), False, True)
        self._write_then_read_discard(emr(0x07d0, 0x07d8), False, True)
        self._write_then_read_discard(emr(0x0bb8, 0x0bc6), False, True)
        self._write_then_read_discard(emr(0x0fa0, 0x0faa), False, True)
        self._write_then_read_discard(emr(0x1194, 0x11ae), False, True)
        self._write_then_read_discard(emr(0x11f8, 0x1206), False, True)
        self._write_then_read_discard(emr(0x1388, 0x13a6), False, True)
        self._write_then_read_discard(emr(0x157c, 0x158c), False, True)
        self._write_then_read_discard(emr(0x1770, 0x17c0), False, True)
        self._write_then_read_discard(emr(0x1964, 0x1979), False, True)
        self._write_then_read_discard(emr(0x1b58, 0x1b5b), False, True)
        self._write_then_read_discard(emr(0x1bbc, 0x1bc7), False, True)
        self._write_then_read_discard(emr(0x1c20, 0x1c21), False, True)
        self._write_then_read_discard(emr(0x1f40, 0x1f40), False, True)
        self._write_then_read_discard(emr(0x2134, 0x214c), False, True)
        self._write_then_read_discard(emr(0x2328, 0x2330), False, True)
        self._write_then_read_discard(emr(0x251c, 0x2525), False, True)
        self._write_then_read_discard(emr(0x27d8, 0x27e2), False, True)
        self._write_then_read_discard(emr(0x280b, 0x280f), False, True)
        self._write_then_read_discard(emr(0x283c, 0x283c), False, True)
        self._write_then_read_discard(emr(0x286e, 0x2886), False, True)

    def prepare_diag(self):
        print('-------- start diag --------')
        # Static event reporting Enable
        self._write_then_read_discard(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x01))

        self._write_then_read_discard(diagcmd.log_mask_scat_1x(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_scat_wcdma(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_scat_gsm(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_scat_umts(), False, True)
        self._write_then_read_discard(diagcmd.log_mask_scat_lte(), False, True)

    def parse_diag(self, pkt, hdlc_encoded = True, check_crc = True, radio_id = 0):
        # Should contain DIAG command and CRC16
        # pkt should not contain trailing 0x7E, and either HDLC encoded or not
        # When the pkt is not HDLC encoded, hdlc_encoded should be set to True
        # radio_id = 0 for default, larger than 1 for SIM 1 and such

        if len(pkt) < 3:
            return

        if hdlc_encoded:
            pkt = util.unwrap(pkt)

        # Check and strip CRC if existing
        if check_crc:
            crc = util.dm_crc16(pkt[:-2])
            crc_pkt = (pkt[-1] << 8) | pkt[-2]
            if crc != crc_pkt:
                util.warning("CRC mismatch: expected 0x{:04x}, got 0x{:04x}".format(crc, crc_pkt))
                util.xxd(pkt)
            pkt = pkt[:-2]

        if pkt[0] == diagcmd.DIAG_LOG_F:
            self.parse_diag_log(pkt, radio_id)

#            if parse_ts:
#                ts = struct.unpack('<Q', pkt[10:16] + b'\x00\x00')[0]
#                ts = util.parse_qxdm_ts(ts)
#                self.writerSIM1.write_cp(sock_content, ts)
#            else:
#                self.writerSIM1.write_cp(sock_content)
        elif pkt[0] == diagcmd.DIAG_EVENT_REPORT_F:
            # TODO: handle event packets
            # self.parse_diag_event(pkt)
            pass
        elif pkt[0] == 0x98:
            # Found on some newer dual SIMs
            self.parse_diag_multisim(pkt)
        else:
            #print("Not parsing non-Log packet %02x" % pkt[0])
            #util.xxd(pkt)
            return

    def run_diag(self, writer_qmdl = None):
        oldbuf = b''
        try:
            while True:
                buf = self.handler.read(0x1000)
                if len(buf) == 0:
                    continue
                buf = oldbuf + buf
                buf_atom = buf.split(b'\x7e')

                if buf[-1] != 0x7e:
                    oldbuf = buf_atom.pop()
                else:
                    oldbuf = b''

                for pkt in buf_atom:
                    if len(pkt) == 0:
                        continue
                    self.parse_diag(pkt)
                    if writer_qmdl:
                        writer_qmdl.write_cp(pkt + b'\x7e')

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        self.handler.read(0x1000)
        print('-------- stop diag --------')
        # Static event reporting Disable
        self._write_then_read_discard(struct.pack('<BB', diagcmd.DIAG_EVENT_REPORT_F, 0x00), False, True)
        self._write_then_read_discard(struct.pack('<LL', diagcmd.DIAG_LOG_CONFIG_F, diagcmd.LOG_CONFIG_DISABLE_OP), False, True)
        self._write_then_read_discard(b'\x7d\x05\x00\x00\x00\x00\x00\x00', False, True)

    def parse_dlf(self):
        oldbuf = b''
        while True:
            buf = self.handler.read(0x100000)
            #print("%d"% len(buf))
            if len(buf) == 0:
                break
            buf = oldbuf + buf

            pkt_len = struct.unpack('<H', buf[0:2])[0]
            while len(buf) >= pkt_len:
                # DLF lacks CRC16/other fancy stuff
                pkt = buf[0:pkt_len]
                pkt = b'\x10\x00' + pkt[0:2] + pkt
                calculated_crc = util.dm_crc16(pkt)
                pkt = pkt + struct.pack('<H', calculated_crc)

                #print("%02x %02x" % (pkt_len, len(buf)))
                self.parse_diag(pkt, hdlc_encoded = False)
                buf = buf[pkt_len:]

                if len(buf) < 2:
                    break
                pkt_len = struct.unpack('<H', buf[0:2])[0]

            oldbuf = buf

    def read_dump(self):
        while self.handler.file_available:
            print("Reading from {}".format(self.handler.fname))
            if self.handler.fname.find('.qmdl') > 0:
                self.run_diag()
            elif self.handler.fname.find('.dlf') > 0:
                self.parse_dlf()
            else:
                print('Unknown baseband dump type, assuming QMDL')
                self.run_diag()
            self.handler.open_next_file()

    # GSM

    def parse_gsm_fcch(self, pkt_ts, pkt, radio_id):
        arfcn_band = (pkt[1] << 8) | pkt[0]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        self.gsm_last_arfcn[radio_id] = arfcn

    def parse_gsm_dsds_fcch(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_fcch(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_sch(self, pkt_ts, pkt, radio_id):
        self.parse_gsm_fcch(pkt_ts, pkt, radio_id)

    def parse_gsm_dsds_sch(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_sch(pkt_ts, pkt[1:], radio_id_pkt - 1)

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
                    print('Radio {}: 2G Serving Cell New: ARFCN {}/BC {}, RxPwr {:.2f}'.format(radio_id, c_arfcn, c_band, c_rxpwr_real))
                i += 1
        else:
            print('Unsupported GSM L1 New Burst Metric version {}'.format(pkt[0]))

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
                print('Radio {}: 2G Serving Cell: ARFCN {}/BC {}, RxPwr {:.2f}'.format(radio_id, c_arfcn, c_band, c_rxpwr_real))
            i += 1

    def parse_gsm_dsds_l1_burst_metric(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_l1_burst_metric(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_l1_surround_cell_ba(self, pkt_ts, pkt, radio_id):
        num_cells = pkt[0]
        print('Radio {}: 2G Cell: # cells {}'.format(radio_id, num_cells))
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
            print('Radio {}: 2G Cell {}: ARFCN {}/BC {}, RxPwr {:.2f}'.format(radio_id, i, s_arfcn, s_band, s_rxpwr_real))

    def parse_gsm_dsds_l1_surround_cell_ba(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_l1_surround_cell_ba(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_l1_serv_aux_meas(self, pkt_ts, pkt, radio_id):
        interim = struct.unpack('<hB', pkt[0:3])
        rxpwr = interim[0]
        snr_is_bad = interim[1]
        rxpwr_real = rxpwr * 0.0625
        print('Radio {}: 2G Serving Cell Aux: RxPwr {:.2f}'.format(radio_id, rxpwr_real))

    def parse_gsm_dsds_l1_serv_aux_meas(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_l1_serv_aux_meas(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_l1_neig_aux_meas(self, pkt_ts, pkt, radio_id):
        num_cells = pkt[0]
        print('Radio {}: 2G Cell Aux: # cells {}'.format(radio_id, num_cells))
        for i in range(num_cells):
            cell_pkt = pkt[1 + 4 * i:1 + 4 * (i + 1)]
            interim = struct.unpack('<Hh', cell_pkt)
            n_arfcn = interim[0] & 0xfff
            n_band = (interim[0] >> 12)
            n_rxpwr = interim[1]

            n_rxpwr_real = n_rxpwr * 0.0625
            print('Radio {}: Cell {}: ARFCN {}/BC {}, RxPwr {:.2f}'.format(radio_id, i, n_arfcn, n_band, n_rxpwr_real))

    def parse_gsm_dsds_l1_neig_aux_meas(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_l1_neig_aux_meas(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_cell_info(self, pkt_ts, pkt, radio_id):
        arfcn_band = (pkt[1] << 8) | pkt[0]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        cell_id = (pkt[5] << 8) | pkt[4]

        self.gsm_last_arfcn[radio_id] = arfcn
        self.gsm_last_cell_id[radio_id] = cell_id

    def parse_gsm_dsds_cell_info(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_cell_info(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gsm_rr(self, pkt_ts, pkt, radio_id):
        chan_type_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = pkt[2]
        l3_message = pkt[3:]

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.gsm_last_arfcn[radio_id]
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
                util.warning('message length longer than 63 ({})'.format(msg_len))
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
                util.warning('message length longer than 63 ({})'.format(msg_len))
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

        self.writeCP(gsmtap_hdr + l3_message, radio_id)

    def parse_gsm_dsds_rr(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_gsm_rr(pkt_ts, pkt[1:], radio_id_pkt - 1)

    def parse_gprs_mac(self, pkt_ts, pkt, radio_id):
        print("Unhandled XDM Header 0x5226: GPRS MAC Packet")

        chan_type_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = pkt[2]
        l3_message = pkt[3:]

        payload_type = util.gsmtap_type.UM

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.gsm_last_arfcn[radio_id]
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

        #self.writeCP(gsmtap_hdr + l3_message, radio_id)

    def parse_gprs_ota(self, pkt_ts, pkt, radio_id):
        msg_dir = pkt[0]
        msg_type = pkt[1]
        msg_len = (pkt[3] << 8) | pkt[2]
        l3_message = pkt[4:]

        arfcn = self.gsm_last_arfcn[radio_id]
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

        self.writeCP(gsmtap_hdr + l3_message, radio_id)

    # 3G
    def parse_wcdma_search_cell_reselection_v0(self, pkt_ts, pkt, radio_id):
        num_wcdma_cells = pkt[0] & 0x3f # lower 6b
        num_gsm_cells = pkt[1] # TODO: check if num_gsm_cells > 0

        print('Radio {}: 3G Cell: # cells {}'.format(radio_id, num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[2 + 10 * i:2 + 10 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt)
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Radio {}: Cell {}: UARFCN {}, PSC {:3d}, RSCP {}, Ec/Io {:.2f}'.format(radio_id, i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))

    def parse_wcdma_search_cell_reselection_v2(self, pkt_ts, pkt, radio_id):
        num_wcdma_cells = pkt[0] & 0x3f # lower 6b
        num_gsm_cells = pkt[1] # TODO: check if num_gsm_cells > 0

        print('Radio {}: 3G Cell: # cells {}'.format(radio_id, num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[7 + 16 * i:7 + 16 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt[:10])
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Radio {}: Cell {}: UARFCN {}, PSC {:3d}, RSCP {}, Ec/Io {:.2f}'.format(radio_id, i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))

    def parse_wcdma_search_cell_reselection(self, pkt_ts, pkt, radio_id):
        pkt_version = (pkt[0] >> 6) # upper 2b

        if pkt_version == 0:
            self.parse_wcdma_search_cell_reselection_v0(pkt_ts, pkt, radio_id)
        elif pkt_version == 2:
            self.parse_wcdma_search_cell_reselection_v2(pkt_ts, pkt, radio_id)
        else:
            print('Unsupported WCDMA search cell reselection version {}'.format(pkt_version))
            util.xxd(pkt)

    def parse_wcdma_cell_id(self, pkt_ts, pkt, radio_id):
        result = struct.unpack('<LLLHHHBBBBBBLL', pkt[0:32])
        # UARFCN UL, UARFCN DL, CID, URA_ID, FLAGS, PSC, PLMN_ID, LAC, RAC
        # PSC needs to be >>4'ed
        self.umts_last_uarfcn_ul[radio_id] = result[0] | (1 << 14)
        self.umts_last_uarfcn_dl[radio_id] = result[1]
        self.umts_last_cell_id[radio_id] = result[2] & 0x7fff

    def parse_wcdma_rrc(self, pkt_ts, pkt, radio_id):
        channel_type, rbid, msg_len = struct.unpack('<BBH', pkt[0:4])
        sib_class = -1
        arfcn = 0
        msg_content = b''

        channel_type_map = {
                0: util.gsmtap_umts_rrc_types.UL_CCCH,
                1: util.gsmtap_umts_rrc_types.UL_DCCH,
                2: util.gsmtap_umts_rrc_types.DL_CCCH,
                3: util.gsmtap_umts_rrc_types.DL_DCCH,
                4: util.gsmtap_umts_rrc_types.BCCH_BCH, # Encoded
                5: util.gsmtap_umts_rrc_types.BCCH_FACH, # Encoded
                6: util.gsmtap_umts_rrc_types.PCCH,
                7: util.gsmtap_umts_rrc_types.MCCH,
                8: util.gsmtap_umts_rrc_types.MSCH,
                10: util.gsmtap_umts_rrc_types.System_Information_Container,
        }

        channel_type_map_extended_type = {
                9: util.gsmtap_umts_rrc_types.BCCH_BCH, # Extension SIBs
                0xFE: util.gsmtap_umts_rrc_types.BCCH_BCH, # Decoded
                0xFF: util.gsmtap_umts_rrc_types.BCCH_FACH # Decoded
        }

        sib_type_map = {
                0: util.gsmtap_umts_rrc_types.MasterInformationBlock,
                1: util.gsmtap_umts_rrc_types.SysInfoType1,
                2: util.gsmtap_umts_rrc_types.SysInfoType2,
                3: util.gsmtap_umts_rrc_types.SysInfoType3,
                4: util.gsmtap_umts_rrc_types.SysInfoType4,
                5: util.gsmtap_umts_rrc_types.SysInfoType5,
                6: util.gsmtap_umts_rrc_types.SysInfoType6,
                7: util.gsmtap_umts_rrc_types.SysInfoType7,
                8: util.gsmtap_umts_rrc_types.SysInfoType8,
                9: util.gsmtap_umts_rrc_types.SysInfoType9,
                10: util.gsmtap_umts_rrc_types.SysInfoType10,
                11: util.gsmtap_umts_rrc_types.SysInfoType11,
                12: util.gsmtap_umts_rrc_types.SysInfoType12,
                13: util.gsmtap_umts_rrc_types.SysInfoType13,
                14: util.gsmtap_umts_rrc_types.SysInfoType13_1,
                15: util.gsmtap_umts_rrc_types.SysInfoType13_2,
                16: util.gsmtap_umts_rrc_types.SysInfoType13_3,
                17: util.gsmtap_umts_rrc_types.SysInfoType13_4,
                18: util.gsmtap_umts_rrc_types.SysInfoType14,
                19: util.gsmtap_umts_rrc_types.SysInfoType15,
                20: util.gsmtap_umts_rrc_types.SysInfoType15_1,
                21: util.gsmtap_umts_rrc_types.SysInfoType15_2,
                22: util.gsmtap_umts_rrc_types.SysInfoType15_3,
                23: util.gsmtap_umts_rrc_types.SysInfoType16,
                24: util.gsmtap_umts_rrc_types.SysInfoType17,
                25: util.gsmtap_umts_rrc_types.SysInfoType15_4,
                26: util.gsmtap_umts_rrc_types.SysInfoType18,
                27: util.gsmtap_umts_rrc_types.SysInfoTypeSB1,
                28: util.gsmtap_umts_rrc_types.SysInfoTypeSB2,
                29: util.gsmtap_umts_rrc_types.SysInfoType15_5,
                30: util.gsmtap_umts_rrc_types.SysInfoType5bis,
                31: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                # Extension SIB
                66: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                67: util.gsmtap_umts_rrc_types.SysInfoType19
        }

        channel_type_map_new = {
                0x80: util.gsmtap_umts_rrc_types.UL_CCCH,
                0x81: util.gsmtap_umts_rrc_types.UL_DCCH,
                0x82: util.gsmtap_umts_rrc_types.DL_CCCH,
                0x83: util.gsmtap_umts_rrc_types.DL_DCCH,
                0x84: util.gsmtap_umts_rrc_types.BCCH_BCH, # Encoded
                0x85: util.gsmtap_umts_rrc_types.BCCH_FACH, # Encoded
                0x86: util.gsmtap_umts_rrc_types.PCCH,
                0x87: util.gsmtap_umts_rrc_types.MCCH,
                0x88: util.gsmtap_umts_rrc_types.MSCH,
        }
        channel_type_map_new_extended_type = {
                0x89: util.gsmtap_umts_rrc_types.BCCH_BCH, # Extension SIBs
                0xF0: util.gsmtap_umts_rrc_types.BCCH_BCH, # Decoded
        }
        sib_type_map_new = {
                0: util.gsmtap_umts_rrc_types.MasterInformationBlock,
                1: util.gsmtap_umts_rrc_types.SysInfoType1,
                2: util.gsmtap_umts_rrc_types.SysInfoType2,
                3: util.gsmtap_umts_rrc_types.SysInfoType3,
                4: util.gsmtap_umts_rrc_types.SysInfoType4,
                5: util.gsmtap_umts_rrc_types.SysInfoType5,
                6: util.gsmtap_umts_rrc_types.SysInfoType6,
                7: util.gsmtap_umts_rrc_types.SysInfoType7,
                8: util.gsmtap_umts_rrc_types.SysInfoType8,
                9: util.gsmtap_umts_rrc_types.SysInfoType9,
                10: util.gsmtap_umts_rrc_types.SysInfoType10,
                11: util.gsmtap_umts_rrc_types.SysInfoType11,
                12: util.gsmtap_umts_rrc_types.SysInfoType12,
                13: util.gsmtap_umts_rrc_types.SysInfoType13,
                14: util.gsmtap_umts_rrc_types.SysInfoType13_1,
                15: util.gsmtap_umts_rrc_types.SysInfoType13_2,
                16: util.gsmtap_umts_rrc_types.SysInfoType13_3,
                17: util.gsmtap_umts_rrc_types.SysInfoType13_4,
                18: util.gsmtap_umts_rrc_types.SysInfoType14,
                19: util.gsmtap_umts_rrc_types.SysInfoType15,
                20: util.gsmtap_umts_rrc_types.SysInfoType15_1,
                21: util.gsmtap_umts_rrc_types.SysInfoType15_2,
                22: util.gsmtap_umts_rrc_types.SysInfoType15_3,
                23: util.gsmtap_umts_rrc_types.SysInfoType16,
                24: util.gsmtap_umts_rrc_types.SysInfoType17,
                25: util.gsmtap_umts_rrc_types.SysInfoType15_4,
                26: util.gsmtap_umts_rrc_types.SysInfoType18,
                27: util.gsmtap_umts_rrc_types.SysInfoTypeSB1,
                28: util.gsmtap_umts_rrc_types.SysInfoTypeSB2,
                29: util.gsmtap_umts_rrc_types.SysInfoType15_5,
                30: util.gsmtap_umts_rrc_types.SysInfoType5bis,
                31: util.gsmtap_umts_rrc_types.SysInfoType19,
                # Extension SIB
                66: util.gsmtap_umts_rrc_types.SysInfoType11bis,
                67: util.gsmtap_umts_rrc_types.SysInfoType19
        }

        if channel_type in channel_type_map.keys():
            arfcn = self.umts_last_uarfcn_dl[radio_id]
            if channel_type == 0 or channel_type == 1:
                arfcn = self.umts_last_uarfcn_ul[radio_id]

            subtype = channel_type_map[channel_type]
            msg_content = pkt[4:]
        elif channel_type in channel_type_map_extended_type.keys():
            arfcn = self.umts_last_uarfcn_dl[radio_id]

            # uint8 subtype, uint8 msg[]
            if pkt[4] in sib_type_map.keys():
                subtype = sib_type_map[pkt[4]]
                msg_content = pkt[5:]
            else:
                print("Unknown WCDMA SIB Class {}".format(pkt[4]))
                return
        elif channel_type in channel_type_map_new.keys():
            # uint16 uarfcn, uint16 psc, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt[4:8])

            subtype = channel_type_map_new[channel_type]
            msg_content = pkt[8:]
        elif channel_type in channel_type_map_new_extended_type.keys():
            # uint16 uarfcn, uint16 psc, uint8 subtype, uint8 msg[]
            arfcn, psc = struct.unpack('<HH', pkt[4:8])

            if pkt[8] in sib_type_map_new.keys():
                subtype = sib_type_map_new[pkt[8]]
                msg_content = pkt[9:]
            else:
                print("Unknown WCDMA new SIB Class {}".format(pkt[8]))
                return
        else:
            print("Unknown WCDMA RRC channel type {}".format(pkt[0]))
            util.xxd(pkt)
            return

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.UMTS_RRC,
            arfcn = arfcn,
            sub_type = subtype,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + msg_content, radio_id)

    def parse_umts_ue_ota(self, pkt_ts, pkt, radio_id):
        msg_hdr = pkt[0:5]
        msg_content = pkt[5:]

        msg_hdr = struct.unpack('<BL', msg_hdr) # 1b direction, 4b length
        arfcn = self.umts_last_uarfcn_dl[radio_id]
        if msg_hdr[0] == 1:
            # Uplink
            arfcn = self.umts_last_uarfcn_ul[radio_id]

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        # msg_hdr[1] == L3 message length
        # Rest of content: L3 message
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.ABIS,
            arfcn = arfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + msg_content, radio_id)

    def parse_umts_ue_ota_dsds(self, pkt_ts, pkt, radio_id):
        radio_id_pkt = pkt[0]
        if radio_id_pkt < 1 or radio_id_pkt > 2:
            print('Unexpected radio ID {}'.format(radio_id_pkt))
            return
        self.parse_umts_ue_ota(pkt_ts, pkt[1:], radio_id_pkt - 1)

    # LTE

    def parse_lte_ml1_scell_meas(self, pkt_ts, pkt, radio_id):
        # Version 1b
        if pkt[0] == 5: # Version 5
            # EARFCN -> 4 bytes
            # PCI, Serv Layer Priority -> 4 bytes
            rrc_rel = pkt[1]
            earfcn = struct.unpack('<L', pkt[4:8])[0]
            pci = (pkt[8] | pkt[9] << 8) & 0x1ff
            serv_layer_priority = (pkt[8] | pkt[9] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[12:20])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[20:36])
            meas_rsrq = interim_1 & 0x3ff
            avg_rsrq = (interim_1 >> 20) & 0x3ff

            meas_rssi = (interim_2 >> 10) # TODO: get to know exact bit mask

            q_rxlevmin = interim_3 & 0x3f
            p_max = (interim_3 >> 6) & 0x7f
            max_ue_tx_pwr = (interim_3 >> 13) & 0x3f
            s_rxlev = (interim_3 >> 19) & 0x7f
            num_drx_s_fail = (interim_3 >> 26)

            s_intra_search = interim_4 & 0x3f
            s_non_intra_search = (interim_4 >> 6) & 0x3f

            if rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt[36:40])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                print('Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(rrc_rel))
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('Radio {}: LTE SCell: EARFCN {}, PCI {:3d}, Measured RSRP {:.2f}, Measured RSSI {:.2f}'.format(radio_id, earfcn, pci, real_rsrp, real_rssi))
        elif pkt[0] == 4: # Version 4
            # Version, RRC standard release, EARFCN, PCI - Serving Layer Priority
            # Measured, Average RSRP, Measured, Average RSRQ, Measured RSSI
            # Q_rxlevmin, P_max, Max UE TX Power, S_rxlev, Num DRX S Fail
            # S Intra Searcn, S Non Intra Search, Meas Rules Updated, Meas Rules
            # R9 Info (last 4b) - Q Qual Min, S Qual, S Intra Search Q, S Non Intra Search Q
            # 04 | 01 | 00 00 | 9C 18 | D6 0A | EC C4 4E 00 | E2 24 4E 00 | FF FC E3 0F | FE D8 0A 00 | 47 AD 56 02 | 1D 31 01 00 | A2 62 41 00 
            rrc_rel = pkt[1]
            earfcn = pkt[4] | pkt[5] << 8
            pci = (pkt[6] | pkt[7] << 8) & 0x1ff
            serv_layer_priority = (pkt[6] | pkt[7] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[8:16])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[16:32])
            meas_rsrq = interim_1 & 0x3ff
            avg_rsrq = (interim_1 >> 20) & 0x3ff

            meas_rssi = (interim_2 >> 10) # TODO: get to know exact bit mask

            q_rxlevmin = interim_3 & 0x3f
            p_max = (interim_3 >> 6) & 0x7f
            max_ue_tx_pwr = (interim_3 >> 13) & 0x3f
            s_rxlev = (interim_3 >> 19) & 0x7f
            num_drx_s_fail = (interim_3 >> 26)

            s_intra_search = interim_4 & 0x3f
            s_non_intra_search = (interim_4 >> 6) & 0x3f

            if rrc_rel == 0x01: # RRC Rel. 9
                r9_data_interim = struct.unpack('<L', pkt[32:36])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                print('Unknown LTE ML1 Serving Cell Meas packet - RRC version {}'.format(rrc_rel))
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('Radio {}: LTE SCell: EARFCN {}, PCI {:3d}, Measured RSRP {:.2f}, Measured RSSI {:.2f}'.format(radio_id, earfcn, pci, real_rsrp, real_rssi))
        else:
            print('Unknown LTE ML1 Serving Cell Meas packet version {}'.format(pkt[0]))
            return

    def parse_lte_ml1_ncell_meas(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 5: # Version 5
            # EARFCN -> 4 bytes
            rrc_rel = pkt[1]
            earfcn = struct.unpack('<L', pkt[4:8])[0]
            q_rxlevmin = (pkt[8] | pkt[9] << 8) & 0x3f
            n_cells = (pkt[8] | pkt[9] << 8) >> 6
            print('Radio {}: LTE NCell: # cells {}'.format(radio_id, n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[12 + 32 * i:12 + 32 * (i + 1)]
                interim = struct.unpack('<LLLLHHLL', n_cell_pkt[0:28])
                n_pci = interim[0] & 0x1ff
                n_meas_rssi = (interim[0] >> 9) & 0x7ff
                n_meas_rsrp = (interim[0] >> 20)
                n_avg_rsrp = (interim[1] >> 12) & 0xfff
                n_meas_rsrq = (interim[2] >> 12) & 0x3ff
                n_avg_rsrq = interim[3] & 0x3ff
                n_s_rxlev = (interim[3] >> 20) & 0x3f
                n_freq_offset = interim[4]
                n_ant0_frame_offset = interim[6] & 0x7ff
                n_ant0_sample_offset = (interim[6] >> 11)
                n_ant1_frame_offset = interim[7] & 0x7ff
                n_ant1_sample_offset = (interim[7] >> 11)

                if rrc_rel == 1: # Rel 9
                    r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                    n_s_qual = r9_info_interim[0]

                n_real_rsrp = -180 + n_meas_rsrp * 0.0625
                n_real_rssi = -110 + n_meas_rssi * 0.0625
                n_real_rsrq = -30 + n_meas_rsrq * 0.0625

                print('Radio {}: Neighbor cell {}: PCI {:3d}, RSRP {:.2f}, RSSI {:.2f}'.format(radio_id, i, n_pci, n_real_rsrp, n_real_rssi))
        elif pkt[0] == 4: # Version 4
            # Version, RRC standard release, EARFCN, Q_rxlevmin, Num Cells, Cell Info
            # Cell Info - PCI, Measured RSSI, Measured RSRP, Average RSRP
            #    Measured RSRQ, Average RSRQ, S_rxlev, Freq Offset
            #    Ant0 Frame Offset, Ant0 Sample Offset, Ant1 Frame Offset, Ant1 Sample Offset
            #    S_qual
            # 04 | 01 | 00 00 9C 18 | 47 00 | 83 48 E4 4D | DE A4 4C 00 | CA B4 CC 32 | B6 D8 42 03 | 00 00 | 00 00 | FF 77 33 01 | FF 77 33 01 | 22 02 01 00 
            rrc_rel = pkt[1]
            earfcn = pkt[4] | pkt[5] << 8
            q_rxlevmin = (pkt[6] | pkt[7] << 8) & 0x3f
            n_cells = (pkt[6] | pkt[7] << 8) >> 6
            print('Radio {}: LTE NCell: # cells {}'.format(radio_id, n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[8 + 32 * i:8 + 32 * (i + 1)]
                interim = struct.unpack('<LLLLHHLL', n_cell_pkt[0:28])
                n_pci = interim[0] & 0x1ff
                n_meas_rssi = (interim[0] >> 9) & 0x7ff
                n_meas_rsrp = (interim[0] >> 20)
                n_avg_rsrp = (interim[1] >> 12) & 0xfff
                n_meas_rsrq = (interim[2] >> 12) & 0x3ff
                n_avg_rsrq = interim[3] & 0x3ff
                n_s_rxlev = (interim[3] >> 20) & 0x3f
                n_freq_offset = interim[4]
                n_ant0_frame_offset = interim[6] & 0x7ff
                n_ant0_sample_offset = (interim[6] >> 11)
                n_ant1_frame_offset = interim[7] & 0x7ff
                n_ant1_sample_offset = (interim[7] >> 11)

                if rrc_rel == 1: # Rel 9
                    r9_info_interim = struct.unpack('<L', n_cell_pkt[28:])
                    n_s_qual = r9_info_interim[0]
                n_real_rsrp = -180 + n_meas_rsrp * 0.0625
                n_real_rssi = -110 + n_meas_rssi * 0.0625
                n_real_rsrq = -30 + n_meas_rsrq * 0.0625

                print('Radio {}: Neighbor cell {}: PCI {:3d}, RSRP {:.2f}, RSSI {:.2f}'.format(radio_id, i, n_pci, n_real_rsrp, n_real_rssi))
        else:
            print('Radio {}: Unknown LTE ML1 Neighbor Meas packet version {}'.format(radio_id, pkt[0]))

    def parse_lte_ml1_cell_info(self, pkt_ts, pkt, radio_id):
        mib_payload = bytes([0, 0, 0])

        if pkt[0] == 1:
            # Version, DL BW, SFN, EARFCN, (Cell ID, PBCH, PHICH Duration, PHICH Resource), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 01 | 64 | A4 01 | 14 05 | 24 42 | 41 05 00 00 | D3 2D 00 00 | 80 53 3D 00 00 00 00 00 | 00 00 A4 A9 | 1D FF | 01 00 
            pkt_content = struct.unpack('<BHH', pkt[1:6])

            self.lte_last_bw_dl[radio_id] = pkt_content[0]
            self.lte_last_cell_id[radio_id] = pkt_content[1]
            self.lte_last_earfcn_dl[radio_id] = pkt_content[2]

            mib_payload = bytes([pkt[27], pkt[26], pkt[25]])
        elif pkt[16] == 2:
            # XXX: not complete
            # Version, DL BW, SFN, EARFCN, (Cell ID 9, PBCH 1, PHICH Duration 3, PHICH Resource 3), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 02 | 4B | F8 00 | 21 07 00 00 | 03 23 00 00 | 00 00 00 00 | 0F 05 00 00 | 2A BD 0B 17 00 00 00 00 | 00 00 F8 84 | 00 00 | 01 00 
            pkt_content = struct.unpack('<BHL', pkt[1:8])

            self.lte_last_bw_dl[radio_id] = pkt_content[0]
            self.lte_last_cell_id[radio_id] = pkt_content[1]
            self.lte_last_earfcn_dl[radio_id] = pkt_content[2]

            mib_payload = bytes([pkt[31], pkt[30], pkt[29]])
        else:
            print('Unknown LTE ML1 cell info packet version {}'.format(pkt[0]))

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = self.lte_last_earfcn_dl[radio_id],
            sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + mib_payload, radio_id)

    def parse_lte_mac_rach_trigger(self, pkt_ts, pkt, radio_id):
        # XXX: Wireshark's GSMTAP dissector does not support PRACH preamble
        print("Unhandled XDM Header 0xB061: LTE MAC RACH Trigger")
        return

    def parse_lte_mac_rach_response(self, pkt_ts, pkt, radio_id):
        # 01 01 | 30 C7 | 06 | 02 | 24 00 | 01 | 00 | 01 | 07 | 1B | FF | 98 FF | 00 00 | 01 | 23 1A | 04 00 | 18 | 1C 01 00 | 07 00 | 06 | 00 46 5C 80 BD 06 48 00 00 00                                      
        msg_content = pkt
        mac_header = b''
        mac_body = b''
        earfcn = self.lte_last_earfcn_dl[radio_id] | (1 << 14)

        if msg_content[0] != 0x01:
            print('Unsupported LTE MAC RACH response packet version %02x' % msg_content[0])
            return

        if msg_content[1] != 0x01:
            print('More than 1 subpacket not supported: %02x' % msg_content[1])
            return 
        
        if msg_content[4] != 0x06:
            print('Expected MAC RACH attempt subpacket, got %02x' % msg_content[4])
            return 

        if msg_content[5] == 0x02:
            if msg_content[9] == 0x01: # RACH Failure, 0x00 == Success
                return 
            if msg_content[11] != 0x07: # not all message present
                print('Not enough message to generate RAR')
                return

            rapid = msg_content[12]
            tc_rnti = msg_content[19] | (msg_content[20] << 8)
            ta = msg_content[21] | (msg_content[22] << 8)
            grant = ((msg_content[24] & 0xf) << 16) | (msg_content[25] << 8) | msg_content[26]

            #print('%04x %04x %06x %04x' % (rapid, ta, grant, tc_rnti))

            # RAR header: RAPID present, RAPID
            # RAR body: TA, Grant, TC-RNTI
            # Byte 1: TA[11:4]
            # Byte 2: TA[3:0] | GRANT[20:16]
            # Byte 3, 4: GRANT[15:0]
            # Byte 5, 6: TC-RNTI
            mac_body = bytes([(1 << 6) | (rapid & 0x3f),
                              (ta & 0x07f0) >> 4, 
                              ((ta & 0x000f) << 4) | ((grant & 0x0f0000) >> 16),
                              (grant & 0x00ff00) >> 8,
                              (grant & 0x0000ff),
                              (tc_rnti & 0xff00) >> 8,
                              tc_rnti & 0x00ff])
            # radioType 1b
            # direction 1b
            # rntiType 1b, rnti 2b
            # UEID 2b
            # SysFN 2b, SubFN 2b
            # Reserved 1b
            mac_header = bytes([0x01, 0x01, 0x02, 0x00, 0x02, 0x00, 0x02, 0x03,
                                0xff, 0x00, 0x08, 0x01])

            self.lte_last_tcrnti[radio_id] = tc_rnti

        else:
            # TODO: RACH response v3, v4
            print('Unsupported RACH response version %02x' % msg_content[5])
            util.xxd(pkt)
            return 

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_MAC,
            arfcn = earfcn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + mac_header + mac_body, radio_id)

    def parse_lte_mac_dl_block(self, pkt_ts, pkt, radio_id):
        earfcn = self.lte_last_earfcn_dl[radio_id]
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved

            n_subpackets = pkt[1]
            pos = 4
            # RNTI Type: {0: C-RNTI, 2: P-RNTI, 3: RA-RNTI, 4: T-C-RNTI, 5: SI-RNTI}
            rnti_type_map = {0: 3, 2: 1, 3: 2, 4: 3, 5: 4}

            for x in range(n_subpackets):
                # pkt[4]: Subpacket ID
                # pkt[5]: Subpacket Version
                # pkt[6:8]: Subpacket Size

                # pkt[8]: Number of DTB entries

                subpkt_id = pkt[pos]
                subpkt_ver = pkt[pos + 1]
                subpkt_size = pkt[pos + 2] | (pkt[pos + 3] << 8)
                if subpkt_id != 0x07:
                    print('Unexpected DL MAC Subpacket ID %s' % subpkt_id)
                    pos += subpkt_size
                    continue

                if subpkt_ver == 0x02:
                    n_samples = pkt[pos + 4]
                    #print("LTE MAC DL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))

                    pos_sample = pos + 5
                    for y in range(n_samples):
                        # for each entry
                        # subp[0:2]: SFN + SubFN
                        # subp[2]: RNTI Type
                        # subp[3]: HARQ ID
                        # subp[4:6]: PMCH ID
                        # subp[6:8]: DL TBS
                        # subp[8]: RLC PDUs
                        # subp[9:11]: Padding
                        # subp[11]: Header Len
                        # subp[12:] Header + CE

                        sfn_subfn = pkt[pos_sample] | (pkt[pos_sample + 1] << 8)
                        sfn = (sfn_subfn & 0xfff0) >> 4
                        subfn = sfn_subfn & 0xf
                        rnti_type = pkt[pos_sample + 2]
                        harq_id = pkt[pos_sample + 3]
                        pmch_id = pkt[pos_sample + 4] | (pkt[pos_sample + 5] << 8)
                        dl_tbs = pkt[pos_sample + 6] | (pkt[pos_sample + 7] << 8)
                        rlc_pdus = pkt[pos_sample + 8]
                        padding = pkt[pos_sample + 9] | (pkt[pos_sample + 10] << 8)
                        header_len = pkt[pos_sample + 11]
                        mac_hdr = pkt[pos_sample + 12:pos_sample + 12 + header_len]

                        gsmtap_rnti_type = 0
                        rnti = 0
                        ueid = 0x3ff
                        if rnti_type in rnti_type_map:
                            gsmtap_rnti_type = rnti_type_map[rnti_type]

                        if rnti_type == 5: # SI-RNTI
                            rnti = 0xffff
                        elif rnti_type == 2: # P-RNTI
                            rnti = 0xfffe
                        else:
                            rnti = self.lte_last_tcrnti[radio_id]

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x01, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = util.create_gsmtap_header(
                            version = 3,
                            payload_type = util.gsmtap_type.LTE_MAC,
                            arfcn = earfcn,
                            frame_number = sfn,
                            sub_slot = subfn,
                            device_sec = ts_sec,
                            device_usec = ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len, mac_hdr))
                        self.writeCP(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, radio_id)
                        pos_sample += (12 + header_len)
                elif subpkt_ver == 0x04:
                    # 01 | 00 00 09 10 | 02 | 01 | 00 00 | 07 00 | 00 | 00 00 | 07 | 40 0C 0F 0F 8F 2D B0 | 00 00
                    # 03 | 00 00 00 2D | 05 | 01 | 00 00 | 1C 00 | 00 | 00 00 | 1C | 00 01 03 27 63 8D DA A5 5C 26 D0 53 90 18 00 00 80 0A 17 55 A2 A8 2F 62 35 F5 06 0C 
                    #    | 00 00 10 2D | 05 | 01 | 00 00 | 07 00 | 00 | 00 00 | 07 | 00 04 2B 8B 50 6D C4 |
                    #    | 00 00 20 2D | 05 | 01 | 00 00 | 12 00 | 00 | 00 00 | 12 | 00 0C 56 05 E8 91 AA 61 23 90 58 0E 74 36 A9 84 8C 40
                    n_samples = pkt[pos + 4]
                    #print("LTE MAC DL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))
                    pos_sample = pos + 5
                    for y in range(n_samples):
                        # for each entry
                        # subp[0:4]: SFN + SubFN
                        # subp[4]: RNTI Type
                        # subp[5]: HARQ ID
                        # subp[6:8]: PMCH ID
                        # subp[8:10]: DL TBS
                        # subp[10]: RLC PDUs
                        # subp[11:12]: Padding
                        # subp[12]: Header Len
                        # subp[13:] Header + CE

                        sfn_subfn = pkt[pos_sample + 2] | (pkt[pos_sample + 3] << 8)
                        sfn = (sfn_subfn & 0xfff0) >> 4
                        subfn = sfn_subfn & 0xf
                        rnti_type = pkt[pos_sample + 4]
                        harq_id = pkt[pos_sample + 5]
                        pmch_id = pkt[pos_sample + 6] | (pkt[pos_sample + 7] << 8)
                        dl_tbs = pkt[pos_sample + 8] | (pkt[pos_sample + 9] << 8)
                        rlc_pdus = pkt[pos_sample + 10]
                        padding = pkt[pos_sample + 11] | (pkt[pos_sample + 12] << 8)
                        header_len = pkt[pos_sample + 13]
                        mac_hdr = pkt[pos_sample + 14:pos_sample + 14 + header_len]

                        gsmtap_rnti_type = 0
                        rnti = 0
                        ueid = 0x3ff
                        if rnti_type in rnti_type_map:
                            gsmtap_rnti_type = rnti_type_map[rnti_type]

                        if rnti_type == 5: # SI-RNTI
                            rnti = 0xffff
                        elif rnti_type == 2: # P-RNTI
                            rnti = 0xfffe
                        else:
                            rnti = self.lte_last_tcrnti[radio_id]

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x01, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = util.create_gsmtap_header(
                            version = 3,
                            payload_type = util.gsmtap_type.LTE_MAC,
                            arfcn = earfcn,
                            frame_number = sfn,
                            sub_slot = subfn,
                            device_sec = ts_sec,
                            device_usec = ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len, mac_hdr))
                        self.writeCP(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, radio_id)
                        pos_sample += (14 + header_len)

                else:
                    print('Unexpected DL MAC Subpacket version %s' % subpkt_ver)
                pos += subpkt_size
        else:
            print('Unknown LTE MAC DL packet version %s' % pkt[0])

    def parse_lte_mac_ul_block(self, pkt_ts, pkt, radio_id):
        earfcn = self.lte_last_earfcn_dl[radio_id] | (1 << 14)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved

            # pkt[4]: Subpacket ID
            # pkt[5]: Subpacket Version
            # pkt[6:8]: Subpacket Size

            # pkt[8]: Number of DTB entries

            # for each entry
            # subp[0:2]: SFN + SubFN
            # subp[2]: RNTI Type
            # subp[3]: HARQ ID
            # subp[4:6]: PMCH ID
            # subp[6:8]: DL TBS
            # subp[8]: RLC PDUs
            # subp[9:11]: Padding
            # subp[11]: Header Len
            # subp[12:] Header + CE

            n_subpackets = pkt[1]
            pos = 4
            # RNTI Type: {0: C-RNTI, 2: P-RNTI, 3: RA-RNTI, 4: T-C-RNTI, 5: SI-RNTI}
            rnti_type_map = {0: 3, 2: 1, 3: 2, 4: 3, 5: 4}

            for x in range(n_subpackets):
                subpkt_id = pkt[pos]
                subpkt_ver = pkt[pos + 1]
                subpkt_size = pkt[pos + 2] | (pkt[pos + 3] << 8)
                if subpkt_id != 0x08:
                    print('Unexpected LTE MAC UL Subpacket ID %s' % subpkt_id)
                    pos += subpkt_size
                    continue

                if subpkt_ver == 0x01:
                    n_samples = pkt[pos + 4]
                    #print("LTE MAC UL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))

                    pos_sample = pos + 5
                    for y in range(n_samples):
                        # RNTI Type: {0: C-RNTI}
                        # BSR Event: {0: None, 1: Periodic, 2: High Data Arrival}
                        # BSR Trig: {0: No BSR, 3: S-BSR, 4: Pad L-BSR}
                        harq_id = pkt[pos_sample]
                        rnti_type = pkt[pos_sample + 1]
                        sfn_subfn = pkt[pos_sample + 2] | (pkt[pos_sample + 3] << 8)
                        sfn = (sfn_subfn & 0xfff0) >> 4
                        subfn = sfn_subfn & 0xf
                        grant = pkt[pos_sample + 4] | (pkt[pos_sample + 5] << 8)
                        rlc_pdus = pkt[pos_sample + 6]
                        padding = pkt[pos_sample + 7] | (pkt[pos_sample + 8] << 8)
                        bsr_event = pkt[pos_sample + 9]
                        bsr_trig = pkt[pos_sample + 10]
                        header_len = pkt[pos_sample + 11]
                        mac_hdr = pkt[pos_sample + 12:pos_sample + 12 + header_len]

                        gsmtap_rnti_type = 0
                        rnti = 0
                        ueid = 0x3ff
                        if rnti_type in rnti_type_map:
                            gsmtap_rnti_type = rnti_type_map[rnti_type]

                        if rnti_type == 0: # C-RNTI
                            rnti = self.lte_last_tcrnti[radio_id]

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x00, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = util.create_gsmtap_header(
                            version = 3,
                            payload_type = util.gsmtap_type.LTE_MAC,
                            arfcn = earfcn,
                            frame_number = sfn,
                            sub_slot = subfn,
                            device_sec = ts_sec,
                            device_usec = ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len, mac_hdr))
                        self.writeCP(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, radio_id)
                        pos_sample += (12 + header_len)
                elif subpkt_ver == 0x02:
                    n_samples = pkt[pos + 4]
                    #print("LTE MAC UL: ID %d Version %d Size %d N_Samples %d" % (subpkt_id, subpkt_ver, subpkt_size, n_samples))

                    pos_sample = pos + 5
                    for y in range(n_samples):
                        # XXX: SFN/SubFN
                        # 03 | 00 | 00 | 02 00 06 2E | A1 00 | 02 | 00 00 | 02 | 03 | 05 | 3D 21 02 01 02 
                        #    | 00 | 00 | 01 00 13 2E | 33 00 | 01 | 1E 00 | 00 | 04 | 07 | 3E 21 0E 1F 00 00 00 
                        #    | 00 | 00 | 02 00 46 2E | E9 00 | 02 | D5 00 | 02 | 03 | 09 | 3D 3A 21 02 21 09 1F 00 13 
                        harq_id = pkt[pos_sample]
                        rnti_type = pkt[pos_sample + 1]
                        sfn_subfn = pkt[pos_sample + 4] | (pkt[pos_sample + 5] << 8)
                        sfn = (sfn_subfn & 0xfff0) >> 4
                        subfn = sfn_subfn & 0xf
                        grant = pkt[pos_sample + 6] | (pkt[pos_sample + 7] << 8)
                        rlc_pdus = pkt[pos_sample + 8]
                        padding = pkt[pos_sample + 9] | (pkt[pos_sample + 10] << 8)
                        bsr_event = pkt[pos_sample + 11]
                        bsr_trig = pkt[pos_sample + 12]
                        header_len = pkt[pos_sample + 13]
                        mac_hdr = pkt[pos_sample + 14:pos_sample + 14 + header_len]

                        gsmtap_rnti_type = 0
                        rnti = 0
                        ueid = 0x3ff
                        if rnti_type in rnti_type_map:
                            gsmtap_rnti_type = rnti_type_map[rnti_type]

                        if rnti_type == 0: # C-RNTI
                            rnti = self.lte_last_tcrnti[radio_id]

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x00, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = util.create_gsmtap_header(
                            version = 3,
                            payload_type = util.gsmtap_type.LTE_MAC,
                            arfcn = earfcn,
                            frame_number = sfn,
                            sub_slot = subfn,
                            device_sec = ts_sec,
                            device_usec = ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len, mac_hdr))
                        self.writeCP(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, radio_id)
                        pos_sample += (14 + header_len)
                else:
                    print('Unexpected LTE MAC UL Subpacket version %s' % subpkt_ver)

                pos += subpkt_size
        else:
            print('Unknown LTE MAC UL packet version %s' % pkt[0])

    # 0x4021: 01|00 000|0 00|10 0001 (valid, bearer id=0, mode=AM, sn=5b, cidx = 33)
    # 0x4222: 01|00 001|0 00|10 0010 (valid, bearer id=1, mode=AM, sn=5b, cidx = 34)
    # 0x4101: 01|00 000|1 00|00 0001 (valid, bearer id=0, mode=AM, sn=12b, cidx = 1)
    # 0x4543: 01|00 010|1 01|00 0011 (valid, bearer id=2, mode=UM, sn=12b, cidx = 3)
    # 0x4905: 01|00 100|1 00|00 0101 (valid, bearer id=4, mode=AM, sn=12b, cidx = 5)
    # 0x4704: 01|00 011|1 00|00 0100 (valid, bearer id=3, mode=AM, sn=12b, cidx = 4)
    # sn: 5b (SRB), 7, 12, 15, 16b (DRB)
    # 33.401 B.2.1: IK(128b), COUNT(32b), BEARER(5b), DIRECTION(1b)
    # EIA2: AES 128bit, CMAC mode (M0..M31 = COUNT, M32...M36 = BEARER, M37 = DIRECTION, M38..M63 = 0, M64... = Message)
    # TODO: what is for 32 byte number

    def parse_lte_pdcp_dl_srb_int(self, pkt_ts, pkt, radio_id):
        earfcn = self.lte_last_earfcn_dl[radio_id]
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                # pkt[4]: Subpacket ID
                # pkt[5]: Subpacket Version
                # pkt[6:8]: Subpacket Size
                subpkt_id = pkt[pos]
                subpkt_ver = pkt[pos + 1]
                subpkt_size = pkt[pos + 2] | (pkt[pos + 3] << 8)

                if subpkt_id != 0xC6:
                    print('Unexpected PDCP DL SRB Subpacket ID %s' % subpkt_id)
                    pos += subpkt_size
                    continue

                if subpkt_ver == 0x01:
                    pos += 4
                    pos += 32
                    ciphering_algo = pkt[pos]
                    integrity_algo = pkt[pos + 1]
                    num_pdus = pkt[pos + 2] | (pkt[pos + 3] << 8)

                    pos_sample = pos + 4
                    for y in range(num_pdus):
                        # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I, XMAC-I
                        # Ciphering: NONE: 0x07, AES: 0x03
                        # Integrity: NONE: 0x07, AES: 0x02
                        pdu_hdr = struct.unpack('<HHHHLLL', pkt[pos_sample:pos_sample + 20])
                        pdcp_pdu = pkt[pos_sample + 20: pos_sample + 20 + pdu_hdr[2]]

                        # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                        # Has header on PDU, CP (0x01), no ROHC
                        # Direction: Downlink (0x01)
                        ws_hdr = bytes([0x00, 0x01, 0x00, 0x03, 0x01, 0x01])
                        self.writeCP(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id)
                        pos_sample += (20 + pdu_hdr[2])

                else:
                    print('Unexpected PDCP DL SRB Subpacket version %s' % subpkt_ver)
                    pos += subpkt_size
                    continue
        else:
            print('Unknown PDCP DL SRB packet version %s' % pkt[16])

    def parse_lte_pdcp_ul_srb_int(self, pkt_ts, pkt, radio_id):
        earfcn = self.lte_last_earfcn_dl[radio_id] | (1 << 14)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if pkt[0] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[1]
            pos = 4

            for x in range(n_subpackets):
                # pkt[4]: Subpacket ID
                # pkt[5]: Subpacket Version
                # pkt[6:8]: Subpacket Size
                subpkt_id = pkt[pos]
                subpkt_ver = pkt[pos + 1]
                subpkt_size = pkt[pos + 2] | (pkt[pos + 3] << 8)

                if subpkt_id != 0xC7:
                    print('Unexpected PDCP DL SRB Subpacket ID %s' % subpkt_id)
                    pos += subpkt_size
                    continue

                if subpkt_ver == 0x01:
                    pos += 4
                    pos += 32
                    ciphering_algo = pkt[pos]
                    integrity_algo = pkt[pos + 1]
                    num_pdus = pkt[pos + 2] | (pkt[pos + 3] << 8)

                    pos_sample = pos + 4
                    for y in range(num_pdus):
                        # cfg, pdu_size, log_size, sfn_subfn, count, MAC-I
                        # Ciphering: NONE: 0x07, AES: 0x03
                        # Integrity: NONE: 0x07, AES: 0x02
                        pdu_hdr = struct.unpack('<HHHHLL', pkt[pos_sample:pos_sample + 16])
                        pdcp_pdu = pkt[pos_sample + 16: pos_sample + 16 + pdu_hdr[2]]

                        # Directly pack PDCP PDU on UDP packet, see epan/packet-pdcp-lte.h of Wireshark
                        # Has header on PDU, CP (0x01), no ROHC
                        # Direction: Uplink (0x00)
                        ws_hdr = bytes([0x00, 0x01, 0x00, 0x03, 0x00, 0x01])
                        self.writeCP(b'pdcp-lte' + ws_hdr + pdcp_pdu, radio_id)
                        pos_sample += (16 + pdu_hdr[2])

                else:
                    print('Unexpected PDCP UL SRB Subpacket version %s' % subpkt_ver)
                    pos += subpkt_size
                    continue
        else:
            print('Unknown PDCP UL SRB packet version %s' % pkt[16])

    def parse_lte_mib(self, pkt_ts, pkt, radio_id):
        msg_content = pkt
        # 1.4, 3, 5, 10, 15, 20 MHz - 6, 15, 25, 50, 75, 100 PRBs
        prb_to_bitval = {6: 0, 15: 1, 25: 2, 50: 3, 75: 4, 100: 5}
        mib_payload = [0, 0, 0]

        if pkt[0] == 1:
            if len(msg_content) != 9:
                return 
            msg_content = struct.unpack('<BHHHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 01 | 00 01 | 14 05 | 54 00 | 02 | 64 

            self.lte_last_cell_id[radio_id] = msg_content[1]
            self.lte_last_earfcn_dl[radio_id] = msg_content[2]
            self.lte_last_earfcn_ul[radio_id] = msg_content[2] + 18000
            self.lte_last_sfn[radio_id] = msg_content[3]
            self.lte_last_tx_ant[radio_id] = msg_content[4]
            self.lte_last_bw_dl[radio_id] = msg_content[5]
            self.lte_last_bw_ul[radio_id] = msg_content[5]
        elif pkt[0] == 2:
            if len(msg_content) != 11:
                return 
            msg_content = struct.unpack('<BHLHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 02 | 03 01 | 21 07 00 00 | F8 00 | 02 | 4B 

            self.lte_last_cell_id[radio_id] = msg_content[1]
            self.lte_last_earfcn_dl[radio_id] = msg_content[2]
            self.lte_last_earfcn_ul[radio_id] = msg_content[2] + 18000
            self.lte_last_sfn[radio_id] = msg_content[3]
            self.lte_last_tx_ant[radio_id] = msg_content[4]
            self.lte_last_bw_dl[radio_id] = msg_content[5]
            self.lte_last_bw_ul[radio_id] = msg_content[5]
        else:
            # TODO: LTE RRC MIB packet version 17 (0x11)
            print('Unknown LTE RRC MIB packet version %s' % pkt[0])
            util.xxd(pkt)
            return 

        sfn4 = int(self.lte_last_sfn[radio_id] / 4)
        # BCCH BCH payload: DL bandwidth 3b, PHICH config (duration 1b, resource 2b), SFN 8b, Spare 10b (all zero)
        if prb_to_bitval.get(self.lte_last_bw_dl[radio_id]) != None:
            mib_payload[0] = (prb_to_bitval.get(self.lte_last_bw_dl[radio_id]) << 5) | (2 << 2) | ((sfn4 & 0b11000000) >> 6)
            mib_payload[1] = (sfn4 & 0b111111) << 2

        mib_payload = bytes(mib_payload)

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = self.lte_last_earfcn_dl[radio_id],
            sub_type = util.gsmtap_lte_rrc_types.BCCH_BCH,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + mib_payload, radio_id)

    def parse_lte_rrc_cell_info(self, pkt_ts, pkt, radio_id):
        if pkt[0] == 2:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 02 | 8F 00 | 14 05 | 64 4B | 64 | 64 | 00 74 BC 01 | D6 05 | 03 00 00 00 | 06 01 | 02 01 00 00
            pkt_content = struct.unpack('<HHHBB', pkt[1:9])

            self.lte_last_cell_id[radio_id] = pkt_content[0]
            self.lte_last_earfcn_dl[radio_id] = pkt_content[1]
            self.lte_last_earfcn_ul[radio_id] = pkt_content[2]
            self.lte_last_bw_dl[radio_id] = pkt_content[3]
            self.lte_last_bw_ul[radio_id] = pkt_content[4]
        elif pkt[16] == 3:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 03 | 4D 00 | 21 07 00 00 | 71 4D 00 00 | 4B | 4B | 33 C8 B0 09 | 15 9B | 03 00 00 00 | CC 01 | 02 0B 00 00
            pkt_content = struct.unpack('<HLLBB', pkt[1:13])

            self.lte_last_cell_id[radio_id] = pkt_content[0]
            self.lte_last_earfcn_dl[radio_id] = pkt_content[1]
            self.lte_last_earfcn_ul[radio_id] = pkt_content[2]
            self.lte_last_bw_dl[radio_id] = pkt_content[3]
            self.lte_last_bw_ul[radio_id] = pkt_content[4]
        else:
            print('Unknown LTE RRC cell info packet version %s' % pkt[0])

    def parse_lte_rrc(self, pkt_ts, pkt, radio_id):
        msg_hdr = b''
        msg_content = b''

        if pkt[0] in (0x08, 0x09, 0x0c, 0x0d, 0x0f, 0x13, 0x14): # Version 8, 9, 12, 13, 15, 19, 20
            # 08 | 0a 72 | 01 | 0e 00 | 9c 18 00 00 | a9 33 | 06 | 00 00 00 00 | 02 00 | 2e 02
            # 09 | 0b 70 | 00 | 00 01 | 14 05 00 00 | 09 91 | 0b | 00 00 00 00 | 07 00 | 40 0b 8e c1 dd 13 b0
            # 0d | 0c 74 | 01 | 32 00 | 38 18 00 00 | 00 00 | 08 | 00 00 00 00 | 02 00 | 2c 00
            # 0f | 0d 21 | 00 | 9e 00 | 14 05 00 00 | 49 8c | 05 | 00 00 00 00 | 07 00 | 40 0c 8e c9 42 89 e0
            # 0f | 0d 21 | 01 | 9e 00 | 14 05 00 00 | 00 00 | 09 | 00 00 00 00 | 1c 00 | 08 10 a5 34 61 41 a3 1c 31 68 04 40 1a 00 49 16 7c 23 15 9f 00 10 67 c1 06 d9 e0 00 fd 2d
            # 13 | 0e 22 | 00 | 0b 00 | fa 09 00 00 | 00 00 | 32 | 00 00 00 00 | 09 00 | 28 18 40 16 08 08 80 00 00
            # 14 | 0e 30 | 01 | 09 01 | 9c 18 00 00 | 00 00 | 09 | 00 00 00 00 | 18 00 | 08 10 a7 14 53 59 a6 05 43 68 c0 3b da 30 04 a6 88 02 8d a2 00 9a 68 40
            msg_hdr = pkt[0:19] # 19 bytes
            msg_content = pkt[19:] # Rest of packet
            if len(msg_hdr) != 19:
                return 

            msg_hdr = struct.unpack('<BHBHLHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1
            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl[radio_id] = earfcn
            self.lte_last_cell_id[radio_id] = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn[radio_id] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[0] in (0x06, 0x07): # Version 6 and 7
            # 06 | 09 B1 | 00 | 07 01 | 2C 07 | 25 34 | 02 | 02 00 00 00 | 12 00 | 40 49 88 05 C0 97 02 D3 B0 98 1C 20 A0 81 8C 43 26 D0 
            msg_hdr = pkt[0:17] # 17 bytes
            msg_content = pkt[17:] # Rest of packet
            if len(msg_hdr) != 17:
                return 

            msg_hdr = struct.unpack('<BHBHHHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl[radio_id] = earfcn
            self.lte_last_cell_id[radio_id] = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn[radio_id] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[0] in (0x02, 0x03, 0x04): # Version 2, 3, 4
            msg_hdr = pkt[0:13] # 13 bytes
            msg_content = pkt[13:] # Rest of packet
            if len(msg_hdr) != 13:
                return 

            msg_hdr = struct.unpack('<BHBHHHBH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl[radio_id] = earfcn
            self.lte_last_cell_id[radio_id] = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn[radio_id] = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)
        else:
            print('Unhandled LTE RRC packet version %s' % pkt[0])
            util.xxd(pkt)
            return 

        if pkt[0] < 9:
            # RRC Packet <v9
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                3: util.gsmtap_lte_rrc_types.MCCH,
                4: util.gsmtap_lte_rrc_types.PCCH,
                5: util.gsmtap_lte_rrc_types.DL_CCCH,
                6: util.gsmtap_lte_rrc_types.DL_DCCH,
                7: util.gsmtap_lte_rrc_types.UL_CCCH,
                8: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt[0] < 13:
            # RRC Packet v9-v12
            rrc_subtype_map = {
                8: util.gsmtap_lte_rrc_types.BCCH_BCH,
                9: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                10: util.gsmtap_lte_rrc_types.MCCH,
                11: util.gsmtap_lte_rrc_types.PCCH,
                12: util.gsmtap_lte_rrc_types.DL_CCCH,
                13: util.gsmtap_lte_rrc_types.DL_DCCH,
                14: util.gsmtap_lte_rrc_types.UL_CCCH,
                15: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt[0] < 15:
            # RRC Packet v13-v14
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                3: util.gsmtap_lte_rrc_types.MCCH,
                4: util.gsmtap_lte_rrc_types.PCCH,
                5: util.gsmtap_lte_rrc_types.DL_CCCH,
                6: util.gsmtap_lte_rrc_types.DL_DCCH,
                7: util.gsmtap_lte_rrc_types.UL_CCCH,
                8: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt[0] < 19:
            # RRC Packet v15-v18
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                3: util.gsmtap_lte_rrc_types.MCCH,
                5: util.gsmtap_lte_rrc_types.PCCH,
                6: util.gsmtap_lte_rrc_types.DL_CCCH,
                7: util.gsmtap_lte_rrc_types.DL_DCCH,
                8: util.gsmtap_lte_rrc_types.UL_CCCH,
                9: util.gsmtap_lte_rrc_types.UL_DCCH
            }
        elif pkt[0] == 19:
            # RRC Packet v19
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                3: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                6: util.gsmtap_lte_rrc_types.MCCH,
                7: util.gsmtap_lte_rrc_types.PCCH,
                8: util.gsmtap_lte_rrc_types.DL_CCCH,
                9: util.gsmtap_lte_rrc_types.DL_DCCH,
                10: util.gsmtap_lte_rrc_types.UL_CCCH,
                11: util.gsmtap_lte_rrc_types.UL_DCCH,
                45: util.gsmtap_lte_rrc_types.BCCH_BCH_NB,
                46: util.gsmtap_lte_rrc_types.BCCH_DL_SCH_NB,
                47: util.gsmtap_lte_rrc_types.PCCH_NB,
                48: util.gsmtap_lte_rrc_types.DL_CCCH_NB,
                49: util.gsmtap_lte_rrc_types.DL_DCCH_NB,
                50: util.gsmtap_lte_rrc_types.UL_CCCH_NB,
                51: util.gsmtap_lte_rrc_types.UL_DCCH_NB
            }
        elif pkt[0] == 20:
            # RRC Packet v20
            rrc_subtype_map = {
                1: util.gsmtap_lte_rrc_types.BCCH_BCH,
                2: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                4: util.gsmtap_lte_rrc_types.MCCH,
                5: util.gsmtap_lte_rrc_types.PCCH,
                6: util.gsmtap_lte_rrc_types.DL_CCCH,
                7: util.gsmtap_lte_rrc_types.DL_DCCH,
                8: util.gsmtap_lte_rrc_types.UL_CCCH,
                9: util.gsmtap_lte_rrc_types.UL_DCCH,
                54: util.gsmtap_lte_rrc_types.BCCH_BCH_NB,
                55: util.gsmtap_lte_rrc_types.BCCH_DL_SCH_NB,
                56: util.gsmtap_lte_rrc_types.PCCH_NB,
                57: util.gsmtap_lte_rrc_types.DL_CCCH_NB,
                58: util.gsmtap_lte_rrc_types.DL_DCCH_NB,
                59: util.gsmtap_lte_rrc_types.UL_CCCH_NB,
                61: util.gsmtap_lte_rrc_types.UL_DCCH_NB
            }

        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        if not (subtype in rrc_subtype_map.keys()):
            print("Unknown RRC subtype 0x%02x for RRC packet version 0x%02x" % (subtype, pkt[0]))
            util.xxd(pkt)
            return 
        
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_RRC,
            arfcn = earfcn,
            frame_number = sfn,
            sub_type = rrc_subtype_map[subtype],
            sub_slot = subfn,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + msg_content, radio_id)

    def parse_lte_nas(self, pkt_ts, pkt, radio_id, plain = False):
        # XXX: Qualcomm does not provide RF information on NAS-EPS
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        earfcn = self.lte_last_earfcn_dl[radio_id]

        msg_content = pkt[4:]
        gsmtap_hdr = util.create_gsmtap_header(
            version = 3,
            payload_type = util.gsmtap_type.LTE_NAS,
            arfcn = earfcn,
            sub_type = 0 if plain else 1,
            device_sec = ts_sec,
            device_usec = ts_usec)

        self.writeCP(gsmtap_hdr + msg_content, radio_id)

    def parse_ip(self, pkt_ts, pkt, radio_id):
        # instance, protocol, ifname, R, FBit, Direction, LBit, seqn, segn, fin_seg, data
        proto_hdr = struct.unpack('<BBBBHH', pkt[0:8])
        # pkt[0] = instance
        # pkt[1] = protocol (0x01 = IP)
        # pkt[2] = ifnameid
        # pkt[3] = 0a00 0000 [a: direction, 0=RX, 1=TX]
        # pkt[4]: seqn
        # pkt[5]: segn/fin_seg (0x8000: fin_seg, 0x7fff: segn)

        ifname_id = proto_hdr[2]
        is_tx = True if (proto_hdr[3] & 0x40 == 0x40) else False
        seqn = proto_hdr[4]
        segn = proto_hdr[5] & 0x7fff
        is_fin = True if (proto_hdr[5] & 0x8000 == 0x8000) else False

        proto_data = pkt[8:]
        pkt_buf = b''

        pkt_id = (ifname_id, is_tx, seqn)
        if is_fin:
            if segn == 0:
                self.writeUP(proto_data, radio_id)
                return
            else:
                if not (pkt_id in self.pending_pkts.keys()):
                    self.writeUP(proto_data, radio_id)
                    return
                pending_pkt = self.pending_pkts.get(pkt_id)
                for x in range(segn):
                    if not (x in pending_pkt.keys()):
                        print("Warning: segment %d for data packet (%d, %s, %d) missing" % (x, ifname_id, is_tx, seqn))
                        continue
                    pkt_buf += pending_pkt[x]
                del self.pending_pkts[pkt_id]
                pkt_buf += proto_data
                self.writeUP(pkt_buf, radio_id)
        else:
            if pkt_id in self.pending_pkts.keys():
                self.pending_pkts[pkt_id][segn] = proto_data
            else:
                self.pending_pkts[pkt_id] = {segn: proto_data}

    def parse_sim(self, pkt_ts, pkt, radio_id, sim_id):
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        msg_content = pkt
        # msg[0]: length
        pos = 1
        rx_buf = b''
        tx_buf = b''

        while pos < len(msg_content):
            if msg_content[pos] == 0x10:
                # 0x10: TX (to SIM)
                tx_buf += bytes([msg_content[pos + 1]])
                pos += 2
            elif msg_content[pos] == 0x80:
                # 0x80: RX (from SIM)
                rx_buf += bytes([msg_content[pos + 1]])
                pos += 2
            elif msg_content[pos] == 0x01:
                # 0x01: Timestamp
                pos += 9
            else:
                print('Not handling unknown type 0x%02x' % msg_content[pos])
                break

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.SIM)

        if len(self.last_tx[sim_id]) == 0:
            if len(tx_buf) > 0:
                self.last_tx[sim_id] = tx_buf
                return
            else:
                self.writeCP(gsmtap_hdr + rx_buf, radio_id)
        elif len(self.last_tx[sim_id]) > 0:
            if len(rx_buf) > 0:
                self.writeCP(gsmtap_hdr + self.last_tx[sim_id] + rx_buf, radio_id)
                self.last_tx[sim_id] = b''
                return
            else:
                self.writeCP(gsmtap_hdr + self.last_tx[sim_id], radio_id)
                self.last_tx[sim_id] = b''
                self.writeCP(gsmtap_hdr + tx_buf)

    def parse_diag_log(self, pkt: "DIAG_LOG_F data without trailing CRC", radio_id = 0):
        if len(pkt) < 16:
            return

        xdm_hdr = pkt[4:16]
        xdm_hdr = struct.unpack('<HHQ', xdm_hdr) # len, ID, TS
        pkt_ts = util.parse_qxdm_ts(xdm_hdr[2])
        pkt_body = pkt[16:]

        if len(pkt_body) != (xdm_hdr[0] - 12):
            util.warning("Packet length mismatch: expected {}, got {}".format(xdm_hdr[0], len(pkt_body)))

        no_process = {
            0xB061: 'LTE MAC RACH Trigger',
            0x5226: 'GPRS MAC Signaling Message',
        }

        process = {
            # SIM
            #0x1098: lambda x, y, z: self.parse_sim(x, y, z, 0), # RUIM Debug
            #0x14CE: lambda x, y, z: self.parse_sim(x, y, z, 1), # UIM DS Data

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

            # WCDMA (3G RRC)
            0x4005: lambda x, y, z: self.parse_wcdma_search_cell_reselection(x, y, z), # WCDMA Search Cell Reselection Rank
            0x4127: lambda x, y, z: self.parse_wcdma_cell_id(x, y, z), # WCDMA Cell ID
            0x412F: lambda x, y, z: self.parse_wcdma_rrc(x, y, z), # WCDMA Signaling Messages

            # UMTS (3G NAS)
            0x713A: lambda x, y, z: self.parse_umts_ue_ota(x, y, z), # UMTS UE OTA
            0x7B3A: lambda x, y, z: self.parse_umts_ue_ota_dsds(x, y, z), # UMTS DSDS NAS Signaling Messages

            # LTE
            # LTE ML1
            0xB17F: lambda x, y, z: self.parse_lte_ml1_scell_meas(x, y, z), # LTE ML1 Serving Cell Meas and Eval
            0xB180: lambda x, y, z: self.parse_lte_ml1_ncell_meas(x, y, z), # LTE ML1 Neighbor Measurements
            0xB197: lambda x, y, z: self.parse_lte_ml1_cell_info(x, y, z), # LTE ML1 Serving Cell Info
            # LTE MAC
            #0xB061: lambda x, y, z: parse_lte_mac_rach_trigger(x, y, z), # LTE MAC RACH Trigger
            0xB062: lambda x, y, z: self.parse_lte_mac_rach_response(x, y, z), # LTE MAC RACH Response
            #0xB063: lambda x, y, z: self.parse_lte_mac_dl_block(x, y, z), # LTE MAC DL Transport Block
            #0xB064: lambda x, y, z: self.parse_lte_mac_ul_block(x, y, z), # LTE MAC UL Transport Block
            # LTE RLC
            # LTE PDCP
            #0xB0A0: lambda x, y, z: self.parse_lte_pdcp_dl_cfg(x, y, z), # LTE PDCP DL Config
            #0xB0B0: lambda x, y, z: self.parse_lte_pdcp_ul_cfg(x, y, z), # LTE PDCP UL Config
            #0xB0A1: lambda x, y, z: self.parse_lte_pdcp_dl_data(x, y, z), # LTE PDCP DL Data PDU
            #0xB0B1: lambda x, y, z: self.parse_lte_pdcp_ul_data(x, y, z), # LTE PDCP UL Data PDU
            #0xB0A2: lambda x, y, z: self.parse_lte_pdcp_dl_ctrl(x, y, z), # LTE PDCP DL Ctrl PDU
            #0xB0B2: lambda x, y, z: self.parse_lte_pdcp_ul_ctrl(x, y, z), # LTE PDCP UL Ctrl PDU
            #0xB0A3: lambda x, y, z: self.parse_lte_pdcp_dl_cip(x, y, z), # LTE PDCP DL Cipher Data PDU
            #0xB0B3: lambda x, y, z: self.parse_lte_pdcp_ul_cip(x, y, z), # LTE PDCP UL Cipher Data PDU
            0xB0A5: lambda x, y, z: self.parse_lte_pdcp_dl_srb_int(x, y, z), # LTE PDCP DL SRB Integrity Data PDU
            0xB0B5: lambda x, y, z: self.parse_lte_pdcp_ul_srb_int(x, y, z), # LTE PDCP UL SRB Integrity Data PDU
            # LTE RRC
            0xB0C1: lambda x, y, z: self.parse_lte_mib(x, y, z), # LTE RRC MIB Message
            0xB0C2: lambda x, y, z: self.parse_lte_rrc_cell_info(x, y, z), # LTE RRC Serving Cell Info
            0xB0C0: lambda x, y, z: self.parse_lte_rrc(x, y, z), # LTE RRC OTA Message
            # LTE NAS
            0xB0E0: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS ESM RX Enc
            0xB0E1: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS ESM TX Enc
            0xB0EA: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS EMM RX Enc
            0xB0EB: lambda x, y, z: self.parse_lte_nas(x, y, z, False), # NAS EMM TX Enc
            0xB0E2: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS ESM RX
            0xB0E3: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS ESM TX
            0xB0EC: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS EMM RX
            0xB0ED: lambda x, y, z: self.parse_lte_nas(x, y, z, True), # NAS EMM TX

            # Generic
            0x11EB: lambda x, y, z: self.parse_ip(x, y, z), # Protocol Services Data
        }

        if xdm_hdr[1] in process.keys():
            process[xdm_hdr[1]](pkt_ts, pkt_body, radio_id)
        elif xdm_hdr[1] in no_process.keys():
            #print("Not handling XDM Header 0x%04x (%s)" % (xdm_hdr[1], no_process[xdm_hdr[1]]))
            return
        else:
            #print("Unhandled XDM Header 0x%04x" % xdm_hdr[1])
            #util.xxd(pkt)
            return

    def parse_diag_multisim(self, pkt):
        # 98 01 00 00 | 01 00 00 00 -> Subscription ID=1
        # 98 01 00 00 | 02 00 00 00 -> Subscription ID=2
        if len(pkt) < 8:
            return

        xdm_hdr = pkt[0:8]
        xdm_hdr = struct.unpack('<BBHL', xdm_hdr) # cmd_id, unknown, dummy, subscription_id
        if xdm_hdr[3] < 1 or xdm_hdr[3] > 2:
            print("Multi radio packet, unknown_1 = {}, subscription_id = {}".format(xdm_hdr[1], xdm_hdr[3]))
            util.xxd(pkt)
        pkt_body = pkt[8:]

        self.parse_diag(pkt_body, hdlc_encoded=False, check_crc=False, 
                radio_id = (xdm_hdr[3] - 1))

__entry__ = QualcommParser

def name():
    return 'qualcomm'

def shortname():
    return 'qc'

