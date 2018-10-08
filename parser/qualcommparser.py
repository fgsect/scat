#!/usr/bin/python3
# coding: utf8
import util
import usb
import struct
import calendar, datetime

class QualcommParser:
    def __init__(self):
        self.gsm_last_cell_id = 0
        self.gsm_last_arfcn = 0

        self.umts_last_cell_id = 0
        self.umts_last_uarfcn_dl = 0
        self.umts_last_uarfcn_ul = 0

        self.lte_last_cell_id = 0
        self.lte_last_earfcn_dl = 0
        self.lte_last_earfcn_ul = 0
        self.lte_last_earfcn_tdd = 0
        self.lte_last_sfn = 0
        self.lte_last_tx_ant = 0
        self.lte_last_bw_dl = 0
        self.lte_last_bw_ul = 0
        self.lte_last_band_ind = 0
        self.lte_last_tcrnti = 1

        self.handler = None
        self.writerCPUP = None

        self.all_messages = False

        self.pending_pkts = dict()

        self.last_tx = [b'', b'']
        self.last_rx = [b'', b'']

        self.name = 'qualcomm'
        self.shortname = 'qc'

    def setHandler(self, handler):
        self.handler = handler

    def setWriter(self, writerCPUP):
        self.writerCPUP = writerCPUP

    def setParameter(self, params):
        for x in params:
            if x == 'all':
                self.all_messages = params[x]
        pass

    def init_diag(self):
        print('-------- initialize diag --------')
        # DIAG Disable?
        self.handler.write(util.generate_packet(b'\x60\x00'))

        buf = self.handler.read(0x100)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_1))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_2))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_3))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_4))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_5))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_6))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.log_config_7))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_1))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_2))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_3))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_4))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_5))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_6))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_7))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_8))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_9))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_10))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_11))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_12))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_13))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_14))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_15))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_16))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_17))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_18))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_19))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_20))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_21))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_22))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(util.emr_23))
        buf = self.handler.read(0x1000)
        buf = util.unwrap(buf)
        util.xxd(buf)

    def prepare_diag(self):
        print('-------- start diag --------')
        # DIAG Enable
        self.handler.write(util.generate_packet(b'\x60\x01'))

        buf = self.handler.read(0x100)
        buf = util.unwrap(buf)
        util.xxd(buf)

        if self.all_messages:
            self.handler.write(util.generate_packet(util.emr_config_1))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_2))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_3))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_4))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_5))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_6))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_7))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_8))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_9))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_10))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_11))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_12))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_13))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_14))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_15))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_16))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_17))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_18))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_19))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_20))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_21))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_22))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.emr_config_23))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_1x_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_wcdma_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_gsm_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_umts_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_dtv_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_lte_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_tdscdma_all))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)
        else:
            self.handler.write(util.generate_packet(util.log_enable_ip))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_wcdma))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_gsm))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_umts))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

            self.handler.write(util.generate_packet(util.log_enable_lte))
            buf = self.handler.read(0x1000)
            buf = util.unwrap(buf)
            util.xxd(buf)

    def parse_diag(self, pkt, wrapped = False, parse_ts = False):
        # Should contain DIAG command and CRC16
        # pkt's trailing 0x7E was stripped, and 0x7D are not unescaped
        if len(pkt) < 3:
            return

        if not wrapped:
            pkt = util.unwrap(pkt)

        if pkt[0] == 0x10:
            pass
        elif pkt[0] == 0x60:
            # TODO: handle event packets
            return
        else:
            print("Not parsing non-Log packet %02x" % pkt[0])
            util.xxd(pkt)
            return

        dm_pkt_len = pkt[2] | (pkt[3] << 8)

        if (4 + dm_pkt_len + 2) != len(pkt):
            util.warning("length mismatch. Possible lack of CRC.")

        crc = util.dm_crc16(pkt[:-2])
        crc_pkt = (pkt[-1] << 8) | pkt[-2]
        if crc != crc_pkt:
            util.warning("CRC mismatch: expected %04x, got %04x" % (crc, crc_pkt))
            util.xxd(pkt)

        if pkt[0] == 0x10:
            sock_content = self.parse_diag_log(pkt)
            if len(sock_content) <= 0:
                return
            if parse_ts:
                ts = struct.unpack('<Q', pkt[10:16] + b'\x00\x00')[0]
                ts = util.parse_qxdm_ts(ts)
                self.writerCPUP.write_cp(sock_content, ts)
            else:
                self.writerCPUP.write_cp(sock_content)

    def run_diag(self):
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

        except KeyboardInterrupt:
            return

    def run_diag_qmdl(self, writer_qmdl):
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
                    writer_qmdl.write_gsmtap(pkt + b'\x7e')

        except KeyboardInterrupt:
            return

    def stop_diag(self):
        print('-------- stop diag --------')
        # DIAG Disable
        self.handler.write(util.generate_packet(b'\x60\x00'))

        buf = self.handler.read(0x100)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(b'\x73\x00\x00\x00\x00\x00\x00\x00'))
        buf = self.handler.read(0x100)
        buf = util.unwrap(buf)
        util.xxd(buf)

        self.handler.write(util.generate_packet(b'\x7d\x05\x00\x00\x00\x00\x00\x00'))
        buf = self.handler.read(0x100)
        buf = util.unwrap(buf)
        util.xxd(buf)

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
                self.parse_diag(pkt, wrapped = True, parse_ts = True)
                buf = buf[pkt_len:]

                if len(buf) < 2:
                    break
                pkt_len = struct.unpack('<H', buf[0:2])[0]

            oldbuf = buf

    def read_dump(self):
        while self.handler.file_available:
            print("Reading from %s" % self.handler.fname)
            if self.handler.fname.find('.qmdl') > 0:
                self.run_diag()
            elif self.handler.fname.find('.dlf') > 0:
                self.parse_dlf()
            else:
                print('Unknown baseband dump type, assuming QMDL')
                self.run_diag()
            self.handler.open_next_file()

    # GSM

    def parse_gsm_fcch(self, xdm_hdr, pkt):
        arfcn_band = (pkt[17] << 8) | pkt[16]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        self.gsm_last_arfcn = arfcn

        return b''

    def parse_gsm_sch(self, xdm_hdr, pkt):
        return self.parse_gsm_fcch(xdm_hdr, pkt)

    def parse_gsm_l1_new_burst_metric(self, xdm_hdr, pkt):
        version = pkt[16]
        if pkt[16] == 4: # Version 4
            chan = pkt[17]
            i = 0
            while (18 + 37 * i + 2) < len(pkt):
                cell_pkt = pkt[18 + 37 * i:18 + 37 * (i + 1)]
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
                    print('2G Serving Cell New: ARFCN %s/BC %s, RxPwr %.2f' % (c_arfcn, c_band, c_rxpwr_real))
                i += 1
        else:
            print('Unsupported GSM L1 New Burst Metric version %s' % pkt[16])
        return b''

    def parse_gsm_l1_burst_metric(self, xdm_hdr, pkt):
        chan = pkt[16]
        # for each 23 bytes
        i = 0
        while (17 + 23 * i + 2) < len(pkt):
            cell_pkt = pkt[17 + 23 * i:17 + 23 * (i + 1)]
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
                print('2G Serving Cell: ARFCN %s/BC %s, RxPwr %.2f' % (c_arfcn, c_band, c_rxpwr_real))
            i += 1
        return b''

    def parse_gsm_l1_surround_cell_ba(self, xdm_hdr, pkt):
        num_cells = pkt[16]
        print('2G Cell: # cells %s' % (num_cells))
        for i in range(num_cells):
            cell_pkt = pkt[17 + 12 * i:17 + 12 * (i + 1)]
            interim = struct.unpack('<HhHLH', cell_pkt)
            s_arfcn = interim[0] & 0xfff
            s_band = (interim[0] >> 12)
            s_rxpwr = interim[1]
            s_bsic = interim[2] # TODO: correctly parse data
            s_fn_offset = interim[3]
            s_time_offset = interim[4]

            s_rxpwr_real = s_rxpwr * 0.0625
            print('Cell %s: ARFCN %s/BC %s, RxPwr %.2f' % (i, s_arfcn, s_band, s_rxpwr_real))
        return b''

    def parse_gsm_l1_serv_aux_meas(self, xdm_hdr, pkt):
        interim = struct.unpack('<hB', pkt[16:19])
        rxpwr = interim[0]
        snr_is_bad = interim[1]
        rxpwr_real = rxpwr * 0.0625
        print('2G Serving Cell Aux: RxPwr %.2f' % (rxpwr_real))

        return b''

    def parse_gsm_l1_neig_aux_meas(self, xdm_hdr, pkt):
        num_cells = pkt[16]
        print('2G Cell Aux: # cells %s' % (num_cells))
        for i in range(num_cells):
            cell_pkt = pkt[17 + 4 * i:17 + 4 * (i + 1)]
            interim = struct.unpack('<Hh', cell_pkt)
            n_arfcn = interim[0] & 0xfff
            n_band = (interim[0] >> 12)
            n_rxpwr = interim[1]

            n_rxpwr_real = n_rxpwr * 0.0625
            print('Cell %s: ARFCN %s/BC %s, RxPwr %.2f' % (i, n_arfcn, n_band, n_rxpwr_real))

        return b''

    def parse_gsm_cell_info(self, xdm_hdr, pkt):
        arfcn_band = (pkt[17] << 8) | pkt[16]
        band = (arfcn_band & 0xF000) >> 24
        arfcn = (arfcn_band & 0x0FFF)

        cell_id = (pkt[21] << 8) | pkt[20]

        self.gsm_last_arfcn = arfcn
        self.gsm_last_cell_id = cell_id

        return b''

    def parse_gsm_rr(self, xdm_hdr, pkt):
        chan_type_dir = pkt[16]
        msg_type = pkt[17]
        msg_len = pkt[18]
        l3_message = pkt[19:]

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.gsm_last_arfcn
        # 0x80: downlink
        if (chan_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = chan_type_dir & 0x7F

        # 0: DCCH, 1: BCCH, 3: CCCH, 4: SACCH
        # DCCH, SACCH requires pseudo length
        rr_channel_map = [8, util.gsmtap_channel.BCCH, 0, util.gsmtap_channel.CCCH, 0x88]
        channel_type = rr_channel_map[chan]

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

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
                util.warning('message length longer than 63 (%s)' % msg_len)
                return b''
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
                util.warning('message length longer than 63 (%s)' % msg_len)
                return b''
            lapdm_len = bytes([(msg_len << 2) | 0x01])

            l3_message = sacch_l1 + lapdm_address + lapdm_control + lapdm_len + l3_message

        # SACCH DL/Measurement Information: Short PD format
        
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.UM,         # Type (Um)
                0,                           # GSM Timeslot
                arfcn,                       # ARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                channel_type,                # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + l3_message

    def parse_gprs_mac(self, xdm_hdr, pkt):
        print("Unhandled XDM Header 0x%04x: GPRS MAC Packet" % xdm_hdr[1])

        chan_type_dir = pkt[16]
        msg_type = pkt[17]
        msg_len = pkt[18]
        l3_message = pkt[19:]

        payload_type = util.gsmtap_type.UM

        if len(l3_message) > msg_len:
            l3_message = l3_message[0:msg_len]

        arfcn = self.gsm_last_arfcn
        # 0x80: downlink
        if (chan_type_dir & 0x80) == 0x00:
            arfcn = arfcn | (1 << 14)
        chan = chan_type_dir & 0x7F

        # 3: PACCH, 4: Unknown
        channel_type = chan

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                payload_type,                # Type (Um)
                0,                           # GSM Timeslot
                arfcn,                       # ARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                channel_type,                # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return b''
        #return gsmtap_hdr + l3_message

    def parse_gprs_ota(self, xdm_hdr, pkt):
        msg_dir = pkt[16]
        msg_type = pkt[17]
        msg_len = (pkt[19] << 8) | pkt[18]
        l3_message = pkt[20:]

        arfcn = self.gsm_last_arfcn
        # 0: uplink, 1: downlink
        if (msg_dir) == 0x00:
            arfcn = arfcn | (1 << 14)

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.ABIS,       # Type (Abis - DTAP)
                0,                           # GSM Timeslot
                arfcn,                       # ARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                0,                           # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + l3_message

        return b''

    # 3G
    def parse_wcdma_search_cell_reselection(self, xdm_hdr, pkt):
        num_wcdma_cells = pkt[16]
        num_gsm_cells = pkt[17] # TODO: check if num_gsm_cells > 0

        print('3G Cell: # cells %s' % (num_wcdma_cells))
        for i in range(num_wcdma_cells):
            cell_pkt = pkt[18 + 10 * i:18 + 10 * (i + 1)]
            cell_pkt_vals = struct.unpack('<HHbhbh', cell_pkt)
            n_cell_uarfcn = cell_pkt_vals[0]
            n_cell_psc = cell_pkt_vals[1]
            n_cell_rscp = cell_pkt_vals[2]
            n_cell_rank_rscp = cell_pkt_vals[3]
            n_cell_ecio = cell_pkt_vals[4]
            n_cell_rank_ecio = cell_pkt_vals[5]
            print('Cell %s: UARFCN %s, PSC %s, RSCP %s, Ec/Io %s' % (i, n_cell_uarfcn, n_cell_psc, n_cell_rscp - 21, n_cell_ecio / 2))
        return b''

    def parse_wcdma_cell_id(self, xdm_hdr, pkt):
        if len(pkt) < 28:
            return b''

        result = struct.unpack('<LLL', pkt[16:28])
        self.umts_last_uarfcn_ul = result[0] | (1 << 14)
        self.umts_last_uarfcn_dl = result[1]
        self.umts_last_cell_id = result[2] & 0x7fff

        return b''

    def parse_wcdma_rrc(self, xdm_hdr, pkt):
        channel_type = pkt[16]
        rbid = pkt[17]
        msg_len = pkt[18] | (pkt[19] << 8)
        sib_class = -1

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
                9: util.gsmtap_umts_rrc_types.BCCH_BCH,
                10: util.gsmtap_umts_rrc_types.System_Information_Container,
                0xFE: util.gsmtap_umts_rrc_types.BCCH_BCH, # Decoded
                0xFF: util.gsmtap_umts_rrc_types.BCCH_FACH # Decoded
                }

        subtype = 0
        try:
            subtype = channel_type_map[pkt[16]]
        except KeyError:
            print("Unknown WCDMA RRC channel type %d" % pkt[16])
            util.xxd(pkt)

        arfcn = self.umts_last_uarfcn_dl
        if channel_type == 0 or channel_type == 1:
            arfcn = self.umts_last_uarfcn_ul

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

        if channel_type == 0xFE or channel_type == 0xFF or channel_type == 9:
            try:
                subtype = sib_type_map[pkt[20]]
            except KeyError:
                print("Unknown WCDMA SIB Class %d" % pkt[20])

            msg_content = pkt[21:]
        else:
            msg_content = pkt[20:]

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.UMTS_RRC,   # Type (UMTS-RRC)
                0,                           # GSM Timeslot
                arfcn,                       # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                subtype,                     # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + msg_content

    def parse_umts_ue_ota(self, xdm_hdr, pkt):
        msg_hdr = pkt[16:21]
        msg_content = pkt[21:-2]

        msg_hdr = struct.unpack('<BL', msg_hdr) # 1b direction, 4b length
        arfcn = self.umts_last_uarfcn_dl
        if msg_hdr[0] == 1:
            # Uplink
            arfcn = self.umts_last_uarfcn_ul

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        # msg_hdr[1] == L3 message length
        # Rest of content: L3 message
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.ABIS,       # Type (Abis - DTAP)
                0,                           # GSM Timeslot
                arfcn,                       # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                0,                           # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + msg_content

    # LTE

    def parse_lte_ml1_scell_meas(self, xdm_hdr, pkt):
        # Version 1b
        if pkt[16] == 5: # Version 5
            # EARFCN -> 4 bytes
            # PCI, Serv Layer Priority -> 4 bytes
            rrc_rel = pkt[17]
            earfcn = struct.unpack('<L', pkt[20:24])[0]
            pci = (pkt[24] | pkt[25] << 8) & 0x1ff
            serv_layer_priority = (pkt[24] | pkt[25] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[28:36])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[36:52])
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
                r9_data_interim = struct.unpack('<L', pkt[52:56])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                print('Unknown LTE ML1 Serving Cell Meas packet - RRC version %s' % rrc_rel)
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('LTE SCell: EARFCN %s, PCI %3s, Measured RSRP %.2f, Measured RSSI %.2f' % (earfcn, pci, real_rsrp, real_rssi))
            return b''
        elif pkt[16] == 4: # Version 4
            # Version, RRC standard release, EARFCN, PCI - Serving Layer Priority
            # Measured, Average RSRP, Measured, Average RSRQ, Measured RSSI
            # Q_rxlevmin, P_max, Max UE TX Power, S_rxlev, Num DRX S Fail
            # S Intra Searcn, S Non Intra Search, Meas Rules Updated, Meas Rules
            # R9 Info (last 4b) - Q Qual Min, S Qual, S Intra Search Q, S Non Intra Search Q
            # 04 | 01 | 00 00 | 9C 18 | D6 0A | EC C4 4E 00 | E2 24 4E 00 | FF FC E3 0F | FE D8 0A 00 | 47 AD 56 02 | 1D 31 01 00 | A2 62 41 00 
            rrc_rel = pkt[17]
            earfcn = pkt[20] | pkt[21] << 8
            pci = (pkt[22] | pkt[23] << 8) & 0x1ff
            serv_layer_priority = (pkt[22] | pkt[23] << 8) >> 9
            meas_rsrp, avg_rsrp = struct.unpack('<LL', pkt[24:32])
            meas_rsrp = meas_rsrp & 0xfff
            avg_rsrp = avg_rsrp & 0xfff

            interim_1, interim_2, interim_3, interim_4 = struct.unpack('<LLLL', pkt[32:48])
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
                r9_data_interim = struct.unpack('<L', pkt[48:52])[0]
                q_qual_min = r9_data_interim & 0x7f
                s_qual = (r9_data_interim >> 7) & 0x7f
                s_intra_search_q = (r9_data_interim >> 14) & 0x3f
                s_nonintra_search_q = (r9_data_interim >> 20) & 0x3f
            else:
                print('Unknown LTE ML1 Serving Cell Meas packet - RRC version %s' % rrc_rel)
            real_rsrp = -180 + meas_rsrp * 0.0625
            real_rssi = -110 + meas_rssi * 0.0625
            real_rsrq = -30 + meas_rsrq * 0.0625
            print('LTE SCell: EARFCN %s, PCI %3s, Measured RSRP %.2f, Measured RSSI %.2f' % (earfcn, pci, real_rsrp, real_rssi))
            return b''
        else:
            print('Unknown LTE ML1 Serving Cell Meas packet version %s' % pkt[16])
            return b''

    def parse_lte_ml1_ncell_meas(self, xdm_hdr, pkt):
        if pkt[16] == 5: # Version 5
            # EARFCN -> 4 bytes
            rrc_rel = pkt[17]
            earfcn = struct.unpack('<L', pkt[20:24])[0]
            q_rxlevmin = (pkt[24] | pkt[25] << 8) & 0x3f
            n_cells = (pkt[24] | pkt[25] << 8) >> 6
            print('LTE NCell: # cells %s' % (n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[28 + 32 * i:28 + 32 * (i + 1)]
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

                print('Neighbor cell %s: PCI %3s, RSRP %.02f, RSSI %.02f' % (i, n_pci, n_real_rsrp, n_real_rssi))

            return b''
        if pkt[16] == 4: # Version 4
            # Version, RRC standard release, EARFCN, Q_rxlevmin, Num Cells, Cell Info
            # Cell Info - PCI, Measured RSSI, Measured RSRP, Average RSRP
            #    Measured RSRQ, Average RSRQ, S_rxlev, Freq Offset
            #    Ant0 Frame Offset, Ant0 Sample Offset, Ant1 Frame Offset, Ant1 Sample Offset
            #    S_qual
            # 04 | 01 | 00 00 9C 18 | 47 00 | 83 48 E4 4D | DE A4 4C 00 | CA B4 CC 32 | B6 D8 42 03 | 00 00 | 00 00 | FF 77 33 01 | FF 77 33 01 | 22 02 01 00 
            rrc_rel = pkt[17]
            earfcn = pkt[20] | pkt[21] << 8
            q_rxlevmin = (pkt[22] | pkt[23] << 8) & 0x3f
            n_cells = (pkt[22] | pkt[23] << 8) >> 6
            print('LTE NCell: # cells %s' % (n_cells))
            for i in range(n_cells):
                n_cell_pkt = pkt[24 + 32 * i:24 + 32 * (i + 1)]
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

                print('Neighbor cell %s: PCI %3s, RSRP %.2f, RSSI %.2f' % (i, n_pci, n_real_rsrp, n_real_rssi))

            return b''
        else:
            print('Unknown LTE ML1 Neighbor Meas packet version %s' % pkt[16])
            return b''
        pass

    def parse_lte_ml1_cell_info(self, xdm_hdr, pkt):
        mib_payload = bytes([0, 0, 0])

        if pkt[16] == 1:
            # Version, DL BW, SFN, EARFCN, (Cell ID, PBCH, PHICH Duration, PHICH Resource), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 01 | 64 | A4 01 | 14 05 | 24 42 | 41 05 00 00 | D3 2D 00 00 | 80 53 3D 00 00 00 00 00 | 00 00 A4 A9 | 1D FF | 01 00 
            pkt_content = struct.unpack('<BHH', pkt[17:22])

            self.lte_last_bw_dl = pkt_content[0]
            self.lte_last_cell_id = pkt_content[1]
            self.lte_last_earfcn_dl = pkt_content[2]

            mib_payload = bytes([pkt[16+27], pkt[16+26], pkt[16+25]])
        elif pkt[16] == 2:
            # XXX: not complete
            # Version, DL BW, SFN, EARFCN, (Cell ID 9, PBCH 1, PHICH Duration 3, PHICH Resource 3), PSS, SSS, Ref Time, MIB Payload, Freq Offset, Num Antennas
            # 02 | 4B | F8 00 | 21 07 00 00 | 03 23 00 00 | 00 00 00 00 | 0F 05 00 00 | 2A BD 0B 17 00 00 00 00 | 00 00 F8 84 | 00 00 | 01 00 
            pkt_content = struct.unpack('<BHL', pkt[17:24])

            self.lte_last_bw_dl = pkt_content[0]
            self.lte_last_cell_id = pkt_content[1]
            self.lte_last_earfcn_dl = pkt_content[2]

            mib_payload = bytes([pkt[16+31], pkt[16+30], pkt[16+29]])
        else:
            print('Unknown LTE ML1 cell info packet version %s' % pkt[16])
            return b''

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond
        
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.LTE_RRC,    # Type (LTE-RRC)
                0,                           # GSM Timeslot
                self.lte_last_earfcn_dl,     # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                4,                           # Subtype (BCCH-BCH)
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + mib_payload

    def parse_lte_mac_rach_trigger(self, xdm_hdr, pkt):
        # XXX: Wireshark's GSMTAP dissector does not support PRACH preamble
        print("Unhandled XDM Header 0x%04x: LTE MAC RACH Trigger" % xdm_hdr[1])
        return b''

    def parse_lte_mac_rach_response(self, xdm_hdr, pkt):
        # 01 01 | 30 C7 | 06 | 02 | 24 00 | 01 | 00 | 01 | 07 | 1B | FF | 98 FF | 00 00 | 01 | 23 1A | 04 00 | 18 | 1C 01 00 | 07 00 | 06 | 00 46 5C 80 BD 06 48 00 00 00                                      
        msg_content = pkt[16:-2]
        mac_header = b''
        mac_body = b''
        earfcn = self.lte_last_earfcn_dl | (1 << 14)

        if msg_content[0] != 0x01:
            print('Unsupported LTE MAC RACH response packet version %02x' % msg_content[0])
            return b''

        if msg_content[1] != 0x01:
            print('More than 1 subpacket not supported: %02x' % msg_content[1])
            return b''
        
        if msg_content[4] != 0x06:
            print('Expected MAC RACH attempt subpacket, got %02x' % msg_content[4])
            return b''

        if msg_content[5] == 0x02:
            if msg_content[9] == 0x01: # RACH Failure, 0x00 == Success
                return b''
            if msg_content[11] != 0x07: # not all message present
                print('Not enough message to generate RAR')
                return b''

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

            self.lte_last_tcrnti = tc_rnti

        else:
            # TODO: RACH response v3
            print('Unsupported RACH response version %02x' % msg_content[5])
            return b''

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond
        
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.LTE_MAC,    # Type (LTE-MAC)
                0,                           # GSM Timeslot
                earfcn,                      # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                0,                           # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + mac_header + mac_body

    def parse_lte_mac_dl_block(self, xdm_hdr, pkt):
        earfcn = self.lte_last_earfcn_dl
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        if pkt[16] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved

            n_subpackets = pkt[17]
            pos = 20
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
                            rnti = self.lte_last_tcrnti

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x01, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                                3,                           # Version
                                7,                           # Header Length
                                util.gsmtap_type.LTE_MAC,    # Type (LTE-MAC)
                                0,                           # GSM Timeslot
                                earfcn,                      # EARFCN
                                0,                           # Signal dBm
                                0,                           # SNR dB
                                sfn,                         # Frame Number
                                0,                           # Subtype
                                0,                           # Antenna Number
                                subfn,                       # Subslot
                                0,                           # Reserved
                                ts_sec,
                                ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len, mac_hdr))
                        self.writerCPUP.write_cp(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, ts)
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
                            rnti = self.lte_last_tcrnti

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x01, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                                3,                           # Version
                                7,                           # Header Length
                                util.gsmtap_type.LTE_MAC,    # Type (LTE-MAC)
                                0,                           # GSM Timeslot
                                earfcn,                      # EARFCN
                                0,                           # Signal dBm
                                0,                           # SNR dB
                                sfn,                         # Frame Number
                                0,                           # Subtype
                                0,                           # Antenna Number
                                subfn,                       # Subslot
                                0,                           # Reserved
                                ts_sec,
                                ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, pmch_id, dl_tbs, rlc_pdus, padding, header_len, mac_hdr))
                        self.writerCPUP.write_cp(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, ts)
                        pos_sample += (14 + header_len)

                else:
                    print('Unexpected DL MAC Subpacket version %s' % subpkt_ver)

                pos += subpkt_size

            return b''
        else:
            print('Unknown LTE MAC DL packet version %s' % pkt[16])
            return b''

    def parse_lte_mac_ul_block(self, xdm_hdr, pkt):
        earfcn = self.lte_last_earfcn_dl | (1 << 14)
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        if pkt[16] == 1:
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

            n_subpackets = pkt[17]
            pos = 20
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
                            rnti = self.lte_last_tcrnti

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x00, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                                3,                           # Version
                                7,                           # Header Length
                                util.gsmtap_type.LTE_MAC,    # Type (LTE-MAC)
                                0,                           # GSM Timeslot
                                earfcn,                      # EARFCN
                                0,                           # Signal dBm
                                0,                           # SNR dB
                                sfn,                         # Frame Number
                                0,                           # Subtype
                                0,                           # Antenna Number
                                subfn,                       # Subslot
                                0,                           # Reserved
                                ts_sec,
                                ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len, mac_hdr))
                        self.writerCPUP.write_cp(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, ts)
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
                            rnti = self.lte_last_tcrnti

                        gsmtap_mac_hdr = struct.pack('>BBBHHHHB', 0x01, 0x00, gsmtap_rnti_type,
                                rnti, ueid, sfn, subfn, 0x01)

                        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                                3,                           # Version
                                7,                           # Header Length
                                util.gsmtap_type.LTE_MAC,    # Type (LTE-MAC)
                                0,                           # GSM Timeslot
                                earfcn,                      # EARFCN
                                0,                           # Signal dBm
                                0,                           # SNR dB
                                sfn,                         # Frame Number
                                0,                           # Subtype
                                0,                           # Antenna Number
                                subfn,                       # Subslot
                                0,                           # Reserved
                                ts_sec,
                                ts_usec)

                        #print("%d:%d %d %d %d %d %d %d %d %d[%s]" % (sfn, subfn, rnti_type, harq_id, grant, rlc_pdus, padding, bsr_event, bsr_trig, header_len, mac_hdr))
                        self.writerCPUP.write_cp(gsmtap_hdr + gsmtap_mac_hdr + mac_hdr, ts)
                        pos_sample += (14 + header_len)
                else:
                    print('Unexpected LTE MAC UL Subpacket version %s' % subpkt_ver)

                pos += subpkt_size
            return b''
        else:
            print('Unknown LTE MAC UL packet version %s' % pkt[16])
            return b''

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

    def parse_lte_pdcp_dl_srb_int(self, xdm_hdr, pkt):
        earfcn = self.lte_last_earfcn_dl
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        if pkt[16] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[17]
            pos = 20

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
                        self.writerCPUP.write_cp(b'pdcp-lte' + ws_hdr + pdcp_pdu, ts)
                        pos_sample += (20 + pdu_hdr[2])

                else:
                    print('Unexpected PDCP DL SRB Subpacket version %s' % subpkt_ver)
                    pos += subpkt_size
                    continue
            return b''
        else:
            print('Unknown PDCP DL SRB packet version %s' % pkt[16])
            return b''

    def parse_lte_pdcp_ul_srb_int(self, xdm_hdr, pkt):
        earfcn = self.lte_last_earfcn_dl | (1 << 14)
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        if pkt[16] == 1:
            # pkt[1]: Number of Subpackets
            # pkt[2:4]: Reserved
            n_subpackets = pkt[17]
            pos = 20

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
                        self.writerCPUP.write_cp(b'pdcp-lte' + ws_hdr + pdcp_pdu, ts)
                        pos_sample += (16 + pdu_hdr[2])

                else:
                    print('Unexpected PDCP UL SRB Subpacket version %s' % subpkt_ver)
                    pos += subpkt_size
                    continue
            return b''
        else:
            print('Unknown PDCP UL SRB packet version %s' % pkt[16])
            return b''

    def parse_lte_mib(self, xdm_hdr, pkt):
        msg_content = pkt[16:-2]
        # 1.4, 3, 5, 10, 15, 20 MHz - 6, 15, 25, 50, 75, 100 PRBs
        prb_to_bitval = {6: 0, 15: 1, 25: 2, 50: 3, 75: 4, 100: 5}
        mib_payload = [0, 0, 0]

        if pkt[16] == 1:
            if len(msg_content) != 9:
                return b''
            msg_content = struct.unpack('<BHHHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 01 | 00 01 | 14 05 | 54 00 | 02 | 64 

            self.lte_last_cell_id = msg_content[1]
            self.lte_last_earfcn_dl = msg_content[2]
            self.lte_last_earfcn_ul = msg_content[2] + 18000
            self.lte_last_sfn = msg_content[3]
            self.lte_last_tx_ant = msg_content[4]
            self.lte_last_bw_dl = msg_content[5]
            self.lte_last_bw_ul = msg_content[5]
        elif pkt[16] == 2:
            if len(msg_content) != 11:
                return b''
            msg_content = struct.unpack('<BHLHBB', msg_content) # Version, Physical CID, EARFCN, SFN, Tx Ant, BW
            # 02 | 03 01 | 21 07 00 00 | F8 00 | 02 | 4B 

            self.lte_last_cell_id = msg_content[1]
            self.lte_last_earfcn_dl = msg_content[2]
            self.lte_last_earfcn_ul = msg_content[2] + 18000
            self.lte_last_sfn = msg_content[3]
            self.lte_last_tx_ant = msg_content[4]
            self.lte_last_bw_dl = msg_content[5]
            self.lte_last_bw_ul = msg_content[5]
        else:
            print('Unknown LTE RRC MIB packet version %s' % pkt[16])
            util.xxd(pkt)
            return b''

        sfn4 = int(self.lte_last_sfn / 4)
        # BCCH BCH payload: DL bandwidth 3b, PHICH config (duration 1b, resource 2b), SFN 8b, Spare 10b (all zero)
        if prb_to_bitval.get(self.lte_last_bw_dl) != None:
            mib_payload[0] = (prb_to_bitval.get(self.lte_last_bw_dl) << 5) | (2 << 2) | ((sfn4 & 0b11000000) >> 6)
            mib_payload[1] = (sfn4 & 0b111111) << 2

        mib_payload = bytes(mib_payload)

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond
        
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.LTE_RRC,    # Type (LTE-RRC)
                0,                           # GSM Timeslot
                self.lte_last_earfcn_dl,     # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                4,                           # Subtype (BCCH-BCH)
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + mib_payload

    def parse_lte_rrc_cell_info(self, xdm_hdr, pkt):
        if pkt[16] == 2:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 02 | 8F 00 | 14 05 | 64 4B | 64 | 64 | 00 74 BC 01 | D6 05 | 03 00 00 00 | 06 01 | 02 01 00 00
            pkt_content = struct.unpack('<HHHBB', pkt[17:25])

            self.lte_last_cell_id = pkt_content[0]
            self.lte_last_earfcn_dl = pkt_content[1]
            self.lte_last_earfcn_ul = pkt_content[2]
            self.lte_last_bw_dl = pkt_content[3]
            self.lte_last_bw_ul = pkt_content[4]
        elif pkt[16] == 3:
            # Version, Physical CID, DL EARFCN, UL EARFCN, DL BW, UL BW, Cell ID, TAC, Band, MCC, MNC Digit/MNC, Allowed Access
            # 03 | 4D 00 | 21 07 00 00 | 71 4D 00 00 | 4B | 4B | 33 C8 B0 09 | 15 9B | 03 00 00 00 | CC 01 | 02 0B 00 00
            pkt_content = struct.unpack('<HLLBB', pkt[17:29])

            self.lte_last_cell_id = pkt_content[0]
            self.lte_last_earfcn_dl = pkt_content[1]
            self.lte_last_earfcn_ul = pkt_content[2]
            self.lte_last_bw_dl = pkt_content[3]
            self.lte_last_bw_ul = pkt_content[4]
        else:
            print('Unknown LTE RRC cell info packet version %s' % pkt[16])

        return b''

    def parse_lte_rrc(self, xdm_hdr, pkt):
        msg_hdr = b''
        msg_content = b''

        if pkt[16] == 0x08 or pkt[16] == 0x09 or pkt[16] == 0x0c or pkt[16] == 0x0f or pkt[16] == 0x13: # Version 8, 9, 0xc, 0xf, 0x13
            # 08 | 0A 72 | 01 | 0E 00 | 9C 18 00 00 | A9 33 | 06 | 00 00 00 00 | 02 00 | 2E 02
            # 09 | 0b 70 | 00 | 00 01 | 14 05 00 00 | 09 91 | 0b | 00 00 00 00 | 07 00 | 40 0b 8e c1 dd 13 b0
            # 0f | 0d 21 | 00 | 9e 00 | 14 05 00 00 | 49 8c | 05 | 00 00 00 00 | 07 00 | 40 0c 8e c9 42 89 e0
            # 0f | 0d 21 | 01 | 9e 00 | 14 05 00 00 | 00 00 | 09 | 00 00 00 00 | 1c 00 | 08 10 a5 34 61 41 a3 1c 31 68 04 40 1a 00 49 16 7c 23 15 9f 00 10 67 c1 06 d9 e0 00 fd 2d
            # 13 | 0e 22 | 00 | 0b 00 | fa 09 00 00 | 00 00 | 32 | 00 00 00 00 | 09 00 | 28 18 40 16 08 08 80 00 00
            msg_hdr = pkt[16:35] # 19 bytes
            msg_content = pkt[35:-2] # Rest of packet
            if len(msg_hdr) != 19:
                return b''

            msg_hdr = struct.unpack('<BHBHLHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1
            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl = earfcn
            self.lte_last_cell_id = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[16] == 0x06 or pkt[16] == 0x07: # Version 6 and 7
            # 06 | 09 B1 | 00 | 07 01 | 2C 07 | 25 34 | 02 | 02 00 00 00 | 12 00 | 40 49 88 05 C0 97 02 D3 B0 98 1C 20 A0 81 8C 43 26 D0 
            msg_hdr = pkt[16:33] # 17 bytes
            msg_content = pkt[33:-2] # Rest of packet
            if len(msg_hdr) != 17:
                return b''

            msg_hdr = struct.unpack('<BHBHHHBLH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len0, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl = earfcn
            self.lte_last_cell_id = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)

        elif pkt[16] == 0x02 or pkt[16] == 0x03 or pkt[16] == 0x04: # Version 2 or 4
            msg_hdr = pkt[16:29] # 13 bytes
            msg_content = pkt[29:-2] # Rest of packet
            if len(msg_hdr) != 13:
                return b''

            msg_hdr = struct.unpack('<BHBHHHBH', msg_hdr) # Version, RRC Release, RBID, Physical CID, EARFCN, SysFN/SubFN, PDUN, Len1

            p_cell_id = msg_hdr[3]
            earfcn = msg_hdr[4]
            self.lte_last_earfcn_dl = earfcn
            self.lte_last_cell_id = p_cell_id
            if msg_hdr[6] == 7 or msg_hdr[6] == 8: # Invert EARFCN for UL-CCCH/UL-DCCH
                earfcn = earfcn | 0x4000
            sfn = (msg_hdr[5] & 0xfff0) >> 4
            self.lte_last_sfn = sfn
            subfn = msg_hdr[5] & 0xf
            subtype = msg_hdr[6]
            # XXX: needs proper field for physical cell id
            sfn = sfn | (p_cell_id << 16)
        else:
            print('Unhandled LTE RRC packet version %s' % pkt[16])
            util.xxd(pkt)
            return b''

        if pkt[16] < 9:
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
        elif pkt[16] < 15:
            # RRC Packet v9-v15
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
        elif pkt[16] < 19:
            # RRC Packet v15-?
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
        else:
            # RRC Packet v19
            # Don't know about version between v15-v19
            rrc_subtype_map = {
                0x03: util.gsmtap_lte_rrc_types.BCCH_DL_SCH,
                0x2e: util.gsmtap_lte_rrc_types.BCCH_DL_SCH_NB,
                0x30: util.gsmtap_lte_rrc_types.DL_CCCH_NB,
                0x31: util.gsmtap_lte_rrc_types.DL_DCCH_NB,
                0x32: util.gsmtap_lte_rrc_types.UL_CCCH_NB,
                0x34: util.gsmtap_lte_rrc_types.UL_DCCH_NB
            }

        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond
        
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                int(util.gsmtap_type.LTE_RRC), # Type (LTE-RRC)
                0,                           # GSM Timeslot
                earfcn,                      # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                sfn,                         # Frame Number
                rrc_subtype_map[subtype],    # Subtype
                0,                           # Antenna Number
                subfn,                       # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + msg_content

    def parse_lte_nas(self, xdm_hdr, pkt, plain = False):
        # XXX: Qualcomm does not provide RF information on NAS-EPS
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond
        earfcn = self.lte_last_earfcn_dl

        uplink_xdm_hdrs = [0xB0E1, 0xB0EB, 0xB0E3, 0xB0ED]
        if xdm_hdr[1] in uplink_xdm_hdrs:
            earfcn = earfcn | 0x4000

        msg_content = pkt[20:-2]
        gsmtap_hdr = struct.pack('!BBBBHBBLBBBBQL', 
                3,                           # Version
                7,                           # Header Length
                util.gsmtap_type.LTE_NAS,    # Type (NAS-EPS)
                0,                           # GSM Timeslot
                earfcn,                      # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                0 if plain else 1,           # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0,                           # Reserved
                ts_sec,
                ts_usec)

        return gsmtap_hdr + msg_content

    def parse_ip(self, xdm_hdr, pkt):
        # instance, protocol, ifname, R, FBit, Direction, LBit, seqn, segn, fin_seg, data
        proto_hdr = struct.unpack('<BBBBHH', pkt[16:24])
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

        proto_data = pkt[24:]
        pkt_buf = b''

        pkt_id = (ifname_id, is_tx, seqn)
        if is_fin:
            if segn == 0:
                self.writerCPUP.write_up(proto_data)
                return b''
            else:
                if not (pkt_id in self.pending_pkts.keys()):
                    self.writerCPUP.write_up(proto_data)
                    return b''
                pending_pkt = self.pending_pkts.get(pkt_id)
                for x in range(segn):
                    if not (x in pending_pkt.keys()):
                        print("Warning: segment %d for data packet (%d, %s, %d) missing" % (x, ifname_id, is_tx, seqn))
                        continue
                    pkt_buf += pending_pkt[x]
                del self.pending_pkts[pkt_id]
                pkt_buf += proto_data
                self.writerCPUP.write_up(pkt_buf)
        else:
            if pkt_id in self.pending_pkts.keys():
                self.pending_pkts[pkt_id][segn] = proto_data
            else:
                self.pending_pkts[pkt_id] = {segn: proto_data}

        return b''

    def parse_sim(self, xdm_hdr, pkt, sim_id):
        ts = util.parse_qxdm_ts(xdm_hdr[3])
        ts_sec = calendar.timegm(ts.timetuple())
        ts_usec = ts.microsecond

        msg_content = pkt[16:-2]
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

        gsmtap_hdr = struct.pack('!BBBBHBBLBBBB', 
                2,                           # Version
                4,                           # Header Length
                util.gsmtap_type.SIM,        # Type (GSM SIM)
                0,                           # GSM Timeslot
                0,                           # EARFCN
                0,                           # Signal dBm
                0,                           # SNR dB
                0,                           # Frame Number
                0,                           # Subtype
                0,                           # Antenna Number
                0,                           # Subslot
                0)                           # Reserved

        if len(self.last_tx[sim_id]) == 0:
            if len(tx_buf) > 0:
                self.last_tx[sim_id] = tx_buf
                return b''
            else:
                return gsmtap_hdr + rx_buf
        elif len(self.last_tx[sim_id]) > 0:
            if len(rx_buf) > 0:
                self.writerCPUP.write_cp(gsmtap_hdr + self.last_tx[sim_id] + rx_buf)
                self.last_tx[sim_id] = b''
                return b''
            else:
                self.writerCPUP.write_cp(gsmtap_hdr + self.last_tx[sim_id])
                self.last_tx[sim_id] = b''
                return gsmtap_hdr + tx_buf

    def parse_diag_log(self, pkt):
        xdm_hdr = pkt[4:16]
        if len(xdm_hdr) != 12:
            return b''

        xdm_hdr = struct.unpack('<HHHQ', xdm_hdr + b'\x00\x00') # len, ID1, ID2, TS (6b, added 2b as quirk)

        #print(hex(xdm_hdr[1]))
        no_process = {
                0xB061: 'LTE MAC RACH Trigger',
                0x5226: 'GPRS MAC Signaling Message',
        }

        process = {
                # SIM
                0x1098: lambda x, y: self.parse_sim(x, y, 0), # RUIM Debug
                0x14CE: lambda x, y: self.parse_sim(x, y, 1), # UIM DS Data

                # GSM
                0x5065: lambda x, y: self.parse_gsm_fcch(x, y), # GSM L1 FCCH Acquisition
                0x5066: lambda x, y: self.parse_gsm_sch(x, y), # GSM L1 SCH Acquisition
                0x506C: lambda x, y: self.parse_gsm_l1_burst_metric(x, y), # GSM L1 Burst Metrics
                0x506A: lambda x, y: self.parse_gsm_l1_new_burst_metric(x, y), # GSM L1 New Burst Metrics
                0x507A: lambda x, y: self.parse_gsm_l1_serv_aux_meas(x, y), # GSM L1 Serving Auxiliary Measurments
                0x507B: lambda x, y: self.parse_gsm_l1_neig_aux_meas(x, y), # GSM L1 Neighbor Cell Auxiliary Measurments
                0x5071: lambda x, y: self.parse_gsm_l1_surround_cell_ba(x, y), # GSM Surround Cell BA List
                0x5134: lambda x, y: self.parse_gsm_cell_info(x, y), # GSM RR Cell Information
                0x512F: lambda x, y: self.parse_gsm_rr(x, y), # GSM RR Signaling Message
                #0x5226: lambda x, y: parse_gprs_mac(x, y), # GPRS MAC Signaling Message
                0x5230: lambda x, y: self.parse_gprs_ota(x, y), # GPRS SM/GMM OTA Signaling Message

                # WCDMA (3G RRC)
                0x4005: lambda x, y: self.parse_wcdma_search_cell_reselection(x, y), # WCDMA Search Cell Reselection Rank
                0x4127: lambda x, y: self.parse_wcdma_cell_id(x, y), # WCDMA Cell ID
                0x412F: lambda x, y: self.parse_wcdma_rrc(x, y), # WCDMA Signaling Messages

                # UMTS (3G NAS)
                0x713A: lambda x, y: self.parse_umts_ue_ota(x, y), # UMTS UE OTA

                # LTE
                # LTE ML1
                0xB17F: lambda x, y: self.parse_lte_ml1_scell_meas(x, y), # LTE ML1 Serving Cell Meas and Eval
                0xB180: lambda x, y: self.parse_lte_ml1_ncell_meas(x, y), # LTE ML1 Neighbor Measurements
                0xB197: lambda x, y: self.parse_lte_ml1_cell_info(x, y), # LTE ML1 Serving Cell Info
                # LTE MAC
                #0xB061: lambda x, y: parse_lte_mac_rach_trigger(x, y), # LTE MAC RACH Trigger
                0xB062: lambda x, y: self.parse_lte_mac_rach_response(x, y), # LTE MAC RACH Response
                0xB063: lambda x, y: self.parse_lte_mac_dl_block(x, y), # LTE MAC DL Transport Block
                0xB064: lambda x, y: self.parse_lte_mac_ul_block(x, y), # LTE MAC UL Transport Block
                # LTE RLC
                # LTE PDCP
                #0xB0A0: lambda x, y: self.parse_lte_pdcp_dl_cfg(x, y), # LTE PDCP DL Config
                #0xB0B0: lambda x, y: self.parse_lte_pdcp_ul_cfg(x, y), # LTE PDCP UL Config
                #0xB0A1: lambda x, y: self.parse_lte_pdcp_dl_data(x, y), # LTE PDCP DL Data PDU
                #0xB0B1: lambda x, y: self.parse_lte_pdcp_ul_data(x, y), # LTE PDCP UL Data PDU
                #0xB0A2: lambda x, y: self.parse_lte_pdcp_dl_ctrl(x, y), # LTE PDCP DL Ctrl PDU
                #0xB0B2: lambda x, y: self.parse_lte_pdcp_ul_ctrl(x, y), # LTE PDCP UL Ctrl PDU
                #0xB0A3: lambda x, y: self.parse_lte_pdcp_dl_cip(x, y), # LTE PDCP DL Cipher Data PDU
                #0xB0B3: lambda x, y: self.parse_lte_pdcp_ul_cip(x, y), # LTE PDCP UL Cipher Data PDU
                0xB0A5: lambda x, y: self.parse_lte_pdcp_dl_srb_int(x, y), # LTE PDCP DL SRB Integrity Data PDU
                0xB0B5: lambda x, y: self.parse_lte_pdcp_ul_srb_int(x, y), # LTE PDCP UL SRB Integrity Data PDU
                # LTE RRC
                0xB0C1: lambda x, y: self.parse_lte_mib(x, y), # LTE RRC MIB Message
                0xB0C2: lambda x, y: self.parse_lte_rrc_cell_info(x, y), # LTE RRC Serving Cell Info
                0xB0C0: lambda x, y: self.parse_lte_rrc(x, y), # LTE RRC OTA Message
                # LTE NAS
                0xB0E0: lambda x, y: self.parse_lte_nas(x, y, False), # NAS ESM RX Enc
                0xB0E1: lambda x, y: self.parse_lte_nas(x, y, False), # NAS ESM TX Enc
                0xB0EA: lambda x, y: self.parse_lte_nas(x, y, False), # NAS EMM RX Enc
                0xB0EB: lambda x, y: self.parse_lte_nas(x, y, False), # NAS EMM TX Enc
                0xB0E2: lambda x, y: self.parse_lte_nas(x, y, True), # NAS ESM RX
                0xB0E3: lambda x, y: self.parse_lte_nas(x, y, True), # NAS ESM TX
                0xB0EC: lambda x, y: self.parse_lte_nas(x, y, True), # NAS EMM RX
                0xB0ED: lambda x, y: self.parse_lte_nas(x, y, True), # NAS EMM TX

                # Generic
                0x11EB: lambda x, y: self.parse_ip(x, y), # Protocol Services Data
        }

        if xdm_hdr[1] in process.keys():
            return process[xdm_hdr[1]](xdm_hdr, pkt)
        elif xdm_hdr[1] in no_process.keys():
            #print("Not handling XDM Header 0x%04x (%s)" % (xdm_hdr[1], no_process[xdm_hdr[1]]))
            return b''
        else:
            print("Unhandled XDM Header 0x%04x" % xdm_hdr[1])
            #util.xxd(pkt)
            return b''

__entry__ = QualcommParser

def name():
    return 'qualcomm'

def shortname():
    return 'qc'

