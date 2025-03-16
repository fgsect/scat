#!/usr/bin/env python3

from collections import namedtuple
import binascii
import calendar
import logging
import struct

import scat.util as util
import scat.parsers.qualcomm.diagcmd as diagcmd

try:
    import gi
    gi.require_version('Qmi', '1.0')
    from gi.repository import Qmi
    has_gobject = True
except ModuleNotFoundError:
    has_gobject = False
except ValueError:
    has_gobject = False

class Diag1xLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.pending_pkts = dict()

        self.last_tx = [b'', b'']
        self.last_rx = [b'', b'']
        self.ip_id = 0

        if self.parent:
            self.display_format = self.parent.display_format
            self.gsmtapv3 = self.parent.gsmtapv3
        else:
            self.display_format = 'x'
            self.gsmtapv3 = False

        i = diagcmd.diag_log_get_1x_item_id
        x = diagcmd.diag_log_code_1x
        self.process = {
            # SIM
            #0x1098: lambda x, y, z: self.parse_sim(x, y, z, 0), # RUIM Debug
            #0x14CE: lambda x, y, z: self.parse_sim(x, y, z, 1), # UIM DS Data

            # Generic
            i(x.LOG_DATA_PROTOCOL_LOGGING_C): lambda x, y, z: self.parse_ip(x, y, z), # Protocol Services Data

            # QMI
            # i(x.LOG_QMI_LINK_01_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 1, False),
            # i(x.LOG_QMI_LINK_01_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 1, True),
            # i(x.LOG_QMI_LINK_02_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 2, False),
            # i(x.LOG_QMI_LINK_02_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 2, True),
            # i(x.LOG_QMI_LINK_03_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 3, False),
            # i(x.LOG_QMI_LINK_03_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 3, True),
            # i(x.LOG_QMI_LINK_04_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 4, False),
            # i(x.LOG_QMI_LINK_04_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 4, True),
            # i(x.LOG_QMI_LINK_05_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 5, False),
            # i(x.LOG_QMI_LINK_05_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 5, True),
            # i(x.LOG_QMI_LINK_06_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 6, False),
            # i(x.LOG_QMI_LINK_06_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 6, True),
            # i(x.LOG_QMI_LINK_07_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 7, False),
            # i(x.LOG_QMI_LINK_07_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 7, True),
            # i(x.LOG_QMI_LINK_08_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 8, False),
            # i(x.LOG_QMI_LINK_08_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 8, True),
            # i(x.LOG_QMI_LINK_09_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 9, False),
            # i(x.LOG_QMI_LINK_09_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 9, True),
            # i(x.LOG_QMI_LINK_10_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 10, False),
            # i(x.LOG_QMI_LINK_10_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 10, True),
            # i(x.LOG_QMI_LINK_11_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 11, False),
            # i(x.LOG_QMI_LINK_11_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 11, True),
            # i(x.LOG_QMI_LINK_12_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 12, False),
            # i(x.LOG_QMI_LINK_12_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 12, True),
            # i(x.LOG_QMI_LINK_13_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 13, False),
            # i(x.LOG_QMI_LINK_13_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 13, True),
            # i(x.LOG_QMI_LINK_14_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 14, False),
            # i(x.LOG_QMI_LINK_14_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 14, True),
            # i(x.LOG_QMI_LINK_15_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 15, False),
            # i(x.LOG_QMI_LINK_15_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 15, True),
            # i(x.LOG_QMI_LINK_16_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 16, False),
            # i(x.LOG_QMI_LINK_16_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 16, True),
            # i(x.LOG_QMI_LINK_17_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 17, False),
            # i(x.LOG_QMI_LINK_17_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 17, True),
            # i(x.LOG_QMI_LINK_18_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 18, False),
            # i(x.LOG_QMI_LINK_18_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 18, True),
            # i(x.LOG_QMI_LINK_19_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 19, False),
            # i(x.LOG_QMI_LINK_19_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 19, True),
            # i(x.LOG_QMI_LINK_20_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 20, False),
            # i(x.LOG_QMI_LINK_20_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 20, True),
            # i(x.LOG_QMI_LINK_21_RX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 21, False),
            # i(x.LOG_QMI_LINK_21_TX_MSG_C): lambda x, y, z: self.parse_qmi_message(x, y, z, 21, True),
            i(x.LOG_QMI_CALL_FLOW_C): lambda x, y, z: self.parse_qmi_call_flow(x, y, z),
            i(x.LOG_QMI_SUPPORTED_INTERFACES_C): lambda x, y, z: self.parse_qmi_supported_interfaces(x, y, z),

            # IMS
            i(x.LOG_IMS_SIP_MESSAGE): lambda x, y, z: self.parse_sip_message(x, y, z),
        }

    def update_parameters(self, display_format, gsmtapv3):
        self.display_format = display_format
        self.gsmtapv3 = gsmtapv3

    def parse_ip(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct = namedtuple('QcDiag1xProtocolData', 'instance protocol ifnameid direction sequence_num segment_num_is_final')
        item = item_struct._make(struct.unpack('<BBBBHH', pkt_body[0:8]))
        item_data = pkt_body[8:]

        # pkt[3] = 0a00 0000 [a: direction, 0=RX, 1=TX]
        is_tx = True if (item.direction & 0x40 == 0x40) else False
        segment_num = item.segment_num_is_final & 0x7fff
        # pkt[5]: segn/fin_seg (0x8000: fin_seg, 0x7fff: segn)
        is_final_segment = True if (item.segment_num_is_final & 0x8000 == 0x8000) else False
        pkt_buf = b''
        pkt_id = (item.ifnameid, is_tx, item.sequence_num)

        if item.protocol != 0x01:
            if self.parent:
                self.parent.logger.log(logging.WARNING, "Data type {} is not IP".format(item.protocol))

        if is_final_segment:
            if segment_num == 0:
                return {'up': [item_data], 'ts': pkt_ts}
            else:
                if not (pkt_id in self.pending_pkts.keys()):
                    return {'up': [item_data], 'ts': pkt_ts}
                pending_pkt = self.pending_pkts.get(pkt_id)
                for x in range(segment_num):
                    if not (x in pending_pkt.keys()):
                        if self.parent:
                            self.parent.logger.log(logging.WARNING, "Segment {} for data packet ({}, {}, {}) missing".format(x, item.ifnameid, is_tx, item.sequence_num))
                        continue
                    pkt_buf += pending_pkt[x]
                del self.pending_pkts[pkt_id]
                pkt_buf += item_data
                return {'up': [pkt_buf], 'ts': pkt_ts}
        else:
            if pkt_id in self.pending_pkts.keys():
                self.pending_pkts[pkt_id][segment_num] = item_data
            else:
                self.pending_pkts[pkt_id] = {segment_num: item_data}

    def parse_qmi_message(self, pkt_header, pkt_body, args, qmi_port, is_tx):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond
        stdout = ''

        if not has_gobject:
            if self.parent:
                self.parent.logger.log(logging.ERROR, 'Decoding QMI message requires PyGObject and libqmi-glib package')
                return

        stdout += 'QMI Port: {}, Direction: {}, Raw data: {}'.format(qmi_port, 'TX' if is_tx else 'RX', binascii.hexlify(pkt_body).decode())
        try:
            q = Qmi.message_new_from_raw(pkt_body)
            stdout += ', {}'.format(str(q))
        except gi.repository.GLib.GError as e:
            stdout += ', error: {}'.format(e)

        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_qmi_call_flow(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        stdout = 'QMI_CALL_FLOW: {}'.format(binascii.hexlify(pkt_body).decode())
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_qmi_supported_interfaces(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        stdout = 'QMI_IFACES: {}'.format(binascii.hexlify(pkt_body).decode())
        return {'stdout': stdout, 'ts': pkt_ts}

    def parse_sim(self, pkt_header, pkt_body, args, sim_id):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        ts_sec = calendar.timegm(pkt_ts.timetuple())
        ts_usec = pkt_ts.microsecond

        msg_content = pkt_body
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
                self.parent.logger.log(logging.WARNING, 'Not handling unknown type 0x%02x' % msg_content[pos])
                break

        gsmtap_hdr = util.create_gsmtap_header(
            version = 2,
            payload_type = util.gsmtap_type.SIM)

        if len(self.last_tx[sim_id]) == 0:
            if len(tx_buf) > 0:
                self.last_tx[sim_id] = tx_buf
                return
            else:
                return {'cp': [gsmtap_hdr + rx_buf], 'ts': pkt_ts}
        elif len(self.last_tx[sim_id]) > 0:
            if len(rx_buf) > 0:
                last_sim_tx = self.last_tx[sim_id] + rx_buf
                self.last_tx[sim_id] = b''
                return {'cp': [gsmtap_hdr + last_sim_tx], 'ts': pkt_ts}
            else:
                last_sim_tx = self.last_tx[sim_id]
                self.last_tx[sim_id] = b''
                return {'cp': [gsmtap_hdr + last_sim_tx, gsmtap_hdr + tx_buf], 'ts': pkt_ts}

    def parse_sip_message(self, pkt_header, pkt_body, args):
        pkt_ts = util.parse_qxdm_ts(pkt_header.timestamp)
        item_struct = namedtuple('QcDiag1xSipMessage', 'version direction has_sdp len_call_id len_pkt len_pkt_real msg_type status_code unk4')
        item = item_struct._make(struct.unpack('<BBB BHH HHL', pkt_body[0:16]))
        # direction: 0: downlink, 1: uplink
        # type: 1: REGISTER 2: INVITE 3: PRACK 5: ACK 6: BYE 7: SUBSCRIBE 8: NOTIFY 14: OPTIONS

        item_data = pkt_body[16:]
        call_id = item_data[:item.len_call_id-1]
        sip_body = item_data[item.len_call_id:item.len_call_id+item.len_pkt_real-1]

        # Wrap SIP inside user-plane UDP packet
        if item.direction == 1:
            udp_hdr = struct.pack('>HHHH', 50600, 5060, len(sip_body)+8, 0)
            ip_hdr = struct.pack('>BBHHBBBBHLL', 0x45, 0x00, len(sip_body)+28,
                self.ip_id, 0x40, 0x00, 0x40, 0x11, 0x0,
                0x0a000002, 0x0a000001
            )
        else:
            udp_hdr = struct.pack('>HHHH', 5060, 50600, len(sip_body)+8, 0)
            ip_hdr = struct.pack('>BBHHBBBBHLL', 0x45, 0x00, len(sip_body)+28,
                self.ip_id, 0x40, 0x00, 0x40, 0x11, 0x0,
                0x0a000001, 0x0a000002
            )
        self.ip_id += 1

        return {'up': [ip_hdr+udp_hdr+sip_body], 'ts': pkt_ts}
