#!/usr/bin/env python3

import scat.util as util

import struct
import calendar
import logging
from collections import namedtuple

class Diag1xLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.pending_pkts = dict()

        self.last_tx = [b'', b'']
        self.last_rx = [b'', b'']
        self.ip_id = 0

        self.process = {
            # SIM
            #0x1098: lambda x, y, z: self.parse_sim(x, y, z, 0), # RUIM Debug
            #0x14CE: lambda x, y, z: self.parse_sim(x, y, z, 1), # UIM DS Data

            # Generic
            0x11EB: lambda x, y, z: self.parse_ip(x, y, z), # Protocol Services Data

            # IMS
            0x156E: lambda x, y, z: self.parse_sip_message(x, y, z),
        }

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
