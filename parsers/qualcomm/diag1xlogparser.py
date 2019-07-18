#!/usr/bin/env python3

from . import diagcmd
import util

import struct
import calendar, datetime
import logging

class Diag1xLogParser:
    def __init__(self, parent):
        self.parent = parent

        self.pending_pkts = dict()

        self.last_tx = [b'', b'']
        self.last_rx = [b'', b'']

        self.process = {
            # SIM
            #0x1098: lambda x, y, z: self.parse_sim(x, y, z, 0), # RUIM Debug
            #0x14CE: lambda x, y, z: self.parse_sim(x, y, z, 1), # UIM DS Data

            # Generic
            0x11EB: lambda x, y, z: self.parse_ip(x, y, z), # Protocol Services Data
        }

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
                self.parent.writer.write_up(proto_data, radio_id, pkt_ts)
                return
            else:
                if not (pkt_id in self.pending_pkts.keys()):
                    self.parent.writer.write_up(proto_data, radio_id, pkt_ts)
                    return
                pending_pkt = self.pending_pkts.get(pkt_id)
                for x in range(segn):
                    if not (x in pending_pkt.keys()):
                        self.parent.logger.log(logging.WARNING, "Warning: segment %d for data packet (%d, %s, %d) missing" % (x, ifname_id, is_tx, seqn))
                        continue
                    pkt_buf += pending_pkt[x]
                del self.pending_pkts[pkt_id]
                pkt_buf += proto_data
                self.parent.writer.write_up(pkt_buf, radio_id, pkt_ts)
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
                self.parent.writer.write_cp(gsmtap_hdr + rx_buf, radio_id, pkt_ts)
        elif len(self.last_tx[sim_id]) > 0:
            if len(rx_buf) > 0:
                self.parent.writer.write_cp(gsmtap_hdr + self.last_tx[sim_id] + rx_buf, radio_id, pkt_ts)
                self.last_tx[sim_id] = b''
                return
            else:
                self.parent.writer.write_cp(gsmtap_hdr + self.last_tx[sim_id], radio_id, pkt_ts)
                self.last_tx[sim_id] = b''
                self.parent.writer.write_cp(gsmtap_hdr + tx_buf, radio_id, pkt_ts)
