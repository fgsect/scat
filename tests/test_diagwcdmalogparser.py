#!/usr/bin/env python3

import unittest
import binascii
import datetime
from collections import namedtuple

import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagwcdmalogparser import DiagWcdmaLogParser

class TestDiagWcdmaLogParser(unittest.TestCase):
    parser = DiagWcdmaLogParser(parent=None)
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    # Layer 1
    def test_parse_wcdma_cell_search(self):
        payload = binascii.unhexlify('82000000000000f1293200b6a5fff1f5ff000000000000f1293100b39effdedeff040000008000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_wcdma_item_id(diagcmd.diag_log_code_wcdma.LOG_WCDMA_SEARCH_CELL_RESELECTION_RANK_C), timestamp=0)
        result = self.parser.parse_wcdma_search_cell_reselection(pkt_header, payload, None)
        expected = '''WCDMA Search Cell: 2 3G cells, 0 2G cells
WCDMA Search Cell: 3G Cell 0: UARFCN: 10737, PSC:  50, RSCP: -95, Ec/Io: -7.50
WCDMA Search Cell: 3G Cell 1: UARFCN: 10737, PSC:  49, RSCP: -98, Ec/Io: -17.00'''
        self.assertEqual(result['stdout'], expected)

    def test_parse_wcdma_pn_search_edition_2(self):
        payload = binascii.unhexlify('05000194FE00020002000200FE00FE00A729FFFFFFFFFFFF0000010401230000CB69D018C000000000000000000000000000005C510300AC4F0300F8520300245103001854030004540300080200007800000078000000740000007100000070000000')
        payload = binascii.unhexlify('05000174FE00020002000200FE00FE00A729FFFFFFFFFFFF0000020401230000CB69D018C0000401230000565C5012C000040000000000000000000000005C510300484F0300884E03004C5103002C5203006C520300BE030000860000007E000000750000006F0000006F000000000000000000000000000000B8E502003CE6020024E8020008E302009CE3020080E50200980200007F00000078000000770000007700000076000000')

    def test_parse_wcdma_freq_scan(self):
        payload = binascii.unhexlify('01031EFE01A3FFA729')

    # Layer 2
    def test_parse_wcdma_rlc_dl_am_signaling_pdu(self):
        payload = binascii.unhexlify('0111010090000200201400')
        payload = binascii.unhexlify('011101009000020020ca00')

    def test_parse_wcdma_rlc_dl_am_control_pdu_log(self):
        payload = binascii.unhexlify('111200020020cacacacaca6eef1305080000650000051b000000b3fff0ff9cfff0ffe8fff0ffecfff0ff00000000dead00081600900241003077f5070016e400d0a70000e005ff0000ffdead00082200900244003077f5070016e400809e0000e005000000ffff0000000000000000000000dead00081600900241003077f5070016e400d0a70000e005ff0000ffdead00082200900244003077f5070016e400809e0000e005000000ffff0000000000000000000000dead000a20009001000000000000900223003077f5070016e400807e0500e0050600f00f0f00d0addead00082600900245003077f5070016e40070840000e00500000000ff0000ff00000000fd')
        # 11 | 12 00 | 02 00 20 14 dd 2b 8d 7b fd 55 02 50 20 0d 65 ff 86 02 | 00 | a8 00 | 70 80 00 00 30 00 00 00 00 00 00 00 00 00 00 00 90 1f 00 00 20 0b ee 09 80 03 68 01 80 83 00 00 10 b5 33 94 a0 8f 2b 34 80 16 9f bf f0 dc 19 6e 20 0c ef 01 80 02 a8 00 90 80 d1 00 00 00 00 00 d0 1d 00 00 00 00 01 00 00 00 55 0f 00 03 ef 09 80 03 68 01 80 83 d1 00 a0 8f 2b 34 80 16 9f bf f0 dc 19 6e d0 7a 66 c7 20 03 ef 07 80 00 f6 00 e0 80 d1 00 00 00 00 00 60 1f 00 00 00 00 01 00 00 00 7f 1e 00 01 f0 01 80 02 a8 00 30 81 00 00 00 00 00 00 40 1e 00 00 00 00 00 00 00 00 65 17 00 03 f0 09 80 03 68 01 | 80 | 83 00 | 00 80 16 9f bf f0 dc 19 6e d0 7a 66 c7 80 46 d6 55 20 0e f1 01 80 02 a8 00 80 81 00 00 00 00 00 00 e0 23 00 00 00 00 00 00 00 00 78 18 00 03 f1 09 80 03 68 01 90 83 00 00 f0 dc 19 6e d0 7a 66
        payload = binascii.unhexlify('11120002002014dd2b8d7bfd550250200d65ff860200a80070800000300000000000000000000000901f0000200bee09800368018083000010b53394a08f2b3480169fbff0dc196e200cef018002a8009080d10000000000d01d0000000001000000550f0003ef09800368018083d100a08f2b3480169fbff0dc196ed07a66c72003ef078000f600e080d10000000000601f00000000010000007f1e0001f0018002a8003081000000000000401e000000000000000065170003f009800368018083000080169fbff0dc196ed07a66c78046d655200ef1018002a8008081000000000000e023000000000000000078180003f1098003680190830000f0dc196ed07a66')

    def test_parse_wcdma_rlc_dl_pdu_cipher_packet(self):
        payload = binascii.unhexlify('0100100100000001f9fa5d800b400000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_wcdma_item_id(diagcmd.diag_log_code_wcdma.LOG_WCDMA_RLC_DL_PDU_CIPHER_PACKET_C), timestamp=0)
        result = self.parser.parse_wcdma_rlc_dl_pdu_cipher_packet(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'WCDMA RLC Cipher DL PDU: LCID: 16, CK: 0x1, Algorithm: UEA1, Message: 0x805dfaf9, Count C: 0x400b')

    def test_parse_wcdma_rlc_ul_pdu_cipher_packet(self):
        payload = binascii.unhexlify('01001000000000ff00000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_wcdma_item_id(diagcmd.diag_log_code_wcdma.LOG_WCDMA_RLC_UL_PDU_CIPHER_PACKET_C), timestamp=0)
        result = self.parser.parse_wcdma_rlc_ul_pdu_cipher_packet(pkt_header, payload, None)
        self.assertEqual(result['stdout'], '')

        payload = binascii.unhexlify('01001001000000010c400000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_wcdma_item_id(diagcmd.diag_log_code_wcdma.LOG_WCDMA_RLC_UL_PDU_CIPHER_PACKET_C), timestamp=0)
        result = self.parser.parse_wcdma_rlc_ul_pdu_cipher_packet(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'WCDMA RLC Cipher UL PDU: LCID: 16, CK: 0x1, Algorithm: UEA1, Count C: 0x400c')

    # RRC
    def test_parse_wcdma_cell_id(self):
        payload = binascii.unhexlify('f1250000a729000041852d0800000700d01802060200030f9d9c000001000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_wcdma_item_id(diagcmd.diag_log_code_wcdma.LOG_WCDMA_CELL_ID_C), timestamp=0)
        result = self.parser.parse_wcdma_cell_id(pkt_header, payload, None)
        expected = 'WCDMA Cell ID: UARFCN: 10663/9713, PSC: 397, MCC/MNC: 262/03, xLAC/xRAC/xCID: 9c9d/1/82d8541'
        self.assertEqual(result['stdout'], expected)

    def test_parse_wcdma_rrc(self):
        payload = binascii.unhexlify('84281f00a7298d01a143f686e52a22282f36928cc1852026d2519830afacda4a330614909b4944')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12, log_id=0x412f, timestamp=0)
        result = self.parser.parse_wcdma_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040c0029a700000000000008000000a143f686e52a22282f36928cc1852026d2519830afacda4a330614909b4944')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('89282a00a7298d014365010240c80ea200618385110030071ba8801819c954400c1a2d7220049e22178885e22178885e2210')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12, log_id=0x412f, timestamp=0)
        result = self.parser.parse_wcdma_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040c0029a70000000000003600000065010240c80ea200618385110030071ba8801819c954400c1a2d7220049e22178885e22178885e2210')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()