#!/usr/bin/env python3

import unittest
import binascii
from collections import namedtuple
import datetime

import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser

class TestDiagNrLogParser(unittest.TestCase):
    parser = DiagNrLogParser(parent=None)
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    # NR RRC
    def test_parse_nr_mib_info(self):
        # Version 0x3
        payload = binascii.unhexlify('030000005001c0ac05009a00003f')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 371904, PCI  336, SFN: 154, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # Version 0x20000
        payload = binascii.unhexlify('0000020050010eb005001e036a1b0c')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 372750, PCI  336, SFN: 30, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00000200dc03de93060000806a0b00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 431070, PCI  988, SFN: 512, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

    def test_parse_nr_rrc_scell_info(self):
        payload = binascii.unhexlify('040000009d02e0ca0900d6c609005a005a0000127df204000000060102010001297900004e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 641760/640726, Bandwidth 90/90 MHz, Band 78, PCI  669, xTAC/xCID 7929/4f27d1200, MCC 262, MNC 01',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('040000001a00a0a40900c492090050005000ca409b060000000006010202000094c000004e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 631968/627396, Bandwidth 80/80 MHz, Band 78, PCI   26, xTAC/xCID c094/69b40ca, MCC 262, MNC 02',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('020003000101006203d580194800222f065e630200183502000a000a00d58019480000000006010202000096c000001c00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 156510/144664, Bandwidth 10/10 MHz, Band 28, PCI  866, xTAC/xCID c096/481980d5, MCC 262, MNC 02',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # Version 0x30003
        payload = binascii.unhexlify('030003000101004b0001c83b57252230001aee0100080e02000a000a0001c83b57050000002e0103dc00008eb921004700')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 126490/134664, Bandwidth 10/10 MHz, Band 71, PCI   75, xTAC/xCID 21b98e/5573bc801, MCC 302, MNC 220',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)


    def test_parse_nr_mm_state(self):
        payload = binascii.unhexlify('0100000003000054f0800254f080a206001636ac480400a040fe')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE), timestamp=0)
        result = self.parser.parse_nr_mm_state(pkt_header, payload, None)
        expected = {'stdout': '5GMM State: 3/0/0, PLMN: 450/  8, TAC: a040fe, GUTI: 450-008-a2-006-16-0448ac36',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # Version 0x30000
        payload = binascii.unhexlify('000003000300000302220203022255c40332d6c214c00021b98e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE), timestamp=0)
        result = self.parser.parse_nr_mm_state(pkt_header, payload, None)
        expected = {'stdout': '5GMM State: 3/0/0, PLMN: 302/220, TAC: 21b98e, GUTI: 302-220-55-3c4-32-c014c2d6',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
