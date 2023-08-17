#!/usr/bin/env python3

import unittest
import binascii
from collections import namedtuple

from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser

class TestDiagNrLogParser(unittest.TestCase):
    parser = DiagNrLogParser(parent=None)
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    # NR RRC
    def test_parse_nr_mib_info(self):
        # Version 0x3
        payload = binascii.unhexlify('030000005001c0ac05009a00003f')
        result = self.parser.parse_nr_mib_info(None, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 371904, PCI  336, SFN: 154, SCS: 15 kHz'}
        self.assertDictEqual(result, expected)

        # Version 0x20000
        payload = binascii.unhexlify('0000020050010eb005001e036a1b0c')
        result = self.parser.parse_nr_mib_info(None, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 372750, PCI  336, SFN: 30, SCS: 15 kHz'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00000200dc03de93060000806a0b00')
        result = self.parser.parse_nr_mib_info(None, payload, None)
        expected = {'stdout': 'NR MIB: NR-ARFCN 431070, PCI  988, SFN: 512, SCS: 15 kHz'}
        self.assertDictEqual(result, expected)

    def test_parse_nr_rrc_scell_info(self):
        payload = binascii.unhexlify('040000009d02e0ca0900d6c609005a005a0000127df204000000060102010001297900004e00')
        result = self.parser.parse_nr_rrc_scell_info(None, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 641760/640726, Bandwidth 90/90 MHz, Band 78, PCI  669, xTAC/xCID 7929/4f27d1200, MCC 262, MNC 01'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('040000001a00a0a40900c492090050005000ca409b060000000006010202000094c000004e00')
        result = self.parser.parse_nr_rrc_scell_info(None, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 631968/627396, Bandwidth 80/80 MHz, Band 78, PCI   26, xTAC/xCID c094/69b40ca, MCC 262, MNC 02'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('020003000101006203d580194800222f065e630200183502000a000a00d58019480000000006010202000096c000001c00')
        result = self.parser.parse_nr_rrc_scell_info(None, payload, None)
        expected = {'stdout': 'NR RRC SCell Info: NR-ARFCN 156510/144664, Bandwidth 10/10 MHz, Band 28, PCI  866, xTAC/xCID c096/481980d5, MCC 262, MNC 02'}
        self.assertDictEqual(result, expected)

    def test_parse_nr_mm_state(self):
        payload = binascii.unhexlify('0100000003000054f0800254f080a206001636ac480400a040fe')
        result = self.parser.parse_nr_mm_state(None, payload, None)
        expected = {'stdout': '5GMM State: 3/0/0, PLMN: 450/  8, TAC: a040fe, GUTI: 450-008-a2-006-16-0448ac36'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()