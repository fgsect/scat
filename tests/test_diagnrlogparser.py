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

if __name__ == '__main__':
    unittest.main()