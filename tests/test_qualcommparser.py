#!/usr/bin/env python3

import unittest
import binascii
import datetime
from collections import namedtuple

from parsers.qualcomm.qualcommparser import QualcommParser

class TestQualcommParser(unittest.TestCase):
    parser = QualcommParser()
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    def test_parse_diag_version(self):
        payload = binascii.unhexlify('004e6f76202032203230323132323a31333a31324f6374203132203230323130323a30303a303073647835352e63702a09ff64003000cf')
        result = self.parser.parse_diag_version(payload)
        expected = {'stdout': 'Compile: Nov  2 2021/22:13:12, Release: Oct 12 2021/02:00:00, Chipset: sdx55.cp'}
        self.assertDictEqual(result, expected)

    def test_parse_ext_build_id(self):
        payload = binascii.unhexlify('7c010000f20c00004e010000524d35303051474c41425231314130364d34470000')
        result = self.parser.parse_diag_ext_build_id(payload)
        expected = {'stdout': 'Build ID: RM500QGLABR11A06M4G'}
        self.assertDictEqual(result, expected)



if __name__ == '__main__':
    unittest.main()
