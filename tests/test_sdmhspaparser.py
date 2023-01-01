#!/usr/bin/env python3

import unittest
import binascii

from parsers.samsung.sdmhspaparser import SdmHspaParser
from parsers.samsung import sdmcmd

class TestSdmHspaParser(unittest.TestCase):
    parser = SdmHspaParser(parent=None)

    def test_sdm_hspa_wcdma_rrc_status(self):
        payload = binascii.unhexlify('7f1300001000c0ffa004205b942c0f00000000007e')
        payload = binascii.unhexlify('7f1300001000acffa0042086648c1001000500007e')

    def test_sdm_hspa_wcdma_serving_cell(self):
        payload = binascii.unhexlify('7f1600001300e9ffa00422e6c4ec3586263c2a500408007e')
        result = self.parser.sdm_hspa_wcdma_serving_cell(payload)
        expected = {'stdout': 'WCDMA Serving Cell: UARFCN 10812/9862, MCC 450, MNC 8'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()