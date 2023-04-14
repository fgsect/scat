#!/usr/bin/env python3

import unittest
import binascii

from parsers.samsung import sdmcmd
from parsers.samsung.sdmhspaparser import SdmHspaParser

class TestSdmHspaParser(unittest.TestCase):
    parser = SdmHspaParser(parent=None, model='e5123')
    maxDiff = None

    def test_sdm_hspa_ul1_rf_info(self):
        # cmc221s:
        self.parser.model = 'cmc221s'
        payload = binascii.unhexlify('3c2a0000b4ffa8e4')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN 10812, RSSI -76.00, TxPwr -70.00'}
        self.assertDictEqual(result, expected)

        # e333:
        self.parser.model = 'e333'
        payload = binascii.unhexlify('44290000adff7cfc')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN 10564, RSSI -83.00, TxPwr -9.00'}
        self.assertDictEqual(result, expected)

        # e355:
        self.parser.model = 'e355'
        payload = binascii.unhexlify('3c2a4f01202a2d3b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN 10812, PSC 335, RSSI -69.00, Ec/No -3.50, RSCP -71.00, TxPwr -12.00'}
        self.assertDictEqual(result, expected)

        # e5123
        self.parser.model = 'e5123'
        payload = binascii.unhexlify('ea0bd501162e2547')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN 3050, PSC 469, RSSI -79.00, Ec/No -1.50, RSCP -79.00, TxPwr 0.00'}
        self.assertDictEqual(result, expected)

    def test_sdm_hspa_ul1_serving_cell(self):
        # e5300
        payload = binascii.unhexlify('d501c6ff0000fdff5000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_SERV_CELL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_serving_cell(packet)
        expected = {'stdout': 'HSPA UL1 Serving Cell: PSC 469, CPICH RSCP -58.00, Delta RSCP 0.00, Ec/No -3.00, DRX 80 ms'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('d501c7ff0000fcff8002')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_SERV_CELL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_serving_cell(packet)
        expected = {'stdout': 'HSPA UL1 Serving Cell: PSC 469, CPICH RSCP -57.00, Delta RSCP 0.00, Ec/No -4.00, DRX 640 ms'}
        self.assertDictEqual(result, expected)

    def test_sdm_hspa_wcdma_rrc_status(self):
        payload = binascii.unhexlify('7f1300001000c0ffa004205b942c0f00000000007e')
        # result = self.parser.sdm_hspa_wcdma_rrc_status(payload)
        # expected = {'stdout': 'WCDMA Serving Cell: UARFCN 10812/9862, MCC 450, MNC 8'}
        # self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('7f1300001000acffa0042086648c1001000500007e')
        # result = self.parser.sdm_hspa_wcdma_rrc_status(payload)
        # expected = {'stdout': 'WCDMA Serving Cell: UARFCN 10812/9862, MCC 450, MNC 8'}
        # self.assertDictEqual(result, expected)

    def test_sdm_hspa_wcdma_serving_cell(self):
        payload = binascii.unhexlify('7f1600001300e9ffa00422e6c4ec3586263c2a500408007e')
        result = self.parser.sdm_hspa_wcdma_serving_cell(payload)
        expected = {'stdout': 'WCDMA Serving Cell: UARFCN 10812/9862, MCC 450, MNC 8'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()