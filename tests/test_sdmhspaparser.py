#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung import sdmcmd
from scat.parsers.samsung.sdmhspaparser import SdmHspaParser

class TestSdmHspaParser(unittest.TestCase):
    parser = SdmHspaParser(parent=None, icd_ver = (6, 22))
    maxDiff = None

    def test_sdm_hspa_ul1_rf_info(self):
        # cmc221s:
        self.parser.icd_ver = (4, 36)
        payload = binascii.unhexlify('3c2a0000b4ffa8e4')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN: 10812, RSSI: -76.00, TxPwr: -70.00'}
        self.assertDictEqual(result, expected)

        # e333:
        self.parser.icd_ver = (4, 80)
        payload = binascii.unhexlify('44290000adff7cfc')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN: 10564, RSSI: -83.00, TxPwr: -9.00'}
        self.assertDictEqual(result, expected)

        # e355:
        self.parser.icd_ver = (5, 17)
        payload = binascii.unhexlify('3c2a4f01202a2d3b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN: 10812, PSC: 335, RSSI: -69.00, Ec/No: -3.50, RSCP: -71.00, TxPwr: -12.00'}
        self.assertDictEqual(result, expected)

        # e5123
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('ea0bd501162e2547')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_UMTS_RF_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_rf_info(packet)
        expected = {'stdout': 'HSPA UL1 RF Info: DL UARFCN: 3050, PSC: 469, RSSI: -79.00, Ec/No: -1.50, RSCP: -79.00, TxPwr: 0.00'}
        self.assertDictEqual(result, expected)

    def test_sdm_hspa_ul1_serving_cell(self):
        # e5300
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('d501c6ff0000fdff5000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_SERV_CELL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_serving_cell(packet)
        expected = {'stdout': 'HSPA UL1 Serving Cell: PSC: 469, CPICH RSCP: -58.00, Delta RSCP: 0.00, Ec/No: -3.00, DRX: 80 ms'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('d501c7ff0000fcff8002')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_SERV_CELL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_serving_cell(packet)
        expected = {'stdout': 'HSPA UL1 Serving Cell: PSC: 469, CPICH RSCP: -57.00, Delta RSCP: 0.00, Ec/No: -4.00, DRX: 640 ms'}
        self.assertDictEqual(result, expected)

    def test_hspa_ul1_intra_freq_resel(self):
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('170067008cffe8ff40008cffe8ff9d018cffe8ffce018cffe8ffc3008cffe8ff25008cffe8ffef008cffe8ff73018cffe8ff9c018cffe8ffd9008cffe8ffe3018cffe8ff70008cffe8ffd6008cffe8ffae018cffe8ff5a018cffe8ff1c018cffe8ff22018cffe8ff06018cffe8ff29018cffe8ff1a008cffe8fffa008cffe8ff65018cffe8ff45018cffe8ff6400000009240004010000004400000058f9e44193d26c4005000000232a000400000000540800000400000014000000000000005927')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTRA_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_intra_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Intra Frequency Reselection:
Measurement 0: PSC: 103, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 1: PSC: 64, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 2: PSC: 413, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 3: PSC: 462, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 4: PSC: 195, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 5: PSC: 37, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 6: PSC: 239, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 7: PSC: 371, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 8: PSC: 412, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 9: PSC: 217, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 10: PSC: 483, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 11: PSC: 112, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 12: PSC: 214, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 13: PSC: 430, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 14: PSC: 346, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 15: PSC: 284, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 16: PSC: 290, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 17: PSC: 262, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 18: PSC: 297, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 19: PSC: 26, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 20: PSC: 250, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 21: PSC: 357, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 22: PSC: 325, CPICH RSCP: -116, CPICH Ec/No: -24
Extra: 6400000009240004010000004400000058f9e44193d26c4005000000232a000400000000540800000400000014000000000000005927'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('19005a01a6ffedff67008cffe8ff05018cffe8ff40008cffe8ff9d018cffe8ffce018cffe8ffc3008cffe8ff25008cffe8ffef008cffe8ff73018cffe8ff9c018cffe8ffd9008cffe8ff70008cffe8ffae018cffe8ffd6008cffe8ff1c018cffe8ff22018cffe8fffa008cffe8ff29018cffe8ff45018cffe8ff65018cffe8ff1a008cffe8ff06018cffe8ff71008cffe8ffe3018cffe8ff4900000074f9e44193d26c4005000000232a0004000000000c0900000400000014000000000000005927')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTRA_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_intra_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Intra Frequency Reselection:
Measurement 0: PSC: 346, CPICH RSCP: -90, CPICH Ec/No: -19
Measurement 1: PSC: 103, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 2: PSC: 261, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 3: PSC: 64, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 4: PSC: 413, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 5: PSC: 462, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 6: PSC: 195, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 7: PSC: 37, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 8: PSC: 239, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 9: PSC: 371, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 10: PSC: 412, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 11: PSC: 217, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 12: PSC: 112, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 13: PSC: 430, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 14: PSC: 214, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 15: PSC: 284, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 16: PSC: 290, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 17: PSC: 250, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 18: PSC: 297, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 19: PSC: 325, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 20: PSC: 357, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 21: PSC: 26, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 22: PSC: 262, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 23: PSC: 113, CPICH RSCP: -116, CPICH Ec/No: -24
Measurement 24: PSC: 483, CPICH RSCP: -116, CPICH Ec/No: -24
Extra: 4900000074f9e44193d26c4005000000232a0004000000000c0900000400000014000000000000005927'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000000000008340045400034d5a000002c06e9bf40e9bcbc669e6ae0146c9c47150f545a7e22ea208010015dec6000000101080a5d7d5e0100017bfb00017bb701030307f3f6dfc43c07e4ff23e7425badd850d28c0484d11f7745fc978b54bda32e6360d864fe1f4427c3d634c0eaa9c935b4eba87f54381d1c3826c6ecf92834c0526d0dddae9a506ccff6609a604fd0a3695336ebe920046daf3ff6afd45d3a60203c1e04ef211c60a272cd3b5e15aab59a676f51f1f41a7c6a2570d8a39bd1ad')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTRA_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_intra_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Intra Frequency Reselection:
Extra: 00000008340045400034d5a000002c06e9bf40e9bcbc669e6ae0146c9c47150f545a7e22ea208010015dec6000000101080a5d7d5e0100017bfb00017bb701030307f3f6dfc43c07e4ff23e7425badd850d28c0484d11f7745fc978b54bda32e6360d864fe1f4427c3d634c0eaa9c935b4eba87f54381d1c3826c6ecf92834c0526d0dddae9a506ccff6609a604fd0a3695336ebe920046daf3ff6afd45d3a60203c1e04ef211c60a272cd3b5e15aab59a676f51f1f41a7c6a2570d8a39bd1ad'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00000000010000000100000000000f00f0ff0000000000000a000000020000000100000020620443020000000100030001000000010000000100000020fb12430000000000000000000000000000000000000000000000000000000001000000a0fb1243a0fd124320ff12430100f8001900f0ff0100200005001e001e00020000010000484f274400000000b42f0543390000000000000000000000c42f05433a0000000000000000000000d42f05433b00000001000000484f274400000000642c')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTRA_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_intra_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Intra Frequency Reselection:
Extra: 0000010000000100000000000f00f0ff0000000000000a000000020000000100000020620443020000000100030001000000010000000100000020fb12430000000000000000000000000000000000000000000000000000000001000000a0fb1243a0fd124320ff12430100f8001900f0ff0100200005001e001e00020000010000484f274400000000b42f0543390000000000000000000000c42f05433a0000000000000000000000d42f05433b00000001000000484f274400000000642c'''}
        self.assertDictEqual(result, expected)

    def test_hspa_ul1_inter_freq_resel(self):
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('0000203031203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030200a3e2041484f27446c617373205b3130335d2028696e74294154495f4d53475f484f27445f53494e474c455f434c49454e540000484f27440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000484f274400000000000000000000000000000000484f274404000000690000009062dc40a803000028692441b6020000504600002863dc40610000003030')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTER_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_inter_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Inter Frequency Reselection:
Extra: 203031203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030203030200a3e2041484f27446c617373205b3130335d2028696e74294154495f4d53475f484f27445f53494e474c455f434c49454e540000484f27440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000484f274400000000000000000000000000000000484f274404000000690000009062dc40a803000028692441b6020000504600002863dc40610000003030'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0100542ab701acfffeff61707320496e636f6d696e67205b373731355d204e535f53544154455f4348414e47455f494e442c2050414c20436c617373205b325d2028696e742970616c5f454d7367436c6173735f52544b5f4d5347202d3e2041544920436c617373205b3130345d2028696e74294154495f4d53475f545950455f4d554c54495f434c49454e54000000484f274400000000b8770443100300006cbd6764000000000000000010030000ffbd676400000000000000000803000000ffffff0000000000000000484f2744484f274400000000484f274404000000940000009062dc40a8030000f0672441b6020000d32003002863dc408c0000004154')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_HSPA_DATA, sdmcmd.sdm_hspa_data.HSPA_UL1_INTER_FREQ_RESEL, payload, timestamp=0x0)
        result = self.parser.sdm_hspa_ul1_inter_freq_resel(packet)
        expected = {'stdout': '''HSPA UL1 Inter Frequency Reselection:
Measurement 0: UARFCN: 10836, PSC: 439, CPICH RSCP: -84, CPICH Ec/No: -2
Extra: 61707320496e636f6d696e67205b373731355d204e535f53544154455f4348414e47455f494e442c2050414c20436c617373205b325d2028696e742970616c5f454d7367436c6173735f52544b5f4d5347202d3e2041544920436c617373205b3130345d2028696e74294154495f4d53475f545950455f4d554c54495f434c49454e54000000484f274400000000b8770443100300006cbd6764000000000000000010030000ffbd676400000000000000000803000000ffffff0000000000000000484f2744484f274400000000484f274404000000940000009062dc40a8030000f0672441b6020000d32003002863dc408c0000004154'''}
        self.assertDictEqual(result, expected)

    def test_sdm_hspa_wcdma_rrc_status(self):
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('7f1300001000c0ffa004205b942c0f00000000007e')
        result = self.parser.sdm_hspa_wcdma_rrc_status(payload)
        expected = {'stdout': 'WCDMA RRC State: RRC Release: UNKNOWN, RRC Status: DISCONNECTED, Domain: IDLE'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('7f1300001000acffa0042086648c1001000500007e')
        result = self.parser.sdm_hspa_wcdma_rrc_status(payload)
        expected = {'stdout': 'WCDMA RRC State: RRC Release: R7, RRC Status: CELL_DCH, Domain: IDLE'}
        self.assertDictEqual(result, expected)

    def test_sdm_hspa_wcdma_serving_cell(self):
        self.parser.icd_ver = (7, 2)
        payload = binascii.unhexlify('7f1600001300e9ffa00422e6c4ec3586263c2a500408007e')
        result = self.parser.sdm_hspa_wcdma_serving_cell(payload)
        expected = {'stdout': 'WCDMA Serving Cell: UARFCN: 10812/9862, MCC: 450, MNC: 8'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()