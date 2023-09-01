#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung.sdmlteparser import SdmLteParser
from scat.parsers.samsung import sdmcmd

class TestSdmLteParser(unittest.TestCase):
    parser = SdmLteParser(parent=None, icd_ver=(6, 34))

    def test_sdm_lte_phy_cell_info(self):
        self.parser.icd_ver = (4, 128)
        payload = binascii.unhexlify('7f3c0000390087ffa002020b418b35d0af0000000000000e067b010000ecc850fb14370000d007000001000e0615010000bc1bcc290000a406000000007e')
        result = self.parser.sdm_lte_phy_cell_info(payload)
        expected = 'LTE PHY Cell Info: EARFCN 1550, PCI 379, PLMN 45008, RSRP: -141.00, RSRQ: -20.00\nLTE PHY Cell Info: NCell 0: EARFCN 1550, PCI 277, RSRP: -107.00, RSRQ: -17.00'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('7f290000260020ffa00202f7f42335d0af0000000000000e067b0100007ce370fea028000078050000007e')
        result = self.parser.sdm_lte_phy_cell_info(payload)
        expected = 'LTE PHY Cell Info: EARFCN 1550, PCI 379, PLMN 45008, RSRP: -104.00, RSRQ: -14.00'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('7f2900002600265ca00202f15b1b22ceaf00000000000032000b0000005ce084036829000058020000007e')
        result = self.parser.sdm_lte_phy_cell_info(payload)
        expected = 'LTE PHY Cell Info: EARFCN 50, PCI 11, PLMN 45006, RSRP: -106.00, RSRQ: -6.00'
        self.assertEqual(result['stdout'], expected)

        self.parser.icd_ver = (6, 34)
        payload = binascii.unhexlify('ceaf000000000000640000000b00000050e21405d8270000e803000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_PHY_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_phy_cell_info(packet)
        expected = 'LTE PHY Cell Info: EARFCN 100, PCI 11, PLMN 45006, RSRP: -102.00, RSRQ: -10.00'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('ceaf000000000000640000000b00000018e37805d8270000e80300000102ea0b00000b0000007017c4220000840300000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_PHY_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_phy_cell_info(packet)
        expected = 'LTE PHY Cell Info: EARFCN 100, PCI 11, PLMN 45006, RSRP: -102.00, RSRQ: -10.00\nLTE PHY Cell Info: NCell 0 (Type 2): ARFCN 3050, PCI 11, RSRP: -89.00, RSRQ: -9.00'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_l2_rach_info(self):
        self.parser.icd_ver = (4, 96)
        payload = binascii.unhexlify('7f1a00001700f308a1223a4dd70803fffffefff4ff95ea0200f4ff7e')
        result = self.parser.sdm_lte_l2_rnti_info(payload)
        expected = {'stdout': 'LTE L2 RNTI Info: SI: 0xffff P: 0xfffe TC: 0xfff4 C: 0xea95 RA: 0x2 0xfff4'}
        self.assertDictEqual(result, expected)

    def test_sdm_lte_rrc_serving_cell(self):
        self.parser.icd_ver = (4, 96)
        payload = binascii.unhexlify('7f2000001d00fe5ba0025092190c22110692000100000000000000ceaf000090017e')
        result = self.parser.sdm_lte_rrc_serving_cell(payload)
        expected = 'LTE RRC Serving Cell: xTAC/xCID 9001/920611, PLMN 45006'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_rrc_state(self):
        self.parser.icd_ver = (6, 34)
        payload = binascii.unhexlify('7f0f00000c002bffa00251f4c3882e007e')
        result = self.parser.sdm_lte_rrc_state(payload)
        expected = 'LTE RRC State: IDLE'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('7f0f00000c0033ffa00251de00892e017e')
        result = self.parser.sdm_lte_rrc_state(payload)
        expected = 'LTE RRC State: CONNECTING'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('7f0f00000c0050ffa00251de8b892e027e')
        result = self.parser.sdm_lte_rrc_state(payload)
        expected = 'LTE RRC State: CONNECTED'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('7f0f00000c0050ffa00251de8b892e037e')
        result = self.parser.sdm_lte_rrc_state(payload)
        expected = 'LTE RRC State: UNKNOWN'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_rrc_ota_packet(self):
        # PCCH
        self.parser.icd_ver = (6, 34)
        payload = binascii.unhexlify('7f1900001600bbffa00252701ebd2f0100070040031e080597e07e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000600000040031e080597e0')]}
        self.assertDictEqual(result, expected)
        # BCCH DL SCH
        payload = binascii.unhexlify('7f1b0000180061ffa002529ca0892e03000900001101a8f200034f217e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d00000000000000000005000000001101a8f200034f21')]}
        self.assertDictEqual(result, expected)
        # UL CCCH
        payload = binascii.unhexlify('7f180000150034ffa002523f10892e0001060051793604aaa67e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000200000051793604aaa6')]}
        self.assertDictEqual(result, expected)
        # DL CCCH
        payload = binascii.unhexlify('7f2b000028004fffa00252de79892e0000190070129813fd94049b7065972ae10c3ece0587600250d08c43007e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000000000070129813fd94049b7065972ae10c3ece0587600250d08c4300')]}
        self.assertDictEqual(result, expected)
        # UL DCCH
        payload = binascii.unhexlify('7f1f00001c0043ffa00252d1cbd72f04010d00480144fd96b7b0e7fcfc5a61607e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d00000000000000000003000000480144fd96b7b0e7fcfc5a6160')]}
        self.assertDictEqual(result, expected)
        # DL DCCH
        payload = binascii.unhexlify('7f2200001f0044ffa002526d4fd82f040010002206005139404663f96ceb25e77880187e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d000000000000000000010000002206005139404663f96ceb25e7788018')]}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()