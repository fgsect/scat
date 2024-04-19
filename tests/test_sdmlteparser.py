#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung.sdmlteparser import SdmLteParser
from scat.parsers.samsung import sdmcmd

class TestSdmLteParser(unittest.TestCase):
    parser = SdmLteParser(parent=None, icd_ver=(6, 22))

    def test_sdm_lte_phy_cell_info(self):
        self.parser.icd_ver = (4, 80)
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

        self.parser.icd_ver = (6, 22)
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

    def test_sdm_lte_l2_rnti_info(self):
        self.parser.icd_ver = (4, 60)
        payload = binascii.unhexlify('7f1a00001700f308a1223a4dd70803fffffefff4ff95ea0200f4ff7e')
        result = self.parser.sdm_lte_l2_rnti_info(payload)
        expected = {'stdout': 'LTE L2 RNTI Info: SI: 0xffff P: 0xfffe TC: 0xfff4 C: 0xea95 RA: 0x2 0xfff4'}
        self.assertDictEqual(result, expected)

    def test_sdm_lte_rrc_serving_cell(self):
        self.parser.icd_ver = (4, 60)
        payload = binascii.unhexlify('7f2000001d00fe5ba0025092190c22110692000100000000000000ceaf000090017e')
        result = self.parser.sdm_lte_rrc_serving_cell(payload)
        expected = 'LTE RRC Serving Cell: xTAC/xCID 9001/920611, PLMN 45006'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_rrc_state(self):
        self.parser.icd_ver = (6, 22)
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
        self.parser.icd_ver = (6, 22)
        payload = binascii.unhexlify('7f1900001600bbffa00252701ebd2f0100070040031e080597e07e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000600000040031e080597e0')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)

        # BCCH DL SCH
        payload = binascii.unhexlify('7f1b0000180061ffa002529ca0892e03000900001101a8f200034f217e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d00000000000000000005000000001101a8f200034f21')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)

        # UL CCCH
        payload = binascii.unhexlify('7f180000150034ffa002523f10892e0001060051793604aaa67e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000200000051793604aaa6')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)

        # DL CCCH
        payload = binascii.unhexlify('7f2b000028004fffa00252de79892e0000190070129813fd94049b7065972ae10c3ece0587600250d08c43007e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d0000000000000000000000000070129813fd94049b7065972ae10c3ece0587600250d08c4300')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)
        # UL DCCH
        payload = binascii.unhexlify('7f1f00001c0043ffa00252d1cbd72f04010d00480144fd96b7b0e7fcfc5a61607e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d00000000000000000003000000480144fd96b7b0e7fcfc5a6160')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)

        # DL DCCH
        payload = binascii.unhexlify('7f2200001f0044ffa002526d4fd82f040010002206005139404663f96ceb25e77880187e')
        result = self.parser.sdm_lte_rrc_ota_packet(payload)
        expected = {'cp': [binascii.unhexlify('02040d000000000000000000010000002206005139404663f96ceb25e7788018')],
            'layer': 'rrc'}
        self.assertDictEqual(result, expected)

    def test_sdm_lte_volte_rtp_packet(self):
        payload = binascii.unhexlify('4a00621b80fe01004001000011cbe2f5')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_RX_PACKET_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_rtp_packet(packet, 0x70)
        expected = 'LTE VoLTE RTP Packet: Dst Port: 7010, Length: 74, Header=128, PT=254, SSRC=0xf5e2cb11, Seq=1, Time=320'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('4a00961580fe0100400100003d24d539')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_TX_PACKET_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_rtp_packet(packet, 0x71)
        expected = 'LTE VoLTE RTP Packet: Dst Port: 5526, Length: 74, Header=128, PT=254, SSRC=0x39d5243d, Seq=1, Time=320'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_volte_tx_stats(self):
        payload = binascii.unhexlify('7e3d24d539961501002a0108f00400052300000000000000090c170000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_TX_OVERALL_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_tx_stats(packet)
        expected = 'LTE VoLTE TX Stats: IP: 2a01:8f0:400:523::9, Dst Port: 5526, PT=126, SSRC=0x39d5243d, 5.90s'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('00fca4c3c3ba2a00000a89dd1200000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_TX_OVERALL_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_tx_stats(packet)
        expected = 'LTE VoLTE TX Stats: IP: 10.137.221.18, Dst Port: 10938, PT=0, SSRC=0xc3c3a4fc, 0.00s'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_volte_rx_stats(self):
        payload = binascii.unhexlify('11cbe2f5621b01002a00002060f59e4f4fae585752f89406')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_RX_OVERALL_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_rx_stats(packet)
        expected = 'LTE VoLTE RX Stats: IP: 2a00:20:60f5:9e4f:4fae:5857:52f8:9406, Dst Port: 7010, SSRC=0xf5e2cb11'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('000000000000ffff00000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_RX_OVERALL_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_rx_stats(packet)
        expected = 'LTE VoLTE RX Stats: IP: Unknown IP type 65535, Dst Port: 0, SSRC=0x00000000'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_volte_tx_rtp_stats(self):
        payload = binascii.unhexlify('ac170000520000002f100000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_TX_RTP_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_tx_rtp_stats(packet)
        expected = 'LTE VoLTE TX RTP Stats: 6.06s, Num Packets: 82, Num Bytes: 4143'
        self.assertEqual(result['stdout'], expected)

        payload = binascii.unhexlify('2c0600005000000020170000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_TX_RTP_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_tx_rtp_stats(packet)
        expected = 'LTE VoLTE TX RTP Stats: 1.58s, Num Packets: 80, Num Bytes: 5920'
        self.assertEqual(result['stdout'], expected)

    def test_sdm_lte_volte_rx_rtp_stats(self):
        payload = binascii.unhexlify('0c1700002801000090550000000000000000000000000000700000009c000000a90100004a000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_LTE_DATA, sdmcmd.sdm_lte_data.LTE_VOLTE_RX_RTP_STAT_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_lte_volte_rx_rtp_stats(packet)
        expected = 'LTE VoLTE RX RTP Stats: 5.90s, Num Packets: 296, Num Bytes: 21904'
        self.assertEqual(result['stdout'], expected)

if __name__ == '__main__':
    unittest.main()