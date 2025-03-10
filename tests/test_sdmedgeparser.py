#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung import sdmcmd
from scat.parsers.samsung.sdmedgeparser import SdmEdgeParser

class TestSdmEdgeParser(unittest.TestCase):
    parser = SdmEdgeParser(parent=None, icd_ver=(6, 22))
    maxDiff = None

    def test_sdm_edge_scell_info(self):
        payload = binascii.unhexlify('ffff00000000000000000000000000000000000000000000000000000000000000000000ffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('2c003d2200080162f2200134012e060001000101000000000000000021011c1cffffffffc202')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 44, BSIC: 0x3d, MCC/MNC: 262/02, xLAC/xRAC/xCID: 134/1/2e06, RxLev: 34 (RSSI: -76)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('04003f1e00060162f220014101291b0001000101000000000000000021021a1affffffffc202')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 4, BSIC: 0x3f, MCC/MNC: 262/02, xLAC/xRAC/xCID: 141/1/291b, RxLev: 30 (RSSI: -80)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('3500141c00060062f210140701bb4400010001000000000000000000210018f9ffffffffd601')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_SCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_scell_info(packet)
        expected = {'stdout': '''EDGE Serving Cell Info: ARFCN: 53, BSIC: 0x14, MCC/MNC: 262/01, xLAC/xRAC/xCID: 1407/1/bb44, RxLev: 28 (RSSI: -82)'''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_ncell_info(self):
        payload = binascii.unhexlify('067300ff35f9f9ffffffff00000000000000ff7600ff28f9f9ffffffff00000000000000ff5400ff26f9f9ffffffff00000000000000ff5200ff23f9f9ffffffff00000000000000ff4100ff1cf9f9ffffffff00000000000000ff4b00ff1df9f9ffffffff00000000000000ff0a73002954002252001f4b001e3a001d76001d41001c430018380018350016000000005ce79b417c061d43fd061d4311071d4300068114620000002875e44600204000020001000000000020282543060100001e0000007c426a413b5936417c426a417c000f1200060062f210140601418d0001000100000200')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_ncell_info(packet)
        expected = {'stdout': '''EDGE Neighbor Cell Info: Identified: 6, Neighbor: 10
EDGE Neighbor Cell Info: Identified Cell 0: ARFCN: 115, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 53 (RSSI: -57)
EDGE Neighbor Cell Info: Identified Cell 1: ARFCN: 118, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 40 (RSSI: -70)
EDGE Neighbor Cell Info: Identified Cell 2: ARFCN: 84, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 38 (RSSI: -72)
EDGE Neighbor Cell Info: Identified Cell 3: ARFCN: 82, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 35 (RSSI: -75)
EDGE Neighbor Cell Info: Identified Cell 4: ARFCN: 65, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 28 (RSSI: -82)
EDGE Neighbor Cell Info: Identified Cell 5: ARFCN: 75, MCC/MNC: 000/000, xLAC: 0, C1: -7, C2: -7, C31: -1, C32: -1, GPRS RA Colour: -1, RxLev: 29 (RSSI: -81)
EDGE Neighbor Cell Info: Neighbor Cell 0: ARFCN: 115, RxLev: 41 (RSSI: -69)
EDGE Neighbor Cell Info: Neighbor Cell 1: ARFCN: 84, RxLev: 34 (RSSI: -76)
EDGE Neighbor Cell Info: Neighbor Cell 2: ARFCN: 82, RxLev: 31 (RSSI: -79)
EDGE Neighbor Cell Info: Neighbor Cell 3: ARFCN: 75, RxLev: 30 (RSSI: -80)
EDGE Neighbor Cell Info: Neighbor Cell 4: ARFCN: 58, RxLev: 29 (RSSI: -81)
EDGE Neighbor Cell Info: Neighbor Cell 5: ARFCN: 118, RxLev: 29 (RSSI: -81)
EDGE Neighbor Cell Info: Neighbor Cell 6: ARFCN: 65, RxLev: 28 (RSSI: -82)
EDGE Neighbor Cell Info: Neighbor Cell 7: ARFCN: 67, RxLev: 24 (RSSI: -86)
EDGE Neighbor Cell Info: Neighbor Cell 8: ARFCN: 56, RxLev: 24 (RSSI: -86)
EDGE Neighbor Cell Info: Neighbor Cell 9: ARFCN: 53, RxLev: 22 (RSSI: -88)'''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_3g_ncell_info(self):
        payload = binascii.unhexlify('00000000a843c745989153645c99d5420f0000000200000054b6c5455003c84279181642000000002c003d2200080162f2200134989153647d02000000000000420000004838e4')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_3G_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_3g_ncell_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0a542a4f01015a3c542a2500016bf0542a4000016bf0542a6700016bf0542a7100016bf0542ac300016bf0542ad900016bf0542aef00016bf0542afa00016bf0542a0501016bf0')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_3G_NCELL_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_3g_ncell_info(packet)
        expected = {'stdout': '''EDGE 3G Neighbor Cell Info: 10 Cells
NCell 0: UARFCN: 10836, PSC: 335, RSSI: 1, RSCP: -90, Ec/No: -6.0
NCell 1: UARFCN: 10836, PSC: 37, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 2: UARFCN: 10836, PSC: 64, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 3: UARFCN: 10836, PSC: 103, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 4: UARFCN: 10836, PSC: 113, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 5: UARFCN: 10836, PSC: 195, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 6: UARFCN: 10836, PSC: 217, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 7: UARFCN: 10836, PSC: 239, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 8: UARFCN: 10836, PSC: 250, RSSI: 1, RSCP: -107, Ec/No: -24.0
NCell 9: UARFCN: 10836, PSC: 261, RSSI: 1, RSCP: -107, Ec/No: -24.0'''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_handover_info(self):
        payload = binascii.unhexlify('000000000000000000000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000000000000000001000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_info(packet)
        expected = {'stdout': ''}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_handover_history_info(self):
        payload = binascii.unhexlify('ffffffff44291501')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_HANDOVER_HISTORY_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_handover_history_info(packet)
        expected = {'stdout': 'EDGE Handover History Info: UARFCN: 10564/PSC: 277'}
        self.assertDictEqual(result, expected)

    def test_sdm_edge_meas_info(self):
        payload = binascii.unhexlify('4400320011000f0000000f00000000003a002d00020021000000340020000900000000003f00ff000100925302000b00ff0001007e4329004e00ff000800010000004500ff0002007c0027004300ff0001006f1c27004d003a000100551f0000ffffff001d00d3470d00')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN: 68, BSIC: 0x32, RxLev: 17 (RSSI: -93), TxLev: 0
EDGE Measurement Info (Neighbor Cell): ARFCN: 58, BSIC: 0x2d, RxLev: 2 (RSSI: -108)
EDGE Measurement Info (Neighbor Cell): ARFCN: 52, BSIC: 0x20, RxLev: 9 (RSSI: -101)
EDGE Measurement Info (Neighbor Cell): ARFCN: 63, BSIC: 0x3f, RxLev: 1 (RSSI: -109)
EDGE Measurement Info (Neighbor Cell): ARFCN: 11, BSIC: 0x3f, RxLev: 1 (RSSI: -109)
EDGE Measurement Info (Neighbor Cell): ARFCN: 78, BSIC: 0x3f, RxLev: 8 (RSSI: -102)
EDGE Measurement Info (Neighbor Cell): ARFCN: 69, BSIC: 0x3f, RxLev: 2 (RSSI: -108)
EDGE Measurement Info (Neighbor Cell): ARFCN: 67, BSIC: 0x3f, RxLev: 1 (RSSI: -109)
EDGE Measurement Info (Neighbor Cell): ARFCN: 77, BSIC: 0x3a, RxLev: 1 (RSSI: -109)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('350014002100000000000000000000003b0018001a00756407004b00ff001300756407003900ff001400000000003e00ff000c00571108003300ff000e00756407004200ff000e000100000035001400220075640700ffffff00000000000000ffffff00000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN: 53, BSIC: 0x14, RxLev: 33 (RSSI: -77), TxLev: 0
EDGE Measurement Info (Neighbor Cell): ARFCN: 59, BSIC: 0x18, RxLev: 26 (RSSI: -84)
EDGE Measurement Info (Neighbor Cell): ARFCN: 75, BSIC: 0x3f, RxLev: 19 (RSSI: -91)
EDGE Measurement Info (Neighbor Cell): ARFCN: 57, BSIC: 0x3f, RxLev: 20 (RSSI: -90)
EDGE Measurement Info (Neighbor Cell): ARFCN: 62, BSIC: 0x3f, RxLev: 12 (RSSI: -98)
EDGE Measurement Info (Neighbor Cell): ARFCN: 51, BSIC: 0x3f, RxLev: 14 (RSSI: -96)
EDGE Measurement Info (Neighbor Cell): ARFCN: 66, BSIC: 0x3f, RxLev: 14 (RSSI: -96)
EDGE Measurement Info (Neighbor Cell): ARFCN: 53, BSIC: 0x14, RxLev: 34 (RSSI: -76)'''}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('350014001e00000000000000000021003b001800120000000000390004000a00e3ac00004b00ff00110047a100004900ff000d0047a100003e0005000d002c57260042000b000a00bd0b1000ffffff00000000000000ffffff00000000000000ffffff00000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_EDGE_DATA, sdmcmd.sdm_edge_data.EDGE_MEAS_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_edge_meas_info(packet)
        expected = {'stdout': '''EDGE Measurement Info (Serving Cell): ARFCN: 53, BSIC: 0x14, RxLev: 30 (RSSI: -80), TxLev: 33
EDGE Measurement Info (Neighbor Cell): ARFCN: 59, BSIC: 0x18, RxLev: 18 (RSSI: -92)
EDGE Measurement Info (Neighbor Cell): ARFCN: 57, BSIC: 0x04, RxLev: 10 (RSSI: -100)
EDGE Measurement Info (Neighbor Cell): ARFCN: 75, BSIC: 0x3f, RxLev: 17 (RSSI: -93)
EDGE Measurement Info (Neighbor Cell): ARFCN: 73, BSIC: 0x3f, RxLev: 13 (RSSI: -97)
EDGE Measurement Info (Neighbor Cell): ARFCN: 62, BSIC: 0x05, RxLev: 13 (RSSI: -97)
EDGE Measurement Info (Neighbor Cell): ARFCN: 66, BSIC: 0x0b, RxLev: 10 (RSSI: -100)'''}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
