#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.samsung.sdmcommonparser import SdmCommonParser
from scat.parsers.samsung import sdmcmd

class TestSdmCommonParser(unittest.TestCase):
    parser = SdmCommonParser(parent=None)

    def test_sdm_common_basic_info(self):
        self.parser.icd_ver = (4, 36)
        payload = binascii.unhexlify('170003002cac6d40960268')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x0f01614f)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 1840.00 MHz/UL: 1745.00 MHz'}
        self.assertDictEqual(result, expected)

        self.parser.icd_ver = (4, 80)
        payload = binascii.unhexlify('170403002cac6d4096026841000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x057687c3)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 4, MIMO: 3, Frequency: DL: 1840.00 MHz/UL: 1745.00 MHz, Extra: 0x00000041'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('170002809dc29c808f9b951f7e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x37bd6120)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x1a7f7e1f'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('170002809dc29c808f9b95157e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x38011941)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x1a7f7e15'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('170402809dc29c808f9b957f1a0000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x3dc0198f)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 4, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x00001a7f'}
        self.assertDictEqual(result, expected)

        self.parser.icd_ver = (5, 80)
        payload = binascii.unhexlify('120501000000000000000075240096')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: WCDMA, Status: 5, MIMO: 1, Frequency: -/-, Extra: 0x96002475'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('13020000062039c060713600000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 2, MIMO: 0, Frequency: DL: 958.40 MHz/UL: 913.40 MHz, Extra: 0x00000000'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('170003c0b32e6c001e85660d0a004b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x4b000a0d'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('190000ffffffffffffffff00210000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0x00002100'}
        self.assertDictEqual(result, expected)

        self.parser.icd_ver = (6, 22)
        payload = binascii.unhexlify('12040040b9fe7fe0c6553a006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: WCDMA, Status: 4, MIMO: 0, Frequency: DL: 2147.40 MHz/UL: UARFCN 9787, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('13010080eaf74440454942006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 1, MIMO: 0, Frequency: -/-, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('1700036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 954.30 MHz/UL: 909.30 MHz, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('190000ffffffffffffffff006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaae1)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('2004036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: NR NSA, Status: 4, MIMO: 3, Frequency: DL: 954.30 MHz/UL: 909.30 MHz, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected)

        self.parser.icd_ver = (8, 0)
        payload = binascii.unhexlify('13040080056f38000000004060c0350000000000c9114700ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 4, MIMO: 0, Frequency: DL: 946.80 MHz/UL: 901.80 MHz, Extra: 0x4711c900, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('170005c0b32e6c00000000001e8566000000008600000000ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 5, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x00000086, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('190000ffffffffffffffffffffffffffffffff00b0c9df00ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0xdfc9b000, Num cells: 0'}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('200405c0b32e6c00000000001e85660000000086000000020503ffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: NR NSA, Status: 4, MIMO: 5, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x00000086, Num cells: 2 (5, 3)'}
        self.assertDictEqual(result, expected)

        self.parser.icd_ver = (9, 0)
        payload = binascii.unhexlify('170003002ca33040c814330000000000ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 816.00 MHz/UL: 857.00 MHz, Extra: 0x00000000, Num cells: 0'}
        self.assertDictEqual(result, expected)

    def test_sdm_common_signaling(self):
        # UMTS NAS
        payload = binascii.unhexlify('01ff0225000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('020402000000000000000000000000000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('01ff0102000803')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('020402004000000000000000000000000803')],
        }
        self.assertDictEqual(result, expected)

        # GPRS MAC DL
        payload = binascii.unhexlify('21ff02170047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'mac',
            'cp': [binascii.unhexlify('0204010000000000000000000b00000047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')],
        }
        self.assertDictEqual(result, expected)
        # GPRS MAC UL
        payload = binascii.unhexlify('21ff01170040212b771021ec118acacacacacacacacacacacacacaca')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'mac',
            'cp': [binascii.unhexlify('0204010040000000000000000b00000040212b771021ec118acacacacacacacacacacacacacaca')],
        }
        self.assertDictEqual(result, expected)

        # GSM RR
        # RR short PD = SACCH
        # payload = binascii.unhexlify('20ff0215001402580cc02a9441d0ec7931dba0c58c2b2b2b2b2b')
        # packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_DATA_SIGNALING_INFO, payload, timestamp=0x0)
        # result = self.parser.sdm_common_signaling(packet)
        # expected = {'cp': [binascii.unhexlify('')]}
        # self.assertDictEqual(result, expected)

        # RR dl with pseudolength = CCCH
        payload = binascii.unhexlify('20ff010300062900')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040200400000000000000000000000062900')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('20ff0217002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('020401000000000000000000020000002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')],
        }
        self.assertDictEqual(result, expected)

        # PD = RR
        payload = binascii.unhexlify('20ff0217000615121200d55cc805d345e00000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('020402000000000000000000000000000615121200d55cc805d345e00000000000000000000000')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('20ff011300061603535986200b611401eca4477140049080')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040200400000000000000000000000061603535986200b611401eca4477140049080')],
        }
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()