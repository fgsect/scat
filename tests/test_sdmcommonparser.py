#!/usr/bin/env python3

import unittest
import binascii

from parsers.samsung.sdmcommonparser import SdmCommonParser
from parsers.samsung import sdmcmd

class TestSdmCommonParser(unittest.TestCase):
    parser = SdmCommonParser(parent=None, model='e5123')

    def test_sdm_common_basic_info(self):
        self.parser.model = 'cmc221s'
        payload = binascii.unhexlify('170003002cac6d40960268')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x0f01614f)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 1840.00/1745.00 MHz'}
        self.assertDictEqual(result, expected)

        self.parser.model = 'e333'
        payload = binascii.unhexlify('170403002cac6d4096026841000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x057687c3)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 1840.00/1745.00 MHz, Extra: 41000000'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('170002809dc29c808f9b951f7e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x37bd6120)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 1f7e7f1a'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('170002809dc29c808f9b95157e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x38011941)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 157e7f1a'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('170402809dc29c808f9b957f1a0000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x3dc0198f)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 7f1a0000'}
        self.assertDictEqual(result, expected)

        self.parser.model = 'e5123'
        payload = binascii.unhexlify('1700036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 954.30/909.30 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('190000ffffffffffffffff006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaae1)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 25, MIMO 0, Frequency 0.00/0.00 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('2004036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 32, MIMO 3, Frequency 954.30/909.30 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)

    def test_sdm_common_signaling(self):
        # UMTS NAS
        payload = binascii.unhexlify('01ff0225000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('020402000000000000000000000000000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')]}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('01ff0102000803')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('020402004000000000000000000000000803')]}
        self.assertDictEqual(result, expected)

        # GPRS MAC DL
        payload = binascii.unhexlify('21ff02170047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('0204010000000000000000000b00000047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')]}
        self.assertDictEqual(result, expected)
        # GPRS MAC UL
        payload = binascii.unhexlify('21ff01170040212b771021ec118acacacacacacacacacacacacacaca')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('0204010040000000000000000b00000040212b771021ec118acacacacacacacacacacacacacaca')]}
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
        expected = {'cp': [binascii.unhexlify('02040200400000000000000000000000062900')]}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('20ff0217002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('020401000000000000000000020000002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')]}
        self.assertDictEqual(result, expected)

        # PD = RR
        payload = binascii.unhexlify('20ff0217000615121200d55cc805d345e00000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('020402000000000000000000000000000615121200d55cc805d345e00000000000000000000000')]}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('20ff011300061603535986200b611401eca4477140049080')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {'cp': [binascii.unhexlify('02040200400000000000000000000000061603535986200b611401eca4477140049080')]}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()