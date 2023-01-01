#!/usr/bin/env python3

import unittest
import binascii

from parsers.samsung.sdmcommonparser import SdmCommonParser
from parsers.samsung import sdmcmd

class TestSdmCommonParser(unittest.TestCase):
    parser = SdmCommonParser(parent=None, model='e5123')

    def test_sdm_common_basic_info(self):
        self.parser.model = 'cmc221s'
        payload = binascii.unhexlify('4f61010f170003002cac6d40960268')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 1840.00/1745.00 MHz'}
        self.assertDictEqual(result, expected)

        self.parser.model = 'e333'
        payload = binascii.unhexlify('c3877605170403002cac6d4096026841000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 1840.00/1745.00 MHz, Extra: 41000000'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('2061bd37170002809dc29c808f9b951f7e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 1f7e7f1a'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('41190138170002809dc29c808f9b95157e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 157e7f1a'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('8f19c03d170402809dc29c808f9b957f1a0000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 2, Frequency 2630.00/2510.00 MHz, Extra: 7f1a0000'}
        self.assertDictEqual(result, expected)

        self.parser.model = 'e5123'
        payload = binascii.unhexlify('c6aaec031700036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 23, MIMO 3, Frequency 954.30/909.30 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('e1aaec03190000ffffffffffffffff006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 25, MIMO 0, Frequency 0.00/0.00 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)
        payload = binascii.unhexlify('c231fd032004036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT 32, MIMO 3, Frequency 954.30/909.30 MHz, Extra: 006f30c300ffffffffffffff'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()