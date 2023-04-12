#!/usr/bin/env python3

import unittest
import binascii

from parsers.samsung.sdmcontrolparser import SdmControlParser
from parsers.samsung import sdmcmd

class TestSdmControlParser(unittest.TestCase):
    parser = SdmControlParser(parent=None, model='e5123')

    def test_sdm_control_start_response(self):
        # Pixel 7
        payload = binascii.unhexlify('7f88000085000000a10001187d92d309194c696256657272062600280041534e100700150c100700150c323032322d31302d32375432333a32312d303730300000000003003d02076735333030672d3232303932332d3232313032382d422d393232393436393b3b33626666316131336661666234373b64655f6f323b77696c6463617264005300007e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: LibVer: 720626002800, ASN: 100700150c100700150c, Date: 2022-10-27T23:21-0700, Extra: g5300g-220923-221028-B-9229469;;3bff1a13fafb47;de_o2;wildcard'}
        self.assertDictEqual(result, expected)

        # S22 (SM-S901B)
        payload = binascii.unhexlify('7f58000055000000a10001461da99441194c696256657272062400000041534e10020014090f0900140346656220323720323032332030373a34323a3331000000000003000d000753393031425858553343574245335100007e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: LibVer: 720624000000, ASN: 10020014090f09001403, Date: Feb 27 2023 07:42:31, Extra: S901BXXU3CWBE'}
        self.assertDictEqual(result, expected)

        # Pixel 6
        payload = binascii.unhexlify('7f99000096000000a100011ab8b7b84f194c696256657204002c00040041534e0f0c00140c0f0900140344656320323520323032312031333a34343a3132000000000001004e22066735313233622d39333336382d3231313232352d422d383032393630393b63666764622d77632d3231313232352d422d383032393630393b30353132363131336661666234373b6e2f613b6e2f61235100007e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: LibVer: 04002c000400, ASN: 0f0c00140c0f09001403, Date: Dec 25 2021 13:44:12, Extra: g5123b-93368-211225-B-8029609;cfgdb-wc-211225-B-8029609;05126113fafb47;n/a;n/a'}
        self.assertDictEqual(result, expected)

        # S21 (SM-G991N)
        payload = binascii.unhexlify('7f58000055008925a100014cd9af0000194c696256657201000000000041534e10020014090f090014034f637420313720323032322030313a35323a3434000000000000000d2206473939314e4b4f553344564a383a1205007e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: LibVer: 010000000000, ASN: 10020014090f09001403, Date: Oct 17 2022 01:52:44, Extra: G991NKOU3DVJ8'}
        self.assertDictEqual(result, expected)

        # S8 (SM-G950F)
        payload = binascii.unhexlify('7f5800005500e505a1000174d20103011947393530465858553141514a350000000000000000000000004f637420323520323031372031363a33313a3234000000000000010d170547393530465858553141514a35550300007e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: G950FXXU1AQJ5, Date: Oct 25 2017 16:31:24, Extra: G950FXXU1AQJ5'}
        self.assertDictEqual(result, expected)

        # Note 4 (SM-N916S)
        payload = binascii.unhexlify('7f54000051001a00a000012b31350601194e393136534b535531424f423200000000000000000000000046656220203420323031352030393a35333a31300000004c5600010d60044e393136534b535531424f42327e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: N916SKSU1BOB2, Date: Feb  4 2015 09:53:10, Extra: N916SKSU1BOB2'}
        self.assertDictEqual(result, expected)

        # S3 (SHV-E210K)
        self.parser.model = 'cmc221s'
        payload = binascii.unhexlify('7f470000440059ffa000017bcdfc0e0119453231304b4b4b4e41330000000000000000000000000000004a616e20323220323031342031323a35353a3032007375706500012036047e')
        result = self.parser.sdm_control_start_response(payload)
        expected = {'stdout': 'SDM Start Response: Version: E210KKKNA3, Date: Jan 22 2014 12:55:02'}
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()