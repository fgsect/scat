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
        self.assertDictEqual(result, expected) # type: ignore

        self.parser.icd_ver = (4, 80)
        payload = binascii.unhexlify('170403002cac6d4096026841000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x057687c3)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 4, MIMO: 3, Frequency: DL: 1840.00 MHz/UL: 1745.00 MHz, Extra: 0x00000041'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('170002809dc29c808f9b951f7e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x37bd6120)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x1a7f7e1f'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('170002809dc29c808f9b95157e7f1a')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x38011941)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x1a7f7e15'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('170402809dc29c808f9b957f1a0000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x3dc0198f)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 4, MIMO: 2, Frequency: DL: 2630.00 MHz/UL: 2510.00 MHz, Extra: 0x00001a7f'}
        self.assertDictEqual(result, expected) # type: ignore

        self.parser.icd_ver = (5, 80)
        payload = binascii.unhexlify('120501000000000000000075240096')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: WCDMA, Status: 5, MIMO: 1, Frequency: -/-, Extra: 0x96002475'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('13020000062039c060713600000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 2, MIMO: 0, Frequency: DL: 958.40 MHz/UL: 913.40 MHz, Extra: 0x00000000'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('170003c0b32e6c001e85660d0a004b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x4b000a0d'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('190000ffffffffffffffff00210000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0x00002100'}
        self.assertDictEqual(result, expected) # type: ignore

        self.parser.icd_ver = (6, 22)
        payload = binascii.unhexlify('12040040b9fe7fe0c6553a006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: WCDMA, Status: 4, MIMO: 0, Frequency: DL: 2147.40 MHz/UL: UARFCN 9787, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('13010080eaf74440454942006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 1, MIMO: 0, Frequency: -/-, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('1700036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaac6)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 954.30 MHz/UL: 909.30 MHz, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('190000ffffffffffffffff006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03ecaae1)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('2004036076e13820d13236006f30c300ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: NR NSA, Status: 4, MIMO: 3, Frequency: DL: 954.30 MHz/UL: 909.30 MHz, Extra: 0xc3306f00, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        self.parser.icd_ver = (8, 0)
        payload = binascii.unhexlify('13040080056f38000000004060c0350000000000c9114700ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: GPRS, Status: 4, MIMO: 0, Frequency: DL: 946.80 MHz/UL: 901.80 MHz, Extra: 0x4711c900, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('170005c0b32e6c00000000001e8566000000008600000000ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 5, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x00000086, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('190000ffffffffffffffffffffffffffffffff00b0c9df00ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: UNKNOWN (0x19), Status: 0, MIMO: 0, Frequency: -/-, Extra: 0xdfc9b000, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('200405c0b32e6c00000000001e85660000000086000000020503ffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: NR NSA, Status: 4, MIMO: 5, Frequency: DL: 1815.00 MHz/UL: 1720.00 MHz, Extra: 0x00000086, Num cells: 2 (5, 3)'}
        self.assertDictEqual(result, expected) # type: ignore

        self.parser.icd_ver = (9, 0)
        payload = binascii.unhexlify('170003002ca33040c814330000000000ffffffffffffff')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_BASIC_INFO, payload, timestamp=0x03fd31c2)
        result = self.parser.sdm_common_basic_info(packet)
        expected = {'stdout': 'Common Basic Info: RAT: LTE, Status: 0, MIMO: 3, Frequency: DL: 816.00 MHz/UL: 857.00 MHz, Extra: 0x00000000, Num cells: 0'}
        self.assertDictEqual(result, expected) # type: ignore

    def test_sdm_common_signaling(self):
        # UMTS NAS
        payload = binascii.unhexlify('01ff0225000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('020402000000000000000000000000000512015abc10a19d3a136b8240e4b9795537c82010d2fea6dac1e87fff23883f052940131d')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('01ff0102000803')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('020402004000000000000000000000000803')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        # GPRS MAC DL
        payload = binascii.unhexlify('21ff02170047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'mac',
            'cp': [binascii.unhexlify('0204010000000000000000000b00000047942b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b')],
        }
        self.assertDictEqual(result, expected) # type: ignore
        # GPRS MAC UL
        payload = binascii.unhexlify('21ff01170040212b771021ec118acacacacacacacacacacacacacaca')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'mac',
            'cp': [binascii.unhexlify('0204010040000000000000000b00000040212b771021ec118acacacacacacacacacacacacacaca')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        # GSM RR
        # RR short PD = SACCH
        # payload = binascii.unhexlify('20ff0215001402580cc02a9441d0ec7931dba0c58c2b2b2b2b2b')
        # packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_DATA_SIGNALING_INFO, payload, timestamp=0x0)
        # result = self.parser.sdm_common_signaling(packet)
        # expected = {'cp': [binascii.unhexlify('')]}
        # self.assertDictEqual(result, expected) # type: ignore

        # RR dl with pseudolength = CCCH
        payload = binascii.unhexlify('20ff010300062900')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040200400000000000000000000000062900')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('20ff0217002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('020401000000000000000000020000002d062200f5d97e6de1eae02d2b2b2b2b2b2b2b2b2b2b2b')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        # PD = RR
        payload = binascii.unhexlify('20ff0217000615121200d55cc805d345e00000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('020402000000000000000000000000000615121200d55cc805d345e00000000000000000000000')],
        }
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('20ff011300061603535986200b611401eca4477140049080')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_signaling(packet)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040200400000000000000000000000061603535986200b611401eca4477140049080')],
        }
        self.assertDictEqual(result, expected) # type: ignore

    def test_sdm_common_nr_rrc_signaling(self):
        # BCCH BCH
        payload = binascii.unhexlify('010101020004005d2624c4')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300010002000400000000fffe5d2624c4')]}
        self.assertDictEqual(result, expected) # type: ignore

        # BCCH DL-SCH
        payload = binascii.unhexlify('01018403008d007c800c02093100802ff3401a19035300800c50010810ca8a081b00d0000033618c215f853b8200800011141b900eb4000088a0008041b04228178ca57248ec5a1f0c71006f103611a8c0000019eae36c916809824c666a36d3802404e3126e254d80be0f9b37020a729b98a0000000000000000000000000000000000000000000000000000000000000000000')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300020002000400000000fffe7c800c02093100802ff3401a19035300800c50010810ca8a081b00d0000033618c215f853b8200800011141b900eb4000088a0008041b04228178ca57248ec5a1f0c71006f103611a8c0000019eae36c916809824c666a36d3802404e3126e254d80be0f9b37020a729b98a0000000000000000000000000000000000000000000000000000000000000000000')]}
        self.assertDictEqual(result, expected) # type: ignore

        # DL DCCH
        payload = binascii.unhexlify('01018d0400070028808fc00b6020')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300040002000400000000fffe28808fc00b6020')]}
        self.assertDictEqual(result, expected) # type: ignore
        # UL DCCH
        payload = binascii.unhexlify('01018c04011e0010c01d4c391177e004179000bf262f220ea61c8f2f693f82e04f070f0f00')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300090002000400000000fffe10c01d4c391177e004179000bf262f220ea61c8f2f693f82e04f070f0f00')]}
        self.assertDictEqual(result, expected) # type: ignore

        # DL CCCH
        payload = binascii.unhexlify('01018b00006e00204020c6d2b80160021ef5f90020cbd800f84460820f380841ac5970249819100ee1002000044506e18020000446c8408096407cc07cdc108a05e3295c923b1687c02662209203203101109003028120106119c7222934149a08400608563126e254fff518ca53d4084560002600')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300030002000400000000fffe204020c6d2b80160021ef5f90020cbd800f84460820f380841ac5970249819100ee1002000044506e18020000446c8408096407cc07cdc108a05e3295c923b1687c02662209203203101109003028120106119c7222934149a08400608563126e254fff518ca53d4084560002600')]}
        self.assertDictEqual(result, expected) # type: ignore
        # UL CCCH
        payload = binascii.unhexlify('01018a00010600174da3638466')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_RRC_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_rrc_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050300070002000400000000fffe174da3638466')]}
        self.assertDictEqual(result, expected) # type: ignore

    def test_sdm_common_nr_nas_signaling(self):
        payload = binascii.unhexlify('013a00005c7e005c00350162f220f1ff010a9bcaad7bb82d608ab0038dd8b4b739b313b8971311efc6107487d798a30e774304b22ea59c58014a6a040d27c0')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_NAS_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_nas_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050400000002000400000000fffe7e005c00350162f220f1ff010a9bcaad7bb82d608ab0038dd8b4b739b313b8971311efc6107487d798a30e774304b22ea59c58014a6a040d27c0')]}
        self.assertDictEqual(result, expected) # type: ignore

        payload = binascii.unhexlify('00070000447e00441b16012c')
        packet = sdmcmd.generate_sdm_packet(0xa0, sdmcmd.sdm_command_group.CMD_COMMON_DATA, sdmcmd.sdm_common_data.COMMON_NR_NAS_SIGNALING_INFO, payload, timestamp=0x0)
        result = self.parser.sdm_common_nr_nas_signaling(packet)
        expected = {'cp': [binascii.unhexlify('03000005050400000002000400000000fffe7e00441b16012c')]}
        self.assertDictEqual(result, expected) # type: ignore


if __name__ == '__main__':
    unittest.main()