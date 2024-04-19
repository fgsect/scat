#!/usr/bin/env python3

import unittest
import binascii

from scat.parsers.hisilicon.hisilogparser import HisiLogParser

class TestHisiLogParser(unittest.TestCase):
    parser = HisiLogParser(parent=None)

    def test_parse_hisi_lte_ota_msg(self):
        # BCCH BCH
        payload = binascii.unhexlify('00022001038120000032F3B300000000000000012014000000AB0000000100000011000000C60F0000076A9000')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000040000006a9000')],
        }
        self.assertDictEqual(result, expected)

        # BCCH DL-SCH
        payload = binascii.unhexlify('0002200103CB200000FCF4B300000000000000012023000000AB0000000100000012000000D90F00000640498805BFCD0322F0382130A0818C4326C0')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0000000000000000000500000040498805bfcd0322f0382130a0818c4326c0')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000220010373210000A706B400000000000000012036000000AB0000000100000019000000D80F00000600801C31186FE292F836059662D001040050EE596AA12F39AF763030A841BFC83AA4749E00')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0000000000000000000500000000801c31186fe292f836059662d001040050ee596aa12f39af763030a841bfc83aa4749e00')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000220010322230000BA34B40000000000000001204E000000AB0000000100000032000000D80F000006010C060591104C6ACC0884D288C030A519A57180614A334BA300C294625244000689E268982588C22886200761C86E1A0171FF00E75A8010FF00E70000')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00000000000000000005000000010c060591104c6acc0884d288c030a519a57180614a334ba300c294625244000689e268982588c22886200761c86e1a0171ff00e75a8010ff00e70000')],
        }
        self.assertDictEqual(result, expected)

        # PCCH
        payload = binascii.unhexlify('0002200103610C00001D2AAC00000000000000012018000000AB0000000100000001000000C90F00000540065CBCDB0FD0')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0000000000000000000600000040065cbcdb0fd0')],
        }
        self.assertDictEqual(result, expected)

        # DL CCCH
        payload = binascii.unhexlify('000220010344100000D9FAAD0000000000000001202E000000AB0000000100000004000000D30F00000368129808FDCE0183B0BA083E8BFF44AE618531B3806009420A1A004220')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0000000000000000000000000068129808fdce0183b0ba083e8bff44ae618531b3806009420a1a004220')],
        }
        self.assertDictEqual(result, expected)

        # UL CCCH
        payload = binascii.unhexlify('000220010316100000A4F6AD00000000000000012017000000AB0000000200000003000000D20F000004465CB8470A08')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00000000000000000002000000465cb8470a08')],
        }
        self.assertDictEqual(result, expected)

        # DL DCCH
        payload = binascii.unhexlify('0002200103E81100009E01AE00000000000000012014000000AB0000000100000006000000D50F000001320220')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00000000000000000001000000320220')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0002200103DC1200006D02AE0000000000000001202F000000AB0000000100000008000000CA0F0000012202353811FB9C0327603EA06D01D875141D8BC5BBA480241A0190003F00')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000010000002202353811fb9c0327603ea06d01d875141d8bc5bba480241a0190003f00')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00022001038D1400005F05AE0000000000000001209E000000AB000000010000000C000000CA0F000001241015E880140C4E32F001ACF0955288F3807F0FA04661B1882F2958CFE3FE916B487156E5A719666B99C25126134283C1204510C0C1084B0CC39029FFE9002884818F0801F24A080808F925040602A1270408068127040A007496820602324B4103811325A0822007085974C11C52CBA400004011004300C8021405300C701D0142449F663469804073240000')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00000000000000000001000000241015e880140c4e32f001acf0955288f3807f0fa04661b1882f2958cfe3fe916b487156e5a719666b99c25126134283c1204510c0c1084b0cc39029ffe9002884818f0801f24a080808f925040602a1270408068127040a007496820602324b4103811325a0822007085974c11c52cba400004011004300c8021405300c701d0142449f663469804073240000')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('000220010362140000F604AE00000000000000012014000000AB000000010000000A000000DA0F0000013A0040')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000010000003a0040')],
        }
        self.assertDictEqual(result, expected)

        # UL DCCH
        payload = binascii.unhexlify('000220010342110000CCFBAD00000000000000012027000000AB0000000200000005000000D40F0000022200262F24A4A060040E98C00BE99708E140AE044000')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000030000002200262F24A4A060040E98C00BE99708E140AE044000')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0002200103C61200004D02AE00000000000000012013000000AB0000000200000007000000D60F0000022A00')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000030000002a00')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00022001039F1300004A03AE00000000000000012013000000AB0000000200000009000000CB0F0000021200')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000030000001200')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00022001037B1400002505AE0000000000000001207A000000AB000000020000000B000000DB0F0000023A0116540004360C8A1541A950AA23820D112000600046384251CFBA167A6BB7284A39F742CF4D76F509473EE859E9AEDB8000659F188213871EBA1A167A6BB6800C80E80EAD3000036125ED2200DBB8500851A3D3C680428D1E9EB4021468F4FF0A010A347A7B8000')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000030000003a0116540004360c8a1541a950aa23820d112000600046384251cfba167a6bb7284a39f742cf4d76f509473ee859e9aedb8000659f188213871eba1a167a6bb6800c80e80ead3000036125ed2200dbb8500851a3d3c680428d1e9eb4021468f4ff0a010a347a7b8000')],
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0002200103111700003161AE00000000000000012015000000AB000000020000000E000000C70F0000020800A530')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000000000000000000030000000800a530')],
        }
        self.assertDictEqual(result, expected)

        # NAS/EPS EMM UL
        payload = binascii.unhexlify('000220010359B601006AFFE40100000000000001205E000000AD00000002000000D80000003C1000000741620BF662F220EEAD65CB8470A004F0F0C0C000200201D011271A8080211001010010810600000000830600000000000A00000D005262F220BFCD5C20003103E560349011035758865D0100E0')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('020412000000000000000000000000000741620BF662F220EEAD65CB8470A004F0F0C0C000200201D011271A8080211001010010810600000000830600000000000A00000D005262F220BFCD5C20003103E560349011035758865D0100E0')],
        }
        self.assertDictEqual(result, expected)

        # NAS/EPS EMM DL
        payload = binascii.unhexlify('0002200103F6B901001E16E501000000000000012013000000AD00000001000000DD0000004D100000075503')
        result = self.parser.hisi_lte_ota_msg(payload[1:25], payload[25:], None)
        expected = {
            'layer': 'nas',
            'cp': [binascii.unhexlify('02041200000000000000000000000000075503')],
        }
        self.assertDictEqual(result, expected)

    def test_parse_hisi(self):
        pass
        # Command 0x20020000 - not handled
        # BCCH DL-SCH
        # payload = binascii.unhexlify('0002200103C8200000F5F4B300000000000000022046000000B3000000AC0000008A020000C106000000000000B300000000000000AC00000022000000C106000000059202010083001200000040498805BFCD0322F0382130A0818C4326C0')
        # payload = binascii.unhexlify('0002200103702100007506B400000000000000022059000000B3000000AC0000009B020000C106000000000000B300000000000000AC00000035000000C10600000002A002010000002500000000801C31186FE292F836059662D001040050EE596AA12F39AF763030A841BFC83AA4749E00')
        # payload = binascii.unhexlify('00022001031F2300008A34B400000000000000022071000000B3000000AC000000C7020000C106000000000000B300000000000000AC0000004D000000C10600000002C40201088D023D000000010C060591104C6ACC0884D288C030A519A57180614A334BA300C294625244000689E268982588C22886200761C86E1A0171FF00E75A8010FF00E70000')
        # PCCH
        # payload = binascii.unhexlify('0002200103712700000541B40000000000000002204D000000B4000000AB0000006D0300008507000000000000B400000000000000AB0000002900000085070000000000001D00000068129808FDCE0183B0BA083E8BFF44AE618531B3806019420A1A0042A0')
        # DL CCCH
        # payload = binascii.unhexlify('000220010340100000D3FAAD0000000000000002204D000000B4000000AB000000C20000008507000000000000B400000000000000AB0000002900000085070000000000001D00000068129808FDCE0183B0BA083E8BFF44AE618531B3806009420A1A004220')
        # NAS-EPS
        # payload = binascii.unhexlify('00022001032740000068F6BA000000000000000220A1000000AD000000AB000000B10600000605000000000000AD00000000000000AB0000007D0000000605000003000000000000000200000000000000000000006500ADEE62F2200059000000170FE55F71060741620BF662F220EEAD65CB8470A004F0F0C0C000200201D011271A8080211001010010810600000000830600000000000A00000D005262F220BFCD5C20003103E560341362F220000F11035758865D0100E0')

    def test_parse_hisi_lte_current_cell_info(self):
        pass


if __name__ == '__main__':
    unittest.main()