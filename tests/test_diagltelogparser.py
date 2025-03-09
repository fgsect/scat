#!/usr/bin/env python3

import unittest
import binascii
import datetime
from collections import namedtuple

import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagltelogparser import DiagLteLogParser

class TestDiagLteLogParser(unittest.TestCase):
    parser = DiagLteLogParser(parent=None)
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    # LTE ML1
    def test_parse_lte_ml1_scell_meas(self):
        # V4
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE SCell: EARFCN: 6300, PCI: 214, Measured RSRP: -101.25, Measured RSSI: -66.62, Measured RSRQ: -14.06')

        # V5
        payload = binascii.unhexlify('05010000160d0000d40e00004bb444005444450039e514133149070048adfe019f310100a23f0000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE SCell: EARFCN: 3350, PCI: 212, Measured RSRP: -111.31, Measured RSSI: -80.88, Measured RSRQ: -10.44')

        payload = binascii.unhexlify('05010000f424000a4d43434d4e434d41524b45527c307c3236327c317c34323330333233347c7c4d43434d4e434d41524b45520a0a434f504d41524b45527c434f504552524f5232363230317c434f504d41524b45520a006306000057755500577555001d75d4111d290b0048ad7e02dd370100a27f4100')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE SCell: EARFCN: 167781620, PCI: 333, Measured RSRP: -127.12, Measured RSSI: 2.75, Measured RSRQ: -22.25')

        payload = binascii.unhexlify('0501000000190000a90d0000d9944d00d9944d006081d5d55d2568bc48ad3e027f314fe0891900e0')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE SCell: EARFCN: 6400, PCI: 425, Measured RSRP: -102.44, Measured RSSI: -77.44, Measured RSRQ: -8.00')

    def test_parse_lte_ml1_ncell_meas(self):
        # V4
        payload = binascii.unhexlify('040100009C1847008348E44DDEA44C00CAB4CC32B6D8420300000000FF773301FF77330122020100')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS), timestamp=0)
        result = self.parser.parse_lte_ml1_ncell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE NCell: EARFCN: 6300, number of cells: 1\n└── Neighbor cell 0: PCI: 131, RSRP: -102.12, RSSI: -75.75, RSRQ: -17.31')

        # V5
        payload = binascii.unhexlify('05010000160d0000480000006cea413bb4433b00b4f3cc33cf3c130200000000ffefc00fffefc00f45081600')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS), timestamp=0)
        result = self.parser.parse_lte_ml1_ncell_meas(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE NCell: EARFCN: 3350, number of cells: 1\n└── Neighbor cell 0: PCI: 108, RSRP: -120.75, RSSI: -94.69, RSRQ: -17.06')

    def test_parse_lte_ml1_scell_meas_response(self):
        # V36
        payload = binascii.unhexlify('0101ffff19240c024006000001000300a01100008f2200000acc030005e6811490ca1200b2a445005a04000000202300b2744a00fef8930449000000fef8e30e440a150000000000a10200000000fbff2c002e000100586412770000ca0c0000a78c0000000000006f00000004000000a428000000000000b7fffffffe0000005ffcfffff0edffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas_response(pkt_header, payload, None)
        self.assertEqual(result['stdout'], '''LTE ML1 SCell Meas Response: EARFCN: 1600, Number of cells: 1, Valid RX: 3
LTE ML1 SCell Meas Response (Cell 0): PCI: 416, SFN/SubFN: 655/8, Serving cell index: 0, is_serving_cell: 1''')

        # V48
        payload = binascii.unhexlify('0101e4a419302801a4050000020003000001ffff5e120000ed070000f2150500f98a6a1fed9f1200a8e44300390400006009960000702200a7844a001861640ff6000000186154111fc20e00000000001f02000005000a00000000002c00360000000000000068186b0d0a002ee806002d3902000000000049070000870400001f150200000000005700000018010000990800008506000000000000000000005d020000ed0b0000ee150500f78a6a1fedc71100a8943a00390400006009960000101f0071644700e594e3088e000000e594830d1c5a0d00000000001c02000005000a00000000002c00360000000000000070189bc100002e310000bc020100000000006f00000010000000a4a000000000000057000000e50000009c0800008a0600000000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas_response(pkt_header, payload, None)
        self.assertEqual(result['stdout'], '''LTE ML1 SCell Meas Response: EARFCN: 1444, Number of cells: 2, Valid RX: 3
LTE ML1 SCell Meas Response (Cell 0): PCI: 94, SFN/SubFN: 1005/1, Serving cell index: 1, is_serving_cell: 1
LTE ML1 SCell Meas Response (Cell 1): PCI: 93, SFN/SubFN: 1005/2, Serving cell index: 1, is_serving_cell: 0''')

        # V60
        payload = binascii.unhexlify('01010000193ca00014050000010000000f00000000010203e48100009a1d0000580e03002c87d10c9a491300cfc44900983441001394450059242500d2244d00041184100891b30d082184108e9a1200eff111008e020000ffff0300090004003900380039003a0000000000784401007b7101004a090100a2a30000ebc10700e23507002701000027010000c10000009500000007755000f4944e000000000008010000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas_response(pkt_header, payload, None)
        self.assertEqual(result['stdout'], '')

        payload = binascii.unhexlify('01015040193c3401060e000002000000030000000001fffff481000059220000420e03002187d1125a96160095755800640500006009960000503200a5555900618595122901000061854515d472170000000000ee020000f7fff9ff00000000260025000000000000000000e7c30200f47c050000000000000000000daa080000000000cd050000af02000000000000000000004db55200000000004d00000061010000030000000001ffffb800000059260000480e03002487d1125a5e150095055700640500006009960000002f0070255600051564100601000006198411e2ca170000000000f9020000f7fff9ff000000002600250000000000000000004ed802007f0c020000000000000000000e020800000000006c010000a6010000000000000000000010655100000000004d00000006010000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_ml1_scell_meas_response(pkt_header, payload, None)
        self.assertEqual(result['stdout'], '')

    def test_parse_lte_ml1_cell_info(self):
        # V1
        payload = binascii.unhexlify('0164A4011405244241050000D32D000080533D00000000000000A4A91DFF0100')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_ml1_cell_info(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00051400000000000004000000a9a400')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc),
            'stdout': 'LTE ML1 Cell Info: EARFCN: 1300, PCI: 36, Bandwidth: 20 MHz, Num antennas: 1'
        }
        self.assertDictEqual(result, expected)

        # V2
        payload = binascii.unhexlify('024BF8002107000003230000000000000F0500002ABD0B17000000000000F88400000100')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_ml1_cell_info(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0007210000000000000400000084f800')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc),
            'stdout': 'LTE ML1 Cell Info: EARFCN: 1825, PCI: 259, Bandwidth: 15 MHz, Num antennas: 1'
        }
        self.assertDictEqual(result, expected)

    def test_parse_lte_ml1_intra_freq_cell_resel(self):
        # 01 02 F8 14 0A 02 0C 00 16 0D 00 00 61 03 00 00 0B 20 84 00 00 00 00 00 02 00 00 00 40 06 00 00 79 25 12 12 A0 4B F8 02 7F F9 CB 38 E3 DE CB 0F 30 48 F8 02 62 11 CB 31 C7 9E CB 0F 5A 45 08 03 4E 71 CA 2E BB 1E CB 0F 15 43 EF 02 39 C9 C9 29 A7 DE CA 0F 16 0D 00 00 79 0F 00 0A 61 4D 5B 03 85 31 8B 4C 34 DF CE 0F 38 18 00 00 79 1C 12 0E 67 62 8E 03 36 B2 11 41 04 DF 0E 00 66 56 8D 03 D2 91 0E 33 CC 5E CD 0F EB 4F 88 03 9E F1 0C 20 80 5E CC 0F
        # 01 03 FC 14 0A 02 0C 00 9C 18 00 00 D6 02 00 00 05 19 10 00 01 00 00 00 85 40 00 00 04 00 00 00 0B 20 38 00 01 00 00 00 03 00 00 00 9C 18 00 00 79 0D 00 04 D6 56 A0 03 B6 69 CD 3F 0A 9F CE 0F 22 0B 00 00 79 07 0C 0C 09 07 00 00 79 06 0C 0C 7D 00 00 00 79 04 16 0A
        pass

    def test_parse_lte_ml1_ncell_meas_request_response(self):
        # 01 02 02 00 1A 02 1C 00 16 0D 00 00 21 00 00 00 60 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1B 04 40 00 16 0D 00 00 01 00 00 00 60 01 00 00 81 13 38 00 82 23 38 00 82 23 38 00 DD 74 03 0C C0 74 D3 0D B5 00 00 00 D2 90 06 00 00 00 00 00 32 00 31 00 FE 06 03 00 FE 06 03 00 00 00 00 00
        # 01 02 02 00 1A 02 3C 00 38 18 00 00 23 00 00 00 67 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 66 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 EB 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1B 04 A8 00 38 18 00 00 03 00 00 00 67 00 00 00 B6 64 4B 00 49 94 44 00 B6 64 4B 00 06 19 F4 10 0F 3D F4 10 C1 01 00 00 4A 09 0E 00 00 00 00 00 35 00 37 00 A2 58 00 00 A2 58 00 00 00 00 00 00 66 00 00 00 71 14 47 00 D3 33 3D 00 71 14 47 00 C0 00 93 09 99 00 03 0C C2 01 00 00 4B 11 0E 00 00 00 00 00 35 00 37 00 82 58 00 00 82 58 00 00 00 00 00 00 EB 01 00 00 35 54 43 00 AD D3 3A 00 35 54 43 00 83 0C 62 08 86 18 62 08 C3 01 00 00 38 19 0E 00 00 00 00 00 35 00 37 00 52 69 00 00 52 69 00 00 00 00 00 00
        pass

    # LTE MAC
    def test_parse_lte_mac_rach_response(self):
        # V2, Msg1, Msg2, Msg3
        payload = binascii.unhexlify('0101a06906022400010001071BFF98FF000001231A0400181C010007000600465C80BD0648000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_RACH_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_mac_rach_response(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e00000000000000000000000000010102091b01015b004c01001a23'),
                binascii.unhexlify('02040e00000000000000000000000000010003021a23091b010100465c80bd0648000000')
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # V3, Msg1, Msg2, Msg3
        payload = binascii.unhexlify('0101a0690603280001000100010718ffa4ff000001c6610b00b4a2000012000120061f423f8d95075800')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_RACH_RESPONSE), timestamp=0)
        result = self.parser.parse_lte_mac_rach_response(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e00000000000000000000000000010102091801015800b2000061c6'),
                binascii.unhexlify('02040e000000000000000000000000000100030261c60918010120061f423f8d95075800')
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # V49, Msg1, Msg2
        payload = binascii.unhexlify('0101739e063134000100010000033f0098ff0000013c6b070058ac010007000000468f47e2d446000000644b0000180001000000d5040000')

        # V49, Msg1, Msg2, Msg3
        payload = binascii.unhexlify('01010000063134000100010001070aff98ff0000011c48070018e2000007000000523b7dfd69b6000000f5540000ff0001000000d6040000')

        # V50, Msg1, Msg2
        payload = binascii.unhexlify('01010000063238000100010000032900a4ffeb000000000195b603000000a0b412000420061f425dc9be41b800885e00001700010000006505000073')

        # V50, Msg1, Msg2, Msg3
        payload = binascii.unhexlify('010100000632380001000100010713ffa0ffeb0000000001ad5a0500000146b412000420061f425dc9be41b400665300001800010000001a05000000')

    def test_parse_lte_mac_dl_block(self):
        # Packet V1, Subpkt V4
        payload = binascii.unhexlify('01011c36070458000402001527030100000900000000095800611418120e7f00020028270407000029000102000a3c201d1f408c61ca51e602004527000700000700000400033d1f1f020049270006000007000102000321021f0000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_DL_TRANSPORT_BLOCK), timestamp=0)
        result = self.parser.parse_lte_mac_dl_block(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e00000000000000000000000000010102042715015800611418120e7f00'),
                binascii.unhexlify('02040e00000000000000000000000000010103042728013c201d1f408c61ca51e6'),
                binascii.unhexlify('02040e00000000000000000000000000010103042745013d1f1f'),
                binascii.unhexlify('02040e000000000000000000000000000101030427490121021f')
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('01011c3607046800060100d91c0003000007000102000324021f0100001d00060000c70301000001040100011d00070000970501000001040100021d00000000a9000106000424809f1f0100061d000400005d000102000324581f0100081d00050000540601000001040000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_DL_TRANSPORT_BLOCK), timestamp=0)
        result = self.parser.parse_lte_mac_dl_block(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e00000000000000000000000000010103041cd90124021f'),
                binascii.unhexlify('02040e00000000000000000000000000010103041d000104'),
                binascii.unhexlify('02040e00000000000000000000000000010103041d010104'),
                binascii.unhexlify('02040e00000000000000000000000000010103041d020124809f1f'),
                binascii.unhexlify('02040e00000000000000000000000000010103041d060124581f'),
                binascii.unhexlify('02040e00000000000000000000000000010103041d080104')
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Packet V49
        payload = binascii.unhexlify('3100000002000400c1420000020000000000000002000000000000000200000002000000c2440000010000000000000001000000000000000100000001000000c3080200030000000300000001000000000000000100000001000000c40a02000100000001000000010000000000000001000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d01000013000000e81d00000001040086830000000b000001010000035801000500000014000000710000000b000000eb210000100103000832000000030000010100000188010004000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_DL_TRANSPORT_BLOCK), timestamp=0)
        result = self.parser.parse_lte_mac_dl_block(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        # self.assertDictEqual(result, expected)

        # Packet V50
        payload = binascii.unhexlify('32000000010000002f00000000000000995d0200700204003903005be5d32d3c06000000801200000001000000000000')

    def test_parse_lte_mac_ul_block(self):
        # Packet V1, Subpkt V2
        payload = binascii.unhexlify('01010000080244000302000100372771000147000304093e3a21211f0000001702000200462757000052000204053e1f00000002000700512779000074000004053e1f0000005700')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_UL_TRANSPORT_BLOCK), timestamp=0)
        result = self.parser.parse_lte_mac_ul_block(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e00000000000000000000000000010003042737013e3a21211f00000017'),
                binascii.unhexlify('02040e00000000000000000000000000010003042746013e1f000000'),
                binascii.unhexlify('02040e00000000000000000000000000010003042751013e1f000000'),
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('0101fc91080248011401000700d32735000100000000010401000000d42741000100000000010401000100d52735000100000000010401000200d62735000100000000010401000300d72735000100000000033a040701000400d82735000100000000010401000500d92735000100000000010401000600e02735000100000000010401000700e12741000100000103033d041b01000000e22741000100000000010401000100e32747000100000000010401000200e42741000100000000010401000300e52741000100000000010401000400e62741000100000000010401000500e72741000100000005033d041401000600e82741000100000000010401000700e92741000100000000010401000000f02751000106000004073e24441f00000001000100f12747000140000203053d24021f0001000700532820000117000203073d3a24021f000c00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_MAC_UL_TRANSPORT_BLOCK), timestamp=0)
        result = self.parser.parse_lte_mac_ul_block(pkt_header, payload, None)
        expected = {
            'layer': 'mac',
            'cp': [
                binascii.unhexlify('02040e000000000000000000000000000100030427d30104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d40104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d50104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d60104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d7013a0407'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d80104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427d90104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e00104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e1013d041b'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e20104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e30104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e40104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e50104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e60104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e7013d0414'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e80104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427e90104'),
                binascii.unhexlify('02040e000000000000000000000000000100030427f0013e24441f000000'),
                binascii.unhexlify('02040e000000000000000000000000000100030427f1013d24021f00'),
                binascii.unhexlify('02040e00000000000000000000000000010003042853013d3a24021f000c'),
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Packet V1, Subpkt V5
        payload = binascii.unhexlify('01010000080514010e01000100b3195d000100000203053d3a010f1c01000100c11961000107000004073e21531f00000001000100c91975000070000004053e1f00000001000100d71979000074000004053e1f00000001000700e3196d000068000004053e1f00000001000500e91979000074000004053e1f00000001000500f71975000251000203073d2102211b1f0001000300031a75000070000004053e1f00000001000100091a7d000078000004053e1f00000001000700151a7d000078000004053e1f00000001000500211a7d000078000004053e1f00000001000300271a7d000078000004053e1f00000001000100331a7d000078000004053e1f00000001000700391a7d000078000004053e1f00000000')

        payload = binascii.unhexlify('01010100080518000101000300112757000052000104053e1f000000')

    # LTE PDCP
    def test_parse_lte_pdcp_dl_cip(self):
        # Packet V1, Subpkt V24
        payload = binascii.unhexlify('01012200C31848008E578ABFBE9DB23813BE851295189A29554C9B9C2D35A9F8D9284DCF08EB0940030302002140080003001722020000000002F4CE224207000300172200000000000028E0')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_PDCP_DL_CIPHER_DATA_PDU), timestamp=0)
        result = self.parser.parse_lte_pdcp_dl_cip(pkt_header, payload, None)
        expected = {
            'layer': 'pdcp',
            'up': [
                binascii.unhexlify('706463702d6c74650001000205030104010102f4ce'),
                binascii.unhexlify('706463702d6c7465000100020503010401010028e0'),
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Packet V1, Subpkt V40
        payload = binascii.unhexlify('010118b9c3283800000000000000000000000000000000000000000000000000000000000000000007070100228413000300d4280400000000044801')

    def test_parse_lte_pdcp_ul_cip(self):
        # Packet V1, Subpkt V26
        payload = binascii.unhexlify('01010000C31A4C008E578ABFBE9DB23813BE851295189A29554C9B9C2D35A9F8D9284DCF08EB09400303020004472E040400102200000000008000600004472E04040018220100000000800160008000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_PDCP_UL_CIPHER_DATA_PDU), timestamp=0)
        result = self.parser.parse_lte_pdcp_ul_cip(pkt_header, payload, None)
        expected = {
            'layer': 'pdcp',
            'up': [
                binascii.unhexlify('706463702d6c7465000200020c03000180006000'),
                binascii.unhexlify('706463702d6c7465000200020c03000180016000'),
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

    def test_parse_lte_pdcp_ul_srb_int(self):
        # Packet V1, Subpkt V1
        payload = binascii.unhexlify('01011861C7015800A397332D66B71076E3F0B985EF0A61313863BC495C4245ED7B5FC4FE2A6462E70302010022421D001D00004000000000BB53CCDA004802A4E98834BDA0FDC45CD12887E711BC73DEA9BC87FC20DACC53BBB00700')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_PDCP_UL_SRB_INTEGRITY_DATA_PDU), timestamp=0)
        result = self.parser.parse_lte_pdcp_ul_srb_int(pkt_header, payload, None)
        expected = {
            'layer': 'pdcp',
            'up': [
                binascii.unhexlify('706463702d6c746500010002050300040101004802a4e98834bda0fdc45cd12887e711bc73dea9bc87fc20dacc53bb'),
            ],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

    # LTE RRC
    def test_parse_lte_rrc(self):
        # V30
        payload = binascii.unhexlify('1e112011400132001914000016ad090000000002000000004c10')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d001419000000000ad1010006004c10')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # V27
        # payload = binascii.unhexlify('1b10100f9000b10186a00000d50700000000070005') # ...
        # pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12, log_id=0xb0c0, timestamp=0)
        # result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        # print(result)
        # V26
        payload = binascii.unhexlify('1a0f400f40010e011307000000000b0000000002001015')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000713000000000000030000001015')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V25
        # payload = binascii.unhexlify('190f3000000009019c180000455102000000003300') #...
        # pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12, log_id=0xb0c0, timestamp=0)
        # result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        # print(result)

        # V24
        payload = binascii.unhexlify('180f22006800e40c000009dc05000000000d0040858ec4e5bfe050dc29151600')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000ce4000000000dc00600090040858ec4e5bfe050dc29151600')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V20
        payload = binascii.unhexlify('140e300109019c1800000000090000000018000810a7145359a6054368c03bda3004a688028da2009a6840')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00189c000000000000030000000810a7145359a6054368c03bda3004a688028da2009a6840')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V19
        payload = binascii.unhexlify('130e22000b00fa090000000032000000000900281840160808800000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0009fa00000000000010000000281840160808800000')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V15
        payload = binascii.unhexlify('0f0d21009e0014050000498c05000000000700400c8ec94289e0') #...
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d0005140000000008c406000900400c8ec94289e0')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V15
        payload = binascii.unhexlify('0f0d21019e0014050000000009000000001c000810a5346141a31c316804401a0049167c23159f001067c106d9e000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d000514000000000000030000000810a5346141a31c316804401a0049167c23159f001067c106d9e000')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V13
        payload = binascii.unhexlify('0d0c74013200381800000000080000000002002c00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d001838000000000000030000002c00')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V9
        payload = binascii.unhexlify('090b700000011405000009910b000000000700400b8ec1dd13b0') #...
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00051400000000091006000900400b8ec1dd13b0')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)
        # V8
        payload = binascii.unhexlify('080a72010e009c180000a933060000000002002e02')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00189c00000000033a010009002e02')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # V6
        payload = binascii.unhexlify('0609B10007012C0725340202000000120040498805C09702D3B0981C20A0818C4326D0')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_OTA_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_rrc(pkt_header, payload, None)
        expected = {
            'layer': 'rrc',
            'cp': [binascii.unhexlify('02040d00072c0000000003420500050040498805c09702d3b0981c20a0818c4326d0')],
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

    def test_parse_lte_mib(self):
        # V1
        payload = binascii.unhexlify('010001140554000264')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_MIB_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_mib(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE MIB Info: EARFCN: 1300, SFN:   84, Bandwidth: 20 MHz, TX antennas: 2')

        # V2
        payload = binascii.unhexlify('02030121070000F800024B')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_MIB_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_mib(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE MIB Info: EARFCN: 1825, SFN:  248, Bandwidth: 15 MHz, TX antennas: 2')

        # V17
        payload = binascii.unhexlify('110b00fa090000b9030e000202000202d002')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_MIB_MESSAGE), timestamp=0)
        result = self.parser.parse_lte_mib(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE MIB-NB Info: EARFCN: 2554, SFN:  953, TX antennas: 2')

    def test_parse_lte_rrc_cell_info(self):
        # V2
        payload = binascii.unhexlify('028F001405644B64640074BC01D60503000000060102010000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_rrc_cell_info(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE RRC SCell Info: EARFCN: 1300/19300, Band: 3, Bandwidth: 20/20 MHz, PCI: 143, MCC: 262, MNC: 01, xTAC/xCID: 5d6/1bc7400')

        # V3
        payload = binascii.unhexlify('034D0021070000714D00004B4B33C8B009159B03000000CC01020B0000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_rrc_cell_info(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE RRC SCell Info: EARFCN: 1825/19825, Band: 3, Bandwidth: 15/15 MHz, PCI: 77, MCC: 460, MNC: 11, xTAC/xCID: 9b15/9b0c833')

        payload = binascii.unhexlify('030b00fa0900004A50000000000b0692000b9005000000c20102060000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_rrc_cell_info(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE RRC SCell Info: EARFCN: 2554/20554, Band: 5, Bandwidth: 0/0 PRBs, PCI: 11, MCC: 450, MNC: 06, xTAC/xCID: 900b/92060b')

        payload = binascii.unhexlify('03eb0138180000885e0000323203c06600045614000000060102030000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_lte_rrc_cell_info(pkt_header, payload, None)
        self.assertEqual(result['stdout'], 'LTE RRC SCell Info: EARFCN: 6200/24200, Band: 20, Bandwidth: 10/10 MHz, PCI: 491, MCC: 262, MNC: 03, xTAC/xCID: 5604/66c003')

    def test_parse_lte_nas(self):
        pass

if __name__ == '__main__':
    unittest.main()
