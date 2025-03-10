#!/usr/bin/env python3

import unittest
import binascii
from collections import namedtuple
import datetime

import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser

class TestDiagNrLogParser(unittest.TestCase):
    parser = DiagNrLogParser(parent=None)
    log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')

    # ML1

    def test_parse_nr_ml1_meas_db_update(self):
        #major 2 minor 7 one beam
        payload = binascii.unhexlify('070002000114000026ffffff44000000991006000100c602000000000000000000000000ffffffffffff0000ffffffffc6027e000100000017caffff0afaffff000000000000000000000000a5a1dbbd4199a005a3bcffff17caffff17caffff0afaffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload, None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 397465, SCell PCI:  710/SSB: 0, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 1 (S: 0)
└── Cell 0: PCI:  710, PBCH SFN: 126, RSRP: -107.82, RSRQ: -11.92, Num Beams: 1
    └── Beam 0: SSB[0] Beam ID: 0/0, RSRP: -134.73/-107.82, Filtered RSRP/RSRQ (Nr2Nr): -107.82/-11.92, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)
        # major 2 minor 9 one beam
        payload = binascii.unhexlify('09000200000000000114000026ffffff44000000991006000100c602000000000000000000000000ffffffffffff0000ffffffffc6027e000100000017caffff0afaffff000000000000000000000000a5a1dbbd4199a005a3bcffff17caffff17caffff0afaffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload, None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 397465, SCell PCI:  710/SSB: 0, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 1 (S: 0)
└── Cell 0: PCI:  710, PBCH SFN: 126, RSRP: -107.82, RSRQ: -11.92, Num Beams: 1
    └── Beam 0: SSB[0] Beam ID: 0/0, RSRP: -134.73/-107.82, Filtered RSRP/RSRQ (Nr2Nr): -107.82/-11.92, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # major 2 minor 7 4 beams
        payload = binascii.unhexlify('070002000114000016040000f8ffffff11ef070001005500020000000000000000000000ffffffffffff0000ffffffff5f00fe000400000064d0ffffa9faffff02000000000000000000000056efbfd9a266dd0e06d0ffff3bcdffff06d0ffffacfaffff0000000000000000010000000000000000000000aed514d75244dd0e64d0ffff4dcdffff64d0ffffa9faffff0000000000000000000000000000000000000000567115d5a22add0efecbffff8ac9fffffecbffff73f9ffff00000000000000000500000000000000000000000e0910f752bc7d05c1caffffcfc8ffffc1caffffedf8ffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)

        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 519953, SCell PCI:   85/SSB: 2, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 1 (S: 0)
└── Cell 0: PCI:   95, PBCH SFN: 254, RSRP: -95.22, RSRQ: -10.68, Num Beams: 4
    └── Beam 0: SSB[2] Beam ID: 0/0, RSRP: -95.95/-101.54, Filtered RSRP/RSRQ (Nr2Nr): -95.95/-10.66, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 1: SSB[1] Beam ID: 0/0, RSRP: -95.22/-101.40, Filtered RSRP/RSRQ (Nr2Nr): -95.22/-10.68, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 2: SSB[0] Beam ID: 0/0, RSRP: -104.02/-108.92, Filtered RSRP/RSRQ (Nr2Nr): -104.02/-13.10, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 3: SSB[5] Beam ID: 0/0, RSRP: -106.49/-110.38, Filtered RSRP/RSRQ (Nr2Nr): -106.49/-14.15, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # major 2 minor 9 4 beams
        payload = binascii.unhexlify('09000200000000000114000016040000f8ffffff11ef070001005500020000000000000000000000ffffffffffff0000ffffffff5f00fe000400000064d0ffffa9faffff02000000000000000000000056efbfd9a266dd0e06d0ffff3bcdffff06d0ffffacfaffff0000000000000000010000000000000000000000aed514d75244dd0e64d0ffff4dcdffff64d0ffffa9faffff0000000000000000000000000000000000000000567115d5a22add0efecbffff8ac9fffffecbffff73f9ffff00000000000000000500000000000000000000000e0910f752bc7d05c1caffffcfc8ffffc1caffffedf8ffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 519953, SCell PCI:   85/SSB: 2, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 1 (S: 0)
└── Cell 0: PCI:   95, PBCH SFN: 254, RSRP: -95.22, RSRQ: -10.68, Num Beams: 4
    └── Beam 0: SSB[2] Beam ID: 0/0, RSRP: -95.95/-101.54, Filtered RSRP/RSRQ (Nr2Nr): -95.95/-10.66, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 1: SSB[1] Beam ID: 0/0, RSRP: -95.22/-101.40, Filtered RSRP/RSRQ (Nr2Nr): -95.22/-10.68, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 2: SSB[0] Beam ID: 0/0, RSRP: -104.02/-108.92, Filtered RSRP/RSRQ (Nr2Nr): -104.02/-13.10, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
    └── Beam 3: SSB[5] Beam ID: 0/0, RSRP: -106.49/-110.38, Filtered RSRP/RSRQ (Nr2Nr): -106.49/-14.15, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # major 2 minor 7, 2 cells
        payload = binascii.unhexlify('07000200010000001501000024056c00de93060002ffffffff0000000000000000000000ffffffffffff0000ffffffff490370020100000080cbffff7ffaffff030000000000000000000000abc904f1024ac10ef9c6ffff90cbffff000000000000000090cbffff87faffff84020e030100000080c5ffff40f6ffff0300000000000000000000004bc805f13a4ac10e65c5ffff41c4ffff000000000000000065c5ffff37f6ffff')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 0
Layer 0: NR-ARFCN: 431070, SCell PCI: 65535/SSB: 15, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 2 (S: 255)
└── Cell 0: PCI:  841, PBCH SFN: 624, RSRP: -105.00, RSRQ: -11.01, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -114.05/-104.88, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): -104.88/-10.95
└── Cell 1: PCI:  644, PBCH SFN: 782, RSRP: -117.00, RSRQ: -19.50, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -117.21/-119.49, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): -117.21/-19.57''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('070002000114000084010000f9ffffffde9306000200dc0303000000ccc7ffffe8c7ffffffffffffffff0000ffffffffdc03a002010000002fcafffff7f9ffff030000000000000000000000c722c408ce9948035bcaffff46c6ffff49cafffffcf9ffff0000000000000000db030e000100000008c8ffffc9f8ffff030000000000000000000000c722c408ce994803d4c7ffff83c5ffff1ec8ffffc3f8ffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 431070, SCell PCI:  988/SSB: 3, RSRP: -112.41/-112.19, RX beam: NA/NA, Num Cells: 2 (S: 0)
└── Cell 0: PCI:  988, PBCH SFN: 672, RSRP: -107.63, RSRQ: -12.07, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -107.29/-115.45, Filtered RSRP/RSRQ (Nr2Nr): -107.43/-12.03, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
└── Cell 1: PCI:  987, PBCH SFN: 14, RSRP: -111.94, RSRQ: -14.43, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -112.34/-116.98, Filtered RSRP/RSRQ (Nr2Nr): -111.77/-14.48, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # major 2 minor 9, corner cases in num_cells
        payload = binascii.unhexlify('09000200008044a001000000d10600008f99f105de930600ff02ffffffff00000000000000000000ffffffffffff0000ffffffffdc03600201000000edc6ffff25f8ffff030000000000000000000000438aa28f6f8c2100edc6ffffbac6ffff00000000000000000000000000000000db03600201000000c3c8ffff28f7ffff0300000000000000000000000f6fa38f778c2100c3c8ffffbec5ffff00000000000000000000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 0
Layer 0: NR-ARFCN: 431070, SCell PCI: 65535/SSB: 15, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 255 (S: 2)
└── Cell 0: PCI:  988, PBCH SFN: 608, RSRP: -114.15, RSRQ: -15.71, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -114.15/-114.55, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00
└── Cell 1: PCI:  987, PBCH SFN: 608, RSRP: -110.48, RSRQ: -17.69, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -110.48/-116.52, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('090002000000d3090114000027070000000000005e63020000016203000300000000000000000000ffffffffffff0000ffffffff62033a010100000047d0ffffa9faffff030000000000000000000000c93eaab40d9bd100d6c8ffff10d1ffff47d0ffffa9faffff0000000000000000')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 20
Layer 0: NR-ARFCN: 156510, SCell PCI:  866/SSB: 0, RSRP: 0.00/0.00, RX beam: NA/NA, Num Cells: 0 (S: 1)
└── Cell 0: PCI:  866, PBCH SFN: 314, RSRP: -95.45, RSRQ: -10.68, Num Beams: 1
    └── Beam 0: SSB[3] Beam ID: 0/0, RSRP: -110.33/-93.88, Filtered RSRP/RSRQ (Nr2Nr): -95.45/-10.68, Filtered RSRP/RSRQ (L2Nr): 0.00/0.00''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

        # Version 3.0
        payload = binascii.unhexlify('00000300000081b601000000ec010000f49bb8f1de930600ff02ffffffff000000000000000000000000000000000000ffffffffffff0000ffffffffa901da01010000001ec7ffff2dfaffff000001000000000000000000c37fa8613b8e260d1ec7ffffd1c6ffff2dfaffffa9f8ffff000000000000000000000000000000000000000000000000000000000000000000000000000000001ec7ffff2dfaffffe701da010100000061c5ffffb6f8ffff0000010000000000000000009bfea7612b8e260d00b2ffffe1c6ffff80eaffffb6f8ffff0000000000000000000000000000000000000000000000000000000000000000000000000000000061c5ffffb6f8ffff')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload), length2=len(payload),
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_ML1_MEAS_DATABASE_UPDATE), timestamp=0)
        result = self.parser.parse_nr_ml1_meas_db_update(pkt_header, payload,None)
        expected = {'stdout': '''NR ML1 Meas Packet: Layers: 1, ssb_periocity: 0
Layer 0: NR-ARFCN: 431070, SCell PCI: 65535/SSB: 15, RSRP: 0.00/0.00/0.00/0.00, RX beam: NA/NA, Num Cells: 2 (S: 255)
└── Cell 0: PCI:  425, PBCH SFN: 474, RSRP: -113.77, RSRQ: -11.65, Num Beams: 1
    └── Beam 0: SSB[0] Beam ID: 0/0, RSRP: -113.77/-114.37, RSRQ: -11.65/-14.68, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): -113.77/-11.65
└── Cell 1: PCI:  487, PBCH SFN: 474, RSRP: -117.24, RSRQ: -14.58, Num Beams: 1
    └── Beam 0: SSB[0] Beam ID: 0/0, RSRP: -156.00/-114.24, RSRQ: -43.00/-14.58, Filtered RSRP/RSRQ (Nr2Nr): 0.00/0.00, Filtered RSRP/RSRQ (L2Nr): -117.24/-14.58''',
                    'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)}
        self.assertDictEqual(result, expected)

    # NR RRC
    def test_parse_nr_mib_info(self):
        # Version 0.3
        payload = binascii.unhexlify('030000005001c0ac05009a00003f')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR MIB: NR-ARFCN: 371904, PCI:  336, SFN: 154, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Version 2.0
        payload = binascii.unhexlify('0000020050010eb005001e036a1b0c')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR MIB: NR-ARFCN: 372750, PCI:  336, SFN: 798, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('00000200dc03de93060000806a0b00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_MIB_INFO), timestamp=0)
        result = self.parser.parse_nr_mib_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR MIB: NR-ARFCN: 431070, PCI:  988, SFN: 0, SCS: 15 kHz',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

    def test_parse_nr_rrc_scell_info(self):
        # Version 0.4
        payload = binascii.unhexlify('040000009d02e0ca0900d6c609005a005a0000127df204000000060102010001297900004e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR RRC SCell Info: NR-ARFCN: 641760/640726, Bandwidth: 90/90 MHz, Band: 78, PCI:  669, MCC: 262, MNC: 01, xTAC/xCID: 7929/4f27d1200',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        payload = binascii.unhexlify('040000001a00a0a40900c492090050005000ca409b060000000006010202000094c000004e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR RRC SCell Info: NR-ARFCN: 631968/627396, Bandwidth: 80/80 MHz, Band: 78, PCI:   26, MCC: 262, MNC: 02, xTAC/xCID: c094/69b40ca',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Version 3.2
        payload = binascii.unhexlify('020003000101006203d580194800222f065e630200183502000a000a00d58019480000000006010202000096c000001c00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR RRC SCell Info: NR-ARFCN: 156510/144664, Bandwidth: 10/10 MHz, Band: 28, PCI:  866, MCC: 262, MNC: 02, xTAC/xCID: c096/481980d5',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Version 3.3
        payload = binascii.unhexlify('030003000101004b0001c83b57252230001aee0100080e02000a000a0001c83b57050000002e0103dc00008eb921004700')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), timestamp=0)
        result = self.parser.parse_nr_rrc_scell_info(pkt_header, payload, None)
        expected = {
            'stdout': 'NR RRC SCell Info: NR-ARFCN: 126490/134664, Bandwidth: 10/10 MHz, Band: 71, PCI:   75, MCC: 302, MNC: 220, xTAC/xCID: 21b98e/5573bc801',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

    def test_parse_nr_rrc_conf_info(self):
        # Version 0.8

        # Version 0.A

        # Version 2.0

        # Version 3.3

        # Version 3.4

        # Version 3.8
        pass

    def test_parse_nr_rrc(self):
        payload = binascii.unhexlify('')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_OTA_MESSAGE), timestamp=0)
        # result = self.parser.parse_nr_rrc(pkt_header, payload, None)
        # expected = {
        # }
        # self.assertDictEqual(result, expected)

        # Version 9

        # Version 12

        # Version 14

        # Version 17

        # Version 19

        # Version 20

        # Version 23

        # Version 26
        payload = binascii.unhexlify('1a000000118001ffff0000000000000000ffffffff48fcb50b000000008a01000000000c81685c40b04432c55fca120dc4e81fa7780018c9230422405d079b6020d6e9d3b89a968d27bc0001a403000001a59c32c562e46e08040000021003420146d00005fb9c0000069d5ce1962c0110038b8d441992305e7046e10dc31b8837d9a6b52b1d2104e467cbbf00202c04930b6a0123ffff0000000200082cc86e1084001ec46ca41c1944174c08008810048000405010161c0954005450c00ca00080099aaa2400a000820610286c0000d2428060400692540304003494a0183001a4b500c2000d262806140069354033e003494a030060490f9349a47493400800c10ece08dc21b8637106f1ffa147398a4e5028200805700008000100000000010ca8080cc554560470001084002a216a5c300e0202208005442d4b8601c080421000a885a9710038180882001510b52e20030422a5400544352a102088018000810180200201c0aa002a284000000801000201400880a000802f0004166208208784ff907f8798cc00100000002b8000f0001a4f78201840008140000001011201001c0000001fd929289494')
        payload = binascii.unhexlify('1a000000118001ffff0000000000000000ffffffff48fc5524000000000900000000001409289f8ec50a4d83')
        payload = binascii.unhexlify('1a000000118001a9010000000000000000de9306000000000c0000000001000000000000')
        payload = binascii.unhexlify('1a0000001180ffa9010000000000000000de9306000000000100000000040000000000022394e0')
        payload = binascii.unhexlify('1a0000001180ffe701000000000000000000ba09000000100100000000040000000000078624a0')
        payload = binascii.unhexlify('1a0000001180ffa9010000000000000000f28406000000f8010000000004000000000056f594e4')
        payload = binascii.unhexlify('1a0000001180ffe7010000000000000000de93060000000001000000000400000000005e2394a0')
        payload = binascii.unhexlify('1a000000118000a9010000000000000000de930600105000020200000054000000000064858c1200012310309315403cd4100002200000d2ce19621f370402000001080004106840280c2003384000bf73800000d3ab9c32c58022007171a88332460bce08dc21b8637106fb35f16a563a80539a6ec300')
        payload = binascii.unhexlify('1a000000118000e701000000000000000000ba0900288000020200000065000000000064858c120001231030981ce04bd6109a04c0000508d1b9861f370402000001080004106840280c2200840000509aba3730d801200ed71a8833224cbde08dc21b8637106e28dc61b9037246fb35f179d63c80498019808c040601008000094af72180000000')


    def test_parse_nr_mm_state(self):
        # Version 0.1
        payload = binascii.unhexlify('0100000003000054f0800254f080a206001636ac480400a040fe')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE), timestamp=0)
        result = self.parser.parse_nr_mm_state(pkt_header, payload, None)
        expected = {
            'stdout': '5GMM State: 3/0/0, MCC/MNC: 450/08, TAC: a040fe, GUTI: 450-08-a2-006-16-0448ac36',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

        # Version 3.0
        payload = binascii.unhexlify('000003000300000302220203022255c40332d6c214c00021b98e00')
        pkt_header = self.log_header(cmd_code=0x10, reserved=0, length1=len(payload) + 12, length2=len(payload) + 12,
                                     log_id=diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_NAS_5GMM_STATE), timestamp=0)
        result = self.parser.parse_nr_mm_state(pkt_header, payload, None)
        expected = {
            'stdout': '5GMM State: 3/0/0, MCC/MNC: 302/220, TAC: 21b98e, GUTI: 302-220-55-3c4-32-c014c2d6',
            'ts': datetime.datetime(1980, 1, 6, 0, 0, tzinfo=datetime.timezone.utc)
        }
        self.assertDictEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
