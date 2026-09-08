#!/usr/bin/env python3

import unittest
import binascii
import logging
import struct
from collections import namedtuple

import scat.util as util
import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagltelogparser import DiagLteLogParser
from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser

_T = util.gsmtapv3_metadata_tags
_NAME = {int(t): t.name for t in _T}
_FLOAT_TAGS = {int(getattr(_T, x)) for x in ('SIGNAL_LEVEL', 'RSSI', 'SNR', 'SINR', 'RSCP',
    'ECIO', 'RSRP', 'RSRQ', 'SS_RSRP', 'CSI_RSRP', 'SRS_RSRP', 'SS_RSRQ', 'CSI_RSRQ',
    'SS_SINR', 'CSI_SINR')}
_H2_TAGS = {int(_T.BSIC_PSC_PCI), int(_T.BAND_INDICATOR), int(_T.SUBFN), int(_T.HFN)}


def decode_gsmtapv3(pkt):
    """Decode a GSMTAPv3 packet into {'_type': name, tag_name: value, ...}."""
    version, _reserved, _hlen, ptype, _stype = struct.unpack('!BBHHH', pkt[0:8])
    assert version == 3, 'expected GSMTAPv3, got version %d' % version
    out = {'_type': util.gsmtapv3_types(ptype).name}
    o = 8
    while o < len(pkt):
        tag = struct.unpack('!H', pkt[o:o+2])[0]
        o += 2
        if tag == int(_T.END_OF_METADATA):
            break
        ln = struct.unpack('!H', pkt[o:o+2])[0]
        o += 2
        val = pkt[o:o+ln]
        o += ln
        if tag in _FLOAT_TAGS:
            v = struct.unpack('!f', val)[0]
        elif tag in _H2_TAGS:
            v = struct.unpack('!H', val)[0]
        elif tag == int(_T.CHANNEL_NUMBER):
            v = struct.unpack('!L', val)[0]
        else:
            v = val
        out[_NAME.get(tag, hex(tag))] = v
    return out


class FakeParent:
    def __init__(self):
        self.cell_kv = False
        self.meas_gsmtap = True
        self.display_format = 'x'
        self.gsmtapv3 = False
        self.logger = logging.getLogger('scat.test')
        self.lte_serving_cell = [{}, {}]
        self.nr_serving_cell = [{}, {}]


log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')


def lte_hdr(code):
    return log_header(0x10, 0, 0, 0, diagcmd.diag_log_get_lte_item_id(code), 0)


class TestBuildSignalStatusReport(unittest.TestCase):
    def test_lte_metrics_and_tags(self):
        pkt = util.build_signal_status_report(6300, pci=214, band=20, rsrp=-101.25, rsrq=-14.0625, rssi=-66.625)
        d = decode_gsmtapv3(pkt)
        self.assertEqual(d['_type'], 'SIGNAL_STATUS_REPORT')
        self.assertEqual(d['CHANNEL_NUMBER'], 6300)
        self.assertEqual(d['BSIC_PSC_PCI'], 214)
        self.assertEqual(d['BAND_INDICATOR'], 20)
        self.assertAlmostEqual(d['RSRP'], -101.25, places=4)
        self.assertAlmostEqual(d['RSRQ'], -14.0625, places=4)
        self.assertAlmostEqual(d['RSSI'], -66.625, places=4)

    def test_nr_uses_ss_tags(self):
        pkt = util.build_signal_status_report(632628, pci=500, rsrp=-88.5, rsrq=-11.5, is_nr=True)
        d = decode_gsmtapv3(pkt)
        self.assertIn('SS_RSRP', d)
        self.assertIn('SS_RSRQ', d)
        self.assertNotIn('RSRP', d)  # NR must not use the LTE tag

    def test_none_metrics_omitted(self):
        pkt = util.build_signal_status_report(6300, pci=1, rsrp=-90.0)
        d = decode_gsmtapv3(pkt)
        self.assertIn('RSRP', d)
        self.assertNotIn('RSRQ', d)
        self.assertNotIn('RSSI', d)


class TestLteMeasGsmtap(unittest.TestCase):
    def setUp(self):
        self.parent = FakeParent()
        self.parser = DiagLteLogParser(parent=self.parent)

    def test_scell_emits_signal_report(self):
        # band comes from the RRC serving-cell cache join
        self.parent.lte_serving_cell[0] = {'pci': 214, 'earfcn': 6300, 'band': 20,
            'plmn': '0', 'mcc': 0, 'mnc': 0, 'tac': 0, 'cid': 0, 'bwmhzdl': 0, 'bwmhzul': 0}
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = self.parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertEqual(len(r['cp']), 1)
        d = decode_gsmtapv3(r['cp'][0])
        self.assertEqual(d['_type'], 'SIGNAL_STATUS_REPORT')
        self.assertEqual(d['CHANNEL_NUMBER'], 6300)
        self.assertEqual(d['BSIC_PSC_PCI'], 214)
        self.assertEqual(d['BAND_INDICATOR'], 20)
        self.assertAlmostEqual(d['RSRP'], -101.25, places=4)
        self.assertAlmostEqual(d['RSRQ'], -14.0625, places=4)
        self.assertAlmostEqual(d['RSSI'], -66.625, places=4)

    def test_ncell_emits_one_report_per_cell(self):
        payload = binascii.unhexlify('040100009C1847008348E44DDEA44C00CAB4CC32B6D8420300000000FF773301FF77330122020100')
        r = self.parser.parse_lte_ml1_ncell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS), payload, dict())
        self.assertEqual(len(r['cp']), 1)
        d = decode_gsmtapv3(r['cp'][0])
        self.assertEqual(d['CHANNEL_NUMBER'], 6300)
        self.assertEqual(d['BSIC_PSC_PCI'], 131)
        self.assertAlmostEqual(d['RSRP'], -102.125, places=4)
        self.assertAlmostEqual(d['RSRQ'], -17.3125, places=4)

    def test_disabled_by_default(self):
        parser = DiagLteLogParser(parent=None)
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertNotIn('cp', r)


class TestNrMeasGsmtap(unittest.TestCase):
    ML1_MEAS = '070002000114000026ffffff44000000991006000100c602000000000000000000000000ffffffffffff0000ffffffffc6027e000100000017caffff0afaffff000000000000000000000000a5a1dbbd4199a005a3bcffff17caffff17caffff0afaffff0000000000000000'

    def setUp(self):
        self.parent = FakeParent()
        self.parser = DiagNrLogParser(parent=self.parent)

    def test_emits_ss_reports(self):
        r = self.parser.parse_nr_ml1_meas_db_update(log_header(0x10, 0, 0, 0, 0, 0), binascii.unhexlify(self.ML1_MEAS), dict())
        # one serving-layer report + one detected-cell report
        self.assertEqual(len(r['cp']), 2)
        serv = decode_gsmtapv3(r['cp'][0])
        self.assertEqual(serv['_type'], 'SIGNAL_STATUS_REPORT')
        self.assertEqual(serv['CHANNEL_NUMBER'], 397465)
        self.assertEqual(serv['BSIC_PSC_PCI'], 710)
        self.assertIn('SS_RSRP', serv)
        ncell = decode_gsmtapv3(r['cp'][1])
        self.assertEqual(ncell['BSIC_PSC_PCI'], 710)
        self.assertAlmostEqual(ncell['SS_RSRP'], -107.8203125, places=4)
        self.assertAlmostEqual(ncell['SS_RSRQ'], -11.921875, places=4)

    def test_disabled_by_default(self):
        parser = DiagNrLogParser(parent=None)
        r = parser.parse_nr_ml1_meas_db_update(log_header(0x10, 0, 0, 0, 0, 0), binascii.unhexlify(self.ML1_MEAS), dict())
        self.assertNotIn('cp', r)


if __name__ == '__main__':
    unittest.main()
