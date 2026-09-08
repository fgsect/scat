#!/usr/bin/env python3

import unittest
import binascii
import logging
from collections import namedtuple

import scat.util as util
import scat.parsers.qualcomm.diagcmd as diagcmd
from scat.parsers.qualcomm.diagltelogparser import DiagLteLogParser
from scat.parsers.qualcomm.diagnrlogparser import DiagNrLogParser


class FakeParent:
    """Minimal stand-in for QualcommParser carrying the --cell-kv flag and the
    per-radio serving-cell identity caches consumed by the log parsers."""
    def __init__(self):
        self.cell_kv = True
        self.display_format = 'x'
        self.gsmtapv3 = False
        self.logger = logging.getLogger('scat.test')
        self.lte_last_cell_id = [0, 0]
        self.lte_last_earfcn_dl = [0, 0]
        self.lte_last_earfcn_ul = [0, 0]
        self.lte_last_bw_dl = [0, 0]
        self.lte_last_bw_ul = [0, 0]
        self.lte_serving_cell = [{}, {}]
        self.nr_serving_cell = [{}, {}]
        self.lte_serving_signal = [{}, {}]
        self.nr_serving_signal = [{}, {}]


log_header = namedtuple('QcDiagLogHeader', 'cmd_code reserved length1 length2 log_id timestamp')


def lte_hdr(code):
    return log_header(0x10, 0, 0, 0, diagcmd.diag_log_get_lte_item_id(code), 0)


class TestCellKvUtil(unittest.TestCase):
    def test_dl_earfcn_to_frequency_hz(self):
        self.assertEqual(util.dl_earfcn_to_frequency_hz(1850), 1870000000)  # B3
        self.assertEqual(util.dl_earfcn_to_frequency_hz(6300), 806000000)   # B20
        self.assertEqual(util.dl_earfcn_to_frequency_hz(2400), 869000000)   # B5
        self.assertEqual(util.dl_earfcn_to_frequency_hz(999999), 0)         # out of range

    def test_nrarfcn_to_frequency_hz(self):
        self.assertEqual(util.nrarfcn_to_frequency_hz(519953), 2599765000)
        self.assertEqual(util.nrarfcn_to_frequency_hz(632628), 3489420000)  # n78
        self.assertEqual(util.nrarfcn_to_frequency_hz(9999999), 0)          # out of range

    def test_format_plmn(self):
        self.assertEqual(util.format_plmn(460, 11, 2), '46011')
        self.assertEqual(util.format_plmn(302, 220, 3), '302220')
        self.assertEqual(util.format_plmn(None, None), '0')

    def test_serving_identity_fields_match_guard(self):
        cache = {'earfcn': 6300, 'pci': 214, 'plmn': '310260', 'mcc': 310, 'mnc': 260,
                 'tac': 7, 'cid': 1, 'band': 20, 'bwmhzdl': 10, 'bwmhzul': 10}
        self.assertEqual(util.serving_identity_fields(cache, 6300, 214)['band'], 20)
        self.assertEqual(util.serving_identity_fields(cache, 6300, 999), {})  # pci mismatch
        self.assertEqual(util.serving_identity_fields(cache, 100, 214), {})   # earfcn mismatch
        self.assertEqual(util.serving_identity_fields({}, 6300, 214), {})     # empty cache


class TestLteCellKv(unittest.TestCase):
    def setUp(self):
        self.parent = FakeParent()
        self.parser = DiagLteLogParser(parent=self.parent)

    def test_scell_meas_kv(self):
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = self.parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertEqual(r['stdout'], 'pci=214,earfcn=6300,earfcn_ul=24300,frequency=806000000,protocol=lte,cell=scell,plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0 rssi=-66.625,rsrp=-101.25,rsrq=-14.0625')

    def test_ncell_meas_kv(self):
        payload = binascii.unhexlify('040100009C1847008348E44DDEA44C00CAB4CC32B6D8420300000000FF773301FF77330122020100')
        r = self.parser.parse_lte_ml1_ncell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_NEIGHBOR_MEASUREMENTS), payload, dict())
        self.assertEqual(r['stdout'], 'pci=131,earfcn=6300,earfcn_ul=24300,frequency=806000000,protocol=lte,cell=ncell,plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0 rssi=-75.75,rsrp=-102.125,rsrq=-17.3125')

    def test_rrc_cell_info_populates_cache(self):
        payload = binascii.unhexlify('034D0021070000714D00004B4B33C8B009159B03000000CC01020B0000')
        self.parser.parse_lte_rrc_cell_info(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), payload, dict())
        self.assertEqual(self.parent.lte_serving_cell[0], {
            'pci': 77, 'earfcn': 1825, 'plmn': '46011', 'mcc': 460, 'mnc': 11,
            'tac': 39701, 'cid': 162580531, 'band': 3, 'bwmhzdl': 15, 'bwmhzul': 15})

    def test_scell_meas_kv_join_hit(self):
        # Serving cell identity from a prior RRC SCell Info is joined onto the ML1 measurement.
        self.parent.lte_serving_cell[0] = {'pci': 214, 'earfcn': 6300, 'plmn': '310260',
            'mcc': 310, 'mnc': 260, 'tac': 7, 'cid': 123456, 'band': 20, 'bwmhzdl': 10, 'bwmhzul': 10}
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = self.parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertEqual(r['stdout'], 'pci=214,earfcn=6300,earfcn_ul=24300,frequency=806000000,protocol=lte,cell=scell,plmn=310260,mcc=310,mnc=260,tac=7,cid=123456,band=20,bwmhzdl=10,bwmhzul=10 rssi=-66.625,rsrp=-101.25,rsrq=-14.0625')

    def test_scell_meas_kv_join_mismatch_guard(self):
        # Cached serving cell is a *different* cell -> identity must NOT be joined.
        self.parent.lte_serving_cell[0] = {'pci': 77, 'earfcn': 1825, 'plmn': '46011',
            'mcc': 460, 'mnc': 11, 'tac': 39701, 'cid': 1, 'band': 3, 'bwmhzdl': 15, 'bwmhzul': 15}
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = self.parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertIn('plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0', r['stdout'])

    def test_default_output_unchanged(self):
        # parent=None => cell_kv defaults off => original human-readable output.
        parser = DiagLteLogParser(parent=None)
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        r = parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        self.assertTrue(r['stdout'].startswith('LTE SCell: EARFCN: 6300'))


class TestNrCellKv(unittest.TestCase):
    ML1_MEAS = '070002000114000026ffffff44000000991006000100c602000000000000000000000000ffffffffffff0000ffffffffc6027e000100000017caffff0afaffff000000000000000000000000a5a1dbbd4199a005a3bcffff17caffff17caffff0afaffff0000000000000000'

    def setUp(self):
        self.parent = FakeParent()
        self.parser = DiagNrLogParser(parent=self.parent)

    def test_meas_db_update_kv(self):
        r = self.parser.parse_nr_ml1_meas_db_update(log_header(0x10, 0, 0, 0, 0, 0), binascii.unhexlify(self.ML1_MEAS), dict())
        self.assertEqual(r['stdout'],
            'pci=710,earfcn=397465,earfcn_ul=397465,frequency=1987325000,protocol=nr,cell=scell,plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0 rssi=0,rsrp=0,rsrq=0\n'
            'pci=710,earfcn=397465,earfcn_ul=397465,frequency=1987325000,protocol=nr,cell=ncell,plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0 rssi=0,rsrp=-107.8203125,rsrq=-11.921875')

    def test_meas_db_update_kv_skips_absent_serving_cell(self):
        # serv_cell_pci == 0xffff means the UE has no serving cell on this measured
        # carrier — SCAT must not emit an all-zero scell row for it. (These bogus
        # rows are what made SA-NR captures look like "no TAC/CID".)
        baseline = self.parser.parse_nr_ml1_meas_db_update(
            log_header(0x10, 0, 0, 0, 0, 0), binascii.unhexlify(self.ML1_MEAS), dict())
        self.assertIn('cell=scell', baseline['stdout'])   # normally emits one
        b = bytearray(binascii.unhexlify(self.ML1_MEAS))
        b[22:24] = b'\xff\xff'   # serv_cell_pci -> 0xffff
        r = self.parser.parse_nr_ml1_meas_db_update(
            log_header(0x10, 0, 0, 0, 0, 0), bytes(b), dict())
        self.assertNotIn('cell=scell', r['stdout'])

    def test_rrc_scell_info_populates_cache(self):
        payload = binascii.unhexlify('040000009d02e0ca0900d6c609005a005a0000127df204000000060102010001297900004e00')
        pkt_header = log_header(0x10, 0, 0, 0, diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), 0)
        self.parser.parse_nr_rrc_scell_info(pkt_header, payload, dict())
        self.assertEqual(self.parent.nr_serving_cell[0], {
            'pci': 669, 'earfcn': 641760, 'earfcn_ul': 640726, 'plmn': '26201',
            'mcc': 262, 'mnc': 1, 'tac': 31017, 'cid': 21248152064, 'band': 78,
            'bwmhzdl': 90, 'bwmhzul': 90})

    def test_meas_db_update_kv_join_hit(self):
        # Serving cell enriched from cache (incl. real UL NR-ARFCN); neighbor cell left untouched
        # even though it shares the same PCI/NR-ARFCN in this capture.
        self.parent.nr_serving_cell[0] = {'pci': 710, 'earfcn': 397465, 'earfcn_ul': 390000,
            'plmn': '26201', 'mcc': 262, 'mnc': 1, 'tac': 31017, 'cid': 999, 'band': 41,
            'bwmhzdl': 100, 'bwmhzul': 100}
        r = self.parser.parse_nr_ml1_meas_db_update(log_header(0x10, 0, 0, 0, 0, 0), binascii.unhexlify(self.ML1_MEAS), dict())
        lines = r['stdout'].split('\n')
        self.assertEqual(lines[0], 'pci=710,earfcn=397465,earfcn_ul=390000,frequency=1987325000,protocol=nr,cell=scell,plmn=26201,mcc=262,mnc=1,tac=31017,cid=999,band=41,bwmhzdl=100,bwmhzul=100 rssi=0,rsrp=0,rsrq=0')
        self.assertIn('cell=ncell,plmn=0,mcc=0,mnc=0,tac=0,cid=0,band=0,bwmhzdl=0,bwmhzul=0', lines[1])


class TestCellIdFromRrc(unittest.TestCase):
    """Order-independent CellID capture: an RRC SCell Info packet emits a full
    identity-bearing kv line joined to the last ML1 serving signal, so CellID is
    captured even when the RRC packet arrives before the next ML1 measurement."""

    def setUp(self):
        self.parent = FakeParent()

    def test_lte_rrc_emits_kv_with_cellid_when_signal_cached(self):
        parser = DiagLteLogParser(parent=self.parent)
        self.parent.lte_serving_signal[0] = {'earfcn': 1825, 'pci': 77,
            'rssi': -60.0, 'rsrp': -95.5, 'rsrq': -11.0}
        payload = binascii.unhexlify('034D0021070000714D00004B4B33C8B009159B03000000CC01020B0000')
        r = parser.parse_lte_rrc_cell_info(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), payload, dict())
        self.assertEqual(r['stdout'], 'pci=77,earfcn=1825,earfcn_ul=19825,frequency=1867500000,protocol=lte,cell=scell,plmn=46011,mcc=460,mnc=11,tac=39701,cid=162580531,band=3,bwmhzdl=15,bwmhzul=15 rssi=-60.0,rsrp=-95.5,rsrq=-11.0')

    def test_lte_rrc_emits_nothing_without_cached_signal(self):
        parser = DiagLteLogParser(parent=self.parent)  # no signal cached
        payload = binascii.unhexlify('034D0021070000714D00004B4B33C8B009159B03000000CC01020B0000')
        r = parser.parse_lte_rrc_cell_info(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_RRC_SERVING_CELL_INFO), payload, dict())
        self.assertEqual(r['stdout'], '')  # all-zero-metric line suppressed

    def test_nr_rrc_emits_kv_with_cellid_when_signal_cached(self):
        parser = DiagNrLogParser(parent=self.parent)
        self.parent.nr_serving_signal[0] = {'earfcn': 641760, 'pci': 669, 'rsrp': -88.0}
        payload = binascii.unhexlify('040000009d02e0ca0900d6c609005a005a0000127df204000000060102010001297900004e00')
        pkt_header = log_header(0x10, 0, 0, 0, diagcmd.diag_log_get_lte_item_id(diagcmd.diag_log_code_5gnr.LOG_5GNR_RRC_SERVING_CELL_INFO), 0)
        r = parser.parse_nr_rrc_scell_info(pkt_header, payload, dict())
        self.assertEqual(r['stdout'], 'pci=669,earfcn=641760,earfcn_ul=640726,frequency=3626400000,protocol=nr,cell=scell,plmn=26201,mcc=262,mnc=1,tac=31017,cid=21248152064,band=78,bwmhzdl=90,bwmhzul=90 rssi=0,rsrp=-88.0,rsrq=0')

    def test_lte_ml1_scell_caches_signal(self):
        parser = DiagLteLogParser(parent=self.parent)
        payload = binascii.unhexlify('040100009C18D60AECC44E00E2244E00FFFCE30FFED80A0047AD56021D310100A2624100')
        parser.parse_lte_ml1_scell_meas(lte_hdr(diagcmd.diag_log_code_lte.LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL), payload, dict())
        sig = self.parent.lte_serving_signal[0]
        self.assertEqual(sig['earfcn'], 6300)
        self.assertEqual(sig['pci'], 214)
        self.assertAlmostEqual(sig['rsrp'], -101.25, places=4)


if __name__ == '__main__':
    unittest.main()
