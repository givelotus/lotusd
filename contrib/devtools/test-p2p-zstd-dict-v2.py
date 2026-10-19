#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reproduction, held-out isolation and framework wire tests for dictionary V2."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
import zstandard

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trainer = load('trainer', ROOT / 'contrib/devtools/gen-p2p-zstd-dict-v2.py')
ws = load('transport', ROOT / 'test/functional/test_framework/ws_transport.py')


class DictionaryV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = trainer.corpus(ROOT / 'contrib/testdata/p2p-zstd-v2/corpus.jsonl.gz')
        cls.raw = ws.p2p_zstd_dict()

    def test_reproduction(self):
        self.assertEqual(trainer.header(trainer.train(self.rows, 8192)),
                         (ROOT / 'src/net_zstd_dict_v2_data.h').read_text())

    def test_held_out_isolation(self):
        altered = copy.deepcopy(self.rows)
        for row in altered:
            if row['group'] == 3:
                row['raw'] = b'changed validation data must never enter trainer'
        self.assertEqual(trainer.train(altered, 8192), self.raw)

    def test_frozen_v1(self):
        old = load('v1', ROOT / 'contrib/devtools/gen-p2p-zstd-dict.py').build()
        self.assertEqual(hashlib.sha256(old).hexdigest(),
                         '203f6f89d0885bf101ee937150ba5357d9bfd917aefdf244b9e56177b50b771d')
        self.assertNotEqual(old, self.raw)
        self.assertEqual(ws.P2P_ZSTD_DICT_VERSION, 2)

    def test_native_stream_framework_decode(self):
        zdict = zstandard.ZstdCompressionDict(self.raw, dict_type=zstandard.DICT_TYPE_RAWCONTENT)
        encoder = zstandard.ZstdCompressor(level=1, dict_data=zdict).compressobj()
        decoder = ws.P2PV2Converter(b'\x01\x02\x03\x04')
        checked = 0
        for row in self.rows:
            if row['group'] != 3:
                continue
            raw = row['raw']
            wire = encoder.compress(raw) + encoder.flush(zstandard.COMPRESSOBJ_FLUSH_BLOCK)
            legacy = decoder.from_wire(wire, compressed=True)
            self.assertEqual(legacy[4:16].rstrip(b'\0').decode(), row['message'])
            self.assertEqual(struct.unpack('<I', legacy[16:20])[0], len(legacy[24:]))
            # Converter adds its legacy test harness envelope without changing
            # any native message payload bytes.
            prefix_len = 1 if raw[0] else 2 + raw[1]
            self.assertEqual(legacy[24:], raw[prefix_len:])
            checked += 1
        self.assertGreater(checked, 100)


if __name__ == '__main__':
    unittest.main()
