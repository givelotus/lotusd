#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reject unknown snapshot commitments, then reindex owned staging metadata."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SnapshotStateLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-chronik=0"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        genesis = node.getblockhash(0)
        original = node.chain_path / "owned-genesis-snapshot.dat"
        missing = node.chain_path / "owned-missing-header-snapshot.dat"
        node.dumptxoutset(str(original), "latest")
        data = bytearray(original.read_bytes())
        assert_equal(data[:5], b"utxo\xff")
        assert len(data) >= 43
        # Preserve file magic, format version and network magic. Only this
        # owned copy's 32-byte base-block hash changes; no fake block is added.
        unknown = "12" * 32
        assert genesis != unknown
        data[11:43] = bytes.fromhex(unknown)[::-1]
        missing.write_bytes(data)
        for snapshot in (original, missing):
            assert_raises_rpc_error(
                -32603,
                "Unable to load UTXO snapshot: assumeutxo block hash in snapshot metadata not recognized",
                node.loadtxoutset,
                str(snapshot),
            )
            assert_equal(node.getblockcount(), 0)
            assert_equal(node.getbestblockhash(), genesis)
            assert not (node.chain_path / "chainstate_snapshot").exists()
        self.stop_node(0)
        # Startup must discard snapshot staging metadata before loading its
        # coin database when reindex-chainstate is explicitly requested. The
        # marker references the real genesis block; no fabricated block or
        # snapshot contents are supplied or activated.
        staging = node.chain_path / "chainstate_snapshot"
        staging.mkdir()
        (staging / "base_blockhash").write_bytes(bytes.fromhex(genesis)[::-1])
        self.start_node(0, ["-logformat=json", "-chronik=0", "-reindex-chainstate"])
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.getbestblockhash(), genesis)
        assert not staging.exists()
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        detected = events["snapshot_chainstate_detected"]
        assert_equal(detected["directory"], str(staging))
        assert_equal(
            detected["message"],
            f"[snapshot] detected active snapshot chainstate ({staging}) - loading",
        )
        switching = events["snapshot_active_chainstate_switching"]
        description = switching["chainstate_description"]
        assert isinstance(description, str) and description
        assert_equal(
            switching["message"],
            f"[snapshot] switching active chainstate to {description}",
        )
        removing = events["snapshot_database_directory_removing"]
        assert_equal(removing["directory"], str(staging))
        assert_equal(
            removing["message"],
            f"Removing leveldb dir at {staging}",
        )
        assert "snapshot_cleanup_base_hash_missing" not in events
        for row in (detected, switching, removing):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        assert "snapshot_activated" not in events
        assert "snapshot_fully_validated" not in events


if __name__ == "__main__":
    SnapshotStateLoggingTest().main()
