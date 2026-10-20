#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mempool persistence logs expose typed counts, seconds and recovery errors."""

import json
import math

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MempoolPersistenceLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-persistmempool=1"]]

    def records(self):
        # Called only with the node stopped, so its async logger has flushed.
        return [
            json.loads(line)
            for line in self.nodes[0].debug_log_path.read_text().splitlines()
            if line.strip()
        ]

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        self.stop_node(0)
        records = self.records()
        assert any(row.get("event") == "mempool_file_open_failed" for row in records)
        self.start_node(0)
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        assert_equal(node.getrawmempool(), [])
        self.stop_node(0)
        records = self.records()
        imported = next(
            row
            for row in records
            if row.get("event") == "mempool_file_import_completed"
        )
        for name in ("succeeded", "failed", "expired", "present", "waiting_broadcast"):
            value = imported[f"mempool_import_{name}_count"]
            assert type(value) is int
            assert_equal(value, 0)
        assert_equal(
            imported["message"],
            "Imported mempool transactions from disk: 0 succeeded, 0 failed, "
            "0 expired, 0 already there, 0 waiting for initial broadcast",
        )
        dumped = next(
            row for row in records if row.get("event") == "mempool_file_dump_completed"
        )
        for name in ("mempool_copy_seconds", "mempool_dump_seconds"):
            value = dumped[name]
            assert type(value) in (int, float) and math.isfinite(value) and value >= 0
        assert dumped["message"].startswith("Dumped mempool: ")
        assert "s to copy, " in dumped["message"] and dumped["message"].endswith(
            "s to dump"
        )
        waiting = next(
            row
            for row in records
            if row.get("event") == "mempool_file_unbroadcast_write_started"
        )
        assert type(waiting["count"]) is int
        assert_equal(waiting["count"], 0)

        # These are owned test files, not a user wallet or node data directory.
        (node.chain_path / "mempool.dat").write_bytes(b"\x01")
        self.start_node(0)
        self.wait_until(lambda: node.getmempoolinfo()["loaded"])
        assert_equal(node.getrawmempool(), [])
        # An unopenable .new file returns false without logging. Instead block
        # the destination rename to exercise the existing caught exception.
        blocked_output = node.chain_path / "mempool.dat"
        blocked_output.unlink()
        blocked_output.mkdir()
        self.stop_node(0)
        blocked_output.rmdir()
        records = self.records()
        for event, text in (
            (
                "mempool_file_deserialize_failed",
                "Failed to deserialize mempool data on disk: ",
            ),
            ("mempool_file_dump_failed", "Failed to dump mempool: "),
        ):
            failed = next(row for row in records if row.get("event") == event)
            assert isinstance(failed["error"], str) and failed["error"]
            assert failed["message"].startswith(text)
            assert failed["message"].endswith(". Continuing anyway.")
            assert "fields_truncated" not in failed


if __name__ == "__main__":
    MempoolPersistenceLoggingTest().main()
