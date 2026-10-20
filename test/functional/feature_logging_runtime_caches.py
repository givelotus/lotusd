#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual early startup cache budgets remain typed unsigned MiB/capacities."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class RuntimeCacheLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-maxsigcachesize=2", "-maxscriptcachesize=2"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        for event, kind in (
            ("signature_cache_initialized", "signature"),
            ("script_execution_cache_initialized", "script execution"),
        ):
            row = by_event[event]
            assert_equal(row["cache_requested_mib"], 2)
            assert isinstance(row["cache_requested_mib"], int)
            allocated = row["cache_allocated_mib"]
            capacity = row["cache_capacity"]
            assert isinstance(allocated, int) and 0 <= allocated <= 2
            assert isinstance(capacity, int) and capacity > 0
            assert_equal(
                row["message"],
                f"Using {allocated} MiB out of 2 MiB requested for {kind} cache, able to store {capacity} elements",
            )
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    RuntimeCacheLoggingTest().main()
