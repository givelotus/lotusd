#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Configured cache budgets remain numeric MiB with unchanged readable precision."""

import json
import math

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CacheBudgetLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [
        ["-logformat=json", "-txindex=1", "-blockfilterindex=1", "-dbcache=96"]
    ]

    def run_test(self):
        node = self.nodes[0]
        # Shutdown flushes the async logger before reading the primary log.
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        for event, suffix in (
            ("cache_block_index_budget", "block index database"),
            ("cache_transaction_index_budget", "transaction index database"),
            ("cache_chainstate_database_budget", "chain state database"),
            ("cache_block_filter_index_budget", "block filter index database"),
        ):
            row = next(row for row in records if row.get("event") == event)
            budget = row["database_cache_mib"]
            assert (
                type(budget) in (int, float) and math.isfinite(budget) and budget >= 0
            )
            if event == "cache_block_filter_index_budget":
                assert isinstance(row["name"], str) and row["name"]
                suffix = f"{row['name']} {suffix}"
            assert_equal(row["message"], f"* Using {budget:.1f} MiB for {suffix}")
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        row = next(
            row for row in records if row.get("event") == "cache_utxo_memory_budget"
        )
        for name in ("utxo_cache_mib", "unused_mempool_cache_mib"):
            value = row[name]
            assert type(value) in (int, float) and math.isfinite(value) and value >= 0
        assert_equal(
            row["message"],
            f"* Using {row['utxo_cache_mib']:.1f} MiB for in-memory UTXO set "
            f"(plus up to {row['unused_mempool_cache_mib']:.1f} MiB of unused mempool space)",
        )
        assert_equal(row["level"], "info")
        assert "fields_truncated" not in row


if __name__ == "__main__":
    CacheBudgetLoggingTest().main()
