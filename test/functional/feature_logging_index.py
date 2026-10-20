#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Typed index startup diagnostics follow real indexing, restart and height."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class IndexLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-txindex=1", "-blockfilterindex=1"]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 2)
        tip = node.getbestblockhash()
        self.wait_until(
            lambda: all(
                row["synced"] and row["best_block_height"] == 2
                for row in node.getindexinfo().values()
            )
        )
        assert_equal(len(node.getindexinfo()), 2)
        assert node.verifychain(4, 0)
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        self.wait_until(
            lambda: all(
                row["synced"] and row["best_block_height"] == 2
                for row in node.getindexinfo().values()
            )
        )
        self.stop_node(0)  # Join index workers and flush the async logger.
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        enabled = [
            row for row in records if row.get("event") == "index_enabled_at_height"
        ]
        for name in ("txindex", "basic block filter index"):
            row = next(
                row for row in enabled if row["name"] == name and row["height"] == 2
            )
            assert type(row["height"]) is int
            assert_equal(row["message"], f"{name} is enabled at height 2")
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    IndexLoggingTest().main()
