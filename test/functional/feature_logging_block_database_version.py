#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real first-start block DB upgrade event agrees with the node's version."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockDatabaseVersionLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        version = node.getnetworkinfo()["version"]
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        event = {row.get("event"): row for row in rows}[
            "block_index_database_upgrading"
        ]
        assert_equal(event["version"], version)
        assert type(event["version"]) is int
        assert_equal(
            event["message"],
            f"Updating the block index database version to {version}",
        )
        assert_equal(event["level"], "info")
        assert "fields_truncated" not in event


if __name__ == "__main__":
    BlockDatabaseVersionLoggingTest().main()
