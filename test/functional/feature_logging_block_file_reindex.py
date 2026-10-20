#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real reindex of an owned genesis block preserves its filename and height."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockFileReindexLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        genesis = node.getblockhash(0)
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        self.start_node(0, ["-logformat=json", "-reindex"])
        self.wait_until(
            lambda: "Reindexing finished" in node.debug_log_path.read_text(), timeout=5
        )
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.getbestblockhash(), genesis)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        reindex = events["block_file_reindexing"]
        assert_equal(reindex["file_number"], 0)
        assert type(reindex["file_number"]) is int
        assert_equal(reindex["message"], "Reindexing block file blk00000.dat...")
        assert_equal(reindex["level"], "info")
        assert "fields_truncated" not in reindex
        imported = events["block_file_external_import_completed"]
        count = imported["imported_block_count"]
        elapsed = imported["elapsed_milliseconds"]
        assert type(count) is int
        assert type(elapsed) is int
        assert_equal(
            imported["message"],
            f"Loaded {count} blocks from external file in {elapsed}ms",
        )
        assert_equal(imported["level"], "info")
        assert "fields_truncated" not in imported


if __name__ == "__main__":
    BlockFileReindexLoggingTest().main()
