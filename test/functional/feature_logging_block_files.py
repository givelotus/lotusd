#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual block-file DB reload and owned empty/missing import diagnostics."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockFileLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        genesis_time = node.getblock(node.getblockhash(0))["time"]
        self.stop_node(0)
        empty = node.chain_path / "owned-empty-block-import.dat"
        missing = node.chain_path / "owned-missing-block-import.dat"
        empty.write_bytes(b"")
        assert not missing.exists()
        self.start_node(
            0, ["-logformat=json", f"-loadblock={empty}", f"-loadblock={missing}"]
        )
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        number = by_event["block_file_last_number"]
        assert_equal(number["source_function"], "LoadBlockIndexDB")
        assert_equal(number["file_number"], 0)
        assert isinstance(number["file_number"], int)
        assert_equal(number["message"], "LoadBlockIndexDB: last block file = 0")
        info = by_event["block_file_last_info"]
        assert_equal(info["source_function"], "LoadBlockIndexDB")
        assert isinstance(info["block_file_info"], str) and info["block_file_info"]
        assert_equal(
            info["message"],
            f"LoadBlockIndexDB: last block file info: {info['block_file_info']}",
        )
        assert_equal(info["file_number"], 0)
        for key in (
            "file_blocks",
            "block_file_bytes",
            "undo_file_bytes",
            "file_first_height",
            "file_last_height",
            "file_first_time_seconds",
            "file_last_time_seconds",
        ):
            assert isinstance(info[key], int) and info[key] >= 0
        assert_equal(info["file_blocks"], 1)
        assert info["block_file_bytes"] > 0
        assert_equal(info["undo_file_bytes"], 0)
        assert_equal(info["file_first_height"], 0)
        assert_equal(info["file_last_height"], 0)
        assert_equal(info["file_first_time_seconds"], genesis_time)
        assert_equal(info["file_last_time_seconds"], genesis_time)
        imported = by_event["block_file_import_started"]
        assert_equal(imported["path"], str(empty))
        assert_equal(imported["message"], f"Importing blocks file {empty}...")
        unopened = by_event["block_file_import_open_failed"]
        assert_equal(unopened["path"], str(missing))
        assert_equal(
            unopened["message"], f"Warning: Could not open blocks file {missing}"
        )
        for row in (number, info, imported, unopened):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    BlockFileLoggingTest().main()
