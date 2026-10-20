#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual startup selection retains signed limits and relative path semantics."""

import json
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ConnectionStartupLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [
        ["-logformat=json", "-avalanche=0", "-maxconnections=7", "-logratelimit=0"]
    ]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        # Keep all files in this test's datadir; only change how startup names it.
        parent = Path(node.datadir).parent
        relative = Path(node.datadir).name
        self.start_node(0, [*self.extra_args[0], f"-datadir={relative}"], cwd=parent)
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        selected = by_event["connection_limits_selected"]
        assert_equal(selected["connection_limit"], 7)
        assert isinstance(selected["connection_limit"], int)
        descriptors = selected["file_descriptor_limit"]
        assert isinstance(descriptors, int)
        assert descriptors >= 7
        assert_equal(
            selected["message"],
            f"Using at most 7 automatic connections ({descriptors} file descriptors available)",
        )
        disabled = by_event["log_rate_limit_disabled"]
        assert_equal(disabled["message"], "Log rate limiting disabled")
        path = by_event["relative_data_directory"]
        assert_equal(path["data_directory_argument"], relative)
        assert_equal(path["directory"], str(parent))
        assert "path" not in path
        assert_equal(
            path["message"],
            f"Warning: relative datadir option '{relative}' specified, which will be interpreted relative to the current working directory '{parent}'. This is fragile, because if bitcoin is started in the future from a different location, it will be unable to locate the current data files. There could also be data loss if bitcoin is started while in a temporary directory.",
        )
        for row in (selected, disabled, path):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    ConnectionStartupLoggingTest().main()
