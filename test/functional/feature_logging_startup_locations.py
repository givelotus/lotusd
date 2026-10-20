#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Startup location fields keep their real paths and existing timestamp guard."""

import json
from datetime import datetime, timezone
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class StartupLocationsLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-logtimestamps=0"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        startup = next(row for row in rows if row.get("event") == "node_startup_time")
        displayed = startup["startup_time"]
        parsed = datetime.fromisoformat(displayed.replace("Z", "+00:00"))
        assert_equal(parsed.tzinfo, timezone.utc)
        assert_equal(startup["message"], "Startup time: " + displayed)
        for event, prefix, expected in (
            ("node_default_data_directory", "Default data directory ", None),
            ("node_active_data_directory", "Using data directory ", node.chain_path),
            ("node_config_file_loaded", "Config file: ", Path(node.bitcoinconf)),
        ):
            row = next(row for row in rows if row.get("event") == event)
            path = Path(row["path"])
            assert path.is_absolute()
            if expected is not None:
                assert_equal(path, expected)
            assert_equal(row["message"], prefix + str(path))
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        assert "fields_truncated" not in startup


if __name__ == "__main__":
    StartupLocationsLoggingTest().main()
