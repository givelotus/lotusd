#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real startup keeps software identity and signed padded timing fields."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class StartupIdentityLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        identity = events["client_version_announced"]
        assert isinstance(identity["client_name"], str) and identity["client_name"]
        assert (
            isinstance(identity["client_version"], str) and identity["client_version"]
        )
        assert_equal(
            identity["message"],
            f"{identity['client_name']} version {identity['client_version']} for the eCash network",
        )
        completed = events["block_index_startup_completed"]
        elapsed = completed["elapsed_milliseconds"]
        assert type(elapsed) is int
        assert_equal(completed["message"], f" block index {elapsed:15d}ms")
        for row in (identity, completed):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    StartupIdentityLoggingTest().main()
