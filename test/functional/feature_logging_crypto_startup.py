#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual early crypto startup copies its implementation label before return."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CryptoStartupLoggingTest(BitcoinTestFramework):
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
        by_event = {row.get("event"): row for row in rows}
        selected = by_event["sha256_implementation_selected"]
        implementation = selected["sha256_implementation"]
        assert isinstance(implementation, str) and implementation
        assert_equal(
            selected["message"], f"Using the '{implementation}' SHA256 implementation"
        )
        assert_equal(selected["level"], "info")
        assert "fields_truncated" not in selected
        # Architecture/capability guards are unchanged. These optional branches
        # are absent on macOS arm64, and this test does not force CPU features.
        for event, text in (
            ("entropy_rdseed_enabled", "Using RdSeed as additional entropy source"),
            ("entropy_rdrand_enabled", "Using RdRand as an additional entropy source"),
        ):
            if event in by_event:
                row = by_event[event]
                assert_equal(row["message"], text)
                assert_equal(row["level"], "info")
                assert "fields_truncated" not in row
                assert "value" not in row


if __name__ == "__main__":
    CryptoStartupLoggingTest().main()
