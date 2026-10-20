#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real priority RPCs preserve native transaction IDs and signed fee increments."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MempoolPriorityLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        txid = "56" * 32
        for delta in (125, -250):
            assert_equal(node.prioritisetransaction(txid, 0, delta), True)
        assert_equal(node.getmempoolinfo()["size"], 0)
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = [
            row
            for row in rows
            if row.get("event") == "mempool_transaction_priority_changed"
        ]
        assert_equal(len(events), 2)
        for row, delta in zip(events, (125, -250), strict=True):
            assert_equal(row["txid"], txid)
            assert type(row["amount_sats"]) is int
            assert_equal(row["amount_sats"], delta)
            assert isinstance(row["fee_delta"], str) and row["fee_delta"]
            assert_equal(row["fee_delta"].startswith("-"), delta < 0)
            assert_equal(
                row["message"],
                f"PrioritiseTransaction: {txid} fee += {row['fee_delta']}",
            )
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    MempoolPriorityLoggingTest().main()
