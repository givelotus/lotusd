#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A real empty regtest block retains exact typed mining summary units."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MinerTemplateLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        blockhash = self.generatetoaddress(
            node, 1, node.get_deterministic_priv_key().address
        )[0]
        serialized_bytes = len(node.getblock(blockhash, 0)) // 2
        assert_equal(node.getblockcount(), 1)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        row = {r.get("event"): r for r in rows}["block_template_created"]
        for field in ("bytes", "count", "amount_sats", "sig_checks"):
            assert type(row[field]) is int
        assert_equal(row["bytes"], serialized_bytes)
        assert_equal(row["count"], 0)
        assert_equal(row["amount_sats"], 0)
        assert_equal(row["sig_checks"], 100)  # Coinbase resource reservation.
        assert_equal(
            row["message"],
            f"CreateNewBlock(): total size: {serialized_bytes} txs: 0 fees: 0 sigChecks 100",
        )
        assert_equal(row["level"], "info")
        assert "fields_truncated" not in row


if __name__ == "__main__":
    MinerTemplateLoggingTest().main()
