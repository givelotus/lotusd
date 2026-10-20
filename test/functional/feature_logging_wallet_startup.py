#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual wallet disable/blocksonly startup keeps original parameter behavior."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletStartupLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    requires = {"wallet"}
    extra_args = [["-logformat=json", "-disablewallet=1", "-wallet=ignored-wallet"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        # Restart without the disabling flag or requested wallet. This exercises
        # SoftSetBoolArg in the real parameter interaction, without creating keys.
        self.start_node(0, ["-logformat=json", "-disablewallet=0", "-blocksonly=1"])
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.listwallets(), [])
        assert_equal(node.getnetworkinfo()["localrelay"], False)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        ignored = by_event["wallet_argument_ignored"]
        assert_equal(ignored["source_function"], "ParameterInteraction")
        assert_equal(ignored["wallet"], "ignored-wallet")
        assert_equal(
            ignored["message"],
            "ParameterInteraction: parameter interaction: -disablewallet -> ignoring -wallet=ignored-wallet",
        )
        disabled = by_event["wallet_disabled"]
        assert_equal(disabled["message"], "Wallet disabled!")
        broadcast = by_event["wallet_broadcast_disabled_by_blocksonly"]
        assert_equal(broadcast["source_function"], "ParameterInteraction")
        assert_equal(
            broadcast["message"],
            "ParameterInteraction: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0",
        )
        for row in (ignored, disabled, broadcast):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    WalletStartupLoggingTest().main()
