#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual chain-tip events retain readable text and expose typed measurements."""

import json
import math

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ChainTipLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def run_test(self):
        node = self.nodes[0]
        with node.assert_debug_log([{"event": "chain_tip_updated", "height": 1}]):
            block_hash = self.generatetoaddress(
                node, 1, node.get_deterministic_priv_key().address
            )[0]
        # Stop flushes the async logger and closes the file. Never race producer
        # completion with the logging worker or substitute a fixed sleep.
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        record = next(
            row
            for row in records
            if row.get("event") == "chain_tip_updated" and row.get("height") == 1
        )
        assert_equal(record["block_hash"], block_hash)
        assert_equal(record["chainstate_role"], "active")
        for name in (
            "height",
            "version",
            "chain_tx_count",
            "block_time_seconds",
            "utxo_cache_bytes",
            "utxo_cache_coins",
        ):
            assert type(record[name]) is int, (name, record[name])
        for name in ("log2_work", "verification_progress", "utxo_cache_mib"):
            assert type(record[name]) in (int, float) and math.isfinite(record[name]), (
                name
            )
        assert_equal(record["utxo_cache_mib"], record["utxo_cache_bytes"] / 1048576)
        assert record["message"].startswith(
            f"UpdateTip: new best={block_hash} height=1 version=0x"
        )
        assert f"date='{record['block_time']}'" in record["message"]
        assert "fields_truncated" not in record


if __name__ == "__main__":
    ChainTipLoggingTest().main()
