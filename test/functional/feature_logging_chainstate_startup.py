#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real startup options keep distinct chainstate/work/pruning field meanings."""

import json
from datetime import datetime, timezone

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ChainstateStartupLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [
        ["-logformat=json", "-assumevalid=01", "-minimumchainwork=01", "-prune=550"]
    ]

    def run_test(self):
        node = self.nodes[0]
        info = node.getblockchaininfo()
        assert_equal(info["blocks"], 0)
        assert_equal(info["pruned"], True)
        header = node.getblockheader(info["bestblockhash"])
        self.stop_node(0)
        self.start_node(0)
        assert_equal(node.getbestblockhash(), info["bestblockhash"])
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        state = by_event["chainstate_initializing"]
        assert isinstance(state["chainstate_description"], str)
        assert state["chainstate_description"].startswith("Chainstate")
        assert_equal(
            state["message"],
            "Initializing chainstate " + state["chainstate_description"],
        )
        assumed = by_event["chainstate_assumed_valid_block"]
        assert_equal(assumed["block_hash"], "0" * 63 + "1")
        assert_equal(
            assumed["message"],
            "Assuming ancestors of block "
            + assumed["block_hash"]
            + " have valid signatures.",
        )
        work = by_event["chainstate_minimum_work"]
        assert_equal(work["minimum_chain_work_hex"], "0" * 63 + "1")
        assert_equal(
            work["message"],
            "Setting nMinimumChainWork=" + work["minimum_chain_work_hex"],
        )
        prune = by_event["chainstate_prune_target"]
        assert_equal(prune["prune_target_mib"], 550)
        assert isinstance(prune["prune_target_mib"], int)
        assert_equal(
            prune["message"],
            "Prune configured to target 550 MiB on disk for block and undo files.",
        )
        loaded = by_event["chainstate_best_chain_loaded"]
        assert_equal(loaded["block_hash"], info["bestblockhash"])
        assert_equal(loaded["height"], info["blocks"])
        expected_time = (
            datetime.fromtimestamp(header["time"], timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        assert_equal(loaded["block_time"], expected_time)
        progress = loaded["verification_progress"]
        assert isinstance(progress, (float, int))
        assert 0 <= progress <= 1
        assert_equal(
            loaded["message"],
            f"Loaded best chain: hashBestChain={info['bestblockhash']} height={info['blocks']} date={expected_time} progress={progress:.6f}",
        )
        for event in (state, assumed, work, prune, loaded):
            assert_equal(event["level"], "info")
            assert "fields_truncated" not in event


if __name__ == "__main__":
    ChainstateStartupLoggingTest().main()
