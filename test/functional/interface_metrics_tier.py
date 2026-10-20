#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the metrics of this tier's own features at /metrics: sealed-header
block rebuilds, snapshot publications, fast sync state, block template build
time and the adaptive block capacity. (Merklix reconciliation is driven by
peers' messages the node does not send itself; its metrics are checked in
the v2_protocol_handler unit tests.)"""

import time

from test_framework.metrics import m, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class TierMetricsTest(BitcoinTestFramework):
    num_nodes = 2
    # Sealed headers go to high-bandwidth peers (the framework turns them
    # off by default)
    extra_args = [
        ["-metrics", "-highbandwidthtx=1", "-testdisablehighbandwidthshorttx=0"],
        ["-metrics", "-highbandwidthtx=1", "-testdisablehighbandwidthshorttx=0"],
    ]

    def fresh_scrape(self, i):
        """A scrape past the one-second rendering cache"""
        time.sleep(1.05)
        return scrape(self.nodes[i])

    def delta(self, after, before, name, **labels):
        return after.total(name, **labels) - before.total(name, **labels)

    def run_test(self):
        node, peer = self.nodes
        wallet = MiniWallet(node)

        s = scrape(node)
        self.log.info("Every label set is present")
        assert_equal(
            s.label_values(m("sealed_headers_total"), "outcome"),
            {"rebuilt", "already_have", "fallback", "invalid", "rejected"},
        )
        assert_equal(len(s.series(m("merklix_rounds_total"))), 4)
        assert_equal(s.value(m("merklix_overflows_total")), 0)

        self.log.info("Fast sync is idle")
        assert_equal(s.value(m("snapshot_sync_state"), state="idle"), 1)
        assert_equal(s.total(m("snapshot_sync_state")), 1)
        assert_equal(s.total(m("snapshot_sync_shards")), 0)
        assert_equal(s.value(m("snapshot_sync_pivot_height")), 0)

        self.log.info("Adaptive block capacity")
        assert s.value(m("adaptive_block_size_bytes"), limit="max") > 0
        assert s.value(m("adaptive_block_size_bytes"), limit="max_generated") > 0
        assert s.value(m("adaptive_block_size_history_complete")) in (0, 1)

        self.log.info("Snapshots are published; mining builds templates")
        before = self.fresh_scrape(0)
        before_peer = self.fresh_scrape(1)
        self.generate(wallet, 3)
        wallet.send_self_transfer(from_node=node)
        self.sync_mempools()
        self.generate(node, 1)
        s = self.fresh_scrape(0)
        for kind in ("chain_tip", "mempool"):
            assert (
                self.delta(s, before, m("snapshot_publications_total"), kind=kind) > 0
            )
            # Every publication is timed
            assert_equal(
                s.value(m("snapshot_publications_total"), kind=kind),
                s.value(m("snapshot_publish_seconds_count"), kind=kind),
            )
        for stage in ("select", "validity", "total"):
            assert_equal(
                self.delta(
                    s, before, m("block_template_build_seconds_count"), stage=stage
                ),
                4,
            )

        self.log.info("The peer rebuilds the blocks from sealed headers")
        s = self.fresh_scrape(1)
        rebuilt = self.delta(
            s, before_peer, m("sealed_headers_total"), outcome="rebuilt"
        )
        assert rebuilt >= 1, s.series(m("sealed_headers_total"))
        assert_equal(
            self.delta(s, before_peer, m("sealed_headers_total"), outcome="invalid"), 0
        )


if __name__ == "__main__":
    TierMetricsTest().main()
