#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Chronik metrics at /metrics: requests by endpoint and status,
WebSocket connections and subscriptions, and the indexer's lag."""

import time

from test_framework.blocktools import create_block, create_coinbase
from test_framework.metrics import m, scrape
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, chronik_sub_to_blocks


class ChronikMetricsTest(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    extra_args = [["-chronik", "-chronikallowpause", "-metrics"]]
    supports_cli = False

    requires = {"chronik"}

    def fresh_scrape(self):
        """A scrape past the one-second rendering cache"""
        time.sleep(1.05)
        return scrape(self.nodes[0])

    def delta(self, after, before, name, **labels):
        return after.total(name, **labels) - before.total(name, **labels)

    def run_test(self):
        node = self.nodes[0]
        chronik = node.get_chronik_client()

        self.log.info("The index follows the tip")
        self.generate(node, 5)
        self.wait_until(
            lambda: (
                scrape(node).value(m("chronik_indexed_height")) == node.getblockcount()
            )
        )
        s = self.fresh_scrape()
        assert_equal(s.value(m("chronik_lag_blocks")), 0)
        assert_equal(len(s.series(m("chronik_requests_total"))), 24 * 4)

        self.log.info("Requests by endpoint and status class")
        before = s
        assert_equal(chronik.blockchain_info().ok().tip_height, 5)
        chronik.block(3).ok()
        chronik.block(1000).err(404)
        chronik.chronik_info().ok()
        s = self.fresh_scrape()
        name = m("chronik_requests_total")
        assert_equal(
            self.delta(s, before, name, endpoint="blockchain_info", code="2xx"), 1
        )
        assert_equal(self.delta(s, before, name, endpoint="block", code="2xx"), 1)
        assert_equal(self.delta(s, before, name, endpoint="block", code="4xx"), 1)
        assert_equal(
            self.delta(s, before, name, endpoint="chronik_info", code="2xx"), 1
        )
        assert_equal(
            self.delta(
                s, before, m("chronik_request_duration_seconds_count"), endpoint="block"
            ),
            2,
        )

        self.log.info("A paused indexer lags behind the tip")
        peer = node.add_p2p_connection(P2PDataStore())
        chronik.pause().ok()
        # Mining RPCs wait for the validation queue, which a paused Chronik
        # holds up: send the blocks over P2P instead.
        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount()
        block_time = node.getblock(node.getbestblockhash())["time"]
        blocks = []
        for i in range(3):
            block = create_block(
                tip, create_coinbase(height + 1 + i), block_time + 1 + i
            )
            block.solve()
            blocks.append(block)
            tip = block.hash_int
        peer.send_blocks_and_test(blocks, node, timeout=10)
        self.wait_until(lambda: scrape(node).value(m("chronik_lag_blocks")) == 3)
        chronik.resume().ok()
        self.wait_until(lambda: scrape(node).value(m("chronik_lag_blocks")) == 0)
        s = self.fresh_scrape()
        assert_equal(self.delta(s, before, name, endpoint="pause", code="2xx"), 1)
        assert_equal(self.delta(s, before, name, endpoint="resume", code="2xx"), 1)

        self.log.info("WebSocket connections and subscriptions")
        ws = chronik.ws()
        chronik_sub_to_blocks(ws, node)
        s = self.fresh_scrape()
        assert_equal(s.value(m("chronik_ws_connections")), 1)
        assert_equal(s.value(m("chronik_ws_subscriptions")), 1)
        assert_equal(self.delta(s, before, name, endpoint="ws"), 1)
        ws.close()
        self.wait_until(lambda: scrape(node).value(m("chronik_ws_connections")) == 0)
        self.wait_until(lambda: scrape(node).value(m("chronik_ws_subscriptions")) == 0)


if __name__ == "__main__":
    ChronikMetricsTest().main()
