#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the P2P health metrics at /metrics: handshake and ping times by
transport and direction, address manager tables, bans, discouragements and
misbehavior by reason."""

import time

from test_framework.messages import MAX_INV_SIZE, MSG_TX, CInv, msg_inv
from test_framework.metrics import m, scrape
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2PMetricsTest(BitcoinTestFramework):
    num_nodes = 2
    extra_args = [["-metrics"], ["-metrics"]]

    def fresh_scrape(self, i=0):
        """A scrape past the one-second rendering cache"""
        time.sleep(1.05)
        return scrape(self.nodes[i])

    def delta(self, after, before, name, **labels):
        return after.total(name, **labels) - before.total(name, **labels)

    def run_test(self):
        node = self.nodes[0]
        s = scrape(node)
        self.log.info("Transports are tcp, ws and wss")
        assert_equal(
            s.label_values(m("p2p_handshake_seconds_count"), "transport"),
            {"tcp", "ws", "wss"},
        )
        assert_equal(len(s.series(m("p2p_handshake_seconds_count"))), 6)
        assert_equal(len(s.series(m("peers"))), 2 * 3 * 8)

        self.log.info("The two nodes' handshake is timed on both sides")
        handshakes = scrape(node).total(m("p2p_handshake_seconds_count"))
        handshakes += scrape(self.nodes[1]).total(m("p2p_handshake_seconds_count"))
        assert handshakes >= 2
        for i in range(2):
            s = scrape(self.nodes[i])
            assert s.total(m("p2p_handshake_seconds_count"), transport="tcp") >= 1
            assert_equal(s.total(m("p2p_handshake_seconds_count"), transport="ws"), 0)

        self.log.info("A P2P peer's handshake is inbound, and pings are timed")
        before = self.fresh_scrape()
        peer = node.add_p2p_connection(P2PInterface())
        node.ping()
        peer.sync_with_ping()
        self.wait_until(
            lambda: (
                all(p["pingtime"] > 0 for p in node.getpeerinfo() if "pingtime" in p)
                and len([p for p in node.getpeerinfo() if "pingtime" in p]) >= 2
            )
        )
        s = self.fresh_scrape()
        assert_equal(
            self.delta(
                s,
                before,
                m("p2p_handshake_seconds_count"),
                direction="inbound",
                transport="tcp",
            ),
            1,
        )
        assert self.delta(s, before, m("p2p_ping_seconds_count"), transport="tcp") >= 2
        assert s.value(m("p2p_ping_seconds_sum"), transport="tcp") > 0

        self.log.info("Address manager tables")
        before = s
        assert node.addpeeraddress("1.2.3.4", 8333)["success"]
        assert node.addpeeraddress("1.2.3.5", 8333, tried=True)["success"]
        s = self.fresh_scrape()
        assert_equal(self.delta(s, before, m("addrman_addresses"), table="new"), 1)
        assert_equal(self.delta(s, before, m("addrman_addresses"), table="tried"), 1)

        self.log.info("Bans")
        node.setban("192.0.2.0/24", "add")
        s = self.fresh_scrape()
        assert_equal(self.delta(s, before, m("p2p_bans_total")), 1)
        assert_equal(s.value(m("p2p_banned_subnets")), 1)
        node.clearbanned()
        assert_equal(self.fresh_scrape().value(m("p2p_banned_subnets")), 0)

        self.log.info("Misbehavior by reason; a local peer is disconnected")
        before = self.fresh_scrape()
        bad = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["Misbehaving", "inv message size"]):
            bad.send_without_ping(msg_inv([CInv(MSG_TX, 1)] * (MAX_INV_SIZE + 1)))
            bad.wait_for_disconnect()
        s = self.fresh_scrape()
        assert_equal(
            self.delta(
                s, before, m("p2p_misbehavior_total"), reason="oversized_message"
            ),
            1,
        )
        assert_equal(self.delta(s, before, m("p2p_misbehavior_total")), 1)
        # 127.0.0.1 is local: disconnected, not discouraged
        assert_equal(
            self.delta(
                s, before, m("p2p_discouragements_total"), outcome="disconnected_local"
            ),
            1,
        )
        assert_equal(len(s.series(m("p2p_misbehavior_total"))), 10)


if __name__ == "__main__":
    P2PMetricsTest().main()
