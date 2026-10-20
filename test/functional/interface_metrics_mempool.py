#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the mempool admission metrics at /metrics: accepted and rejected
transactions, accepted fee rates, removals, the minimum fee rates and the
orphan pool."""

import time
from decimal import Decimal

from test_framework.messages import COutPoint, msg_tx
from test_framework.metrics import m, scrape
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet

EXPIRY_HOURS = 1


class MempoolMetricsTest(BitcoinTestFramework):
    num_nodes = 1
    extra_args = [
        ["-metrics", "-maxorphantx=1", f"-mempoolexpiry={EXPIRY_HOURS}"],
    ]

    def fresh_scrape(self):
        """A scrape past the one-second rendering cache"""
        time.sleep(1.05)
        return scrape(self.nodes[0])

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, 10)

        before = self.fresh_scrape()
        assert_equal(
            len(before.series(m("mempool_rejected_total"))), 13
        )  # every reason, from the start
        assert_equal(
            before.label_values(m("mempool_removed_total"), "reason"),
            {
                "expiry",
                "sizelimit",
                "reorg",
                "block",
                "conflict",
                "avalanche",
                "manual",
            },
        )

        self.log.info("An accepted transaction and its fee rate")
        tx = wallet.send_self_transfer(from_node=node)
        entry = node.getmempoolentry(tx["txid"])
        fee_sats = int(entry["fees"]["base"] * 100)
        s = self.fresh_scrape()
        assert_equal(
            s.value(m("mempool_accepted_total"))
            - before.value(m("mempool_accepted_total")),
            1,
        )
        name = m("mempool_accepted_fee_rate_sats_per_byte")
        assert_equal(s.value(name + "_count") - before.value(name + "_count"), 1)
        rate = s.value(name + "_sum") - before.value(name + "_sum")
        vsize = len(tx["hex"]) // 2  # no sigchecks surcharge for this size
        assert abs(rate - fee_sats / vsize) < 0.01, (rate, fee_sats, vsize)
        # The sample is in the bucket for its rate
        bucket = min(
            float(ls["le"])
            for ls, _ in s.series(name + "_bucket")
            if float(ls["le"]) >= rate
        )
        assert_equal(
            s.value(name + "_bucket", le=f"{bucket:g}")
            - before.value(name + "_bucket", le=f"{bucket:g}"),
            1,
        )

        self.log.info("Rejections are counted by reason")
        missing = wallet.create_self_transfer()["tx"]
        missing.vin[0].prevout = COutPoint(0x1234, 0)
        assert_raises_rpc_error(
            -25,
            "bad-txns-inputs-missingorspent",
            node.sendrawtransaction,
            missing.serialize().hex(),
        )
        overspend = wallet.create_self_transfer()["tx"]
        overspend.vout[0].nValue += 10**10
        assert_raises_rpc_error(
            -26,
            "bad-txns-in-belowout",
            node.sendrawtransaction,
            overspend.serialize().hex(),
        )
        # testmempoolaccept is not counted
        node.testmempoolaccept([missing.serialize().hex()])
        s = self.fresh_scrape()

        def rejected(sample, reason):
            return sample.value(m("mempool_rejected_total"), reason=reason)

        assert_equal(
            rejected(s, "missing_inputs") - rejected(before, "missing_inputs"), 1
        )
        assert_equal(rejected(s, "consensus") - rejected(before, "consensus"), 1)

        self.log.info("Removals: in a block, and expired")
        self.generate(node, 1)
        s = self.fresh_scrape()
        assert_equal(
            s.value(m("mempool_removed_total"), reason="block")
            - before.value(m("mempool_removed_total"), reason="block"),
            1,
        )
        old = wallet.send_self_transfer(from_node=node)["txid"]
        entry_time = node.getmempoolentry(old)["time"]
        node.setmocktime(entry_time + EXPIRY_HOURS * 3600 + 5)
        # Expiry is checked when a transaction is added
        wallet.send_self_transfer(from_node=node)
        assert old not in node.getrawmempool()
        node.setmocktime(0)
        s = self.fresh_scrape()
        assert_equal(
            s.value(m("mempool_removed_total"), reason="expiry")
            - before.value(m("mempool_removed_total"), reason="expiry"),
            1,
        )

        self.log.info("Minimum fee rates")
        info = node.getmempoolinfo()
        assert_equal(
            s.value(m("mempool_min_fee_rate_sats_per_byte"), kind="rolling"), 0
        )
        effective = s.value(m("mempool_min_fee_rate_sats_per_byte"), kind="effective")
        # XEC per kB -> sats per byte
        assert effective >= info["minrelaytxfee"] * 100 / 1000
        # estimatefee reports the same floor (XEC per kB)
        assert abs(Decimal(str(effective)) - node.estimatefee() * 100 / 1000) < Decimal(
            "0.001"
        )

        self.log.info("Orphans held, and evicted beyond -maxorphantx")
        peer = node.add_p2p_connection(P2PInterface())
        orphans = []
        for _ in range(2):
            parent = wallet.create_self_transfer()
            child = wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])
            orphans.append(child)
            peer.send_and_ping(msg_tx(child["tx"]))
        self.wait_until(
            lambda: scrape(node).value(m("tx_pool_transactions"), pool="orphan") == 1
        )
        s = self.fresh_scrape()
        assert_equal(
            s.value(m("tx_pool_removed_total"), pool="orphan", reason="evicted")
            - before.value(m("tx_pool_removed_total"), pool="orphan", reason="evicted"),
            1,
        )
        assert_equal(s.value(m("tx_pool_transactions"), pool="conflicting"), 0)


if __name__ == "__main__":
    MempoolMetricsTest().main()
