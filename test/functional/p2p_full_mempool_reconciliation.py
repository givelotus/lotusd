#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Complete-mempool reconciliation over pinned slab Merklix snapshots.

Two nodes share a chain, then diverge while disconnected: each admits
transactions the other has never seen. The live reconciliation window is
made tiny and allowed to expire, so on reconnection only complete-mempool
reconciliation (scope 5) can repair the difference. It must:

 - capture by pinning the mempool's slab Merklix tree (no rebuild fallback),
 - advertise and evaluate a MinHash hint with every offer,
 - recover every missing transaction through authenticated pages,
 - leave both mempools equal and mineable (template Subtree A roots valid).
"""
import http.client
import re
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, rpc_port
from test_framework.wallet import MiniWallet

ONLY_0 = 40
ONLY_1 = 15


class FullMempoolReconciliationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-txreconwindow=1", "-txreconinterval=250", "-metrics", "-debug=txrelay"]
        ] * 2

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def metrics(self, i):
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(i), timeout=30)
        conn.request("GET", "/metrics")
        body = conn.getresponse().read().decode()
        conn.close()
        out = {}
        for line in body.splitlines():
            m = re.match(r"^(fullnode_(?:fullrecon|txmerklix)_\w+)(\{[^}]*\})? (\S+)$", line)
            if m:
                out[m.group(1)] = float(m.group(3))
        return out

    def run_test(self):
        wallet = MiniWallet(self.nodes[0])
        self.generate(wallet, 101)
        wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=ONLY_0 + ONLY_1)
        self.generate(self.nodes[0], 1)
        wallet.rescan_utxos()
        self.sync_blocks()

        self.log.info("Diverge both mempools while disconnected")
        self.disconnect_nodes(0, 1)
        utxos = wallet.get_utxos(mark_as_spent=True, confirmed_only=True)
        only0, only1 = [], []
        for i, utxo in enumerate(utxos[: ONLY_0 + ONLY_1]):
            node = 0 if i < ONLY_0 else 1
            tx = wallet.create_self_transfer(utxo_to_spend=utxo)["tx"]
            self.nodes[node].sendrawtransaction(tx.serialize().hex())
            (only0 if node == 0 else only1).append(tx.txid_hex)
        assert_equal(len(self.nodes[0].getrawmempool()), ONLY_0)
        assert_equal(len(self.nodes[1].getrawmempool()), ONLY_1)
        # Let the one-second live window expire so it cannot carry them.
        time.sleep(2.5)

        self.log.info("Reconnect: complete-mempool reconciliation repairs both sides")
        before = [self.metrics(i) for i in range(2)]
        self.connect_nodes(0, 1)
        everything = set(only0 + only1)
        self.wait_until(
            lambda: all(set(n.getrawmempool()) == everything for n in self.nodes),
            timeout=90,
        )
        time.sleep(1.1)  # /metrics caches a scrape for one second
        after = [self.metrics(i) for i in range(2)]

        def delta(i, name):
            return after[i].get(name, 0) - before[i].get(name, 0)

        recovered = sum(delta(i, "fullnode_fullrecon_sketch_actual_recovered_total") for i in range(2))
        self.log.info(f"recovered through scope 5: {recovered:.0f} of {len(everything)} one-sided txs")
        assert recovered > 0
        assert sum(delta(i, "fullnode_fullrecon_coverage_complete_total") for i in range(2)) >= 1
        assert sum(delta(i, "fullnode_fullrecon_sketch_offers_total") for i in range(2)) >= 1
        for i in range(2):
            assert after[i]["fullnode_fullrecon_capture_pins_total"] >= 1
            assert_equal(after[i].get("fullnode_fullrecon_capture_fallbacks_total", 0), 0)
            assert after[i]["fullnode_txmerklix_pins_total"] >= 1
        bucks = sum(
            p["bytesrecv_per_msg"].get("merklixbuck", 0)
            for n in self.nodes
            for p in n.getpeerinfo()
        )
        assert bucks > 0

        self.log.info("Both views are mineable: template roots from the slab tree")
        tmpl = self.nodes[1].getblocktemplate()
        assert_equal(len(tmpl["transactions"]), len(everything))
        # Admissions reach the tree through deferred overlay batches; the
        # template flushed them, so the live leaves now cover every member.
        time.sleep(1.1)
        assert self.metrics(1)["fullnode_txmerklix_live_leaves"] >= len(everything)
        self.generate(self.nodes[1], 1)
        self.sync_blocks()
        for n in self.nodes:
            assert_equal(n.getrawmempool(), [])


if __name__ == "__main__":
    FullMempoolReconciliationTest().main()
