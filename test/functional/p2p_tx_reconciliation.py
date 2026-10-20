#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Nucleation relay: continuous reconciliation is the safety net under fan-out.

Six nodes in a ring relay with a fan-out of 1, and each also has three
silent P2P peers that never relay: most announcements go to a silent peer
and stop there. Every 250 ms each node sends a LIVE_MEMPOOL summary of the
transactions it admitted in the last 30 s to its next peer, which fetches
what it lacks. Every node must get every transaction, and reconciliation
messages must have been used.
"""

import http.client
import re
import time

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import rpc_port
from test_framework.wallet import MiniWallet

NODES = 6
SILENT = 3
TXS = 20


class SilentPeer(P2PInterface):
    """Accepts announcements, never asks for or relays anything"""

    def on_inv(self, message):
        pass


class TxReconciliationTest(BitcoinTestFramework):
    num_nodes = NODES
    topology = tuple((i, (i + 1) % NODES) for i in range(NODES))
    extra_args = [
        [
            "-txrelayfanoutmin=1",
            "-txrelayfanoutpct=0",
            "-txrelayfanoutmax=1",
            "-txreconinterval=250",
            "-txreconwindow=30",
            "-metrics",
            "-debug=txrelay",
        ]
    ] * NODES

    def relay_metrics(self, i):
        """{(name, labels): value} of node i's fullnode_txrelay_ metrics"""
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(i), timeout=30)
        conn.request("GET", "/metrics")
        body = conn.getresponse().read().decode()
        conn.close()
        out = {}
        for line in body.splitlines():
            m = re.match(r"^(fullnode_txrelay_\w+)(\{[^}]*\})? (\S+)$", line)
            if m:
                out[(m.group(1), m.group(2) or "")] = float(m.group(3))
        return out

    def metric(self, name, labels=""):
        return sum(self.relay_metrics(i).get((name, labels), 0) for i in range(NODES))

    def run_test(self):
        for node in self.nodes:
            for _ in range(SILENT):
                node.add_p2p_connection(SilentPeer())
        wallet = MiniWallet(self.nodes[0])
        wallet.rescan_utxos()
        wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=TXS)
        self.generate(self.nodes[0], 1)
        wallet.rescan_utxos()

        self.log.info("Fan-out 1 with silent peers; reconciliation fills the gaps")
        start = time.time()
        txids = []
        for i in range(TXS):
            # Enter at different nodes, over RPC (sent to all of that node's
            # peers, then fan-out 1 onwards).
            tx = wallet.create_self_transfer(confirmed_only=True)["tx"]
            self.nodes[(2 * i) % NODES].sendrawtransaction(tx.serialize().hex())
            txids.append(tx.txid_hex)

        def have_all():
            return all(set(txids) <= set(n.getrawmempool()) for n in self.nodes)

        self.wait_until(have_all, timeout=60)
        self.log.info(
            f"All {NODES} nodes have all {TXS} txs after {time.time() - start:.2f} s"
        )

        syncs = sum(
            p["bytessent_per_msg"].get("merklixsync", 0)
            for n in self.nodes
            for p in n.getpeerinfo()
        )
        fetched = sum(
            p["bytesrecv_per_msg"].get("shorttx", 0)
            for n in self.nodes
            for p in n.getpeerinfo()
        )
        self.log.info(
            f"merklixsync bytes sent {syncs}, shorttx bytes received {fetched}"
        )
        assert syncs > 0
        assert fetched > 0
        # The relay metrics agree.
        time.sleep(1.1)  # the metrics endpoint caches a scrape for 1 s
        rounds = self.metric("fullnode_txrelay_recon_rounds_total")
        recon_fetched = self.metric("fullnode_txrelay_recon_fetched_total")
        short_sent = self.metric(
            "fullnode_txrelay_announce_sent_total", '{kind="short"}'
        )
        bodies = self.metric("fullnode_txrelay_body_recv_total")
        dup = self.metric("fullnode_txrelay_body_dup_total")
        self.log.info(
            f"recon rounds {rounds}, recon-fetched ids {recon_fetched}, short "
            f"announcements {short_sent}, bodies {bodies} ({dup} duplicate)"
        )
        assert rounds > 0
        assert recon_fetched > 0
        assert short_sent > 0
        assert bodies >= (NODES - 1) * TXS
        with self.nodes[1].assert_debug_log(["[txrelay] reconciliation summary of"]):
            time.sleep(0.6)
        # Summaries go only to peers that negotiated reconciliation.
        for n in self.nodes:
            for p in n.getpeerinfo():
                if "testnode" not in p["subver"]:
                    assert p["bytessent_per_msg"].get("merklixsync", 0) == 0


if __name__ == "__main__":
    TxReconciliationTest().main()
