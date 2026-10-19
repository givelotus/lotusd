#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Nucleation relay: transactions are announced to a fan-out of peers.

1. node0 alone with P2P observers and a fixed fan-out of 3: each relayed
   transaction is announced to exactly 3 peers, a transaction node0
   originated (RPC) to every peer.
2. Twelve nodes, ring plus random chords, default fan-out: every node gets
   every transaction.
"""

import random

from test_framework.messages import msg_tx
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

FANOUT = 3
OBSERVERS = 12


class InvObserver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.announced = set()

    def on_inv(self, message):
        for inv in message.inv:
            self.announced.add(inv.hash)


def ring_and_chords(n, chords, seed):
    rng = random.Random(seed)
    edges = {(i, (i + 1) % n) for i in range(n)}
    while len(edges) < n + chords:
        a, b = rng.sample(range(n), 2)
        if (a, b) not in edges and (b, a) not in edges:
            edges.add((a, b))
    return sorted(edges)


class TxRelayFanoutTest(BitcoinTestFramework):
    num_nodes = 12
    topology = "none"
    extra_args = [
        [
            f"-txrelayfanoutmin={FANOUT}",
            "-txrelayfanoutpct=0",
            f"-txrelayfanoutmax={FANOUT}",
        ]
    ] + [[]] * 11

    def run_test(self):
        self.test_fanout_count()
        self.test_network_delivery()

    def test_fanout_count(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        wallet.rescan_utxos()
        sender = node.add_p2p_connection(P2PInterface())
        observers = [node.add_p2p_connection(InvObserver()) for _ in range(OBSERVERS)]

        self.log.info("Relayed transactions go to exactly the fan-out")
        reached = set()
        txids = []
        for _ in range(20):
            tx = wallet.create_self_transfer()["tx"]
            sender.send_and_ping(msg_tx(tx))
            txids.append(tx.txid_int)
            self.wait_until(
                lambda: sum(tx.txid_int in o.announced for o in observers) >= FANOUT
            )
        for o in observers:
            o.sync_with_ping()
        for txid in txids:
            to = [i for i, o in enumerate(observers) if txid in o.announced]
            assert_equal(len(to), FANOUT)
            reached.update(to)
        # Picked at random: over 20 transactions most observers got some.
        assert len(reached) > FANOUT * 2, reached
        # The sender knows its transactions and is never announced to.
        self.log.info("A transaction node0 originated goes to every peer")
        txid = wallet.send_self_transfer(from_node=node)["txid"]
        self.wait_until(lambda: all(int(txid, 16) in o.announced for o in observers))
        node.disconnect_p2ps()
        self.generate(node, 1, sync_fun=self.no_op)

    def test_network_delivery(self):
        self.log.info("Twelve nodes, ring plus chords: everyone gets every tx")
        self.restart_node(0, extra_args=[])
        for a, b in ring_and_chords(self.num_nodes, 8, seed=7):
            self.connect_nodes(a, b)
        self.sync_blocks()
        wallet = MiniWallet(self.nodes[0])
        wallet.rescan_utxos()
        # Confirmed coins for every transaction below
        wallet.send_self_transfer_multi(from_node=self.nodes[0], num_outputs=40)
        self.generate(self.nodes[0], 1)
        wallet.rescan_utxos()
        sender = self.nodes[5].add_p2p_connection(P2PInterface())
        txids = []
        for i in range(30):
            # Confirmed inputs only, so any node can accept it directly.
            tx = wallet.create_self_transfer(confirmed_only=True)["tx"]
            if i % 2:
                # Relayed (entered over P2P at node5)
                sender.send_and_ping(msg_tx(tx))
            else:
                # Originated by a node (RPC)
                self.nodes[i % self.num_nodes].sendrawtransaction(tx.serialize().hex())
            txids.append(tx.txid_hex)
        self.sync_mempools(timeout=60)
        for node in self.nodes:
            mempool = set(node.getrawmempool())
            assert all(t in mempool for t in txids)


if __name__ == "__main__":
    TxRelayFanoutTest().main()
