#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Transactions from peers admitted on the admission thread (-parallelmempool).

node0 admits peer transactions on its admission thread with scripts verified
outside cs_main; node1 runs with -parallelmempool=0 (serial admission on the
message handler thread). The nodes are not connected while transactions are
sent, and every check that compares them sends both the same messages.

Covered:
- the same sequence of really signed transactions (valid, a dependent chain,
  a child before its parent, a double spend, one below the relay fee, a
  duplicate) gives the same mempool on both nodes;
- a peer's later message waits for its transactions: when the pong for a
  ping sent right after a transaction arrives, that transaction has a
  verdict;
- several peers at once, with the same transaction from all of them and a
  double spend racing between two of them: every valid transaction is
  admitted once, exactly one side of the double spend, nobody punished;
- a transaction with an invalid signature gets its sender disconnected,
  as with serial admission;
- a block mined while transactions are in flight leaves a consistent
  mempool (regtest checks it on every admission).
"""

from test_framework.messages import msg_tx
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


class MalformedTx(msg_tx):
    def serialize(self):
        return b"\x01"


class ParallelAdmissionTest(BitcoinTestFramework):
    num_nodes = 2
    setup_clean_chain = True
    extra_args = [
        ["-parallelmempool=1", "-parallelmempoolthreads=4"],
        ["-parallelmempool=0"],
    ]

    def fund(self, count):
        """Split mature coinbases into `count` confirmed single-key outputs."""
        node = self.nodes[0]
        per_fanout = 50
        fanouts = (count + per_fanout - 1) // per_fanout
        self.generate(self.wallet, fanouts)
        self.generate(node, 101)
        self.wallet.rescan_utxos()
        for _ in range(fanouts):
            self.wallet.send_self_transfer_multi(
                from_node=node,
                utxos_to_spend=[self.wallet.get_utxo(confirmed_only=True)],
                num_outputs=per_fanout,
            )
        self.generate(node, 1)
        self.wallet.rescan_utxos()

    def spend(self, **kwargs):
        return self.wallet.create_self_transfer(**kwargs)

    def send_all(self, peer, txs):
        for tx in txs:
            peer.send_without_ping(msg_tx(tx["tx"]))
        peer.sync_with_ping()

    def mempool(self, node):
        return sorted(node.getrawmempool())

    def run_test(self):
        node0, node1 = self.nodes
        self.wallet = MiniWallet(node0, mode=MiniWalletMode.RAW_P2PK)
        self.fund(450)
        self.sync_blocks()
        self.disconnect_nodes(0, 1)

        self.log.info("Same sequence, same mempool as serial admission")
        independent = [self.spend() for _ in range(40)]
        chain = self.wallet.create_self_transfer_chain(chain_length=5)
        orphan_parent = self.spend()
        orphan_child = self.spend(utxo_to_spend=orphan_parent["new_utxo"])
        utxo = self.wallet.get_utxo()
        first = self.spend(utxo_to_spend=utxo)
        second = self.spend(utxo_to_spend=utxo, fee_rate=6000)
        low_fee = self.spend(fee_rate=0)
        sequence = (
            independent[:20]
            + chain
            + [orphan_child, first]
            + independent[20:]
            + [second, orphan_parent, low_fee, independent[0]]
        )
        for node in (node0, node1):
            peer = node.add_p2p_connection(P2PInterface())
            self.send_all(peer, sequence)
        expected = sorted(
            [t["txid"] for t in independent + chain]
            + [orphan_parent["txid"], orphan_child["txid"], first["txid"]]
        )
        for node in (node0, node1):
            self.wait_until(lambda n=node: self.mempool(n) == expected)
        assert_equal(self.mempool(node0), self.mempool(node1))
        for node in (node0, node1):
            assert node.p2ps[0].is_connected
            node.disconnect_p2ps()

        self.log.info("A ping after a transaction is answered after its verdict")
        peer = node0.add_p2p_connection(P2PInterface())
        for _ in range(20):
            parent = self.spend()
            child = self.spend(utxo_to_spend=parent["new_utxo"])
            peer.send_without_ping(msg_tx(parent["tx"]))
            peer.send_without_ping(msg_tx(child["tx"]))
            peer.sync_with_ping()
            mempool = set(node0.getrawmempool())
            assert parent["txid"] in mempool and child["txid"] in mempool
        node0.disconnect_p2ps()

        self.log.info("Several peers at once, duplicates and a double spend race")
        peers = [node0.add_p2p_connection(P2PInterface()) for _ in range(4)]
        batch = [self.spend() for _ in range(120)]
        duplicate = self.spend()
        utxo = self.wallet.get_utxo()
        side_a = self.spend(utxo_to_spend=utxo)
        side_b = self.spend(utxo_to_spend=utxo, fee_rate=6000)
        before = set(node0.getrawmempool())
        for i, tx in enumerate(batch):
            peers[i % 4].send_without_ping(msg_tx(tx["tx"]))
        for p in peers:
            p.send_without_ping(msg_tx(duplicate["tx"]))
        peers[0].send_without_ping(msg_tx(side_a["tx"]))
        peers[1].send_without_ping(msg_tx(side_b["tx"]))
        for p in peers:
            p.sync_with_ping()
        mempool = set(node0.getrawmempool()) - before
        assert {t["txid"] for t in batch} <= mempool
        assert duplicate["txid"] in mempool
        assert (side_a["txid"] in mempool) != (side_b["txid"] in mempool)
        assert_equal(len(mempool), len(batch) + 2)
        assert all(p.is_connected for p in peers)
        node0.disconnect_p2ps()

        self.log.info("Malformed tails preserve their already decoded valid prefix")
        prefix = [self.spend() for _ in range(24)]
        for node in (node0, node1):
            peer = node.add_p2p_connection(P2PInterface())
            payload = b"".join(peer.build_message(msg_tx(tx["tx"])) for tx in prefix)
            payload += peer.build_message(MalformedTx())
            peer.send_raw_message(payload)
            self.wait_until(
                lambda n=node: all(tx["txid"] in n.getrawmempool() for tx in prefix)
            )
            node.disconnect_p2ps()

        self.log.info("An invalid signature disconnects its sender on both nodes")
        bad = self.spend()
        bad_tx = bad["tx"]
        script_sig = bytearray(bad_tx.vin[0].scriptSig)
        script_sig[10] ^= 0x01
        bad_tx.vin[0].scriptSig = bytes(script_sig)
        for node in (node0, node1):
            peer = node.add_p2p_connection(P2PInterface())
            with node.assert_debug_log(["mandatory-script-verify-flag-failed"]):
                peer.send_without_ping(msg_tx(bad_tx))
                peer.wait_for_disconnect()
            assert bad_tx.txid_hex not in node.getrawmempool()

        self.log.info("A block mined while transactions are in flight")
        peers = [node0.add_p2p_connection(P2PInterface()) for _ in range(2)]
        batch = [self.spend() for _ in range(150)]
        for i, tx in enumerate(batch):
            peers[i % 2].send_without_ping(msg_tx(tx["tx"]))
            if i == 75:
                self.generate(node0, 1, sync_fun=self.no_op)
        for p in peers:
            p.sync_with_ping()
        tip = node0.getbestblockhash()
        confirmed = set(node0.getblock(tip)["tx"])
        mempool = set(node0.getrawmempool())
        for tx in batch:
            assert tx["txid"] in mempool or tx["txid"] in confirmed
        assert all(p.is_connected for p in peers)

        self.log.info("Shutdown fences admission producers with work in flight")
        for i in range(40):
            peers[i % 2].send_without_ping(msg_tx(self.spend()["tx"]))
        self.stop_node(0)


if __name__ == "__main__":
    ParallelAdmissionTest().main()
