#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Nucleation relay: short-id transaction announcements (invshort).

1. A node offers sendinvshort after verack. A P2P peer that offers it back
   gets 8-byte short ids; a peer that does not gets ordinary INVs.
2. A P2P peer announcing a short id the node lacks gets a getshorttx for it
   under the announced epoch.
3. Six nodes relay over invshort only and all receive every transaction.
4. Short ids forced to 6 bits (-txrelaytestshortidbits): colliding
   transactions may be skipped by relay, but a block naming them by full id
   still brings every node to the same tip.
"""

from test_framework.messages import (
    TXRELAY_INVSHORT,
    msg_invshort,
    msg_sendinvshort,
    msg_tx,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class ShortIdPeer(P2PInterface):
    def __init__(self, offer):
        super().__init__()
        self.offer = offer
        self.offered = None
        self.short_ids = []
        self.invs = []
        self.getshorttx = []

    def on_sendinvshort(self, message):
        self.offered = message.flags
        if self.offer:
            self.send_without_ping(msg_sendinvshort(flags=TXRELAY_INVSHORT))

    def on_invshort(self, message):
        self.short_ids += [(message.epoch_id, s) for s in message.short_ids]

    def on_inv(self, message):
        self.invs += [i.hash for i in message.inv]

    def on_getshorttx(self, message):
        self.getshorttx.append(message)


class TxRelayInvShortTest(BitcoinTestFramework):
    num_nodes = 6
    topology = "none"
    extra_args = [[]] * 4 + [["-txrelaytestshortidbits=6"]] * 2

    def run_test(self):
        self.test_negotiation()
        self.test_request()
        self.test_network()
        self.test_collisions()

    def test_negotiation(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)
        self.wallet.rescan_utxos()
        self.log.info("Short ids only to peers that negotiate them")
        stock = node.add_p2p_connection(ShortIdPeer(offer=False))
        nucl = node.add_p2p_connection(ShortIdPeer(offer=True))
        self.wait_until(lambda: nucl.offered is not None)
        assert_equal(nucl.offered & TXRELAY_INVSHORT, TXRELAY_INVSHORT)
        nucl.sync_with_ping()
        txid = self.wallet.send_self_transfer(from_node=node)["txid"]
        self.wait_until(lambda: int(txid, 16) in stock.invs)
        self.wait_until(lambda: len(nucl.short_ids) == 1)
        assert int(txid, 16) not in nucl.invs
        epoch, _ = nucl.short_ids[0]
        assert_equal(epoch, int(node.getbestblockhash(), 16))
        node.disconnect_p2ps()

    def test_request(self):
        node = self.nodes[0]
        self.log.info("A missing short id is fetched with getshorttx")
        nucl = node.add_p2p_connection(ShortIdPeer(offer=True))
        self.wait_until(lambda: nucl.offered is not None)
        nucl.sync_with_ping()
        tx = self.wallet.create_self_transfer()["tx"]
        epoch = int(node.getbestblockhash(), 16)
        # Any short id the node lacks makes it ask.
        nucl.send_and_ping(msg_invshort(epoch, [0x1234567890ABCDEF]))
        self.wait_until(lambda: len(nucl.getshorttx) == 1)
        req = nucl.getshorttx[0]
        assert_equal(req.context_id, epoch)
        assert_equal(req.short_ids, [0x1234567890ABCDEF])
        nucl.send_and_ping(msg_tx(tx))
        assert tx.txid_hex in node.getrawmempool()
        node.disconnect_p2ps()
        # Transactions already in a mempool are not announced to peers that
        # connect later: start the network part with empty mempools.
        self.generate(node, 1, sync_fun=self.no_op)

    def test_network(self):
        self.log.info("Four nodes relay over invshort")
        for a, b in [(0, 1), (1, 2), (2, 3), (3, 0)]:
            self.connect_nodes(a, b)
        self.sync_all(self.nodes[:4])
        txids = []
        for i in range(12):
            txids.append(
                self.wallet.send_self_transfer(from_node=self.nodes[0])["txid"]
            )
        self.sync_mempools(self.nodes[:4])
        for n in self.nodes[:4]:
            for p in n.getpeerinfo():
                # Transactions went by short id, not by INV entry.
                assert p["bytessent_per_msg"].get("inv", 0) < 36 * len(txids)
        assert any(
            p["bytessent_per_msg"].get("invshort", 0) > 0
            for n in self.nodes[1:4]
            for p in n.getpeerinfo()
        )
        self.generate(self.nodes[0], 1, sync_fun=lambda: self.sync_all(self.nodes[:4]))

    def test_collisions(self):
        self.log.info("6-bit short ids: a block still syncs colliding txs")
        a, b = self.nodes[4], self.nodes[5]
        self.connect_nodes(4, 5)
        self.connect_nodes(4, 0)
        self.sync_blocks()
        wallet = MiniWallet(a)
        wallet.rescan_utxos()
        for _ in range(30):
            wallet.send_self_transfer(from_node=a)
        self.wait_until(lambda: len(b.getrawmempool()) > 0)
        missing = set(a.getrawmempool()) - set(b.getrawmempool())
        self.log.info(f"node5 lacks {len(missing)} of 30 after relay")
        self.generate(a, 1, sync_fun=lambda: self.sync_blocks([a, b]))
        assert_equal(a.getbestblockhash(), b.getbestblockhash())


if __name__ == "__main__":
    TxRelayInvShortTest().main()
