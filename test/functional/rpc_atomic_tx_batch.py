#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Atomic raw batches preserve ABC validation and relay dependency chains."""
import copy
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class AtomicTxBatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-avalanche=0"], ["-avalanche=0"]]

    def run_test(self):
        node, peer = self.nodes
        wallet = MiniWallet(node)
        self.generate(wallet, 102)
        chain = wallet.create_self_transfer_chain(chain_length=40)
        raw = [tx["hex"] for tx in chain]
        ids = [tx["txid"] for tx in chain]
        tested = node.testrawtxbatch(raw, 0)
        assert tested["allowed"]
        assert_equal(len(tested["results"]), len(raw))
        assert all(result["allowed"] for result in tested["results"])
        assert_equal(node.getrawmempool(), [])

        bad = copy.deepcopy(chain[-1]["tx"])
        bad.vin[0].prevout.txid = 42
        for batch in ([raw[0], bad.serialize().hex()], list(reversed(raw)), [raw[0], raw[0]]):
            assert not node.submitrawtxbatch(batch, 0)["accepted"]
            assert_equal(node.getrawmempool(), [])
        assert not node.submitrawtxbatch(raw, Decimal("0.01"))["accepted"]
        assert_equal(node.getrawmempool(), [])
        malformed = raw.copy()
        malformed[7] = "badhex-at-seven"
        malformed[35] = "badhex-at-thirtyfive"
        assert_raises_rpc_error(-22, "TX decode failed: badhex-at-seven",
                                node.submitrawtxbatch, malformed, 0)
        assert_equal(node.getrawmempool(), [])
        submitted = node.submitrawtxbatch(raw, 0)
        assert submitted["accepted"]
        assert_equal(submitted["txids"], ids)
        self.sync_mempools()
        assert_equal(sorted(node.getrawmempool()), sorted(ids))
        assert_equal(sorted(peer.getrawmempool()), sorted(ids))
        template = node.getblocktemplate()
        assert_equal(sorted(tx["txid"] for tx in template["transactions"]), sorted(ids))
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])
        assert_equal(peer.getrawmempool(), [])


if __name__ == "__main__":
    AtomicTxBatchTest().main()
