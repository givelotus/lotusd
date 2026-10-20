#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Paid native Coin metadata survives a deterministic partial chainstate flush."""

import http.client

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import NativeMiniWallet


class NativeCoinRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.supports_cli = False
        self.extra_args = [["-dbcache=4", "-dbbatchsize=200000"], []]

    def setup_network(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        # Deliberately unconnected: node0 receives exactly the paid block below.

    def run_test(self):
        recovering, reference = self.nodes
        wallet = NativeMiniWallet(reference)
        # Mature enough actual native coinbases for twenty independent paid
        # transactions. Replay this setup explicitly into the recovery node.
        for blockhash in self.generate(wallet, 120, sync_fun=self.no_op):
            assert_equal(
                recovering.submitblock(reference.getblock(blockhash, False)), None
            )
        funding = [
            wallet.send_self_transfer_multi(from_node=reference, num_outputs=250)
            for _ in range(20)
        ]
        assert_equal(sum(len(tx["new_utxos"]) for tx in funding), 5000)
        assert all(tx["tx"].nVersion == 7 for tx in funding)
        [tip] = self.generate(reference, 1, sync_fun=self.no_op)
        expected = reference.gettxoutsetinfo()["hash_serialized"]
        block = reference.getblock(tip, False)

        # Every partial batch crashes, independently of RNG state. On restart,
        # disable the fault so recovery must complete rather than crash again.
        self.restart_node(0, self.extra_args[0] + ["-dbcrashratio=1"])
        with recovering.assert_debug_log(["Simulating a crash. Goodbye."]):
            try:
                recovering.submitblock(block)
                recovering.gettxoutsetinfo()  # Force a dirty coins-cache flush.
            except (OSError, http.client.HTTPException):
                pass
            self.wait_for_node_exit(0, timeout=30)
        self.start_node(0, self.extra_args[0])
        assert_equal(recovering.getbestblockhash(), tip)
        assert_equal(recovering.gettxoutsetinfo()["hash_serialized"], expected)

        # Replay must also restore the parent native state needed by the next
        # block, not merely make the ordinary coins hash match.
        [child] = self.generate(reference, 1, sync_fun=self.no_op)
        assert_equal(recovering.submitblock(reference.getblock(child, False)), None)
        assert_equal(recovering.getbestblockhash(), child)
        expected = reference.gettxoutsetinfo()["hash_serialized"]
        tip = child

        # Both undo and a second connect must preserve the same authenticated
        # fee-share/expiration bytes, followed by an ordinary clean restart.
        for node in self.nodes:
            node.invalidateblock(tip)
        assert_equal(
            recovering.gettxoutsetinfo()["hash_serialized"],
            reference.gettxoutsetinfo()["hash_serialized"],
        )
        for node in self.nodes:
            node.reconsiderblock(tip)
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.gettxoutsetinfo()["hash_serialized"], expected)
        self.restart_node(0, self.extra_args[0])
        assert_equal(recovering.gettxoutsetinfo()["hash_serialized"], expected)


if __name__ == "__main__":
    NativeCoinRecoveryTest().main()
