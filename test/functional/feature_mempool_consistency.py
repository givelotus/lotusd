#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise actual startup defaults and explicit checks through admission/reorg."""
from test_framework import wallet as wallets
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class MempoolConsistencyTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    supports_cli = False
    extra_args = [["-avalanche=0", "-persistmempool=0"]]

    def run_test(self):
        node = self.nodes[0]
        # The native protocol's wallet adapter is added by its later layer;
        # the shared checker policy test also runs without that optional layer.
        wallet_type = getattr(wallets, "NativeMiniWallet", wallets.MiniWallet)
        wallet = wallet_type(node)
        self.generate(wallet, 101)
        with node.assert_debug_log(["Checking mempool with 1 transactions"]):
            wallet.send_self_transfer(from_node=node, confirmed_only=True)
        self.generate(wallet, 1)

        self.stop_node(0)
        # Test actual node defaults, rather than the framework's explicit opt-in.
        node.default_args.remove("-checkmempool=1")
        self.start_node(0)
        with node.assert_debug_log(["TransactionAddedToMempool"],
                                   unexpected_msgs=["Checking mempool with"]):
            tx = wallet.send_self_transfer(from_node=node, confirmed_only=True)
            assert_equal(node.getrawmempool(), [tx["txid"]])
            node.logging()  # Flush the entire completed admission's log records.
        self.generate(wallet, 1)

        self.restart_node(0, extra_args=self.extra_args[0] + ["-checkmempool=1"])
        with node.assert_debug_log(["Checking mempool with 1 transactions"]):
            tx = wallet.send_self_transfer(from_node=node, confirmed_only=True)
        block = self.generate(wallet, 1)[0]
        assert_equal(node.getrawmempool(), [])
        with node.assert_debug_log(["accepted after reorg"]):
            node.invalidateblock(block)
            assert_equal(node.getrawmempool(), [tx["txid"]])
        # invalidateblock reaccepts via the disconnect pool, not the ordinary
        # admission wrapper. Trigger its checker with another real admission,
        # so the asserted scan includes the transaction restored by the reorg.
        with node.assert_debug_log(["Checking mempool with 2 transactions"]):
            additional = wallet.send_self_transfer(from_node=node, confirmed_only=True)
        assert_equal(set(node.getrawmempool()), {tx["txid"], additional["txid"]})
        node.reconsiderblock(block)
        assert_equal(node.getrawmempool(), [additional["txid"]])
        self.generate(wallet, 1)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    MempoolConsistencyTest().main()
