#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Default MiniWallet spends legacy coins; NativeMiniWallet spends V2 coins."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode, NativeMiniWallet


class WalletTransactionFamiliesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-avalanche=0"]]

    def run_test(self):
        node = self.nodes[0]
        wallets = [
            (MiniWallet(node), 2, 1),
            (MiniWallet(node, mode=MiniWalletMode.RAW_P2PK), 2, 1),
            (NativeMiniWallet(node), 7, 7),
            (NativeMiniWallet(node, mode=MiniWalletMode.RAW_P2PK), 7, 7),
        ]
        for wallet, coinbase_version, _ in wallets:
            block_hash = self.generate(wallet, 1)[0]
            coinbase = node.getblock(block_hash, 2)["tx"][0]
            assert_equal(coinbase["version"], coinbase_version)
        # Mature all four independently typed funding outputs.
        self.generatetodescriptor(node, 100, "raw(51)")
        txids = []
        for wallet, _, version in wallets:
            wallet.rescan_utxos()
            transfer = wallet.send_self_transfer(from_node=node)
            tx = transfer["tx"]
            assert_equal(tx.nVersion, version)
            assert_equal(
                node.getrawtransaction(transfer["txid"], True)["version"], version
            )
            for txin in tx.vin:
                if version in (1, 2):
                    assert txin.scriptSig
                    assert_equal(getattr(txin, "nFlags", 0), 0)
                    assert not getattr(txin, "vWitnesses", [])
                else:
                    assert not txin.scriptSig
                    assert_equal(getattr(txin, "nFlags", 1), 1)
                    assert txin.vWitnesses
            txids.append(transfer["txid"])
        mined = self.generatetodescriptor(node, 1, "raw(51)")[0]
        included = node.getblock(mined)["tx"]
        assert all(txid in included for txid in txids)
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    WalletTransactionFamiliesTest().main()
