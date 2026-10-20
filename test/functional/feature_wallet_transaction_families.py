#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Default MiniWallet spends legacy coins; NativeMiniWallet spends V2 coins."""

from test_framework.currency import RpcCurrency
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
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
        currency = RpcCurrency.from_node(node)
        assert_equal(currency.atoms_per_unit, 1000000)
        # Node-attached fee estimation must convert the RPC relay fee to atoms.
        probe = CTransaction()
        probe.vin = [CTxIn(COutPoint(0, 0))]
        probe.vout = [CTxOut(10000, b"\x51")]
        expected_size = probe.billable_size() + 107
        assert_equal(node.calculate_fee(probe), expected_size)
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
            utxo = wallet.get_utxo(mark_as_spent=False)
            # An unsent one-atom fee checks sub-cent accounting independently
            # of policy minimums. Keep the actual sent default fee unchanged.
            one_atom = wallet.create_self_transfer_multi(
                utxos_to_spend=[utxo], fee_per_output=1
            )
            assert_equal(currency.to_atoms(one_atom["fee"]), 1)
            assert_equal(
                currency.to_atoms(utxo["value"])
                - sum(out.nValue for out in one_atom["tx"].vout),
                1,
            )
            transfer = wallet.send_self_transfer(from_node=node, utxo_to_spend=utxo)
            # All four families retain the old 300000 atoms/kB default.
            assert_equal(
                currency.to_atoms(transfer["fee"]),
                len(transfer["tx"].serialize()) * 300,
            )
            assert_equal(
                currency.to_atoms(
                    node.getmempoolentry(transfer["txid"])["fees"]["base"]
                ),
                currency.to_atoms(transfer["fee"]),
            )
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
