#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet recognizes its V2 outputs after deserialization.

A V2 single-branch output on the wire commits to BranchLeaf(script) instead of
carrying the script. The coinbases a wallet mines are V2 outputs, so after a
restart (wallet database), and for blocks read back from disk while the wallet
was unloaded, the wallet only sees the synthetic wire script. It must map it
back to its own script: listtransactions must agree with txcount and with what
it listed before the restart, the balance must survive, and the restored
coins must stay spendable.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def listing(wallet):
    return sorted(
        (e["txid"], e["category"], e.get("vout", -1), str(e["amount"]))
        for e in wallet.listtransactions("*", 10_000)
    )


class WalletV2OutputScriptsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def check_consistent(self, wallet):
        info = wallet.getwalletinfo()
        txids = {e["txid"] for e in wallet.listtransactions("*", 10_000)}
        assert_equal(len(txids), info["txcount"])

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        mine_to = wallet.getnewaddress()
        self.generatetoaddress(node, 101, mine_to)
        for _ in range(3):
            wallet.sendtoaddress(wallet.getnewaddress(), Decimal("1000000"))
        self.generatetoaddress(node, 1, mine_to)

        before = listing(wallet)
        info = wallet.getwalletinfo()
        assert_equal(info["txcount"], 105)
        self.check_consistent(wallet)

        self.log.info("Restart the node with the same datadir")
        self.restart_node(0)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(listing(wallet), before)
        after = wallet.getwalletinfo()
        assert_equal(after["txcount"], info["txcount"])
        assert_equal(after["balance"], info["balance"])
        assert_equal(after["immature_balance"], info["immature_balance"])
        self.check_consistent(wallet)

        self.log.info("Coins restored from the database stay spendable")
        txid = wallet.sendtoaddress(wallet.getnewaddress(), Decimal("1000000"))
        self.generatetoaddress(node, 1, mine_to)
        assert_equal(wallet.gettransaction(txid)["confirmations"], 1)
        self.check_consistent(wallet)

        self.log.info("Blocks connected while the wallet is unloaded")
        count = wallet.getwalletinfo()["txcount"]
        node.unloadwallet(self.default_wallet_name)
        node.createwallet("other")
        self.generatetoaddress(node, 5, mine_to)
        node.loadwallet(self.default_wallet_name)
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        assert_equal(wallet.getwalletinfo()["txcount"], count + 5)
        self.check_consistent(wallet)

        self.log.info("A rescan from disk finds the same transactions")
        before = listing(wallet)
        wallet.rescanblockchain()
        assert_equal(listing(wallet), before)


if __name__ == "__main__":
    WalletV2OutputScriptsTest().main()
