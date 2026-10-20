#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Known legacy script bytes do not imply ownership of a native VM policy."""

from test_framework.messages import lotus_v2_branch_leaf
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.xpiaddr import encode


class NativePolicyOwnershipTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-coinbaseversion=7", "-gbtwithoutpeers=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        legacy = wallet.getnewaddress()
        legacy_info = wallet.getaddressinfo(legacy)
        assert_equal(legacy_info["ismine"], True)
        # This is an explicit test-only native root, not an address conversion
        # offered by the product. These bytes mean different opcodes in the VM.
        native_root = lotus_v2_branch_leaf(bytes.fromhex(legacy_info["scriptPubKey"]))
        unsupported = encode("rxpi", native_root)
        before = wallet.getwalletinfo()["txcount"]
        block = node.rpc.generatetoaddress(1, unsupported, 1_000_000, 7)[0]
        coinbase = node.getblock(block)["tx"][0]
        assert_raises_rpc_error(
            -5, "Invalid or non-wallet transaction id", wallet.gettransaction, coinbase
        )
        assert_equal(wallet.getwalletinfo()["txcount"], before)
        assert_equal(wallet.getwalletinfo()["immature_balance"], 0)


if __name__ == "__main__":
    NativePolicyOwnershipTest().main()
