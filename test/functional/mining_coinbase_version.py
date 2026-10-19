#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the selection of the coinbase version.

A coinbase is either a V2 coinbase (version 7) or, on regtest only, a legacy
coinbase (version 1 or 2). -coinbaseversion sets the node's default, and the
mining RPCs take a coinbase_version argument that overrides it.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class MiningCoinbaseVersionTest(BitcoinTestFramework):
    def set_test_params(self):
        # getblocktemplate needs a peer.
        self.num_nodes = 2
        self.setup_clean_chain = True

    def coinbase_of(self, block_hash):
        node = self.nodes[0]
        block = node.getblock(block_hash, 2)
        return block["tx"][0]

    def run_test(self):
        node = self.nodes[0]
        address = node.get_deterministic_priv_key().address
        descriptor = f"addr({address})"

        self.log.info("The framework default is a legacy version 2 coinbase")
        [h] = self.generatetoaddress(node, 1, address)
        cb = self.coinbase_of(h)
        assert_equal(cb["version"], 2)

        self.log.info("coinbase_version selects the coinbase form")
        for version in (1, 2, 7):
            [h] = self.generatetoaddress(node, 1, address, coinbase_version=version)
            assert_equal(self.coinbase_of(h)["version"], version)
            [h] = self.generatetodescriptor(
                node, 1, descriptor, coinbase_version=version
            )
            assert_equal(self.coinbase_of(h)["version"], version)
            h = self.generateblock(node, address, [], coinbase_version=version)["hash"]
            assert_equal(self.coinbase_of(h)["version"], version)
            tmpl = node.getblocktemplate({"coinbase_version": version})
            assert_equal(
                node.decoderawtransaction(tmpl["coinbasetxhex"])["version"],
                version,
            )

        self.log.info("Other versions are refused")
        for version in (0, 3, 6, 8):
            assert_raises_rpc_error(
                -8,
                "coinbase_version must be 1, 2 or 7",
                lambda: node.generatetoaddress(
                    1, address, coinbase_version=version, invalid_call=False
                ),
            )
            assert_raises_rpc_error(
                -8,
                "coinbase_version must be 1, 2 or 7",
                node.getblocktemplate,
                {"coinbase_version": version},
            )

        self.log.info("-coinbaseversion sets the default")
        self.restart_node(0, ["-coinbaseversion=7"])
        self.connect_nodes(0, 1)
        [h] = self.generatetoaddress(node, 1, address)
        assert_equal(self.coinbase_of(h)["version"], 7)
        tmpl = node.getblocktemplate()
        assert_equal(node.decoderawtransaction(tmpl["coinbasetxhex"])["version"], 7)

        self.log.info("-coinbaseversion accepts only 1, 2 or 7")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            ["-coinbaseversion=3"], "Error: -coinbaseversion must be 1, 2 or 7."
        )

        self.log.info("A legacy coinbase is refused off regtest")
        node.assert_start_raises_init_error(
            ["-regtest=0", "-testnet", "-acceptnonstdtxn=0", "-coinbaseversion=2"],
            "Error: -coinbaseversion=1 and -coinbaseversion=2 are allowed only "
            "on regtest.",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == "__main__":
    MiningCoinbaseVersionTest().main()
