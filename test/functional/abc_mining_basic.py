#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests for Bitcoin ABC mining RPCs
"""

from test_framework.blocktools import SUBSIDY
from test_framework.cdefs import (
    BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO,
    DEFAULT_MAX_BLOCK_SIZE,
)
from test_framework.messages import (
    COIN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
)

from decimal import Decimal


class AbcMiningRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[
            '-enableminerfund',
            '-allownonstdtxnconsensus=1',
        ], [
            '-allownonstdtxnconsensus=1',
        ]]

    def run_test(self):
        node = self.nodes[0]
        address = node.get_deterministic_priv_key().address

        # Assert the results of getblocktemplate have expected values. Keys not
        # in 'expected' are not checked.
        def assert_getblocktemplate(expected):
            # Always test these values in addition to those passed in
            expected = {**expected, **{
                'sigoplimit': DEFAULT_MAX_BLOCK_SIZE // BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO,
            }}

            blockTemplate = node.getblocktemplate()
            for key, value in expected.items():
                assert_equal(blockTemplate[key], value)

        def get_best_coinbase():
            return node.getblock(node.getbestblockhash(), 2)['tx'][0]

        # TODO: Cannot use getblocktemplate for block after genesis
        # JSONRPC error: Bitcoin ABC is in initial sync and waiting for blocks...

        # Generate first block after genesis
        node.generatetoaddress(1, address)

        # We expect the coinbase to uphold the mining rule
        coinbase = get_best_coinbase()
        assert_greater_than_or_equal(len(coinbase['vout']), 5)
        total = Decimal()
        for o in coinbase['vout']:
            total += o['value']

        assert_equal(total, SUBSIDY)

        # We don't need to test all fields in getblocktemplate since many of
        # them are covered in mining_basic.py
        assert_equal(node.getmempoolinfo()['size'], 0)
        share_amount = SUBSIDY * COIN // 26
        assert_getblocktemplate({
            'coinbasetxn': {
                # We expect to see the miner fund addresses in every block
                'minerfund': {
                    'outputs': [
                        {'scriptPubKey': 'a914260617ebf668c9102f71ce24aba97fcaaf9c666a87',
                        'value': share_amount},
                        {'scriptPubKey': '76a91407d6f95a81155b7f706d5bc85106fbc77409e36e88ac',
                        'value': share_amount},
                        {'scriptPubKey': '76a914ba9113bbb9c6880bb877a284299f21d13365e52888ac',
                        'value': share_amount},
                        {'scriptPubKey': '6a1ac8e1f6e5a0ede5f2e3f9a0efeea0ede5aca0e1a0f3e9eeeee5f2',
                        'value': 10 * share_amount},
                    ],
                },
            },
            # Although the coinbase value need not necessarily be the same as
            # the last block due to halvings and fees, we know this to be true
            # since we are not crossing a halving boundary and there are no
            # transactions in the mempool.
            'coinbasevalue': SUBSIDY * COIN,
        })


if __name__ == '__main__':
    AbcMiningRPCTest().main()
