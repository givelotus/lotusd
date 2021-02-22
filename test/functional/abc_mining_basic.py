#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests for Bitcoin ABC mining RPCs
"""

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

MINER_FUND_ADDR = 'bchreg:pqnqv9lt7e5vjyp0w88zf2af0l92l8rxdgd35g0pkl'


class AbcMiningRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[
            '-enableminerfund',
        ], []]

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

        block_reward = 50

        # TODO: Cannot use getblocktemplate for block after genesis
        # JSONRPC error: Bitcoin ABC is in initial sync and waiting for blocks...

        # Generate first block after genesis
        node.generatetoaddress(1, address)

        # We expect the coinbase to uphold the mining rule
        coinbase = get_best_coinbase()
        assert_greater_than_or_equal(len(coinbase['vout']), 2)
        total = Decimal()
        for o in coinbase['vout']:
            total += o['value']

        assert_equal(total, block_reward)

        # We don't need to test all fields in getblocktemplate since many of
        # them are covered in mining_basic.py
        assert_equal(node.getmempoolinfo()['size'], 0)
        assert_getblocktemplate({
            'coinbasetxn': {
                # We expect to see the miner fund addresses in every block
                'minerfund': {
                    'addresses': [MINER_FUND_ADDR],
                    'minimumvalue': block_reward * 8 // 100 * COIN,
                },
            },
            # Although the coinbase value need not necessarily be the same as
            # the last block due to halvings and fees, we know this to be true
            # since we are not crossing a halving boundary and there are no
            # transactions in the mempool.
            'coinbasevalue': block_reward * COIN,
        })


if __name__ == '__main__':
    AbcMiningRPCTest().main()
