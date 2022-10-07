#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests for Bitcoin ABC mining RPCs
"""

from test_framework.blocktools import SUBSIDY
from decimal import Decimal

from test_framework.cdefs import (
    BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO,
    DEFAULT_MAX_BLOCK_SIZE,
)
from test_framework.messages import (
    COIN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal


class AbcMiningRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[
            '-enableminerfund',
            '-allownonstdtxnconsensus=1',
        ], [
            '-enableminerfund',
            '-allownonstdtxnconsensus=1',
        ]]

    def setup_network(self):
        self.setup_nodes()

        # Connect node0 to all other nodes so getblocktemplate will return results
        # (getblocktemplate has a sanity check that ensures it's connected to a network)
        # Since the other nodes are mining blocks "in the future" compared to node0,
        # node0 will not broadcast blocks between the other nodes.
        for n in range(1, len(self.nodes)):
            self.connect_nodes(0, n)

    def run_for_node(self, node):
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
        block_template_data = node.getblocktemplate()
        expected_funding_outputs = 13
        miner_fund_outputs = block_template_data['coinbasetxn']['minerfund']['outputs']
        assert_equal(len(miner_fund_outputs), 13)
        assert_equal(block_template_data['coinbasevalue'], SUBSIDY * COIN)
        for output in miner_fund_outputs:
            assert_equal(output['value'], share_amount)

    def run_test(self):
        # node0 is for connectivity only and is not mined on (see
        # setup_network)
        self.run_for_node(self.nodes[1])


if __name__ == '__main__':
    AbcMiningRPCTest().main()
