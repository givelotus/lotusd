#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Tests for Lotus `getrawunsolvedblock` rpc call
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_array_result,
)
from test_framework.messages import (
    CBlock,
    FromHex,
)

from decimal import Decimal

NUM_TRANSACTIONS = 10


class LotusGetRawUnsolvedBlock(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def run_test(self):
        node = self.nodes[0]
        address = node.get_deterministic_priv_key().address
        # Generate generate some blocks and mature the coinbases
        node.generatetoaddress(101, address)
        last_generated_block = node.getbestblockhash()
        txids = [node.sendtoaddress(node.getnewaddress(), 1)
                 for x in range(NUM_TRANSACTIONS)]
        response = node.getrawunsolvedblock(address)
        block = FromHex(CBlock(), response['blockhex'])
        # coinbase and the 3 transactions we sent
        assert_equal(block.hashMerkleRoot, block.calc_merkle_root())
        # Should have all the transactions, plus the coinbase tx
        assert_equal(len(block.vtx), NUM_TRANSACTIONS+1)
        # Skip coinbase. Transactions should be sorted by Id
        txids.sort()
        for idx in range(NUM_TRANSACTIONS):
            # All transactions found and in order
            assert_equal(txids[idx], block.vtx[idx+1].txid_hex)
        block.solve()
        node.submitblock(block.serialize().hex())
        response = node.getbestblockhash()
        assert_equal(response, block.hash)
        # Ensure the transactions are confirmed and in the wallet
        txns = node.listsinceblock(last_generated_block)['transactions']
        for idx in range(NUM_TRANSACTIONS):
            assert_array_result(txns,
                                {'txid': txids[idx]},
                                {'blockhash': block.hash, 'confirmations': 1})


if __name__ == '__main__':
    LotusGetRawUnsolvedBlock().main()
