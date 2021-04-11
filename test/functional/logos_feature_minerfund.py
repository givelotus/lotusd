#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    make_conform_to_ctor,
    SUBSIDY,
)
from test_framework.messages import ToHex, CTxOut, CTxIn, COutPoint, CTransaction, COIN
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal


class MinerFundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            '-enableminerfund',
        ]]

    def run_test(self):
        node = self.nodes[0]

        # Mine a block, contains coinbase with miner fund
        anyonecanspend_address = node.decodescript('51')['p2sh']
        node.generatetoaddress(1, anyonecanspend_address)

        def get_best_coinbase():
            return node.getblock(node.getbestblockhash(), 2)['tx'][0]

        # 10 Lotus per share
        share_amount = SUBSIDY / 26

        # Now we send part of the coinbase to the fund.
        coinbase = get_best_coinbase()
        expected_outputs = [
            {'scriptPubKey': 'a914260617ebf668c9102f71ce24aba97fcaaf9c666a87',
             'value': share_amount},
            {'scriptPubKey': '76a91407d6f95a81155b7f706d5bc85106fbc77409e36e88ac',
             'value': share_amount},
            {'scriptPubKey': '76a914ba9113bbb9c6880bb877a284299f21d13365e52888ac',
             'value': share_amount},
            {'scriptPubKey': '6a1ac8e1f6e5a0ede5f2e3f9a0efeea0ede5aca0e1a0f3e9eeeee5f2',
             'value': 10 * share_amount},
        ]
        assert_equal(len(coinbase['vout']), 1 + len(expected_outputs))
        for actual_output, expected_output in zip(coinbase['vout'][1:], expected_outputs):
            assert_equal(actual_output['value'], expected_output['value'])
            assert_equal(actual_output['scriptPubKey']['hex'], expected_output['scriptPubKey'])

        best_block_hash = node.getbestblockhash()
        block_time = node.getblockheader(best_block_hash)['time']
        block_height = node.getblockcount() + 1
        coinbase = create_coinbase(block_height)

        # Submit a custom block that does not send anything
        # to the fund and check if it is rejected.
        coinbase.vout[0].scriptPubKey = CScript([OP_HASH160, bytes(20), OP_EQUAL])
        coinbase.vout[0].nValue = int(SUBSIDY * COIN)
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16), coinbase, block_time + 1)
        block.solve()
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Submit a custom block that does send the required outputs
        # with the miner reward output in the middle (which is allowed)
        # but with the outputs in the wrong order (which is not allowed)
        coinbase.vout = []
        for output in expected_outputs:
            coinbase.vout.append(CTxOut(int(output['value'] * COIN),
                                        CScript(bytes.fromhex(output['scriptPubKey']))))
        coinbase.vout.insert(2, CTxOut(int(SUBSIDY / 2 * COIN),
                                       CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        coinbase.vout[4], coinbase.vout[3] = coinbase.vout[3], coinbase.vout[4]
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16), coinbase, block_time + 1)
        block.solve()
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Fix the order and block is valid
        coinbase.vout[4], coinbase.vout[3] = coinbase.vout[3], coinbase.vout[4]
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16), coinbase, block_time + 1)
        block.solve()
        assert_equal(node.submitblock(ToHex(block)), None)

        # Mature block 1
        node.generatetoaddress(100, anyonecanspend_address)
        best_block_hash = node.getbestblockhash()
        best_block_header = node.getblockheader(best_block_hash)
        # Build tx that send all money (130 Lotus) to miners
        # Half of that is burned, so 65 Lotus remain
        coin = int(node.getblock(node.getblockhash(1))['tx'][0], 16)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(coin, 0), CScript([b'\x51'])))
        pad_tx(tx)
        # Each share gets 1.25 times more due to fees
        share_multiplier = Decimal('1.25')
        coinbase = create_coinbase(best_block_header['height'] + 1)
        coinbase.vout[0] = CTxOut(int(share_multiplier * SUBSIDY / 2 * COIN),
                                  CScript([OP_HASH160, bytes(20), OP_EQUAL]))
        for output in expected_outputs:
            coinbase.vout.append(CTxOut(int(share_multiplier * output['value'] * COIN),
                                        CScript(bytes.fromhex(output['scriptPubKey']))))
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16), coinbase, best_block_header['time'] + 1)
        block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        assert_equal(node.submitblock(ToHex(block)), None)


if __name__ == '__main__':
    MinerFundTest().main()
