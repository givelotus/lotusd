#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    prepare_block,
    SUBSIDY,
)
from test_framework.messages import ToHex, CTxOut, CTxIn, COutPoint, CTransaction, COIN
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal

ACTIVATION_TIME = 2000000000

class MinerFundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[
            '-enableminerfund',
            f'-exodusactivationtime={ACTIVATION_TIME}',
        ]] * 2

    def run_test(self):
        node = self.nodes[0]

        # Mine a block, contains coinbase with miner fund
        anyonecanspend_address = node.decodescript('51')['p2sh']
        node.generatetoaddress(1, anyonecanspend_address)

        def get_best_coinbase():
            return node.getblock(node.getbestblockhash(), 2)['tx'][0]

        # 10 Lotus per share
        share_amount = SUBSIDY / 26
        block_template = node.getblocktemplate()
        expected_outputs = block_template['coinbasetxn']['minerfund']['outputs']

        # Now we send part of the coinbase to the fund.
        best_coinbase = get_best_coinbase()
        expected_number_of_outputs = 13
        assert_equal(len(best_coinbase['vout']),
                     2 + expected_number_of_outputs)
        for actual_output in best_coinbase['vout'][2:]:
            assert_equal(actual_output['value'], share_amount)

        best_block_hash = node.getbestblockhash()
        block_time = node.getblockheader(best_block_hash)['time']
        block_height = node.getblockcount() + 1
        coinbase = create_coinbase(block_height)

        # Submit a custom block that does not send anything
        # to the fund and check if it is rejected.
        coinbase.vout[1].scriptPubKey = CScript(
            [OP_HASH160, bytes(20), OP_EQUAL])
        coinbase.vout[1].nValue = int(SUBSIDY * COIN)
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16),
                             coinbase, block_height, block_time + 1)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Submit a custom block that sends the required outputs
        # with the miner reward at the end (which is allowed)
        coinbase.vout[1:] = []
        for output in expected_outputs:
            coinbase.vout.append(CTxOut(int(output['value']),
                                        CScript(bytes.fromhex(output['scriptPubKey']))))
        coinbase.vout.insert(2, CTxOut(int(SUBSIDY / 2 * COIN),
                                       CScript([OP_HASH160, bytes(20), OP_EQUAL])))
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16),
                             coinbase, block_height, block_time + 1)

        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), None)

        # Mature block 1
        node.generatetoaddress(100, anyonecanspend_address)
        best_block_hash = node.getbestblockhash()
        best_block_header = node.getblockheader(best_block_hash)
        # Build tx that send all money (130 Lotus) to miners
        # Half of that is burned, so 65 Lotus remain
        coin = int(node.getblock(node.getblockhash(1))['tx'][0], 16)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
        pad_tx(tx)
        # Each share gets 1.25 times more due to fees
        share_multiplier = Decimal('1.25')
        block_height = best_block_header['height'] + 1
        coinbase = create_coinbase(block_height)
        coinbase.vout[1] = CTxOut(int(share_multiplier * SUBSIDY / 2 * COIN),
                                  CScript([OP_HASH160, bytes(20), OP_EQUAL]))
        block_template = node.getblocktemplate()
        expected_outputs = block_template['coinbasetxn']['minerfund']['outputs']
        for output in expected_outputs:
            coinbase.vout.append(CTxOut(int(share_multiplier * output['value']),
                                        CScript(bytes.fromhex(output['scriptPubKey']))))
        coinbase.rehash()
        block = create_block(int(best_block_hash, 16),
                             coinbase, block_height, best_block_header['time'] + 1)
        block.vtx.append(tx)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), None)


if __name__ == '__main__':
    MinerFundTest().main()
