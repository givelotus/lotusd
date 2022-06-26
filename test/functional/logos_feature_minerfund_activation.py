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
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal

EXODUS_ACTIVATION_TIME = 2000000000
LEVITICUS_ACTIVATION_TIME = 2010000000

# see consensus/addresses.h
GENESIS_SCRIPTS = [
    "a914b6c79031b71d86ab0d617e1e1e706ec4ee34b07f87",
    "76a914b8ae1c47effb58f72f7bca819fe7fc252f9e852e88ac",
    "76a914b50b86a893d80c9e2ee72b199612374b7b4c1cd888ac",
    "76a914da76a31b6760dcb90aa469c15965da6e80096e4588ac",
    "76a9141325d2d8ba6e8c7d99ff66d21530917cc73429d288ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a91419e8d8d0edab6ec43f04b656bff72af78d63ff6588ac",
    "76a914c6492d4e44dcd0051e60a8add6af02b2f291b2aa88ac",
    "76a914b5aeafec9f2972110c4c6af9508a3c41e1d3c73b88ac",
    "76a9147c28aa91b93faf8aee0a6520a0a83f42dbc4a45b88ac",
    "76a914b18eb08c4978e73480743b1598061d3cf38e10a888ac",
    "76a9147d0893d1a278bab27e7ad92ed88bd7dceafd83a588ac",
    "76a9144b869f9a55c57003df178bdc801184109d904f8b88ac",
]
EXODUS_SCRIPTS = [
    "76a914b50b86a893d80c9e2ee72b199612374b7b4c1cd888ac",
    "76a914b20e7aad4df2a23bf412665019c41c96712acc6888ac",
    "76a9141325d2d8ba6e8c7d99ff66d21530917cc73429d288ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a9142a1e4c7ecaa87d49d2089a130413bd5cd2f99eaf88ac",
    "76a91403f95bc854e8209bbd662c940326404be9bc8a8288ac",
    "76a914b922f264776251674d69f13edbe2704377d8d4e688ac",
    "76a914c3150272548e0bc82a54aaed8f634b3496bf34d088ac",
    "76a9141199efaa97f8126b7f0a196dbefb000ac85bf16788ac",
    "76a9142b54c6576b50bc8909201489ddc2d5c84317890a88ac",
    "76a91419e8d8d0edab6ec43f04b656bff72af78d63ff6588ac",
    "76a9142e2f1b2961a548b7107fdd4520c743afeabc991d88ac",
    "76a914471d545492d9c94c1f630ba0507d3e378854f3d088ac",
]
LEVITICUS_SCRIPTS = [
    "76a914efd3d5363e91d73406f673022d9f9932ac7a6e2188ac",
    "76a91431bd7246ae1a24718c7ff6307f44b1d29a88e88188ac",
    "76a9141325d2d8ba6e8c7d99ff66d21530917cc73429d288ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a91484f1dbc598d1adce41e1ad3011e60b7502c0d0db88ac",
    "76a914e25ff1cb0a6000b56115ac4b178393f8a0ad215488ac",
    "76a91434ed5cae3056b8f990506aec8f2bd94cbf469c7588ac",
    "76a914e8d6cc8137617e2156baf25f2de823860d1579a888ac",
    "76a914b6284fbf3145dc2687fa02d00417cf094dd801cf88ac",
    "76a914453596826cff68b6206b7739ff9a911a22cae72d88ac",
    "76a9149dadb10adf30160eda6defe210983fb471b88a8e88ac",
    "76a91419e8d8d0edab6ec43f04b656bff72af78d63ff6588ac",
    "76a914a77122c592e9d24d51ad1dae37de73d77d7bc7f788ac",
]

class MinerFundActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            '-enableminerfund',
            f'-exodusactivationtime={EXODUS_ACTIVATION_TIME}',
            f'-leviticusactivationtime={LEVITICUS_ACTIVATION_TIME}',
        ]]

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        # Mine a block, contains coinbase with miner fund
        anyonecanspend_address = node.decodescript('51')['p2sh']
        node.generatetoaddress(1, anyonecanspend_address)

        def make_block_with_cb_scripts(scripts):
            best_block_hash = node.getbestblockhash()
            block_time = node.getblockheader(best_block_hash)['time']
            block_height = node.getblockcount() + 1
            coinbase = create_coinbase(block_height)
            coinbase.vout[1].nValue = int(SUBSIDY * COIN) // 2
            coinbase.vout[1].scriptPubKey = CScript([OP_HASH160, bytes(20), OP_EQUAL])
            for script in scripts:
                coinbase.vout.append(CTxOut(int(SUBSIDY * COIN) // 26, CScript(bytes.fromhex(script))))
            coinbase.rehash()
            block = create_block(int(best_block_hash, 16),
                                coinbase, block_height, block_time + 1)
            return block

        # Pre-fork minerfund with wrong (i.e. post-fork) scripts
        block = make_block_with_cb_scripts(EXODUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')
        block = make_block_with_cb_scripts(LEVITICUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # With correct scripts, except last script
        block = make_block_with_cb_scripts(
            GENESIS_SCRIPTS[:-1] + [EXODUS_SCRIPTS[-1]])
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # With correct scripts
        block = make_block_with_cb_scripts(GENESIS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), None)

        # Set mocktime for Exodus activation
        node.setmocktime(EXODUS_ACTIVATION_TIME)

        # Mine 11 blocks with EXODUS_ACTIVATION_TIME in the middle
        # That moves MTP exactly to EXODUS_ACTIVATION_TIME
        for i in range(-6, 6):
            block = make_block_with_cb_scripts(GENESIS_SCRIPTS)
            block.nTime = EXODUS_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)
        assert_equal(node.getblockchaininfo()['mediantime'], EXODUS_ACTIVATION_TIME)

        # Now the using the genesis addresses fails
        block = make_block_with_cb_scripts(GENESIS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Now the using the leviticus addresses fails
        block = make_block_with_cb_scripts(LEVITICUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Using new scripts now works
        block = make_block_with_cb_scripts(EXODUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), None)

        # Set mocktime for Leviticus activation
        node.setmocktime(LEVITICUS_ACTIVATION_TIME)
        # Mine 11 blocks with LEVITICUS_ACTIVATION_TIME in the middle
        # That moves MTP exactly to LEVITICUS_ACTIVATION_TIME
        for i in range(-6, 6):
            block = make_block_with_cb_scripts(EXODUS_SCRIPTS)
            block.nTime = LEVITICUS_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)
        assert_equal(node.getblockchaininfo()['mediantime'], LEVITICUS_ACTIVATION_TIME)

        # Now the using the genesis addresses fails
        block = make_block_with_cb_scripts(GENESIS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Now the using the exodus addresses fails
        block = make_block_with_cb_scripts(EXODUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Using new scripts now works
        block = make_block_with_cb_scripts(LEVITICUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), None)


if __name__ == '__main__':
    MinerFundActivationTest().main()
