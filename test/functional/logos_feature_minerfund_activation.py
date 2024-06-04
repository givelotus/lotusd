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
NUMBERS_ACTIVATION_TIME = 2020000000
DEUTERONOMY_ACTIVATION_TIME = 2030000000
JOSHUA_ACTIVATION_TIME = 2040000000
JUDGES_ACTIVATION_TIME = 2050000000
RUTH_ACTIVATION_TIME = 2060000000

REPLAYPROTECTION_ACTIVATION_TIME = RUTH_ACTIVATION_TIME

# see consensus/addresses.h, use getaddressinfo to get the scriptPubKey
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
NUMBERS_SCRIPTS = [
    "76a9145e38e8e232aca63350fb59a0d8465189c7d0549188ac",
    "76a914193354a1a0b2e3097a1d54c2958207fff6ff775188ac",
    "76a9141325d2d8ba6e8c7d99ff66d21530917cc73429d288ac",
    "76a9146d2c8cb2d031c09862c5fbde900ae8cc0570d1ce88ac",
    "76a914d64134ac890bd18831560f0c4ef5cea5c976484888ac",
    "76a914a05d68eaceaefe5cdc1b0794a762f21cf578c5d688ac",
    "76a9149bef68961730d891b117424de78f47891b7d8c5f88ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a914c0dba2b28f0fb9b49b58135ce37fef8ce978b75888ac",
    "76a914b9e0eeacd624c507796bce80316eb836c495d2cc88ac",
    "76a9147f66047ab92de6ad4d62f609fc123c49fb63d4ff88ac",
    "76a91461cebabeaa6365887bb95d95e62b848fa365506388ac",
    "76a914b59008144c4f883e3b1fd9e18e479bc2f877fca788ac",
]
DEUTERONOMY_SCRIPTS = [
    "76a9140f0f21219533cc9cdd692887d9bd4aa2d8de2a5688ac",
    "76a91489991036959af60a1a08625fb5695f4967268e1f88ac",
    "76a914118c8e65b8fe0f33c175bc039f94a15225fe409e88ac",
    "76a914322889c5791a7daa1ad0cd1ade6487e85696968f88ac",
    "76a91429f63d6931bf0d782aab1c230c178be2446ab02488ac",
    "76a91479f8cda245128982b9c49169a7453a94a1af332d88ac",
    "76a91479f8cda245128982b9c49169a7453a94a1af332d88ac",
    "76a9148d91da546b8689c0b366e05b96fd1acb9c4f5b7688ac",
    "76a9148d91da546b8689c0b366e05b96fd1acb9c4f5b7688ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a9146a171891ab9443020bd2755ef79c6e59efc5926588ac",
    "76a9149f3201e09dc27f8ac71672118ae28ae7c804326e88ac",
    "76a9149f3201e09dc27f8ac71672118ae28ae7c804326e88ac",
    "76a9149f3201e09dc27f8ac71672118ae28ae7c804326e88ac",
    "76a9149f3248570eff3658b794f29e6e59f394eca8f69988ac",
    "76a9149f3248570eff3658b794f29e6e59f394eca8f69988ac",
    "76a9149f3248570eff3658b794f29e6e59f394eca8f69988ac",
    "76a914017cc7d3bb5512f21835cac23bd92b361393dcd288ac",
    "76a914017cc7d3bb5512f21835cac23bd92b361393dcd288ac",
    "76a914017cc7d3bb5512f21835cac23bd92b361393dcd288ac",
    "76a914017cc7d3bb5512f21835cac23bd92b361393dcd288ac",
    "76a914017cc7d3bb5512f21835cac23bd92b361393dcd288ac",
]
JOSHUA_SCRIPTS = [
    "76a9142eedc5ad3d142181417daea01076846edfba998088ac",
]
JUDGES_SCRIPTS = [
    "76a9149208ecc785c92968481a92aee7024b77e54d27dc88ac",
]

class MinerFundActivationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            '-enableminerfund',
            f'-exodusactivationtime={EXODUS_ACTIVATION_TIME}',
            f'-leviticusactivationtime={LEVITICUS_ACTIVATION_TIME}',
            f'-numbersactivationtime={NUMBERS_ACTIVATION_TIME}',
            f'-deuteronomyactivationtime={DEUTERONOMY_ACTIVATION_TIME}',
            f'-joshuaactivationtime={JOSHUA_ACTIVATION_TIME}',
            f'-judgesactivationtime={JUDGES_ACTIVATION_TIME}',
            f'-replayprotectionactivationtime={REPLAYPROTECTION_ACTIVATION_TIME}',
        ]]

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        # Mine a block, use coin to test replay protection
        key = node.get_deterministic_priv_key()
        key_script = node.validateaddress(key.address)['scriptPubKey']
        coinblockhash = node.generatetoaddress(1, key.address)[0]
        cointxid = node.getblock(coinblockhash)['tx'][0]

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

        # Make a block with the appropriate coinbase output post-numbers upgrade
        def make_block_cb_post_numbers(scripts):
            best_block_hash = node.getbestblockhash()
            block_time = node.getblockheader(best_block_hash)['time']
            block_height = node.getblockcount() + 1
            coinbase = create_coinbase(block_height)
            coinbase.vout[1].nValue = int(SUBSIDY * COIN) // 2
            coinbase.vout[1].scriptPubKey = CScript([OP_HASH160, bytes(20), OP_EQUAL])
            script = scripts[block_height % len(scripts)]
            coinbase.vout.append(CTxOut(int(SUBSIDY * COIN) // 2, CScript(bytes.fromhex(script))))
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

        # Set mocktime for Numbers activation
        node.setmocktime(NUMBERS_ACTIVATION_TIME)
        # Mine 11 blocks with NUMBERS_ACTIVATION_TIME in the middle
        # That moves MTP exactly to NUMBERS_ACTIVATION_TIME
        for i in range(-6, 6):
            block = make_block_with_cb_scripts(LEVITICUS_SCRIPTS)
            block.nTime = NUMBERS_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)
        assert_equal(node.getblockchaininfo()['mediantime'], NUMBERS_ACTIVATION_TIME)

        # Now the using the genesis addresses fails
        block = make_block_with_cb_scripts(GENESIS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Now the using the exodus addresses fails
        block = make_block_with_cb_scripts(EXODUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Now the using the leviticus addresses fails
        block = make_block_with_cb_scripts(LEVITICUS_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # now mine 26 blocks to ensure all addresses pass
        for i in range(0, 26):
            block = make_block_cb_post_numbers(NUMBERS_SCRIPTS)
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        # Using the deuteronomy addresses before upgrade fails
        block = make_block_cb_post_numbers(DEUTERONOMY_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Set mocktime for Deuteronomy activation
        node.setmocktime(DEUTERONOMY_ACTIVATION_TIME)
        # Mine 11 blocks with DEUTERONOMY_ACTIVATION_TIME in the middle
        # That moves MTP exactly to DEUTERONOMY_ACTIVATION_TIME
        for i in range(-6, 6):
            block = make_block_cb_post_numbers(NUMBERS_SCRIPTS)
            block.nTime = DEUTERONOMY_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        assert_equal(node.getblockchaininfo()['mediantime'],
                     DEUTERONOMY_ACTIVATION_TIME)
        
        # Now the using the genesis, exodus, leviticus, or numbers addresses fails
        for block in [
            make_block_with_cb_scripts(GENESIS_SCRIPTS),
            make_block_with_cb_scripts(EXODUS_SCRIPTS),
            make_block_with_cb_scripts(LEVITICUS_SCRIPTS),
            make_block_cb_post_numbers(NUMBERS_SCRIPTS),
        ]:
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')

        # Using the Deuteronomy scripts now works
        for i in range(0, 26):
            block = make_block_cb_post_numbers(DEUTERONOMY_SCRIPTS)
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        # Using the joshua addresses before upgrade fails
        block = make_block_cb_post_numbers(JOSHUA_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')
        node.setmocktime(JOSHUA_ACTIVATION_TIME)

        # Mine 11 blocks with JOSHUA_ACTIVATION in the middle
        # That moves MTP exactly to JOSHUA_ACTIVATION
        for i in range(-6, 6):
            block = make_block_cb_post_numbers(DEUTERONOMY_SCRIPTS)
            block.nTime = JOSHUA_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        assert_equal(node.getblockchaininfo()['mediantime'],
                     JOSHUA_ACTIVATION_TIME)
        
        # Now the using the genesis, exodus, leviticus, or numbers, and deuteronomy addresses fails
        for block in [
            make_block_with_cb_scripts(GENESIS_SCRIPTS),
            make_block_with_cb_scripts(EXODUS_SCRIPTS),
            make_block_with_cb_scripts(LEVITICUS_SCRIPTS),
            make_block_cb_post_numbers(NUMBERS_SCRIPTS),
            make_block_cb_post_numbers(DEUTERONOMY_SCRIPTS),
        ]:
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')
       
        # Using the Joshua scripts now works
        for i in range(0, 12):
            block = make_block_cb_post_numbers(JOSHUA_SCRIPTS)
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        # Using the judges addresses before upgrade fails
        block = make_block_cb_post_numbers(JUDGES_SCRIPTS)
        prepare_block(block)
        assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')
        node.setmocktime(JOSHUA_ACTIVATION_TIME)

        # Mine 11 blocks with JUDGES_ACTIVATION in the middle
        # That moves MTP exactly to JUDGES_ACTIVATION
        for i in range(-6, 6):
            block = make_block_cb_post_numbers(JOSHUA_SCRIPTS)
            block.nTime = JUDGES_ACTIVATION_TIME + i
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        assert_equal(node.getblockchaininfo()['mediantime'],
                     JUDGES_ACTIVATION_TIME)
        
        # Now the using the genesis, exodus, leviticus, or numbers, and deuteronomy addresses fails
        for block in [
            make_block_with_cb_scripts(GENESIS_SCRIPTS),
            make_block_with_cb_scripts(EXODUS_SCRIPTS),
            make_block_with_cb_scripts(LEVITICUS_SCRIPTS),
            make_block_cb_post_numbers(NUMBERS_SCRIPTS),
            make_block_cb_post_numbers(DEUTERONOMY_SCRIPTS),
            make_block_cb_post_numbers(JOSHUA_SCRIPTS),
        ]:
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), 'bad-cb-minerfund')
       
        # Using the Joshua scripts now works
        for i in range(0, 12):
            block = make_block_cb_post_numbers(JUDGES_SCRIPTS)
            prepare_block(block)
            assert_equal(node.submitblock(ToHex(block)), None)

        # Check replay protection is not enabled yet
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(cointxid, 16), 1))]
        tx.vout = [CTxOut(int(SUBSIDY * COIN) // 2 - 1000,
                          CScript.fromhex(key_script))]
        raw_tx = node.signrawtransactionwithkey(tx.serialize().hex(), [key.key])
        node.sendrawtransaction(raw_tx['hex'])


if __name__ == '__main__':
    MinerFundActivationTest().main()
