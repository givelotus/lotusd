#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal
import copy
import time

from test_framework.blocktools import (
    create_coinbase,
    prepare_block,
    SUBSIDY,
)
from test_framework.messages import ToHex, COIN, CBlock, hash256, uint256_from_compact, CBlockMetadataField
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
)
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_equal


def hash256_int(x):
    return int.from_bytes(hash256(x), 'little')


class NewBlockHeaderTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-whitelist=noban@127.0.0.1']]

    def fail_block(self, block, reject_reason, force_send=False):
        self.nodes[0].p2p.send_blocks_and_test([block], self.nodes[0], success=False, force_send=force_send, reject_reason=reject_reason)

    def block_from_template(self, block_template):
        coinbase = create_coinbase(block_template['height'])
        coinbase.vout[1].scriptPubKey = CScript([OP_HASH160, bytes(20), OP_EQUAL])
        block = CBlock()
        block.hashPrevBlock = int(block_template['previousblockhash'], 16)
        block.nBits = 0x207fffff
        block.nTime = block_template['mintime']
        block.nHeight = block_template['height']
        block.hashEpochBlock = int(block_template['epochblockhash'], 16)
        block.vtx = [coinbase]
        return block

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        # OP_TRUE in P2SH
        address = node.decodescript('51')['p2sh']
        # burn script
        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])

        prevblockhash = node.getbestblockhash()

        coinbase = create_coinbase(201)
        coinbase.vout[1].scriptPubKey = p2sh_script
        coinbase.rehash()
        sample_block = CBlock()
        sample_block.vtx = [coinbase]
        sample_block.hashPrevBlock = int(prevblockhash, 16)
        sample_block.nBits = 0x207fffff
        sample_block.nTime = 1600000036
        sample_block.nReserved = 0
        sample_block.nHeaderVersion = 1
        sample_block.nHeight = 201
        sample_block.hashEpochBlock = 0
        sample_block.hashMerkleRoot = sample_block.calc_merkle_root()
        sample_block.hashExtendedMetadata = hash256_int(b'\0')
        sample_block.update_size()

        # Using legacy hashing algo
        block = copy.deepcopy(sample_block)
        target = uint256_from_compact(block.nBits)
        block.rehash()
        while hash256_int(block.serialize()) > target or block.sha256 <= target:
            block.nNonce += 1
            block.rehash()
        self.fail_block(block, force_send=True, reject_reason='high-hash')
        del block

        # Claimed size already excessive (before doing any other checks)
        block = copy.deepcopy(sample_block)
        block.nSize = 32_000_001
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-size')
        del block

        # Incorrect nBits
        block = copy.deepcopy(sample_block)
        block.nBits = 0x207ffffe
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-diffbits')
        del block

        # Block too old
        block = copy.deepcopy(sample_block)
        block.nTime = 1600000035
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='time-too-old')
        del block

        # nReserved must be 0
        block = copy.deepcopy(sample_block)
        block.nReserved = 0x0100
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-reserved')
        del block

        # nHeaderVersion must be 1
        block = copy.deepcopy(sample_block)
        block.nHeaderVersion = 0
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-version')
        block.nHeaderVersion = 2
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-version')
        del block

        # Incorrect claimed height
        block = copy.deepcopy(sample_block)
        block.nHeight = 200
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-height')
        block.nHeight = 202
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-height')
        del block

        # Invalid epoch block
        block = copy.deepcopy(sample_block)
        block.hashEpochBlock = 1
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='bad-blk-epoch')
        del block

        # Time too far into the future
        block = copy.deepcopy(sample_block)
        block.nTime = int(time.time()) + 2 * 60 * 60 + 1
        block.solve()
        self.fail_block(block, force_send=True, reject_reason='time-too-new')
        del block

        # Invalid merkle root
        block = copy.deepcopy(sample_block)
        block.hashMerkleRoot = 0
        block.solve()
        self.fail_block(block, reject_reason='bad-txnmrklroot')
        del block

        # Invalid metadata hash
        block = copy.deepcopy(sample_block)
        block.hashExtendedMetadata = 0
        block.solve()
        self.fail_block(block, reject_reason='bad-metadata-hash')
        del block

        # Non-empty metadata
        block = copy.deepcopy(sample_block)
        block.vMetadata.append(CBlockMetadataField(0, b''))
        block.rehash_extended_metadata()
        block.solve()
        self.fail_block(block, reject_reason='bad-metadata')
        del block

        # Claimed nSize doesn't match actual size
        block = copy.deepcopy(sample_block)
        block.nSize = 1
        block.solve()
        self.fail_block(block, reject_reason='blk-size-mismatch')
        del block

        block_template = node.getblocktemplate()
        assert_equal(block_template.pop('capabilities'), ['proposal'])
        assert_equal(block_template.pop('version'), 1)
        assert_equal(block_template.pop('previousblockhash'), prevblockhash)
        assert_equal(block_template.pop('epochblockhash'), '0000000000000000000000000000000000000000000000000000000000000000')
        assert_equal(block_template.pop('transactions'), [])
        assert_equal(block_template.pop('coinbaseaux'), {})
        assert_equal(block_template.pop('coinbasevalue'), int(SUBSIDY * COIN))
        assert_equal(block_template.pop('coinbasetxn'), {'minerfund': {'outputs': []}})
        block_template.pop('longpollid')
        assert_equal(block_template.pop('target'), '7fffff0000000000000000000000000000000000000000000000000000000000')
        assert_equal(block_template.pop('mintime'), 1600000036)
        assert_equal(block_template.pop('mutable'), ['time', 'transactions', 'prevblock'])
        assert_equal(block_template.pop('noncerange'), '00000000ffffffff')
        assert_equal(block_template.pop('sigoplimit'), 226950)
        assert_equal(block_template.pop('sizelimit'), 32000000)
        block_template.pop('curtime')
        assert_equal(block_template.pop('bits'), '207fffff')
        assert_equal(block_template.pop('height'), 201)
        assert_equal(block_template, {})

        # Check epoch hash is 0 for the first 20 blocks
        for height in range(201, 221):
            block_template = node.getblocktemplate()
            assert_equal(block_template['epochblockhash'], '00' * 32)
            block = self.block_from_template(block_template)
            block.hashEpochBlock = 0
            prepare_block(block)
            node.p2p.send_blocks_and_test([block], node)
            del block
    
        # Move to end of epoch
        node.generatetoaddress(4819, address)
        assert_equal(node.getblockcount(), 5039)

        epochblockhash = node.getbestblockhash()
        epochblock = node.getblock(epochblockhash)
        assert_equal(epochblock['epochblockhash'], '00' * 32)

        # getblocktemplate gives us current tip as epoch block hash
        block_template = node.getblocktemplate()
        assert_equal(block_template['epochblockhash'], epochblockhash)
        assert_equal(block_template['previousblockhash'], epochblockhash)

        # Using 0 as epoch block hash is now invalid
        block = self.block_from_template(block_template)
        block.hashEpochBlock = 0
        prepare_block(block)
        self.fail_block(block, force_send=True, reject_reason='bad-blk-epoch')

        # Setting current tip as epoch hash makes the block valid
        block.hashEpochBlock = int(epochblockhash, 16)
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)
        del block

        # getblocktemplate still gives us the same epoch block hash
        block_template = node.getblocktemplate()
        assert_equal(block_template['epochblockhash'], epochblockhash)
        assert_equal(block_template['previousblockhash'], node.getbestblockhash())

        # Block after that still requires epoch block hash
        block = self.block_from_template(block_template)
        block.hashEpochBlock = int(epochblockhash, 16)
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)
        del block

        # Test 48-bit nTime
        node.setmocktime(2**32)  # smallest number that does not fit in 32-bit number
        block_template = node.getblocktemplate()
        assert_equal(block_template['curtime'], 2**32)
        block = self.block_from_template(block_template)
        block.nTime = 2**32
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)
        del block

        node.setmocktime(2**48 - 1)  # biggest possible 48-bit number
        block_template = node.getblocktemplate()
        assert_equal(block_template['curtime'], 2**48 - 1)
        block = self.block_from_template(block_template)
        block.nTime = 2**48 - 1
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node)
        del block


if __name__ == '__main__':
    NewBlockHeaderTest().main()
