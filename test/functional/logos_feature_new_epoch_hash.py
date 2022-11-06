#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import (
    create_coinbase,
    prepare_block,
)
from test_framework.messages import (
    CBlock,
    CBlockMetadataField,
    to_epoch_nbits,
    uint256_from_compact,
)
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
)
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

from io import BytesIO


ACTIVATION_TIME = 2000000000


class NewEpochHashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            '-whitelist=noban@127.0.0.1',
            f'-leviticusactivationtime={ACTIVATION_TIME}',
        ]]

    def fail_block(self, block, reject_reason, force_send=False):
        self.nodes[0].p2p.send_blocks_and_test([block], self.nodes[0], success=False, force_send=force_send, reject_reason=reject_reason)

    def make_unsolved_block(self, address):
        result = self.nodes[0].getrawunsolvedblock(address)
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(result['blockhex'])))
        return block

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        # Block hash must be below this number to become an epoch block in the new epoch mechanism
        epoch_nbits = to_epoch_nbits(0x207f_ffff)
        assert_equal(epoch_nbits, 0x1f06_8067)
        epoch_target = uint256_from_compact(epoch_nbits)

        # OP_TRUE in P2SH
        address = node.decodescript('51')['p2sh']

        # OP_FALSE in P2SH
        burn_address = node.decodescript('00')['p2sh']

        # Move our clock around the upgrade time
        node.setmocktime(ACTIVATION_TIME - 10000)

        # Check epoch hash is 0 for the first 20 blocks
        for height in range(201, 221):
            block = self.make_unsolved_block(burn_address)
            assert_equal(block.hashEpochBlock, 0)
            block.solve()
            node.p2p.send_blocks_and_test([block], node)
            del block

        # Move 7 blocks before end of legacy epoch
        node.generatetoaddress(4812, address)
        assert_equal(node.getblockcount(), 5032)

        self.log.info("Approach to just before upgrade activation")
        # Move our clock to the upgrade time so we will accept future-timestamped blocks.
        node.setmocktime(ACTIVATION_TIME)

        # Mine five blocks with timestamp starting at ACTIVATION_TIME-1
        for i in range(-1, 5):
            block = self.make_unsolved_block(burn_address)
            assert_equal(block.hashEpochBlock, 0)
            block.nTime = ACTIVATION_TIME + i
            block.solve()
            node.p2p.send_blocks_and_test([block], node)

        # We make block 5038 a lucky block, but new epoch mechanism not yet in place
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, 0)
        block.solve_epoch()

        # Now just 1 block is missing for the end of legacy epoch
        assert_equal(node.getblockcount(), 5038)

        # We made it such that the last block of the legacy epoch activates
        # the new epoch mechanism, to test if this case is handled gracefully.
        activation_block = self.make_unsolved_block(burn_address)
        # Previous block is lucky, but new epoch mechanism wasn't activated yet
        assert_equal(activation_block.hashEpochBlock, 0)
        activation_block.solve()
        node.p2p.send_blocks_and_test([activation_block], node)
        assert_equal(node.getblockcount(), 5039)

        # New rules activated, therefore, block 5040 still has epoch 0
        epoch_block = self.make_unsolved_block(burn_address)
        assert_equal(epoch_block.hashEpochBlock, 0)

        # Find rare epoch hash (<1s on regtest):
        epoch_block.solve_epoch()
        node.p2p.send_blocks_and_test([epoch_block], node)

        # Block 5041 now has the new epoch hash
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, epoch_block.sha256)
        # Make sure block 5041 is *not* an epoch block
        block.solve_non_epoch()
        node.p2p.send_blocks_and_test([block], node)

        # Block 5042 still requires block 5040's hash
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, epoch_block.sha256)

        # Reorg chain; we make the activation block lucky
        node.invalidateblock(activation_block.hash)
        assert_equal(node.getblockcount(), 5038)
        activation_block = self.make_unsolved_block(burn_address)
        # Previous block was lucky, but new epoch mechanism wasn't activated yet
        assert_equal(activation_block.hashEpochBlock, 0)
        activation_block.solve_epoch()
        node.p2p.send_blocks_and_test([activation_block], node)

        # Epoch hash is now the hash of the (lucky) activation block
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, activation_block.sha256)
        # Make sure block 5040 is *not* an epoch block
        block.solve_non_epoch()
        node.p2p.send_blocks_and_test([block], node)

        # Block 5041 still requires block 5039's hash
        block_template = node.getblocktemplate()
        assert_equal(block_template['epochblockhash'], activation_block.hash)


if __name__ == '__main__':
    NewEpochHashTest().main()
