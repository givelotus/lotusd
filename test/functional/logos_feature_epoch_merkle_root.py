#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from decimal import Decimal
import copy
import time
from io import BytesIO


from test_framework.blocktools import (
    create_coinbase,
    prepare_block,
    SUBSIDY,
)
from test_framework.messages import ToHex, COIN, CBlock, hash256, uint256_from_compact, CBlockMetadataField, ser_uint256, get_merkle_root
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

ACTIVATION_TIME = 2000000000


def hash256_int(x):
    return int.from_bytes(hash256(x), 'little')


def calc_merkle_root(merkle_roots):
    hashes = []
    for merkle_root in merkle_roots:
        hashes.append(ser_uint256(merkle_root))
    return get_merkle_root(hashes)[0]


def calc_epoch_merkle_root(merkle_roots):
    merkle_root, num_layers = get_merkle_root(merkle_roots)
    return merkle_root + bytes([num_layers])


class EpochMerkleRootTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            '-whitelist=noban@127.0.0.1',
            f'-leviticusactivationtime={ACTIVATION_TIME}',
        ]]

    def make_unsolved_block(self, address):
        result = self.nodes[0].getrawunsolvedblock(address)
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(result['blockhex'])))
        return block

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())

        # burn script
        burn_address = node.decodescript('00')['p2sh']

        # Keep track of merkle roots to compute epoch merkle root
        genesis_hash = node.getbestblockhash()
        epoch_roots = [calc_merkle_root([int(genesis_hash, 16), int(node.getblockheader(genesis_hash)['merkleroot'], 16)])]

        self.log.info("Generate 10 blocks")
        block_hashes = node.generatetoaddress(10, burn_address)
        for block_hash in block_hashes:
            epoch_roots.append(calc_merkle_root([int(block_hash, 16), int(node.getblockheader(block_hash)['merkleroot'], 16)]))

        self.log.info("Block with any metadata is rejected")
        block = self.make_unsolved_block(burn_address)
        block.vMetadata = [CBlockMetadataField(fieldId=1, data=b'\0'*33)]
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata, forbidden extended metadata field')
        del block

        self.log.info("New block should have no metadata (yet)")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, 0)
        assert_equal(block.vMetadata, [])
        assert_equal(block.hashExtendedMetadata, hash256_int(b'\0'))
        block.solve()
        node.p2p.send_blocks_and_test([block], node)
        epoch_roots.append(calc_merkle_root([block.sha256, block.hashMerkleRoot]))
        del block

        self.log.info("Approach to just before upgrade activation")
        # Move our clock to the upgrade time so we will accept future-timestamped blocks.
        node.setmocktime(ACTIVATION_TIME)

        self.log.info("Mine six blocks with timestamp starting at ACTIVATION_TIME-1")
        self.log.info("All shouldn't have any metadata")
        for i in range(-1, 5):
            block = self.make_unsolved_block(burn_address)
            assert_equal(block.hashEpochBlock, 0)
            assert_equal(block.vMetadata, [])
            assert_equal(block.hashExtendedMetadata, hash256_int(b'\0'))
            block.nTime = ACTIVATION_TIME + i
            block.solve()
            node.p2p.send_blocks_and_test([block], node)
            epoch_roots.append(calc_merkle_root([block.sha256, block.hashMerkleRoot]))
            del block

        self.log.info("MTP is exactly at ACTIVATION_TIME now")
        block_template = node.getblocktemplate()
        assert_equal(block_template['mintime'], ACTIVATION_TIME)

        self.log.info("Activation block with any metadata is still rejected")
        block = self.make_unsolved_block(burn_address)
        block.vMetadata = [CBlockMetadataField(fieldId=1, data=b'\0'*33)]
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata, forbidden extended metadata field')
        del block

        self.log.info("Activation block still shouldn't have metadata")
        activation_block = self.make_unsolved_block(burn_address)
        assert_equal(activation_block.hashEpochBlock, 0)
        assert_equal(activation_block.vMetadata, [])
        assert_equal(activation_block.hashExtendedMetadata, hash256_int(b'\0'))
        activation_block.solve_non_epoch()  # may not be epoch
        node.p2p.send_blocks_and_test([activation_block], node)
        epoch_roots.append(calc_merkle_root([activation_block.sha256, activation_block.hashMerkleRoot]))

        self.log.info("Next block should have metadata now")

        self.log.info("Block without metadata is rejected")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, 0)
        block.vMetadata = []
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata, invalid number of metadata fields')
        del block

        self.log.info("Block with 2 metadata fields is rejected, too")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, 0)
        block.vMetadata.append(CBlockMetadataField(fieldId=2, data=b'\0'*32))
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata, invalid number of metadata fields')
        del block

        self.log.info("Block with a metadata field other than 1 is rejected")
        block = self.make_unsolved_block(burn_address)
        block.vMetadata = [CBlockMetadataField(fieldId=0, data=b'\0'*33)]
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata, forbidden extended metadata field')
        del block

        self.log.info("Epoch Merkle root must be 33 bytes")
        block = self.make_unsolved_block(burn_address)
        block.vMetadata = [CBlockMetadataField(fieldId=1, data=b'\0'*32)]
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-metadata-field, invalid EPOCH_MERKLE_ROOT length')
        del block

        self.log.info("Block has to have correct epoch merkle root")
        block = self.make_unsolved_block(burn_address)
        block.vMetadata = [CBlockMetadataField(fieldId=1, data=b'\0'*33)]
        prepare_block(block)
        node.p2p.send_blocks_and_test([block], node, success=False,
                                      reject_reason='bad-epoch-merkle-root, invalid epoch merkle root')
        del block

        self.log.info("Mine block with correct epoch Merkle root")
        self.log.info("Note: Epoch extends all the way back to genesis here")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, 0)
        expected_epoch_merkle_root = calc_epoch_merkle_root(epoch_roots + [calc_merkle_root([0, block.hashMerkleRoot])])
        assert_equal(block.vMetadata, [CBlockMetadataField(fieldId=1, data=expected_epoch_merkle_root)])
        # explicitly check serialization: <num fields: VarInt> <fieldId: uint32_t> <data size: VarInt> <data: bytes>
        assert_equal(block.hashExtendedMetadata, hash256_int(b'\x01\x01\0\0\0\x21' + expected_epoch_merkle_root))
        block.solve_non_epoch()  # may not be epoch
        node.p2p.send_blocks_and_test([block], node)
        epoch_roots.append(calc_merkle_root([block.sha256, block.hashMerkleRoot]))
        del block

        self.log.info("New epoch block has one extra merkle root in Epoch Merkle root")
        epoch_block = self.make_unsolved_block(burn_address)
        assert_equal(epoch_block.hashEpochBlock, 0)
        expected_epoch_merkle_root = calc_epoch_merkle_root(epoch_roots + [calc_merkle_root([0, epoch_block.hashMerkleRoot])])
        assert_equal(epoch_block.vMetadata, [CBlockMetadataField(fieldId=1, data=expected_epoch_merkle_root)])
        epoch_block.solve_epoch()
        node.p2p.send_blocks_and_test([epoch_block], node)

        self.log.info("Next block should only have own merkle root now as epoch merkle root")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, epoch_block.sha256)
        expected_epoch_merkle_root = calc_merkle_root([0, block.hashMerkleRoot]) + b'\x01'
        assert_equal(block.vMetadata, [CBlockMetadataField(fieldId=1, data=expected_epoch_merkle_root)])
        assert_equal(block.hashExtendedMetadata, hash256_int(b'\x01\x01\0\0\0\x21' + expected_epoch_merkle_root))
        block.solve()
        node.p2p.send_blocks_and_test([block], node)
        del block

        self.log.info("Reorg activation block and make it an epoch block")
        node.invalidateblock(activation_block.hash)

        epoch_block = self.make_unsolved_block(burn_address)
        assert_equal(epoch_block.hashEpochBlock, 0)
        assert_equal(epoch_block.vMetadata, [])
        assert_equal(epoch_block.hashExtendedMetadata, hash256_int(b'\0'))
        epoch_block.solve_epoch()  # must be epoch
        node.p2p.send_blocks_and_test([epoch_block], node)

        self.log.info("Next block has metadata now")
        block = self.make_unsolved_block(burn_address)
        assert_equal(block.hashEpochBlock, epoch_block.sha256)
        expected_epoch_merkle_root = calc_merkle_root([0, block.hashMerkleRoot]) + b'\x01'
        assert_equal(block.vMetadata, [CBlockMetadataField(fieldId=1, data=expected_epoch_merkle_root)])
        assert_equal(block.hashExtendedMetadata, hash256_int(b'\x01\x01\0\0\0\x21' + expected_epoch_merkle_root))
        block.solve()
        node.p2p.send_blocks_and_test([block], node)
        del block


if __name__ == '__main__':
    EpochMerkleRootTest().main()
