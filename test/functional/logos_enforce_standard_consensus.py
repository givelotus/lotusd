#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -allownonstdtxnconsensusconsensus option."""

import re

from test_framework.txtools import pad_tx
from test_framework.script import hash160
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    make_conform_to_ctor,
    SUBSIDY,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    COIN,
)
from test_framework.util import (
    wait_until,
    assert_equal,
)
from test_framework.mininode import (
    P2PDataStore,
)
from test_framework.script import (
    CScript,
    OP_TRUE,
    OP_HASH160,
    OP_EQUAL,
    OP_NOP10,
)
from test_framework.test_framework import BitcoinTestFramework


class EnforceStandardConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1",
                            "-acceptnonstdtxn=0",
                            "-allownonstdtxnconsensus=1"]]

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())
        # OP_TRUE in P2SH to keep txs standard
        address = node.decodescript('51')['p2sh']
        num_mature_coins = 10
        node.generatetoaddress(num_mature_coins, address)
        node.generatetoaddress(100, address)

        value = int(SUBSIDY * COIN)

        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])

        def make_tx(coin_height):
            assert coin_height <= num_mature_coins
            block_hash = node.getblockhash(coin_height)
            coin = int(node.getblock(block_hash)['tx'][0], 16)
            # make non-standard transaction
            tx = CTransaction()
            tx.vin.append(
                CTxIn(COutPoint(coin, 0), CScript([b'\x51'])))
            return tx

        def make_block():
            parent_block_header = node.getblockheader(node.getbestblockhash())
            coinbase = create_coinbase(parent_block_header['height'] + 1)
            coinbase.vout[0].scriptPubKey = p2sh_script
            coinbase.calc_sha256()
            block = create_block(
                int(parent_block_header['hash'], 16), coinbase, parent_block_header['time'] + 1)
            return block

        # make a few non-standard txs
        nonstd_txs = []
        # bare OP_TRUE is a non-standard output
        bare_op_true_tx = make_tx(1)
        bare_op_true_tx.vout.append(
            CTxOut(value - 1000, CScript([OP_TRUE])))
        pad_tx(bare_op_true_tx)
        nonstd_txs.append(([bare_op_true_tx], 'scriptpubkey'))

        # version 0 is a non-standard version
        version_0_tx = make_tx(2)
        version_0_tx.nVersion = 0
        pad_tx(version_0_tx)
        nonstd_txs.append(([version_0_tx], 'version'))

        # version 3 is a non-standard version
        version_3_tx = make_tx(3)
        version_3_tx.nVersion = 3
        pad_tx(version_3_tx)
        nonstd_txs.append(([version_3_tx], 'version'))        

        # dust is non-standard (but ok in blocks)
        dust_tx = make_tx(4)
        dust_tx.vout.append(
            CTxOut(539, p2sh_script))
        dust_tx.vout.append(
            CTxOut(value - 2000, p2sh_script))
        pad_tx(dust_tx)
        nonstd_txs.append(([dust_tx], 'dust'))

        # OP_NOP10 is non-standard
        nop10_script = CScript([OP_NOP10, OP_TRUE])
        nop10_fund_tx = make_tx(5)
        nop10_fund_tx.vout.append(
            CTxOut(value - 2000, CScript([OP_HASH160, hash160(nop10_script), OP_EQUAL])))
        pad_tx(nop10_fund_tx)
        nop10_fund_tx.rehash()

        nop10_spend_tx = CTransaction()
        nop10_spend_tx.vin.append(
            CTxIn(COutPoint(nop10_fund_tx.sha256, 0), CScript([nop10_script])))
        pad_tx(nop10_spend_tx)
        nonstd_txs.append(([nop10_fund_tx, nop10_spend_tx], 'non-mandatory-script-verify-flag (NOPx reserved for soft-fork upgrades)'))
        
        # also make a few standard txs to check if they still work
        std_txs = []
        p2sh_tx = make_tx(6)
        p2sh_tx.vout.append(
            CTxOut(value - 1000, p2sh_script))
        pad_tx(p2sh_tx)
        std_txs.append(p2sh_tx)

        # version 1 is a standard version
        version_1_tx = make_tx(7)
        version_1_tx.nVersion = 1
        pad_tx(version_1_tx)
        std_txs.append(version_1_tx)

        # version 2 is a standard version
        version_2_tx = make_tx(8)
        version_2_tx.nVersion = 2
        pad_tx(version_2_tx)
        std_txs.append(version_2_tx)
        
        # amount above dust limit is standard
        non_dust_tx = make_tx(9)
        non_dust_tx.vout.append(
            CTxOut(540, p2sh_script))
        non_dust_tx.vout.append(
            CTxOut(value - 2000, p2sh_script))
        non_dust_tx.rehash()
        std_txs.append(non_dust_tx)

        # ==== FIRST TEST ====
        # -acceptnonstdtxn=0 -allownonstdtxnconsensus=1
        # Original Bitcoin behavior: standardness is policy but not consensus 
        # ====            ====

        # verify non-standard txs are rejected from mempool
        for txs, reason in nonstd_txs:
            if len(txs) > 1:
                # txs before last one treated as setup txs
                node.p2p.send_txs_and_test(txs[:-1], node)
            node.p2p.send_txs_and_test(txs[-1:], node, success=False, reject_reason=reason)

        # verify standard txs are accepted into mempool
        node.p2p.send_txs_and_test(std_txs, node)

        # verify both sets of txs are accepted as blocks
        nonstd_block = make_block()
        nonstd_block.vtx.extend(
            tx
            for txs, _ in nonstd_txs
            for tx in txs
        )
        nonstd_block.vtx.extend(std_txs)
        make_conform_to_ctor(nonstd_block)
        nonstd_block.hashMerkleRoot = nonstd_block.calc_merkle_root()
        nonstd_block.solve()
        # send nonstd_block, expected accept
        node.p2p.send_blocks_and_test([nonstd_block], node)
        node.invalidateblock(node.getbestblockhash())


        # ==== SECOND TEST ====
        # -acceptnonstdtxn=0 -allownonstdtxnconsensus=0
        # New Logos behavior: standardness is both policy and consensus
        # ====             ====

        # This is default behavior and doesn't require parameters
        self.restart_node(0, ["-whitelist=noban@127.0.0.1"])
        node.add_p2p_connection(P2PDataStore())

        # verify txs are rejected from mempool
        for txs, reason in nonstd_txs:
            if len(txs) > 1:
                # txs before last one treated as setup txs
                node.p2p.send_txs_and_test(txs[:-1], node)
            node.p2p.send_txs_and_test(txs[-1:], node, success=False, reject_reason=reason)

        # verify standard txs are accepted into mempool
        node.p2p.send_txs_and_test(std_txs, node)

        # verify txs in blocks are rejected
        for txs, reason in nonstd_txs:
            block = make_block()
            block.vtx += txs
            make_conform_to_ctor(block)
            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()
            if reason == 'dust':
                # verify dust is actually allowed in block
                node.p2p.send_blocks_and_test([block], node)
                node.invalidateblock(node.getbestblockhash())
            else:
                if 'NOPx' in reason:
                    reason = 'blk-bad-inputs'
                else:
                    reason = 'contains a non-standard transaction (and fRequireStandardConsensus is true)'
                node.p2p.send_blocks_and_test([block], node, success=False, reject_reason=reason)

        # verify std txs are accepted as blocks
        std_block = make_block()
        std_block.vtx.extend(std_txs)
        make_conform_to_ctor(std_block)
        std_block.hashMerkleRoot = std_block.calc_merkle_root()
        std_block.solve()
        # send std_block, expected accept
        node.p2p.send_blocks_and_test([std_block], node)
        node.invalidateblock(node.getbestblockhash())

        # ==== THIRD TEST ====
        # -acceptnonstdtxn=1 -allownonstdtxnconsensus=0
        # Invalid configuration: standardness not policy but consensus
        # ====            ====
        node.stop_node()
        node.start(["-acceptnonstdtxn=1",
                    "-allownonstdtxnconsensus=0"])
        def is_node_stopped_with_error():
            if not node.running:
                return True
            return_code = node.process.poll()
            if return_code is None:
                return False
            node.running = False
            node.process = None
            node.rpc_connected = False
            node.rpc = None
            node.log.debug("Node stopped")
            return True

        wait_until(is_node_stopped_with_error, timeout=5)
        node.stderr.flush()
        assert_equal(
            open(node.stderr.name).read(),
            'Error: -acceptnonstdtxn=1 -allownonstdtxnconsensus=0 is an invalid combination\n')

        # ==== FOURTH TEST ====
        # -acceptnonstdtxn=1 -allownonstdtxnconsensus=1
        # Standardness neither policy nor consensus, everything goes
        # ====             ====

        # use node.start as node already stopped in previous test
        node.start(["-acceptnonstdtxn=1",
                    "-allownonstdtxnconsensus=1"])
        node.wait_for_rpc_connection()
        node.add_p2p_connection(P2PDataStore())

        # verify non-standard txs are accepted to mempool (except OP_NOP10)
        node.p2p.send_txs_and_test(
            [
                tx
                for txs, _ in nonstd_txs[:-1]
                for tx in txs
            ],
            node)

        # verify standard txs are accepted into mempool
        node.p2p.send_txs_and_test(std_txs, node)
        # fund tx for OP_NOP10 is accepted
        node.p2p.send_txs_and_test([nop10_fund_tx], node)
        # spend tx for OP_NOP10 is still rejected
        node.p2p.send_txs_and_test([nop10_spend_tx], node, success=False)
        nonstd_block.nTime += 1  # tweak time so we don't collide with invalidateblock
        nonstd_block.solve()
        # verify (tweaked) non-standard block from before is valid
        node.p2p.send_blocks_and_test([nonstd_block], node)


if __name__ == '__main__':
    EnforceStandardConsensusTest().main()
