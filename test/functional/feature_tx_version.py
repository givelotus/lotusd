# Copyright (c) 2023 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test enforcement of strict tx version. A transaction has version 1 or 2
(legacy) or 7 (V2); any other version has no serialization, so a transaction
or block carrying one does not decode (bad-txns-version).
"""

from typing import Optional

from test_framework.address import P2SH_OP_TRUE, SCRIPTSIG_OP_TRUE
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.messages import CBlock, FromHex, msg_block, msg_tx
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.txtools import pad_tx
from test_framework.util import assert_greater_than_or_equal

# The legacy versions. A version 7 transaction cannot spend these legacy
# coins without the bridge, which other tests cover.
OK_VERSIONS = [1, 2]
BAD_VERSIONS = [
    0x80000000,
    0x80000001,
    0xFFFFFFFE,
    0xFFFFFFFF,
    0,
    3,
    0x100,
    0x7FFFFFFF,
    # The former wrapped forms of version 7 in the legacy grammar.
    0x80000007,
    0xC0000007,
]

START_TIME = 1_900_000_000


class TxVersionTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    extra_args = [
        [
            "-acceptnonstdtxn=0",
            "-whitelist=127.0.0.1",
        ]
    ]

    def run_test(self):
        self.block_heights = {}

        node = self.nodes[0]
        node.setmocktime(START_TIME)
        peer = node.add_p2p_connection(P2PDataStore())

        genesis = FromHex(CBlock(), node.getblock(node.getbestblockhash(), 0))

        # Mine us some coins
        blocks = [genesis]
        num_spendable_txs = 30
        spendable_txs = []
        for i in range(100 + num_spendable_txs):
            block = self.make_block(blocks[-1])
            if i < num_spendable_txs:
                spendable_txs.append(block.vtx[0])
            blocks.append(block)
        peer.send_blocks_and_test(blocks[1:], node, success=True)

        # Get out of IBD to avoid the node rejecting the transactions
        self.generate(node, 1)
        assert not node.getblockchaininfo()["initialblockdownload"]

        def test_mempool_accepts_ok_versions():
            for ok_version in OK_VERSIONS:
                spendable_tx = spendable_txs.pop(0)
                tx = self.make_tx(spendable_tx, nVersion=ok_version)
                peer.send_txs_and_test([tx], node, success=True)

        def test_mempool_rejects_bad_versions():
            bad_version_txs = []
            for bad_version in BAD_VERSIONS:
                spendable_tx = spendable_txs.pop(0)
                tx = self.make_tx(spendable_tx, nVersion=bad_version)
                bad_version_txs.append(tx)
                with node.assert_debug_log(
                    ["ProcessMessages(tx", "Exception 'bad-txns-version"]
                ):
                    peer.send_and_ping(msg_tx(tx))
                assert tx.txid_hex not in node.getrawmempool()
            return bad_version_txs

        self.log.info("These are always OK for the mempool")
        test_mempool_accepts_ok_versions()

        self.log.info("Bad versions do not decode")
        bad_version_txs = test_mempool_rejects_bad_versions()

        self.log.info("We CANNOT mine blocks with txs with bad versions")
        tip = node.getbestblockhash()
        for bad_tx in bad_version_txs:
            block = self.make_block(blocks[-1], txs=[bad_tx])
            self.send_undecodable_block(peer, node, block, tip)

        self.log.info("We CANNOT mine blocks with a coinbase with a bad version")
        for bad_version in BAD_VERSIONS:
            block = self.make_block(blocks[-1], coinbase_version=bad_version)
            self.send_undecodable_block(peer, node, block, tip)

    def send_undecodable_block(self, peer, node, block, tip):
        with node.assert_debug_log(
            ["ProcessMessages(block", "Exception 'bad-txns-version"]
        ):
            peer.send_and_ping(msg_block(block))
        assert node.getbestblockhash() == tip

    def make_tx(self, spend_tx, nVersion):
        value = spend_tx.vout[0].nValue - 1000
        assert_greater_than_or_equal(value, 546)
        tx = create_tx_with_script(
            spend_tx, 0, amount=value, script_pub_key=P2SH_OP_TRUE
        )
        tx.nVersion = nVersion
        tx.vin[0].scriptSig = SCRIPTSIG_OP_TRUE
        pad_tx(tx)
        return tx

    def make_block(
        self,
        prev_block: CBlock,
        *,
        nTime: Optional[int] = None,
        coinbase_version=None,
        txs=None,
    ) -> CBlock:
        block_time = prev_block.nTime + 1 if nTime is None else nTime
        height = self.block_heights.get(prev_block.hash_int, 0) + 1
        coinbase = create_coinbase(height)
        coinbase.vout[0].scriptPubKey = P2SH_OP_TRUE
        if coinbase_version is not None:
            coinbase.nVersion = coinbase_version

        block = create_block(prev_block.hash_int, coinbase, block_time, txlist=txs)
        block.solve()
        self.block_heights[block.hash_int] = height
        return block


if __name__ == "__main__":
    TxVersionTest().main()
