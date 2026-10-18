#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin developers
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Accepted regtest zero-root parents retain state under their real block hash.

Legacy P2P spends reproduce the regtest compatibility path; native batch RPC
rejection of legacy transactions remains a separate contract.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.key import ECKey
from test_framework.messages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import OP_CHECKSIG, OP_TRUE, CScript
from test_framework.signature_hash import (
    SIGHASH_ALL,
    SIGHASH_FORKID,
    SignatureHashForkId,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NativeZeroRootStateCacheTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1"]]
        self.heights = {}

    def best_block(self, node):
        block = FromHex(CBlock(), node.getblock(node.getbestblockhash(), 0))
        self.heights[block.hash_int] = node.getblockcount()
        return block

    def block(self, parent, transactions=()):
        height = self.heights[parent.hash_int] + 1
        block = create_block(
            parent.hash_int,
            create_coinbase(height),
            parent.nTime + 1,
            txlist=transactions,
        )
        assert_equal(block.hashStateRoot, 0)
        block.solve()
        self.heights[block.hash_int] = height
        return block

    def run_test(self):
        node = self.nodes[0]
        node.add_p2p_connection(P2PDataStore())
        tip = self.best_block(node)
        parents = []
        blocks = []
        for _ in range(10):
            tip = self.block(tip)
            blocks.append(tip)
            parents.append(tip.vtx[0])
        node.p2ps[0].send_blocks_and_test(blocks, node)
        self.generate(node, COINBASE_MATURITY, sync_fun=self.no_op)
        tip = self.best_block(node)

        key = ECKey()
        key.set(b"Schnorr!" * 4, True)
        script = CScript([key.get_pubkey().get_bytes(), OP_CHECKSIG])
        fundings, spends = [], []
        for use_schnorr in (False, True):
            parent = parents.pop()
            value = parent.vout[0].nValue
            funding = create_tx_with_script(
                parent, 0, b"", amount=value, script_pub_key=script
            )
            fundings.append(funding)
            spend = CTransaction()
            spend.vin.append(CTxIn(COutPoint(funding.txid_int, 0), b""))
            spend.vout.append(CTxOut(value - 1000, CScript([OP_TRUE])))
            hash_type = SIGHASH_ALL | SIGHASH_FORKID
            digest = SignatureHashForkId(script, spend, 0, hash_type, value)
            signature = (
                key.sign_schnorr(digest) if use_schnorr else key.sign_ecdsa(digest)
            )
            spend.vin[0].scriptSig = CScript([signature + bytes([hash_type & 0xFF])])
            spends.append(spend)
        funding_block = self.block(tip, fundings)
        node.p2ps[0].send_blocks_and_test([funding_block], node)
        node.p2ps[0].send_txs_and_test(spends, node)
        # Before the repair, the real zero-root parent hash misses its cached
        # state: full validation derives fee0/expiry131712 while overlay mining
        # derives fee1000/expiry132712, and this RPC fails bad-blk-stateroot.
        self.generate(node, 1, sync_fun=self.no_op)
        mined = self.best_block(node)
        assert {spend.txid_hex for spend in spends}.issubset(
            tx.txid_hex for tx in mined.vtx
        )
        assert_equal(node.getrawmempool(), [])


if __name__ == "__main__":
    NativeZeroRootStateCacheTest().main()
