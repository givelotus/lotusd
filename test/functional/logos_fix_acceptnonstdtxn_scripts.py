#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -acceptnonstdtxn also works for Scripts."""

from test_framework.txtools import pad_tx
from test_framework.script import hash160
from test_framework.blocktools import SUBSIDY
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    COIN,
)
from test_framework.p2p import (
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


class FixAcceptNonstandardScriptsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1",
                            "-acceptnonstdtxn=1",
                            "-allownonstdtxnconsensus=1"]]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())
        # OP_TRUE in P2SH to keep txs standard
        address = node.decodescript('51')['p2sh']
        node.generatetoaddress(101, address)

        value = int(SUBSIDY * COIN)

        block_hash = node.getblockhash(1)
        coin = int(node.getblock(block_hash)['tx'][0], 16)

        # OP_NOP10 is non-standard
        nop10_script = CScript([OP_NOP10, OP_TRUE])
        nop10_fund_tx = CTransaction()
        nop10_fund_tx.vin.append(
            CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
        nop10_fund_tx.vout.append(
            CTxOut(value - 2000, CScript([OP_HASH160, hash160(nop10_script), OP_EQUAL])))
        pad_tx(nop10_fund_tx)
        nop10_fund_tx.rehash()

        peer.send_txs_and_test([nop10_fund_tx], node)

        nop10_spend_tx = CTransaction()
        nop10_spend_tx.vin.append(
            CTxIn(COutPoint(nop10_fund_tx.txid, 0), CScript([nop10_script])))
        pad_tx(nop10_spend_tx)

        # Succeeds because of -acceptnonstdtxn=1
        peer.send_txs_and_test([nop10_spend_tx], node)


if __name__ == '__main__':
    FixAcceptNonstandardScriptsTest().main()
