# Copyright (c) 2023 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test if Chronik properly shuts down.

This tests a case where, when processing large blocks with lots of ins/outs, Chronik
would lag behind. When shutting down at that moment, Chronik would continue to process
blocks which, if we're not careful, might have been freed in the node already, resulting
in a segfault.
"""

from test_framework.blocktools import GENESIS_BLOCK_HASH, create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, msg_block
from test_framework.p2p import P2PDataStore
from test_framework.script import OP_TRUE, CScript
from test_framework.test_framework import BitcoinTestFramework


class ChronikShutdown(BitcoinTestFramework):
    setup_clean_chain = True
    num_nodes = 1
    extra_args = [["-chronik"]]
    rpc_timeout = 240

    requires = {"chronik"}

    def run_test(self):
        mocktime = 1300000000
        node = self.nodes[0]
        node.setmocktime(mocktime)
        peer = node.add_p2p_connection(P2PDataStore())
        self.wait_until(lambda: peer.is_connected, timeout=10)

        last_block_hash = GENESIS_BLOCK_HASH
        coinbase_txs = []
        for i in range(1, 200):
            coinbase_tx = create_coinbase(i)
            coinbase_tx.vout[0].scriptPubKey = CScript([OP_TRUE])
            coinbase_txs.append(coinbase_tx)
            txs = []
            if i > 101:
                txid = coinbase_txs[i - 101].txid_int
                # Preserve all 8,000 fan outputs and 2,666 three-input
                # spends under the universal 256-output transaction limit.
                split_tx = CTransaction()
                split_tx.vin = [CTxIn(COutPoint(txid, 0))]
                split_tx.vout = [CTxOut(250_000, CScript([OP_TRUE]))] * 32
                txs.append(split_tx)
                fan_outpoints = []
                for split_idx in range(32):
                    fan_tx = CTransaction()
                    fan_tx.vin = [CTxIn(COutPoint(split_tx.txid_int, split_idx))]
                    fan_tx.vout = [CTxOut(1000, CScript([OP_TRUE]))] * 250
                    txs.append(fan_tx)
                    fan_outpoints.extend(
                        COutPoint(fan_tx.txid_int, k) for k in range(250)
                    )
                assert len(fan_outpoints) == 8000
                for j in range(0, 7997, 3):
                    tx = CTransaction()
                    tx.vin = [CTxIn(fan_outpoints[k]) for k in range(j, j + 3)]
                    tx.vout = [CTxOut(1000, CScript([OP_TRUE]))]
                    txs.append(tx)
            block = create_block(
                int(last_block_hash, 16), coinbase_tx, mocktime + i, txlist=txs
            )
            block.solve()
            last_block_hash = block.hash_hex
            peer.send_without_ping(msg_block(block))

        self.stop_nodes()


if __name__ == "__main__":
    ChronikShutdown().main()
