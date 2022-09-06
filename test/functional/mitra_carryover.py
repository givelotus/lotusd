#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtranscation RPCs.

Test the following RPCs with Mitra txs:
   - sendrawtransaction
"""

from decimal import Decimal
from test_framework.blocktools import SUBSIDY
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import CScript, OP_HASH160, OP_EQUAL
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# Create one-input, one-output, no-fee transaction:
class MitraCarryoverTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.log.info('Decode Mitra transactions')

        node = self.nodes[0]

        anyonecanspend_address = node.decodescript('51')['p2sh']
        anyonecanspend_script = bytes.fromhex(node.validateaddress(anyonecanspend_address)['scriptPubKey'])
        burn_address = node.decodescript('00')['p2sh']
        node.generatetoaddress(1, anyonecanspend_address)
        node.generatetoaddress(100, burn_address)

        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])

        block_hash = node.getblockhash(1)
        utxo_txid = bytes.fromhex(node.getblock(block_hash)['tx'][0])

        # Valid tx creating carryover
        tx_raw_hex = (
            "07000000" +
            "00" + # No preambles
            "01" + # One input
                utxo_txid[::-1].hex() +
                "01000000" +
                "ffffffff" + # sequence
                int(SUBSIDY * COIN).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "00" # No carryover
                "00" # No preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "01" + # One output
                int(SUBSIDY * COIN - 1000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "03" "223344" # carryover
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        mitra_txid = node.sendrawtransaction(tx_raw_hex)
        node.generatetoaddress(1, burn_address)

        # Invalid tx, wrong carryover
        tx_raw_hex = (
            "07000000" +
            "00" + # No preambles
            "01" + # One input
                bytes.fromhex(mitra_txid)[::-1].hex() +
                "00000000" +
                "ffffffff" + # sequence
                int((SUBSIDY * COIN) - 1000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "03" "223355" # carryover
                "00" # No preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "01" + # One output
                int(SUBSIDY * COIN - 2000).to_bytes(8, 'little').hex() +
                bytes([len(p2sh_script)]).hex() + p2sh_script.hex() +
                "00" # carryover
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        assert_raises_rpc_error(-26,
                                "bad-txns-input-output-mismatch",
                                node.sendrawtransaction,
                                tx_raw_hex)

        # Valid tx spending
        tx_raw_hex = (
            "07000000" +
            "00" + # No preambles
            "01" + # One input
                bytes.fromhex(mitra_txid)[::-1].hex() +
                "00000000" +
                "ffffffff" + # sequence
                int((SUBSIDY * COIN) - 1000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "03" "223344" # carryover
                "00" # No preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "01" + # One output
                int(SUBSIDY * COIN - 2000).to_bytes(8, 'little').hex() +
                bytes([len(p2sh_script)]).hex() + p2sh_script.hex() +
                "00" # carryover
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        node.sendrawtransaction(tx_raw_hex)

if __name__ == '__main__':
    MitraCarryoverTest().main()
