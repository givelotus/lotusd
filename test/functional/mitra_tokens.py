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
    hash256,
)
from test_framework.script import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# Create one-input, one-output, no-fee transaction:
class MitraTokenTest(BitcoinTestFramework):
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
        utxo_txid = bytes.fromhex(node.getblock(block_hash)['tx'][0])[::-1]

        preamble = CScript([
            # Either: Genesis tx, self-evident
            OP_IF,
                OP_0,
                OP_PICKINPUTOUTPOINT,
                utxo_txid + b'\x01\0\0\0',
                OP_EQUAL,
            # Or: Normal send transfer, cannot create tokens
            OP_ELSE,
                OP_THISINDEX,
                OP_PICKPREAMBLEHASH,
                # Sum inputs that have this preamble's hash as preamble merkle root
                OP_0,
                OP_NUMINPUTS,
                OP_LOOP,
                    OP_1SUB,
                    OP_DUP,
                    OP_PICKINPUTPREAMBLEMERKLEROOT,
                    OP_3,
                    OP_PICK,
                    OP_EQUAL,
                    OP_IF,
                        OP_DUP,
                        OP_PICKINPUTCARRYOVER,
                        OP_BIN2NUM,
                        OP_ROT,
                        OP_ADD,
                        OP_SWAP,
                    OP_ENDIF,
                    OP_DUP,
                OP_ENDLOOP,
                OP_DROP,
                OP_NIP,

                # Sum outputs
                OP_0,
                OP_NUMOUTPUTS,
                OP_LOOP,
                    OP_1SUB,
                    OP_DUP,
                    OP_PICKOUTPUTCARRYOVER,
                    OP_BIN2NUM,
                    OP_ROT,
                    OP_ADD,
                    OP_SWAP,
                    OP_DUP,
                OP_ENDLOOP,
                OP_DROP,

                # Verify inputs >= outputs
                OP_GREATERTHANOREQUAL,
            OP_ENDIF,
        ])
        preamble_hash = hash256(preamble)

        # Genesis tx
        tx_raw_hex = (
            "07000000" +
            "01" + # 1 preamble
                bytes([len(preamble)]).hex() + preamble.hex() +
                "01" # 1 witness
                    "01" "01" # Genesis path
                "00" # No loop counts
            "01" + # One input
                utxo_txid.hex() +
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
                "01" "10" # Carryover = token amount
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        genesis_txid_hex = node.sendrawtransaction(tx_raw_hex)
        genesis_txid = bytes.fromhex(genesis_txid_hex)[::-1]

        # Spend tx 1
        tx_raw_hex = (
            "07000000" +
            "01" + # 1 preamble
                bytes([len(preamble)]).hex() + preamble.hex() +
                "01" # 1 witness
                    "00"
                "00" # No loop counts
            "01" + # One input
                genesis_txid.hex() +
                "00000000" +
                "ffffffff" + # sequence
                int(SUBSIDY * COIN - 1000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "10" # Carryover = token amount
                "01" + preamble_hash.hex() + # Token preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "02" + # 2 outputs
                int(SUBSIDY * COIN - 3000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "05" + # token amount
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "0b" + # token amount
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        spend1_txid_hex = node.sendrawtransaction(tx_raw_hex)
        spend1_txid = bytes.fromhex(spend1_txid_hex)[::-1]

        # Invalid tx: insufficient input tokens
        tx_raw_hex = (
            "07000000" +
            "01" + # 1 preamble
                bytes([len(preamble)]).hex() + preamble.hex() +
                "01" # 1 witness
                    "00"
                "00" # No loop counts
            "01" + # One input
                spend1_txid.hex() +
                "00000000" +
                "ffffffff" + # sequence
                int(SUBSIDY * COIN - 3000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "05" # Carryover = token amount
                "01" + preamble_hash.hex() + # Token preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "02" + # 2 outputs
                int(SUBSIDY * COIN - 5000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "03" + # Overspend
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "03" + # Overspend
            "00000000"
        )
        assert_raises_rpc_error(-26,
                                "mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)",
                                node.sendrawtransaction,
                                tx_raw_hex)

        # Spend tx 2
        tx_raw_hex = (
            "07000000" +
            "01" + # 1 preamble
                bytes([len(preamble)]).hex() + preamble.hex() +
                "01" # 1 witness
                    "00"
                "00" # No loop counts
            "02" + # Two inputs
                # Input 0:
                spend1_txid.hex() +
                "00000000" +
                "ffffffff" + # sequence
                int(SUBSIDY * COIN - 3000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "05" # Carryover = token amount
                "01" + preamble_hash.hex() + # Token preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" + # No loop counts
                # Input 1:
                spend1_txid.hex() +
                "01000000" +
                "ffffffff" + # sequence
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "0b" # Carryover = token amount
                "01" + preamble_hash.hex() + # Token preamble merkle root
                "01" "01" "51" # 1 witness, 0x51
                "00" # No loop counts
            "04" + # 2 outputs
                int(SUBSIDY * COIN - 10000).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "03" + # token amount
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "04" + # token amount
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "05" + # token amount
                int(546).to_bytes(8, 'little').hex() +
                bytes([len(anyonecanspend_script)]).hex() + anyonecanspend_script.hex() +
                "01" "02" + # token amount, burns 2 tokens
            "00000000"
        )

        node.decoderawtransaction(tx_raw_hex)
        node.sendrawtransaction(tx_raw_hex)

if __name__ == '__main__':
    MitraTokenTest().main()
