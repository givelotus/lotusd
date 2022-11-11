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
from test_framework.script import CScript, OP_HASH160, OP_EQUAL
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


# Create one-input, one-output, no-fee transaction:
class MitraTxidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.log.info('Decode Mitra transactions')

        node = self.nodes[0]

        tx_preamble_script = "0087"
        tx_preamble = (
            "02" + tx_preamble_script +
            "02" # 2 witnesses
                "05" "1122334455"
                "00"
            "03" "010203" # loop counts
        )

        tx_input_begin = (
            "0102030405060708091011121314151617181920212223242526272829303132" # hash
            "01000000" # vout
            "ffffffff" # sequence
            "0605040302010000" # amount
            "020087" # scriptPubKey
            "09000100000000000000" # carryover
        )
        tx_input_preamble_merkle_root = "aabbccddeeff0044aabbccddeeff0044aabbccddeeff0044aabbccddeeff0044"
        tx_input = (
            tx_input_begin +
            "01" + tx_input_preamble_merkle_root +
            "02" # 2 witnesses
                "05" "1122334455"
                "00"
            "03" "010203" # loop counts
        )

        tx_output = (
            "0605040302010000" # amount
            "020087" # scriptPubKey
            "09000100000000000000" # carryover
        )

        result = node.decoderawtransaction(
            "07000000"
            "01" + tx_preamble +
            "01" + tx_input +
            "01" + tx_output +
            "00000000"
        )

        txid_preimage = (
            "07000000" +
            hash256(bytes.fromhex(tx_preamble_script)).hex() +
            hash256(bytes.fromhex(tx_input_begin + tx_input_preamble_merkle_root)).hex() +
            "01" +
            hash256(bytes.fromhex(tx_output)).hex() +
            "01" +
            "00000000"
        )
        txid = hash256(bytes.fromhex(txid_preimage))[::-1].hex()

        assert_equal(result['txid'], txid)

if __name__ == '__main__':
    MitraTxidTest().main()
