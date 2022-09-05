#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtranscation RPCs.

Test the following RPCs with Mitra txs:
   - decoderawtransaction
"""

from decimal import Decimal
from test_framework.messages import (
    COIN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


# Create one-input, one-output, no-fee transaction:
class MitraRawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.log.info('Decode Mitra transactions')

        node = self.nodes[0]

        result = node.decoderawtransaction(
            "07000000"
            "00" # No preambles
            "00" # No inputs
            "00" # No outputs
            "00000000"
        )
        result.pop('txid'); result.pop('hash'); result.pop('size')
        assert_equal(result, {
            'version': 7,
            'locktime': 0,
            'preambles': [],
            'vin': [],
            'vout': [],
        })

        result = node.decoderawtransaction(
            "07000000"
            "00" # No preambles
            "00" # No inputs
            "01" # 1 output
                "0605040302010000" # amount
                "020087" # scriptPubKey
                "09000100000000000000" # carryover
            "00000000"
        )
        result.pop('txid'); result.pop('hash'); result.pop('size')
        assert_equal(result, {
            'version': 7,
            'locktime': 0,
            'preambles': [],
            'vin': [],
            'vout': [{
                'value': Decimal(0x010203040506) / COIN,
                'n': 0,
                'scriptPubKey': {'asm': '0 OP_EQUAL', 'hex': '0087', 'type': 'nonstandard'},
                'carryover': '000100000000000000',
            }],
        })

        result = node.decoderawtransaction(
            "07000000"
            "00" # No preambles
            "01" # 1 input
                "0102030405060708091011121314151617181920212223242526272829303132" # hash
                "01000000" # vout
                "ffffffff" # sequence
                "0605040302010000" # amount
                "020087" # scriptPubKey
                "09000100000000000000" # carryover
                "00" # No preamble merkle root
                "00" # No witnesses
                "00" # No loop counts
            "00" # No outputs
            "00000000"
        )
        result.pop('txid'); result.pop('hash'); result.pop('size')
        assert_equal(result, {
            'version': 7,
            'locktime': 0,
            'preambles': [],
            'vin': [{
                'txid': '3231302928272625242322212019181716151413121110090807060504030201',
                'vout': 1,
                'preambleMerkleRoot': '0000000000000000000000000000000000000000000000000000000000000000',
                'value': Decimal(0x010203040506) / COIN,
                'scriptPubKey': {'asm': '0 OP_EQUAL', 'hex': '0087', 'type': 'nonstandard'},
                'carryover': '000100000000000000',
                'witnesses': [],
                'loopCounts': '',
                'sequence': 0xffffffff,
            }],
            'vout': [],
        })

        result = node.decoderawtransaction(
            "07000000"
            "00" # No preambles
            "01" # 1 input
                "0102030405060708091011121314151617181920212223242526272829303132" # hash
                "01000000" # vout
                "ffffffff" # sequence
                "0605040302010000" # amount
                "020087" # scriptPubKey
                "09000100000000000000" # carryover
                "01" "aabbccddeeff0044aabbccddeeff0044aabbccddeeff0044aabbccddeeff0044" # preamble merkle root
                "02" # 2 witnesses
                    "05" "1122334455"
                    "00"
                "03" "010203" # loop counts
            "00" # No outputs
            "00000000"
        )
        result.pop('txid'); result.pop('hash'); result.pop('size')
        assert_equal(result, {
            'version': 7,
            'locktime': 0,
            'preambles': [],
            'vin': [{
                'txid': '3231302928272625242322212019181716151413121110090807060504030201',
                'vout': 1,
                'preambleMerkleRoot': '4400ffeeddccbbaa4400ffeeddccbbaa4400ffeeddccbbaa4400ffeeddccbbaa',
                'value': Decimal(0x010203040506) / COIN,
                'scriptPubKey': {'asm': '0 OP_EQUAL', 'hex': '0087', 'type': 'nonstandard'},
                'carryover': '000100000000000000',
                'witnesses': ['1122334455', ''],
                'loopCounts': '010203',
                'sequence': 0xffffffff,
            }],
            'vout': [],
        })

        result = node.decoderawtransaction(
            "07000000"
            "01" # 1 preamble
                "020087"
                "02" # 2 witnesses
                    "05" "1122334455"
                    "00"
                "03" "010203" # loop counts
            "00" # No inputs
            "00" # No outputs
            "00000000"
        )
        result.pop('txid'); result.pop('hash'); result.pop('size')
        assert_equal(result, {
            'version': 7,
            'locktime': 0,
            'preambles': [{
                'predicateScript': {'asm': '0 OP_EQUAL', 'hex': '0087'},
                'witnesses': ['1122334455', ''],
                'loopCounts': '010203',
            }],
            'vin': [],
            'vout': [],
        })

if __name__ == '__main__':
    MitraRawTransactionsTest().main()
