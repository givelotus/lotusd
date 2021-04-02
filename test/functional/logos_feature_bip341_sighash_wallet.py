#!/usr/bin/env python3
# Copyright (c) 2021 Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test whether the wallet can sign transactions using the BIP341 sighash."""

from decimal import Decimal
import hashlib
import io

from test_framework.key import ECPubKey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_BIP341,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_FORKID,
    SignatureHashBIP341,
)
from test_framework.test_framework import BitcoinTestFramework


TESTCASES = [
    dict(outputs=1, sig_hash_types=['ALL|BIP341']),
    dict(outputs=10, sig_hash_types=['ALL|BIP341']),
    dict(outputs=2, sig_hash_types=['ALL|BIP341|ANYONECANPAY', 'ALL|BIP341']),
    dict(outputs=3, sig_hash_types=['NONE|BIP341']),
    dict(outputs=4, sig_hash_types=['NONE|BIP341|ANYONECANPAY', 'ALL|BIP341']),
    dict(outputs=5, sig_hash_types=['SINGLE|BIP341']),
    dict(outputs=6, sig_hash_types=['SINGLE|BIP341|ANYONECANPAY', 'ALL|BIP341']),
    dict(outputs=10, sig_hash_types=['ALL|BIP341',
                                     'ALL|BIP341|ANYONECANPAY',
                                     'NONE|BIP341',
                                     'NONE|BIP341|ANYONECANPAY',
                                     'SINGLE|BIP341',
                                     'SINGLE|BIP341|ANYONECANPAY']),
]


class Bip341SighashWallet(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    BASE_TYPES = {
        'ALL': SIGHASH_ALL,
        'NONE': SIGHASH_NONE,
        'SINGLE': SIGHASH_SINGLE,
    }

    ALGORITHM = {
        'FORKID': SIGHASH_FORKID,
        'BIP341': SIGHASH_BIP341,
    }

    def parse_sig_hash_type(self, sig_hash_type: int):
        base_type, algorithm, *who_can_pay = sig_hash_type.split('|')
        base_type = self.BASE_TYPES[base_type]
        algorithm = self.ALGORITHM[algorithm]
        who_can_pay = SIGHASH_ANYONECANPAY if who_can_pay == ['ANYONECANPAY'] else 0
        return base_type | algorithm | who_can_pay

    def run_test(self):
        node = self.nodes[0]
        node.generate(30)
        node.generate(100)
        fee = 10_000
        wallet_unspent = node.listunspent()
        for test_case in TESTCASES:
            num_inputs = len(test_case['sig_hash_types'])
            spent_outputs = wallet_unspent[:num_inputs]
            del wallet_unspent[:num_inputs]
            assert len(spent_outputs) == num_inputs
            total_input_amount = sum(output['amount'] for output in spent_outputs)
            max_output_amount = (total_input_amount - fee) / test_case['outputs']
            tx = CTransaction()
            for i in range(test_case['outputs']):
                output_amount = max_output_amount - i * Decimal('0.00000047')
                output_script = CScript([OP_HASH160, i.to_bytes(20, 'big'), OP_EQUAL])
                tx.vout.append(CTxOut(int(output_amount * COIN), output_script))
            spent_outputs_deser = []
            for spent_output in spent_outputs:
                tx.vin.append(CTxIn(COutPoint(int(spent_output['txid'], 16), spent_output['vout']), CScript()))
                spent_outputs_deser.append(
                    CTxOut(int(spent_output['amount'] * COIN),
                           CScript(bytes.fromhex(spent_output['scriptPubKey'])))
                )
            unsigned_tx = tx.serialize().hex()
            for i, sig_hash_type in enumerate(test_case['sig_hash_types']):
                raw_signed_tx = node.signrawtransactionwithwallet(unsigned_tx, None, sig_hash_type)['hex']
                signed_tx = CTransaction()
                signed_tx.deserialize(io.BytesIO(bytes.fromhex(raw_signed_tx)))
                stack_items = list(CScript(signed_tx.vin[i].scriptSig))
                sig = stack_items[0]
                pubkey = ECPubKey()
                pubkey.set(stack_items[1])
                sig_hash_type_int = self.parse_sig_hash_type(sig_hash_type)
                sighash = SignatureHashBIP341(
                    tx_to=tx,
                    spent_utxos=spent_outputs_deser,
                    sig_hash_type=sig_hash_type_int,
                    input_index=i,
                    executed_script_hash=hashlib.sha256(spent_outputs_deser[i].scriptPubKey).digest(),
                )
                assert pubkey.verify_ecdsa(sig[:-1], sighash)


if __name__ == '__main__':
    Bip341SighashWallet().main()
