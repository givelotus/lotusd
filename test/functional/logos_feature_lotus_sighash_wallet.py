#!/usr/bin/env python3
# Copyright (c) 2021 Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test whether the wallet can sign transactions using the Lotus sighash."""

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
    hash256,
)
from test_framework.script import (
    CScript,
    OP_HASH160,
    OP_EQUAL,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_LOTUS,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_FORKID,
    SignatureHashLotus,
)
from test_framework.test_framework import BitcoinTestFramework


TESTCASES = [
    dict(outputs=1, sig_hash_types=['ALL|LOTUS']),
    dict(outputs=10, sig_hash_types=['ALL|LOTUS']),
    dict(outputs=2, sig_hash_types=['ALL|LOTUS|ANYONECANPAY', 'ALL|LOTUS']),
    dict(outputs=3, sig_hash_types=['NONE|LOTUS']),
    dict(outputs=4, sig_hash_types=['NONE|LOTUS|ANYONECANPAY', 'ALL|LOTUS']),
    dict(outputs=5, sig_hash_types=['SINGLE|LOTUS']),
    dict(outputs=6, sig_hash_types=['SINGLE|LOTUS|ANYONECANPAY', 'ALL|LOTUS']),
    dict(outputs=10, sig_hash_types=['ALL|LOTUS',
                                     'ALL|LOTUS|ANYONECANPAY',
                                     'NONE|LOTUS',
                                     'NONE|LOTUS|ANYONECANPAY',
                                     'SINGLE|LOTUS',
                                     'SINGLE|LOTUS|ANYONECANPAY']),
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
        'LOTUS': SIGHASH_LOTUS,
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
        fee = Decimal('10000') / COIN
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
                # Make sure each UTXO is unique
                output_amount = max_output_amount - i * Decimal('0.000047')
                output_script = CScript([OP_HASH160, i.to_bytes(20, 'big'), OP_EQUAL])
                tx.vout.append(CTxOut(int(output_amount * COIN), output_script))
            # Build deserialized outputs so we can compute the sighash below
            spent_outputs_deser = []
            for spent_output in spent_outputs:
                tx.vin.append(CTxIn(COutPoint(int(spent_output['txid'], 16), spent_output['vout']), CScript()))
                spent_outputs_deser.append(
                    CTxOut(int(spent_output['amount'] * COIN),
                           CScript(bytes.fromhex(spent_output['scriptPubKey'])))
                )
            unsigned_tx = tx.serialize().hex()
            for i, sig_hash_type in enumerate(test_case['sig_hash_types']):
                # Sign transaction using wallet
                raw_signed_tx = node.signrawtransactionwithwallet(unsigned_tx, None, sig_hash_type)['hex']
                # Extract signature and pubkey from scriptSig
                signed_tx = CTransaction()
                signed_tx.deserialize(io.BytesIO(bytes.fromhex(raw_signed_tx)))
                stack_items = list(CScript(signed_tx.vin[i].scriptSig))
                sig = stack_items[0]
                pubkey = ECPubKey()
                pubkey.set(stack_items[1])
                sig_hash_type_int = self.parse_sig_hash_type(sig_hash_type)
                # Build expected sighash
                sighash = SignatureHashLotus(
                    tx_to=tx,
                    spent_utxos=spent_outputs_deser,
                    sig_hash_type=sig_hash_type_int,
                    input_index=i,
                    executed_script_hash=hash256(spent_outputs_deser[i].scriptPubKey),
                )
                # Verify sig signs the above sighash and has the expected sighash type
                assert pubkey.verify_ecdsa(sig[:-1], sighash)
                assert sig[-1] == sig_hash_type_int


if __name__ == '__main__':
    Bip341SighashWallet().main()
