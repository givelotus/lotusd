#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that we can broadcast transactions spending a Taproot output using the key
spend path.

Outputs have the form:

OP_SCRIPTTYPE OP_1 <33-byte commitment pubkey>
or
OP_SCRIPTTYPE OP_1 <33-byte commitment pubkey> <32-byte state>

and inputs have the form:

<65-byte Schnorr signature using Lotus sighash>
"""

from test_framework.key import ECKey
from test_framework.blocktools import SUBSIDY
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_EQUAL,
    OP_HASH160,
    OP_SCRIPTTYPE,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_LOTUS,
    SIGHASH_FORKID,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SignatureHashLotus,
)
from test_framework.test_framework import BitcoinTestFramework


TESTCASES = [
    dict(outputs=1, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS]),
    dict(outputs=10, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS]),
    dict(outputs=2, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY]),
    dict(outputs=3, inputs=1, sig_hash_types=[SIGHASH_NONE | SIGHASH_LOTUS]),
    dict(outputs=4, inputs=1, sig_hash_types=[SIGHASH_NONE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY]),
    dict(outputs=5, inputs=1, sig_hash_types=[SIGHASH_SINGLE | SIGHASH_LOTUS]),
    dict(outputs=6, inputs=1, sig_hash_types=[SIGHASH_SINGLE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY]),
    dict(outputs=10, inputs=6, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS,
                                               SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                                               SIGHASH_NONE | SIGHASH_LOTUS,
                                               SIGHASH_NONE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                                               SIGHASH_SINGLE | SIGHASH_LOTUS,
                                               SIGHASH_SINGLE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY]),
    dict(outputs=1, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=10, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=2, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=3, inputs=1, sig_hash_types=[SIGHASH_NONE | SIGHASH_LOTUS],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=4, inputs=1, sig_hash_types=[SIGHASH_NONE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=5, inputs=1, sig_hash_types=[SIGHASH_SINGLE | SIGHASH_LOTUS],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=6, inputs=1, sig_hash_types=[SIGHASH_SINGLE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=10, inputs=6, sig_hash_types=[SIGHASH_ALL | SIGHASH_LOTUS,
                                               SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                                               SIGHASH_NONE | SIGHASH_LOTUS,
                                               SIGHASH_NONE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                                               SIGHASH_SINGLE | SIGHASH_LOTUS,
                                               SIGHASH_SINGLE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY],
         ecdsa=True, error='Taproot key spend signature must be Schnorr'),
    dict(outputs=4, inputs=1, sig_hash_types=[SIGHASH_LOTUS], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x20, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x21, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x2f, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x60, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=1, inputs=3, sig_hash_types=[0x63, 0x61, 0x61]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x61, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x62, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x63, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x64, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x6f, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0x71, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xe0, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xe1, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xe2, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xe3, 0x63]),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xe4, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xef, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=3, sig_hash_types=[0x61, 0xf1, 0x63], error='Signature hash type missing or not understood'),
    dict(outputs=5, inputs=1, sig_hash_types=[SIGHASH_FORKID], error='Signature hash type missing or not understood'),
    dict(outputs=4, inputs=1, sig_hash_types=[SIGHASH_ALL],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=3, inputs=1, sig_hash_types=[SIGHASH_NONE],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=2, inputs=1, sig_hash_types=[SIGHASH_SINGLE],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=6, inputs=1, sig_hash_types=[SIGHASH_ALL | SIGHASH_FORKID],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=6, inputs=1, sig_hash_types=[SIGHASH_NONE | SIGHASH_FORKID],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=6, inputs=1, sig_hash_types=[SIGHASH_SINGLE | SIGHASH_FORKID],
         error='Taproot key spend signatures must use SIGHASH_LOTUS'),
    dict(outputs=3, inputs=1, sig_hash_types=[0x21], error='Invalid Taproot key spend signature', suffix=0x61),
    dict(outputs=3, inputs=1, sig_hash_types=[0x81], error='Invalid Taproot key spend signature', suffix=0xe1),
    dict(outputs=3, inputs=1, sigs=[b''], error='Invalid Taproot key spend signature'),
    'ENABLE_REPLAY_PROTECTION',
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead60], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead61]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead62]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead63]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead64], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead6f], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdead71], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeade0], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeade1]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeade2]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeade3]),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeade4], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeadef], error='Signature hash type missing or not understood'),
    dict(outputs=3, inputs=1, sig_hash_types=[0xffdeadf1], error='Signature hash type missing or not understood'),
]

ACTIVATION_TIME = 2000000000

class TaprootKeySpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=noban@127.0.0.1',
                            f'-replayprotectionactivationtime={ACTIVATION_TIME}']]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())
        # Allocate as many UTXOs as are needed
        num_utxos = sum(test_case['inputs']
                        for test_case in TESTCASES
                        if isinstance(test_case, dict))

        value = int(SUBSIDY * 1_000_000)
        fee = 10_000

        max_utxo_value = (value - fee) // num_utxos
        private_keys = []
        public_keys = []
        spendable_outputs = []
        executed_scripts = []
        utxo_idx = 0
        # Prepare UTXOs for the tests below
        for test_case in TESTCASES:
            if test_case == 'ENABLE_REPLAY_PROTECTION':
                continue
            for _ in range(test_case['inputs']):
                private_key = ECKey()
                private_key.generate()
                private_keys.append(private_key)
                public_key = private_key.get_pubkey()
                public_keys.append(public_key)
                utxo_value = max_utxo_value - utxo_idx * 100  # deduct 100*i coins for unique amounts
                utxo_script = CScript([OP_SCRIPTTYPE, OP_1, public_key.get_bytes()])
                executed_scripts.append(utxo_script)
                spendable_outputs.append(CTxOut(utxo_value, utxo_script))
                utxo_idx += 1

        anyonecanspend_address = node.decodescript('51')['p2sh']
        burn_address = node.decodescript('00')['p2sh']
        p2sh_script = CScript([OP_HASH160, bytes(20), OP_EQUAL])
        node.generatetoaddress(1, anyonecanspend_address)
        node.generatetoaddress(100, burn_address)

        # Build and send fan-out transaction creating all the UTXOs
        block_hash = node.getblockhash(1)
        coin = int(node.getblock(block_hash)['tx'][0], 16)
        tx_fan_out = CTransaction()
        tx_fan_out.vin.append(CTxIn(COutPoint(coin, 1), CScript([b'\x51'])))
        tx_fan_out.vout = spendable_outputs
        tx_fan_out.rehash()

        # Broadcast fan-out tx
        peer.send_txs_and_test([tx_fan_out], node)

        utxo_idx = 0
        key_idx = 0
        for test_case in TESTCASES:
            if test_case == 'ENABLE_REPLAY_PROTECTION':
                node.setmocktime(ACTIVATION_TIME)
                node.generatetoaddress(11, burn_address)
                continue
            # Build tx for this test, will broadcast later
            tx = CTransaction()
            num_inputs = test_case['inputs']
            spent_outputs = spendable_outputs[:num_inputs]
            del spendable_outputs[:num_inputs]
            assert len(spent_outputs) == num_inputs
            total_input_amount = sum(output.nValue for output in spent_outputs)
            max_output_amount = (total_input_amount - fee) // test_case['outputs']
            for i in range(test_case['outputs']):
                output_amount = max_output_amount - i * 77
                output_script = CScript([OP_HASH160, i.to_bytes(20, 'big'), OP_EQUAL])
                tx.vout.append(CTxOut(output_amount, output_script))
            for _ in range(test_case['inputs']):
                tx.vin.append(CTxIn(COutPoint(tx_fan_out.txid, utxo_idx), CScript()))
                utxo_idx += 1
            if test_case.get('sigs', None) is not None:
                for i, sig in enumerate(test_case['sigs']):
                    tx.vin[i].scriptSig = CScript([sig])
                    key_idx += 1
            else:
                for i, sig_hash_type in enumerate(test_case['sig_hash_types']):
                    # Compute sighash for this input; we sign it manually using sign_ecdsa/sign_schnorr
                    # and then broadcast the complete transaction
                    sighash = SignatureHashLotus(
                        tx_to=tx,
                        spent_utxos=spent_outputs,
                        sig_hash_type=sig_hash_type,
                        input_index=i,
                    )
                    if test_case.get('sig', None) is not None:
                        signature = test_case['sig']
                    if test_case.get('ecdsa', False):
                        signature = private_keys[key_idx].sign_ecdsa(sighash)
                    else:
                        signature = private_keys[key_idx].sign_schnorr(sighash)
                    signature += bytes([test_case.get('suffix', sig_hash_type & 0xff)])
                    # Build correct scriptSig
                    tx.vin[i].scriptSig = CScript([signature])
                    key_idx += 1
            # Broadcast transaction and check success/failure
            tx.rehash()
            if 'error' not in test_case:
                peer.send_txs_and_test([tx], node)
            else:
                peer.send_txs_and_test([tx], node, success=False, reject_reason=test_case['error'])


if __name__ == '__main__':
    TaprootKeySpendTest().main()
