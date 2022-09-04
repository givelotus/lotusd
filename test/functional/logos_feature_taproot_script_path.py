#!/usr/bin/env python3
# Copyright (c) 2021 The Logos Foundation
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that we can broadcast transactions spending a Taproot output using the
script spend path.

Outputs have the form:

OP_SCRIPTTYPE OP_1 <33-byte commitment pubkey>
or
OP_SCRIPTTYPE OP_1 <33-byte commitment pubkey> <32-byte state>

and inputs have the form:

<input 0> ... <input n> <leaf script> <control block>
"""

from test_framework.blocktools import SUBSIDY
from test_framework.key import ECKey, ECPubKey
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
    OP_2DUP,
    OP_CAT,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_CODESEPARATOR,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_FROMALTSTACK,
    OP_HASH160,
    OP_IF,
    OP_OR,
    OP_REVERSEBYTES,
    OP_SCRIPTTYPE,
    OP_SWAP,
    OP_TOALTSTACK,
    OP_TUCK,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_LOTUS,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_FORKID,
    SignatureHashLotus,
    SignatureHashForkId,
    TaggedHash,
)
from test_framework.test_framework import BitcoinTestFramework

PRIVATE_KEYS = []
PUBLIC_KEYS = []
for _ in range(18):
    private_key = ECKey()
    private_key.generate()
    PRIVATE_KEYS.append(private_key.get_bytes())
    PUBLIC_KEYS.append(private_key.get_pubkey().get_bytes())

script_checksig = dict(script_inputs=[], script=[PUBLIC_KEYS[0], OP_CHECKSIG], keys=[PRIVATE_KEYS[0]])
script_checksig_state = dict(script_inputs=[],
                             script=[PUBLIC_KEYS[0][0], OP_SWAP, OP_CAT, OP_CHECKSIG],
                             keys=[PRIVATE_KEYS[0]], state=PUBLIC_KEYS[0][1:])

def nth_script(n):
    return dict(script_inputs=[], script=[PUBLIC_KEYS[n], OP_CHECKSIG], keys=[PRIVATE_KEYS[n]])

all_lotus_sig_hash_types = [SIGHASH_ALL | SIGHASH_LOTUS,
                            SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                            SIGHASH_NONE | SIGHASH_LOTUS,
                            SIGHASH_NONE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY,
                            SIGHASH_SINGLE | SIGHASH_LOTUS,
                            SIGHASH_SINGLE | SIGHASH_LOTUS | SIGHASH_ANYONECANPAY]

all_forkid_sig_hash_types = [SIGHASH_ALL | SIGHASH_FORKID,
                             SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
                             SIGHASH_NONE | SIGHASH_FORKID,
                             SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
                             SIGHASH_SINGLE | SIGHASH_FORKID,
                             SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY]

TX_CASES = [
    dict(outputs=1, inputs=[((script_checksig, script_checksig_state), 0, [SIGHASH_ALL | SIGHASH_LOTUS])]),
    dict(outputs=8, inputs=[((script_checksig_state, script_checksig), 0, [SIGHASH_ALL | SIGHASH_FORKID])]),
    dict(
        outputs=8,
        inputs=[
            (dict(script_inputs=[],
                  script=[PUBLIC_KEYS[3]] + [OP_TUCK, OP_CHECKSIGVERIFY] * 22 + [OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[3]] * 23,
                  schnorr=True),
             0, [SIGHASH_ALL | SIGHASH_LOTUS] * 23),
        ],
    ),
    dict(
        outputs=8,
        inputs=[
            (dict(script_inputs=[],
                  script=[PUBLIC_KEYS[4]] + [OP_2DUP, OP_CHECKSIGVERIFY] * 40 + [OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[4]],
                  schnorr=True),
             0, [SIGHASH_ALL | SIGHASH_LOTUS])
        ],
        error='Input SigChecks limit exceeded',
    ),
    dict(
        outputs=6,
        inputs=[
            (dict(script_inputs=[0],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[:6],
                  schnorr=False),
             0, all_lotus_sig_hash_types),
            (dict(script_inputs=[0],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[2:8],
                  schnorr=False),
             0, all_forkid_sig_hash_types),
            (dict(script_inputs=[0],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[4:10],
                  schnorr=False),
             0, all_lotus_sig_hash_types),
            (dict(script_inputs=[bytes([0b00111111, 0])],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[:6],
                  schnorr=True),
             0, all_forkid_sig_hash_types),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (
                (
                    (
                        (
                            nth_script(0),
                            (nth_script(1), nth_script(2)),
                        ),
                        (
                            (
                                nth_script(3),
                                (
                                    (nth_script(4), nth_script(5)),
                                    (
                                        nth_script(6),
                                        (
                                            nth_script(7),
                                            (nth_script(8), nth_script(9)),
                                        ),
                                    ),
                                ),
                            ),
                            (
                                (nth_script(10), nth_script(11)),
                                (
                                    nth_script(12),
                                    (nth_script(13), nth_script(14)),
                                ),
                            ),
                        ),
                    ),
                    (
                        nth_script(15),
                        (nth_script(16), nth_script(17)),
                    ),
                ),
                i,
                [SIGHASH_ALL | SIGHASH_LOTUS],
            )
            for i in range(18)
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[1],
                  script=[PUBLIC_KEYS[0], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[0]]),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
        error='Extra items left on stack after execution',
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[:6],
                  schnorr=True),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS] * 6),
        ],
        error='Signature cannot be 65 bytes in CHECKMULTISIG',
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[bytes([0b00111111, 0])],
                  script=[6] + PUBLIC_KEYS[:10] + [10, OP_CHECKMULTISIG],
                  keys=PRIVATE_KEYS[:6],
                  schnorr=False),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS] * 6),
        ],
        error='Only Schnorr signatures allowed in this operation',
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0],
                  script=[OP_SWAP,
                          OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF,
                          PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=2),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
        error='Signature must be zero for failed CHECK(MULTI)SIG operation',
    ),
    dict(
        outputs=1,
        inputs=[(script_checksig, 0, [SIGHASH_ALL | SIGHASH_LOTUS])],
        suffix=0x20,
        error='Signature hash type missing or not understood',
    ),
    dict(
        outputs=1,
        inputs=[(script_checksig, 0, [SIGHASH_ALL | SIGHASH_LOTUS])],
        suffix=0x21,
        error='Signature hash type missing or not understood',
    ),
    dict(
        outputs=1,
        inputs=[(script_checksig, 0, [SIGHASH_ALL | SIGHASH_LOTUS])],
        suffix=0x21,
        error='Signature hash type missing or not understood',
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[],
                 script=[bytes(reversed(PUBLIC_KEYS[4])), OP_REVERSEBYTES, OP_CHECKSIG],
                 keys=[PRIVATE_KEYS[4]]),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0],
                  script=[OP_OR, PUBLIC_KEYS[5], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[5]]),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[1],
                  script=[OP_SWAP, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF, PUBLIC_KEYS[6], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[6]],
                  codesep=2),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0],
                  script=[OP_SWAP, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF, PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=4),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[1, 1],
                  script=[OP_TOALTSTACK,
                          OP_IF, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ELSE, OP_IF, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ENDIF,
                          OP_FROMALTSTACK, PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=3),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0, 1],
                  script=[OP_TOALTSTACK,
                          OP_IF, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ELSE, OP_IF, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ENDIF,
                          OP_FROMALTSTACK, PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=5),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[1, 0],
                  script=[OP_TOALTSTACK,
                          OP_IF, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ELSE, OP_IF, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ENDIF,
                          OP_FROMALTSTACK, PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=9),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    dict(
        outputs=1,
        inputs=[
            (dict(script_inputs=[0, 0],
                  script=[OP_TOALTSTACK,
                          OP_IF, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ELSE, OP_IF, OP_CODESEPARATOR, OP_ENDIF,
                          OP_ENDIF,
                          OP_FROMALTSTACK, PUBLIC_KEYS[7], OP_CHECKSIG],
                  keys=[PRIVATE_KEYS[7]],
                  codesep=0xffff_ffff),
             0,
             [SIGHASH_ALL | SIGHASH_LOTUS]),
        ],
    ),
    'ENABLE_REPLAY_PROTECTION',
    dict(outputs=1, inputs=[(script_checksig, 0, [0xffdead60])], error='Signature hash type missing or not understood'),
    dict(outputs=1, inputs=[(script_checksig, 0, [0xffdead61])]),
    dict(outputs=1, inputs=[(script_checksig, 0, [0xffdead62])]),
    dict(outputs=1, inputs=[(script_checksig, 0, [0xffdead63])]),
    dict(outputs=1, inputs=[(script_checksig, 0, [0xffdead64])], error='Signature hash type missing or not understood'),
]

ACTIVATION_TIME = 2000000000

def ser_script(script: bytes) -> bytes:
    if len(script) < 0xfd:
        return bytes([len(script)]) + script
    elif len(script) <= 0xffff:
        return b'\xfd' + len(script).to_bytes(2, 'little') + script
    else:
        raise ValueError('script too long')


def taproot_tree_helper(tree):
    if isinstance(tree, dict):
        script_case = tree
        leaf_version = script_case.get('leaf_version', 0xc0)
        h = TaggedHash("TapLeaf", bytes([leaf_version]) + ser_script(CScript(script_case['script'])))
        return dict(items=[dict(leaf=dict(script_case=script_case, tapleaf_hash=h), path=bytes())], hash=h)
    left_result = taproot_tree_helper(tree[0])
    right_result = taproot_tree_helper(tree[1])
    ret = [dict(leaf=item['leaf'], path=item['path'] + right_result['hash'])
           for item in left_result['items']] + \
          [dict(leaf=item['leaf'], path=item['path'] + left_result['hash'])
            for item in right_result['items']]
    if right_result['hash'] < left_result['hash']:
        left_hash, right_hash = right_result['hash'], left_result['hash']
    else:
        left_hash, right_hash = left_result['hash'], right_result['hash']
    return dict(items=ret, hash=TaggedHash("TapBranch", left_hash + right_hash))


class TaprootScriptSpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=noban@127.0.0.1',
                            f'-replayprotectionactivationtime={ACTIVATION_TIME}']]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())
        # Allocate as many UTXOs as are needed
        num_utxos = sum(len(tx_case['inputs'])
                        for tx_case in TX_CASES
                        if isinstance(tx_case, dict))

        value = int(SUBSIDY * 1_000_000)
        fee = 10_000

        pubkey_bytes = bytes.fromhex('020000000000000000000000000000000000000000000000000000000000000001')
        pubkey = ECPubKey()
        pubkey.set(pubkey_bytes)

        max_utxo_value = (value - fee) // num_utxos
        spendable_outputs = []
        utxo_idx = 0
        # Prepare UTXOs for the tests below
        for tx_case in TX_CASES:
            if tx_case == 'ENABLE_REPLAY_PROTECTION':
                continue
            for tree, leaf_idx, _ in tx_case['inputs']:
                utxo_value = max_utxo_value - utxo_idx * 100  # deduct 100*i coins for unique amounts

                tree_result = taproot_tree_helper(tree)
                merkle_root = tree_result['hash']
                tweak_hash = TaggedHash("TapTweak", pubkey_bytes + merkle_root)
                commitment = pubkey.add(tweak_hash)
                ops = [OP_SCRIPTTYPE, OP_1, commitment.get_bytes()]
                script_case = tree_result['items'][leaf_idx]['leaf']['script_case']
                if script_case.get('state', False):
                    ops.append(script_case['state'])
                utxo_script = CScript(ops)
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

        peer.send_txs_and_test([tx_fan_out], node)

        utxo_idx = 0
        for tx_case in TX_CASES:
            if tx_case == 'ENABLE_REPLAY_PROTECTION':
                node.setmocktime(ACTIVATION_TIME)
                node.generatetoaddress(11, burn_address)
                continue
            num_inputs = len(tx_case['inputs'])
            num_outputs = tx_case['outputs']
            # Build tx for this test, will broadcast later
            tx = CTransaction()
            spent_outputs = spendable_outputs[:num_inputs]
            del spendable_outputs[:num_inputs]
            assert len(spent_outputs) == num_inputs
            total_input_amount = sum(output.nValue for output in spent_outputs)
            max_output_amount = (total_input_amount - fee) // num_outputs
            for i in range(num_outputs):
                output_amount = max_output_amount - i * 77
                output_script = CScript([OP_HASH160, i.to_bytes(20, 'big'), OP_EQUAL])
                tx.vout.append(CTxOut(output_amount, output_script))
            for _ in range(num_inputs):
                tx.vin.append(CTxIn(COutPoint(tx_fan_out.txid, utxo_idx), CScript()))
                utxo_idx += 1
            for input_idx, input_case in enumerate(tx_case['inputs']):
                tree, leaf_idx, sig_hash_types = input_case
                tree_result = taproot_tree_helper(tree)
                result_item = tree_result['items'][leaf_idx]
                leaf = result_item['leaf']
                script_case = leaf['script_case']
                exec_script = CScript(script_case['script'])
                keys = script_case.get('keys', [])
                assert len(sig_hash_types) == len(keys)
                sigs = []
                for sig_hash_type, key in zip(sig_hash_types, keys):
                    if sig_hash_type & SIGHASH_LOTUS == SIGHASH_LOTUS:
                        sighash = SignatureHashLotus(
                            tx_to=tx,
                            spent_utxos=spent_outputs,
                            sig_hash_type=sig_hash_type,
                            input_index=input_idx,
                            executed_script_hash=leaf['tapleaf_hash'],
                            codeseparator_pos=script_case.get('codesep', 0xffff_ffff),
                        )
                    elif sig_hash_type & SIGHASH_FORKID:
                        sighash = SignatureHashForkId(
                            exec_script, tx, input_idx, sig_hash_type, spent_outputs[input_idx].nValue,
                        )
                    else:
                        raise NotImplemented
                    private_key = ECKey()
                    private_key.set(key, True)
                    if script_case.get('schnorr', False):
                        signature = private_key.sign_schnorr(sighash)
                    else:
                        signature = private_key.sign_ecdsa(sighash)
                    signature += bytes([tx_case.get('suffix', sig_hash_type & 0xff)])
                    sigs.append(signature)
                control_block = bytearray(pubkey_bytes)
                control_block[0] = 0xc0
                control_block[0] |= int(pubkey_bytes[0] == 0x03)
                control_block += result_item['path']
                tx.vin[input_idx].scriptSig = CScript(script_case['script_inputs'] + sigs + [exec_script, control_block])
            # Broadcast transaction and check success/failure
            tx.rehash()
            if 'error' not in tx_case:
                peer.send_txs_and_test([tx], node)
            else:
                peer.send_txs_and_test([tx], node, success=False, reject_reason=tx_case['error'])


if __name__ == '__main__':
    TaprootScriptSpendTest().main()
