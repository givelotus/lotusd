"""Offline authenticated runner gate; Python independently signs exact P01 bytes."""
import argparse
import dataclasses
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('runner')
parser.add_argument('reference')
a = parser.parse_args()
sys.path.insert(0, a.reference)
from coincurve import PrivateKey
from lotus_v2_reference.encoding import Output, Profile, encode_output
from lotus_v2_reference.signing import (Input, Transaction, TxProfile, Witness,
    encode_transaction, signing_message, identity_digests)
from lotus_v2_reference.vm import branch_leaf_hash

profile = TxProfile(256, 256, 256, 8192, 1024, 8192, 64)
out_profile = Profile(16, 16, 812, 8192)
key = PrivateKey((3).to_bytes(32, 'big'))
public = key.public_key_xonly.format()
script = b'\x20' + public + b'\xbb'
chain = bytes(range(32))
coin = Output(0, 2000, None, (branch_leaf_hash(script),), ((0,),))
created = dataclasses.replace(coin, value=1000)
tx = Transaction(0, (Input(b'\x11'*32, 0, 0xffffffff, 1, 0, (Witness(script),)),), (created,))

def call(tx, coin=coin, chain=chain):
    result = subprocess.run([a.runner, '--context', encode_transaction(tx, profile).hex(),
        chain.hex(), '0', '0', encode_output(coin, out_profile).hex()],
        text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result
    return result.stdout.split()

for mode in range(3):
    digest = signing_message(tx, profile, chain, (coin,), 0, 0, mode)
    signature = key.sign_schnorr(digest, bytes(32)) + (bytes([mode]) if mode else b'')
    signed = dataclasses.replace(tx, inputs=(dataclasses.replace(tx.inputs[0],
        witnesses=(Witness(script, (), (signature,)),)),))
    result = call(signed)
    assert result[0] == 'S' and result[1] == result[2] and result[3] == '01' + '00'*15, result
    wrong_signature = PrivateKey((4).to_bytes(32, 'big')).sign_schnorr(digest, bytes(32)) + (bytes([mode]) if mode else b'')
    wrong_key = dataclasses.replace(signed, inputs=(dataclasses.replace(signed.inputs[0],
        witnesses=(Witness(script, (), (wrong_signature,)),)),))
    assert call(wrong_key)[0] == 'I'
    assert call(signed, chain=b'\xff'*32)[0] == 'I'
    assert call(signed, coin=dataclasses.replace(coin, value=1999))[0] == 'I'
    assert call(signed, coin=dataclasses.replace(coin, branches=(bytes(32),)))[0] == 'I'
    # Witness arguments change TxHash without changing TxID; signature remains valid
    # only if the script consumes the exact expected argument stack.
    mutated = dataclasses.replace(signed, inputs=(dataclasses.replace(signed.inputs[0],
        witnesses=(Witness(script, (), (signature[:-1],)),)),))
    assert identity_digests(mutated, profile, chain).txid == identity_digests(signed, profile, chain).txid
    assert identity_digests(mutated, profile, chain).txhash != identity_digests(signed, profile, chain).txhash
    assert call(mutated)[0] == 'I'
    if mode == 2:
        absent = dataclasses.replace(signed, outputs=())
        assert call(absent)[0] == 'I'
# Automatic success cannot bypass branch authentication.
auto = b'\x5e'
auto_tx = dataclasses.replace(tx, inputs=(dataclasses.replace(tx.inputs[0], witnesses=(Witness(auto),)),))
auto_coin = dataclasses.replace(coin, branches=(branch_leaf_hash(auto),))
assert call(auto_tx, coin=auto_coin)[0] == 'A'
assert call(auto_tx, coin=coin)[0] == 'I'
print('authenticated context runner: FULL/partial modes, mutations, absent SINGLE, success membership passed')
# Mint starts with an implicit positive delta. The runner derives it from the
# token output/input totals and never accepts a caller-supplied value.
mint_script = b'\x79\x20' + public + b'\xbb'
root = branch_leaf_hash(mint_script)
mint = Input(root, 0, 0xffffffff, 3, 0, (Witness(mint_script),))
minted = Output(1, 100, root, (branch_leaf_hash(b'\x4e'),), ((0,),))
funding_coin = dataclasses.replace(coin, branches=(branch_leaf_hash(b'\x4e'),))
funding = dataclasses.replace(tx.inputs[0], witnesses=(Witness(b'\x4e'),))
mint_tx = Transaction(0, (funding, mint), (minted,))

def mint_call(candidate):
    result = subprocess.run([a.runner, '--context', encode_transaction(candidate, profile).hex(),
        chain.hex(), '1', '0', encode_output(funding_coin, out_profile).hex(), '-'], text=True, capture_output=True, timeout=10)
    return result.returncode, result.stdout.split()

message = signing_message(mint_tx, profile, chain, (funding_coin, None), 1, 0, 0, (100).to_bytes(16, 'little'))
signature = key.sign_schnorr(message, bytes(32))
signed_mint = dataclasses.replace(mint_tx, inputs=(funding, dataclasses.replace(mint,
    witnesses=(Witness(mint_script, (), (signature,)),)),))
assert mint_call(signed_mint)[1][0] == 'S'
for suffix in (b'\x01', b'\x02', b'\x00'):
    bad = dataclasses.replace(signed_mint, inputs=(funding, dataclasses.replace(mint,
        witnesses=(Witness(mint_script, (), (signature + suffix,)),)),))
    assert mint_call(bad)[1][0] == 'I'
changed_delta = dataclasses.replace(signed_mint, outputs=(dataclasses.replace(minted, value=99),))
assert mint_call(changed_delta)[1][0] == 'I'
assert mint_call(dataclasses.replace(signed_mint, outputs=()))[0] == 2
print('mint: derived positive delta, FULL-only framing, delta mutation passed')
