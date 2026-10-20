#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Version 7 (V2) transactions in tests, and the legacy bridge.

A legacy (version 1 or 2) transaction is the eCash CTransaction of
messages.py, named by SHA256d. A version 7 transaction uses the V2 fields of
the same class (input nFlags/nPathIndex/vWitnesses, V2 outputs, nV2Lock).
This module builds version 7 transactions, computes their V2 signing
messages, and signs the two legacy bridge input kinds:

- P2PKH bridge: a v7 input spends a legacy P2PKH coin with an empty witness
  script and arguments [BIP340 signature, 33-byte public key].
- P2SH bridge: a v7 input spends a legacy P2SH coin with the redeem script as
  witness script and the scriptSig pushes as arguments. Signatures are legacy
  signatures (plus a hashtype of 0x41, 0xC1 or 0xC3) over the V2 message.

The signing message matches lotus::v2::SigningMessage; the vectors in
src/test/data/v2_legacy_bridge.json are checked by both implementations.
"""

import hashlib
import json
import os
import unittest
from decimal import Decimal
from io import BytesIO

from .hash import hash160
from .key import SECP256K1, SECP256K1_G, SECP256K1_ORDER, ECKey
from .messages import (
    V2_REGTEST_CHAIN_ID,
    XEC,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    _lotus_v2_encode_output,
    _lotus_v2_to_output,
    lotus_v2_branch_leaf,
    lotus_v2_compute_tx_identities,
    lotus_v2_indexed_tree_root,
    lotus_v2_tagged_hash,
    ser_compact_size,
    ser_string,
    ser_uint256,
)

V2_OP_TRUE = b"\x4e"
V2_OP_CHECKSIG = 0xBB
SEQUENCE_FINAL = 0xFFFFFFFF

# Legacy hashtypes of a P2SH bridge signature and the V2 mode each selects.
BRIDGE_HASHTYPE_MODES = {0x41: 0, 0xC1: 1, 0xC3: 2}


class LegacyCoin:
    """A spent legacy coin: value (satoshis) and scriptPubKey."""

    def __init__(self, value, script):
        self.value = value
        self.script = bytes(script)

    def wire(self):
        # LegacyCoinWire: 0x80 || value u64le || CompactSize || script.
        return b"\x80" + self.value.to_bytes(8, "little") + ser_string(self.script)


class V2Coin:
    """A spent V2 coin: an output tuple (flags, value, token, branches, paths)."""

    def __init__(self, out_tuple):
        self.out = out_tuple

    def wire(self):
        return _lotus_v2_encode_output(self.out)


def coin_of(txout):
    """The spent coin a CTxOut becomes."""
    if getattr(txout, "vBranches", None):
        return V2Coin(_lotus_v2_to_output(txout))
    return LegacyCoin(int(txout.nValue), bytes(txout.scriptPubKey))


def legacy_bridge_leaf(coin_script, witness_script):
    return lotus_v2_tagged_hash(
        "Lotus/v2/branch",
        b"\x03" + ser_string(bytes(coin_script)) + ser_string(bytes(witness_script)),
    )


def v2_txout(value, branch_leaf):
    """A V2 output with one branch and one path [0]."""
    txout = CTxOut()
    txout.nFlags = 0
    txout.nValue = value
    txout.tokenId = b"\x00" * 32
    txout.vBranches = [branch_leaf]
    txout.vPaths = [[0]]
    txout.scriptPubKey = _lotus_v2_encode_output(
        (0, value, b"\x00" * 32, [branch_leaf], [[0]])
    )
    return txout


def v2_op_true_txout(value):
    return v2_txout(value, lotus_v2_branch_leaf(V2_OP_TRUE))


def v7_input(prevout, script=b"", arguments=None, sequence=SEQUENCE_FINAL):
    """A version 7 spend input with one witness and no siblings."""
    txin = CTxIn(prevout, b"", sequence)
    txin.nFlags = 1
    txin.nPathIndex = 0
    txin.vWitnesses = [(bytes(script), [], list(arguments or []))]
    return txin


def new_v7_tx(lock=0):
    tx = CTransaction()
    tx.nVersion = 7
    tx.fHasV2Lock = True
    tx.nV2Lock = lock
    tx.nLockTime = 0
    return tx


def _input_core(txin):
    out = (
        ser_uint256(txin.prevout.txid)
        + (txin.prevout.n & 0xFFFFFFFF).to_bytes(4, "little")
        + (txin.nSequence & 0xFFFFFFFF).to_bytes(4, "little")
        + bytes([txin.nFlags])
        + ser_compact_size(txin.nPathIndex)
        + ser_compact_size(len(txin.vWitnesses))
    )
    for script, siblings, _ in txin.vWitnesses:
        out += ser_string(bytes(script)) + ser_compact_size(len(siblings))
        out += b"".join(siblings)
    return out


def _output_leaf(txout):
    wire = _lotus_v2_encode_output(_lotus_v2_to_output(txout))
    return lotus_v2_tagged_hash("Lotus/v2/output", ser_compact_size(len(wire)) + wire)


def signing_message(
    tx, coins, input_index, mode, witness_index=0, chain_id=V2_REGTEST_CHAIN_ID
):
    """The V2 signing message of a spend invocation of a version 7 tx.

    coins are the spent coins (LegacyCoin or V2Coin) in input order.
    """
    assert tx.nVersion == 7 and mode in (0, 1, 2)
    assert len(coins) == len(tx.vin)
    txin = tx.vin[input_index]
    coin = coins[input_index]
    script = bytes(txin.vWitnesses[witness_index][0])
    if isinstance(coin, LegacyCoin):
        assert witness_index == 0 and txin.nPathIndex == 0
        branch_index = 0
        leaf = legacy_bridge_leaf(coin.script, script)
    else:
        branch_index = coin.out[4][txin.nPathIndex][witness_index]
        leaf = lotus_v2_branch_leaf(script)
    selector = (
        b"\x01"
        + input_index.to_bytes(4, "little")
        + branch_index.to_bytes(4, "little")
        + leaf
    )
    preimage = bytes(chain_id) + bytes([mode])
    if mode == 0:
        txid, _ = lotus_v2_compute_tx_identities(tx)
        coin_leaves = [
            lotus_v2_tagged_hash(
                "Lotus/v2/coinentry", ser_compact_size(len(c.wire())) + c.wire()
            )
            for c in coins
        ]
        preimage += txid + lotus_v2_indexed_tree_root(coin_leaves)
    else:
        wire = coin.wire()
        own = lotus_v2_tagged_hash(
            "Lotus/v2/owninput",
            _input_core(txin) + ser_compact_size(len(wire)) + wire,
        )
        if mode == 1:
            outputs = lotus_v2_indexed_tree_root([_output_leaf(o) for o in tx.vout])
        else:
            assert input_index < len(tx.vout)
            outputs = _output_leaf(tx.vout[input_index])
        lock = tx.nV2Lock if getattr(tx, "fHasV2Lock", False) else 0
        preimage += (
            (7).to_bytes(4, "little") + lock.to_bytes(8, "little") + own + outputs
        )
    return lotus_v2_tagged_hash("Lotus/v2/sighash", preimage + selector)


def _bip340_tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def bip340_sign(secret, msg, aux=b"\x00" * 32):
    """A BIP340 signature (64 bytes) of a 32-byte message."""
    d0 = int.from_bytes(secret, "big")
    assert 0 < d0 < SECP256K1_ORDER and len(msg) == 32
    p = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, d0)]))
    d = d0 if p[1] % 2 == 0 else SECP256K1_ORDER - d0
    px = p[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_bip340_tagged("BIP0340/aux", aux), "big")).to_bytes(
        32, "big"
    )
    k0 = (
        int.from_bytes(_bip340_tagged("BIP0340/nonce", t + px + msg), "big")
        % SECP256K1_ORDER
    )
    assert k0 != 0
    r = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, k0)]))
    k = k0 if r[1] % 2 == 0 else SECP256K1_ORDER - k0
    rx = r[0].to_bytes(32, "big")
    e = (
        int.from_bytes(_bip340_tagged("BIP0340/challenge", rx + px + msg), "big")
        % SECP256K1_ORDER
    )
    return rx + ((k + e * d) % SECP256K1_ORDER).to_bytes(32, "big")


def p2pkh_bridge_input(prevout, pubkey, sequence=SEQUENCE_FINAL):
    """A P2PKH bridge input with a placeholder signature."""
    return v7_input(prevout, b"", [b"\x00" * 64, bytes(pubkey)], sequence)


def sign_p2pkh_bridge(tx, coins, input_index, key, mode=0):
    """Sign P2PKH bridge input input_index with an ECKey in the mode."""
    msg = signing_message(tx, coins, input_index, mode)
    sig = bip340_sign(key.get_bytes(), msg) + (bytes([mode]) if mode else b"")
    script, siblings, args = tx.vin[input_index].vWitnesses[0]
    tx.vin[input_index].vWitnesses[0] = (script, siblings, [sig] + list(args[1:]))


def p2sh_bridge_input(prevout, redeem_script, arguments, sequence=SEQUENCE_FINAL):
    return v7_input(prevout, redeem_script, arguments, sequence)


def p2sh_bridge_signature(tx, coins, input_index, key, hashtype=0x41):
    """A legacy ECDSA signature with its hashtype over the V2 message."""
    msg = signing_message(tx, coins, input_index, BRIDGE_HASHTYPE_MODES[hashtype])
    return key.sign_ecdsa(msg) + bytes([hashtype])


def p2pkh_script(pubkey):
    from .script import OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, CScript

    return CScript(
        [OP_DUP, OP_HASH160, hash160(bytes(pubkey)), OP_EQUALVERIFY, OP_CHECKSIG]
    )


class LegacyMiniWallet:
    """Legacy (version 2) anyone-can-spend coins: P2SH(OP_TRUE), spent with
    the scriptSig OP_TRUE push.

    The framework's MiniWallet is a V2 wallet. This is the legacy MiniWallet
    the bridge tests fund legacy coins from: it mines legacy (version 2)
    coinbases to its P2SH(OP_TRUE) script and finds its coins with
    scantxoutset, which matches legacy scripts.
    """

    def __init__(self, test_node):
        from .script import OP_EQUAL, OP_HASH160, OP_TRUE, CScript

        self._test_node = test_node
        self._utxos = []
        self._scriptPubKey = bytes(
            CScript([OP_HASH160, hash160(bytes(CScript([OP_TRUE]))), OP_EQUAL])
        )
        self.rescan_utxos()

    @staticmethod
    def _create_utxo(*, txid, vout, value, height, coinbase, confirmations):
        return {
            "txid": txid,
            "vout": vout,
            "value": value,
            "height": height,
            "coinbase": coinbase,
            "confirmations": confirmations,
        }

    def get_descriptor(self):
        return self._test_node.getdescriptorinfo(f"raw({self._scriptPubKey.hex()})")[
            "descriptor"
        ]

    def get_scriptPubKey(self):
        return self._scriptPubKey

    def rescan_utxos(self, *, include_mempool=True):
        """Drop all utxos and rescan the utxo set"""
        self._utxos = []
        res = self._test_node.scantxoutset(
            action="start", scanobjects=[self.get_descriptor()]
        )
        assert res["success"]
        for utxo in res["unspents"]:
            self._utxos.append(
                self._create_utxo(
                    txid=utxo["txid"],
                    vout=utxo["vout"],
                    value=utxo["amount"],
                    height=utxo["height"],
                    coinbase=utxo["coinbase"],
                    confirmations=res["height"] - utxo["height"] + 1,
                )
            )
        if include_mempool:
            for txid in sorted(self._test_node.getrawmempool()):
                self.scan_tx(self._test_node.getrawtransaction(txid=txid, verbose=True))

    def scan_tx(self, tx):
        """Scan the tx and adjust the internal list of owned utxos"""
        for spent in tx["vin"]:
            try:
                self.get_utxo(txid=spent["txid"], vout=spent["vout"])
            except StopIteration:
                pass
        for out in tx["vout"]:
            if out["scriptPubKey"]["hex"] == self._scriptPubKey.hex():
                self._utxos.append(
                    self._create_utxo(
                        txid=tx["txid"],
                        vout=out["n"],
                        value=out["value"],
                        height=0,
                        coinbase=False,
                        confirmations=0,
                    )
                )

    def generate(self, num_blocks, **kwargs):
        """Mine legacy coinbases to the P2SH(OP_TRUE) script and rescan."""
        kwargs.setdefault("coinbase_version", 2)
        kwargs.setdefault("invalid_call", False)
        blocks = self._test_node.generatetodescriptor(
            num_blocks, self.get_descriptor(), **kwargs
        )
        self.rescan_utxos()
        return blocks

    def get_utxo(self, *, txid="", vout=None, mark_as_spent=True):
        """Return the largest mature utxo (or the one given) and mark it spent."""
        from .blocktools import COINBASE_MATURITY

        self._utxos = sorted(self._utxos, key=lambda k: (k["value"], -k["height"]))
        blocks_height = self._test_node.getblockchaininfo()["blocks"]
        if txid:
            utxo_filter = filter(lambda utxo: txid == utxo["txid"], self._utxos)
        else:
            utxo_filter = reversed(
                [
                    utxo
                    for utxo in self._utxos
                    if not utxo["coinbase"]
                    or COINBASE_MATURITY - 1 <= blocks_height - utxo["height"]
                ]
            )
        if vout is not None:
            utxo_filter = filter(lambda utxo: vout == utxo["vout"], utxo_filter)
        index = self._utxos.index(next(utxo_filter))
        if mark_as_spent:
            return self._utxos.pop(index)
        return self._utxos[index]

    def create_self_transfer(self, *, fee=1000, utxo_to_spend=None):
        """A version 2 transaction paying utxo_to_spend back to the wallet."""
        from .address import SCRIPTSIG_OP_TRUE
        from .txtools import pad_tx

        utxo = utxo_to_spend or self.get_utxo()
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [
            CTxIn(
                COutPoint(int(utxo["txid"], 16), utxo["vout"]),
                SCRIPTSIG_OP_TRUE,
                0,
            )
        ]
        tx.vout = [CTxOut(int(utxo["value"] * XEC) - fee, self._scriptPubKey)]
        pad_tx(tx, 100, deterministic=True)
        txid = tx.txid_hex
        return {
            "new_utxo": self._create_utxo(
                txid=txid,
                vout=0,
                value=Decimal(tx.vout[0].nValue) / XEC,
                height=0,
                coinbase=False,
                confirmations=0,
            ),
            "txid": txid,
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def sendrawtransaction(self, *, from_node, tx_hex):
        txid = from_node.sendrawtransaction(tx_hex)
        self.scan_tx(from_node.decoderawtransaction(tx_hex))
        return txid

    def send_self_transfer(self, *, from_node, **kwargs):
        tx = self.create_self_transfer(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def send_to(self, *, from_node, scriptPubKey, amount, fee=1000):
        """Send amount to scriptPubKey, change to the wallet; returns (txid, n)."""
        tx = self.create_self_transfer(fee=0)["tx"]
        assert tx.vout[0].nValue >= amount + fee
        tx.vout[0].nValue -= amount + fee
        tx.vout.append(CTxOut(amount, scriptPubKey))
        txid = self.sendrawtransaction(from_node=from_node, tx_hex=tx.serialize().hex())
        return txid, len(tx.vout) - 1

    def create_self_transfer_chain(self, *, chain_length, utxo_to_spend=None):
        """chain_length transactions, each spending its predecessor."""
        tip = utxo_to_spend or self.get_utxo()
        chain = []
        for _ in range(chain_length):
            tx = self.create_self_transfer(utxo_to_spend=tip)
            tip = tx["new_utxo"]
            chain.append(tx)
        return chain


class MiniWalletV7:
    """V2 anyone-can-spend (OP_TRUE) coins and version 7 transfers.

    Coins come from two sources:
    - bridging a legacy MiniWallet's P2SH(OP_TRUE) coins (fund_from): the
      P2SH bridge runs the redeem script OP_TRUE;
    - version 7 coinbases mined to raw(4e) by a node started with
      -coinbaseversion=7 (generate). scantxoutset matches legacy scripts
      only, so generate reads the coinbases of the blocks it mines.
    """

    FEE = 10000
    DESCRIPTOR = "raw(4e)"

    def __init__(self, node):
        self._node = node
        self._utxos = []

    @staticmethod
    def is_own_output(value, script_hex):
        """Whether an output (as RPC hex) is a V2 OP_TRUE output."""
        raw = bytes.fromhex(script_hex)
        branched = _lotus_v2_encode_output(
            (0, value, b"\x00" * 32, [lotus_v2_branch_leaf(V2_OP_TRUE)], [[0]])
        )
        # A coinbase output may also carry the plain script with no branches.
        plain = b"\x00" + value.to_bytes(8, "little") + ser_string(V2_OP_TRUE)
        return raw in (branched, plain)

    def generate(self, num_blocks, **kwargs):
        """Mine version 7 coinbases to raw(4e) and record their outputs."""
        blocks = self._node.generatetodescriptor(num_blocks, self.DESCRIPTOR, **kwargs)
        for blockhash in blocks:
            block = self._node.getblock(blockhash, 2)
            coinbase = block["tx"][0]
            for out in coinbase["vout"]:
                value = int(out["value"] * XEC)
                if self.is_own_output(value, out["scriptPubKey"]["hex"]):
                    self._utxos.append(
                        {
                            "txid": coinbase["txid"],
                            "vout": out["n"],
                            "value": value,
                            "height": block["height"],
                            "coinbase": True,
                        }
                    )
        return blocks

    def fund_from(self, legacy_wallet, count=1):
        """Bridge count legacy MiniWallet coins into V2 OP_TRUE coins."""
        from .script import OP_TRUE, CScript

        txids = []
        for _ in range(count):
            utxo = legacy_wallet.get_utxo()
            value = int(utxo["value"] * XEC) - self.FEE
            tx = new_v7_tx()
            tx.vin = [
                p2sh_bridge_input(
                    COutPoint(int(utxo["txid"], 16), utxo["vout"]),
                    bytes(CScript([OP_TRUE])),
                    [],
                )
            ]
            tx.vout = [v2_op_true_txout(value)]
            txids.append(self.sendrawtransaction(tx))
        return txids

    def sendrawtransaction(self, tx, from_node=None):
        txid = (from_node or self._node).sendrawtransaction(tx.serialize().hex())
        assert txid == tx.txid_hex
        for n, out in enumerate(tx.vout):
            self._utxos.append(
                {
                    "txid": txid,
                    "vout": n,
                    "value": int(out.nValue),
                    "height": None,
                    "coinbase": False,
                }
            )
        return txid

    def get_utxo(self):
        """Pop the first spendable coin (coinbases need 100 confirmations)."""
        height = self._node.getblockcount()
        for i, utxo in enumerate(self._utxos):
            if not utxo["coinbase"] or height - utxo["height"] + 1 >= 100:
                return self._utxos.pop(i)
        raise StopIteration("no spendable V2 coin")

    def create_self_transfer(self, utxo=None):
        utxo = utxo or self.get_utxo()
        tx = new_v7_tx()
        tx.vin = [v7_input(COutPoint(int(utxo["txid"], 16), utxo["vout"]), V2_OP_TRUE)]
        tx.vout = [v2_op_true_txout(utxo["value"] - self.FEE)]
        return tx

    def send_self_transfer(self, from_node=None):
        tx = self.create_self_transfer()
        self.sendrawtransaction(tx, from_node)
        return tx


def _vector_path():
    return os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "src",
        "test",
        "data",
        "v2_legacy_bridge.json",
    )


def coins_from_vector(entries):
    coins = []
    for c in entries:
        if "script" in c:
            coins.append(LegacyCoin(c["value"], bytes.fromhex(c["script"])))
        else:
            out = CTxOut()
            out.nValue = c["value"]
            out.scriptPubKey = bytes.fromhex(c["v2output"])
            coins.append(V2Coin(_lotus_v2_to_output(out)))
    return coins


class TestFrameworkV7Tx(unittest.TestCase):
    def test_signing_message_vectors(self):
        with open(_vector_path(), encoding="utf8") as f:
            vectors = json.load(f)
        self.assertTrue(vectors)
        for v in vectors:
            tx = CTransaction()
            tx.deserialize(BytesIO(bytes.fromhex(v["tx"])))
            coins = coins_from_vector(v["coins"])
            msg = signing_message(
                tx,
                coins,
                v["input"],
                v["mode"],
                chain_id=bytes.fromhex(v["chain_id"]),
            )
            self.assertEqual(msg.hex(), v["message"], v["comment"])

    def test_legacy_round_trip_and_sha256d(self):
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(0x1234, 1), b"\x51", 0xFFFFFFFE)]
        tx.vout = [CTxOut(5000, b"\x51")]
        raw = tx.serialize()
        tx2 = CTransaction()
        tx2.deserialize(BytesIO(raw))
        self.assertEqual(tx2.serialize(), raw)
        txid, txhash = lotus_v2_compute_tx_identities(tx2)
        expected = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
        self.assertEqual(txid, expected)
        self.assertEqual(txhash, expected)

    def test_bip340_sign_verifies(self):
        key = ECKey()
        key.set((7).to_bytes(32, "big"), True)
        msg = hashlib.sha256(b"msg").digest()
        sig = bip340_sign(key.get_bytes(), msg)
        p = SECP256K1.affine(key.get_pubkey().p)
        # BIP340 verify against the x-only key.
        px = p[0].to_bytes(32, "big")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        e = (
            int.from_bytes(
                _bip340_tagged("BIP0340/challenge", sig[:32] + px + msg), "big"
            )
            % SECP256K1_ORDER
        )
        x, y, z = SECP256K1.lift_x(p[0])
        pe = (x, y if y % 2 == 0 else SECP256K1.p - y, z)
        R = SECP256K1.affine(
            SECP256K1.mul([(SECP256K1_G, s), (pe, SECP256K1_ORDER - e)])
        )
        self.assertEqual(R[0], r)
        self.assertEqual(R[1] % 2, 0)
