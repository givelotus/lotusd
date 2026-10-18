# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A limited-functionality wallet, which may replace a real wallet in tests"""

import hashlib
import secrets
from copy import deepcopy
from decimal import Decimal
from enum import Enum
from typing import Any, Optional

from test_framework import cashaddr
from test_framework.address import (
    base58_to_byte,
    key_to_p2pkh,
)
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.currency import XPI_RPC_CURRENCY, RpcCurrency
from test_framework.hash import hash160
from test_framework.key import SECP256K1, SECP256K1_G, SECP256K1_ORDER, ECKey
from test_framework.messages import (
    XEC,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    _lotus_v2_decode_output_bytes,
    _lotus_v2_encode_output,
    _lotus_v2_to_output,
    lotus_v2_branch_leaf,
    lotus_v2_indexed_tree_root,
    lotus_v2_tagged_hash,
    ser_string,
    ser_uint256,
)
from test_framework.script import (
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    CScript,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    satoshi_round,
)

DEFAULT_FEE_ATOMS = 10000
DEFAULT_FEE = XPI_RPC_CURRENCY.from_atoms(DEFAULT_FEE_ATOMS)


class MiniWalletMode(Enum):
    """Determines the transaction type the MiniWallet is creating and spending.

    ADDRESS_OP_TRUE commits the native automatic-success branch (0x4e).
    RAW_P2PK commits an x-only key and native CHECKSIG (0xbb), spending with
    a 65-byte mode-1 BIP340 signature. The historical enum names are retained
    for callers; neither mode emits legacy scripts or ECDSA signatures.
    """

    ADDRESS_OP_TRUE = 1
    RAW_P2PK = 3


class MiniWallet:
    def __init__(self, test_node, *, mode=MiniWalletMode.ADDRESS_OP_TRUE):
        self._test_node = test_node
        self._currency = RpcCurrency.from_node(test_node)
        self._utxos = []
        self._input_values = {}
        self._mode = mode

        assert isinstance(mode, MiniWalletMode)
        if mode == MiniWalletMode.RAW_P2PK:
            # use simple deterministic private key (k=1)
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, "big"), True)
            pub_key = self._priv_key.get_pubkey().get_bytes()
            # Native VM: x-only BIP340 CHECKSIG, not legacy ECDSA OP_CHECKSIG.
            self._scriptPubKey = b"\x20" + pub_key[1:] + b"\xbb"
        elif mode == MiniWalletMode.ADDRESS_OP_TRUE:
            self._scriptPubKey = b"\x4e"
        else:
            raise AssertionError(f"Unsupported MiniWalletMode {mode}")

        # When the pre-mined test framework chain is used, it contains coinbase
        # outputs to the MiniWallet's default address in blocks 76-100
        # (see method BitcoinTestFramework._initialize_chain())
        # The MiniWallet needs to rescan_utxos() in order to account
        # for those mature UTXOs, so that all txs spend confirmed coins
        self.rescan_utxos()

    def _create_utxo(self, *, txid, vout, value, height, coinbase, confirmations):
        self._input_values[(txid, vout)] = int(value * XEC)
        return {
            "txid": txid,
            "vout": vout,
            "value": value,
            "height": height,
            "coinbase": coinbase,
            "confirmations": confirmations,
        }

    def rescan_utxos(self, *, include_mempool=True):
        """Rebuild owned native coins from authoritative RPC transaction data."""
        # Native canonical scriptPubKeys contain the value as well as the
        # commitment; scantxoutset's exact-script matcher cannot find every
        # value of a branch. Keep one outpoint map throughout this full scan.
        # Rebuilding from the active chain preserves reorg/restart semantics.
        owned = {}
        height = self._test_node.getblockcount()
        for n in range(height + 1):
            block = self._test_node.getblock(self._test_node.getblockhash(n), 2)
            self._apply_transactions(
                owned, block["tx"], height=n, confirmations=height - n + 1
            )
        if include_mempool:
            self._apply_transactions(
                owned,
                [
                    self._test_node.getrawtransaction(txid, True)
                    for txid in self._test_node.getrawmempool()
                ],
            )
        self._utxos = list(owned.values())

    def _apply_transactions(self, owned, transactions, *, height=0, confirmations=0):
        # Node-validated blocks and mempool entries may use CTOR order rather
        # than dependency order. Add all owned outputs, then remove every spent
        # outpoint. A parent output spent anywhere in this batch cannot survive.
        # This is linear in outputs + inputs, independent of the owned-set size.
        transactions = list(transactions)
        commitment = (
            0,
            b"\x00" * 32,
            [lotus_v2_branch_leaf(self._scriptPubKey)],
            [[0]],
        )
        for tx in transactions:
            coinbase = bool(tx["vin"] and "coinbase" in tx["vin"][0])
            for out in tx["vout"]:
                decoded = _lotus_v2_decode_output_bytes(
                    bytes.fromhex(out["scriptPubKey"]["hex"])
                )
                if decoded == commitment:
                    key = (tx["txid"], out["n"])
                    owned[key] = self._create_utxo(
                        txid=key[0],
                        vout=key[1],
                        value=out["value"],
                        height=height,
                        coinbase=coinbase,
                        confirmations=confirmations,
                    )
        for tx in transactions:
            for spent in tx["vin"]:
                if "txid" in spent:
                    owned.pop((spent["txid"], spent["vout"]), None)

    def _scan_transactions(self, transactions, **kwargs):
        owned = {(u["txid"], u["vout"]): u for u in self._utxos}
        self._apply_transactions(owned, transactions, **kwargs)
        self._utxos = list(owned.values())

    def scan_tx(self, tx, *, height=0, confirmations=0):
        """Apply a transaction to the internally tracked owned coins."""
        self._scan_transactions([tx], height=height, confirmations=confirmations)

    def sign_tx(self, tx, amount=None, fixed_length=True):
        """Sign tx that has been created by MiniWallet"""
        tx.nVersion = 7
        for out in tx.vout:
            flags, value, token, branches, paths = _lotus_v2_to_output(out)
            out.nFlags, out.tokenId = flags, token
            out.vBranches, out.vPaths = branches, paths
            out.scriptPubKey = _lotus_v2_encode_output(
                (flags, value, token, branches, paths)
            )
        output_root = lotus_v2_indexed_tree_root(
            [
                lotus_v2_tagged_hash("Lotus/v2/output", ser_string(out.scriptPubKey))
                for out in tx.vout
            ]
        )
        lock = (
            tx.nV2Lock
            if tx.fHasV2Lock
            else 0
            if tx.nLockTime == 0
            else ((tx.nLockTime << 8) | (1 if tx.nLockTime < 500000000 else 2))
        )
        for index, txin in enumerate(tx.vin):
            txin.nFlags, txin.nPathIndex = 1, 0
            txin.scriptSig = self._scriptPubKey
            args = []
            if self._mode == MiniWalletMode.RAW_P2PK:
                value = self._input_values.get(
                    (f"{txin.prevout.txid:064x}", txin.prevout.n)
                )
                if value is None and len(tx.vin) == 1:
                    value = amount
                assert value is not None, (
                    "individual input amount required for native signing"
                )
                leaf = lotus_v2_branch_leaf(self._scriptPubKey)
                coin = _lotus_v2_encode_output(
                    (0, int(value), b"\x00" * 32, [leaf], [[0]])
                )
                core = (
                    ser_uint256(txin.prevout.txid)
                    + txin.prevout.n.to_bytes(4, "little")
                    + txin.nSequence.to_bytes(4, "little")
                    + b"\x01\x00\x01"
                    + ser_string(self._scriptPubKey)
                    + b"\x00"
                )
                own = lotus_v2_tagged_hash("Lotus/v2/owninput", core + ser_string(coin))
                selector = b"\x01" + index.to_bytes(4, "little") + b"\x00" * 4 + leaf
                digest = lotus_v2_tagged_hash(
                    "Lotus/v2/sighash",
                    b"\x00" * 32
                    + b"\x01"
                    + (7).to_bytes(4, "little")
                    + lock.to_bytes(8, "little")
                    + own
                    + output_root
                    + selector,
                )
                # BIP340 uses even-Y public keys and nonces. Fresh nonces avoid
                # reusing a signing nonce across modified test transactions.
                secret = int.from_bytes(self._priv_key.get_bytes(), "big")
                pub = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, secret)]))
                secret = SECP256K1_ORDER - secret if pub[1] & 1 else secret
                nonce = secrets.randbelow(SECP256K1_ORDER - 1) + 1
                point = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, nonce)]))
                nonce = SECP256K1_ORDER - nonce if point[1] & 1 else nonce
                rx = point[0].to_bytes(32, "big")
                tag = hashlib.sha256(b"BIP0340/challenge").digest()
                challenge = (
                    int.from_bytes(
                        hashlib.sha256(
                            tag + tag + rx + pub[0].to_bytes(32, "big") + digest
                        ).digest(),
                        "big",
                    )
                    % SECP256K1_ORDER
                )
                args = [
                    rx
                    + ((nonce + challenge * secret) % SECP256K1_ORDER).to_bytes(
                        32, "big"
                    )
                    + b"\x01"
                ]
            txin.vWitnesses = [(self._scriptPubKey, [], args)]

    def generate(self, num_blocks, **kwargs):
        """Generate blocks with coinbase outputs to the internal address, and call rescan_utxos"""
        kwargs.setdefault("invalid_call", False)
        blocks = self._test_node.generatetodescriptor(
            num_blocks, self.get_descriptor(), **kwargs
        )
        # Calling rescan_utxos here makes sure that after a generate the utxo
        # set is in a clean state. For example, the wallet will update
        # - if the caller consumed utxos, but never used them
        # - if the caller sent a transaction that is not mined
        # - after block re-orgs
        # - the utxo height for mined mempool txs
        # - However, the wallet will not consider remaining mempool txs
        self.rescan_utxos()
        return blocks

    def get_descriptor(self):
        return self._test_node.getdescriptorinfo(f"raw({self._scriptPubKey.hex()})")[
            "descriptor"
        ]

    def get_scriptPubKey(self):
        return self._scriptPubKey

    def get_utxo(
        self,
        *,
        txid: str = "",
        vout: Optional[int] = None,
        mark_as_spent=True,
        confirmed_only=False,
    ):
        """
        Returns a utxo and marks it as spent (pops it from the internal list)

        Args:
        txid: get the first utxo we find from a specific transaction
        """
        # Put the largest utxo last
        self._utxos = sorted(self._utxos, key=lambda k: (k["value"], -k["height"]))
        blocks_height = self._test_node.getblockchaininfo()["blocks"]
        mature_coins = list(
            filter(
                lambda utxo: (
                    not utxo["coinbase"]
                    or COINBASE_MATURITY - 1 <= blocks_height - utxo["height"]
                ),
                self._utxos,
            )
        )
        if txid:
            utxo_filter: Any = filter(lambda utxo: txid == utxo["txid"], self._utxos)
        else:
            # By default the largest utxo
            utxo_filter = reversed(mature_coins)
        if vout is not None:
            utxo_filter = filter(lambda utxo: vout == utxo["vout"], utxo_filter)
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo["confirmations"] > 0, utxo_filter)
        index = self._utxos.index(next(utxo_filter))

        if mark_as_spent:
            return self._utxos.pop(index)
        else:
            return self._utxos[index]

    def get_utxos(
        self,
        *,
        include_immature_coinbase=False,
        mark_as_spent=True,
        confirmed_only=False,
    ):
        """Returns the list of all utxos and optionally mark them as spent"""
        if not include_immature_coinbase:
            blocks_height = self._test_node.getblockchaininfo()["blocks"]
            utxo_filter = filter(
                lambda utxo: (
                    not utxo["coinbase"]
                    or COINBASE_MATURITY - 1 <= blocks_height - utxo["height"]
                ),
                self._utxos,
            )
        else:
            utxo_filter = self._utxos
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo["confirmations"] > 0, utxo_filter)
        utxos = deepcopy(list(utxo_filter))
        if mark_as_spent:
            self._utxos = []
        return utxos

    def send_self_transfer(self, *, from_node, **kwargs):
        """Call create_self_transfer and send the transaction."""
        tx = self.create_self_transfer(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def send_to(self, *, from_node, scriptPubKey, amount, fee=1000):
        """
        Create and send a tx with an output to a given scriptPubKey/amount,
        plus a change output to our internal address. To keep things simple, a
        fixed fee given in Satoshi is used.
        Note that this method fails if there is no single internal utxo
        available that can cover the cost for the amount and the fixed fee
        (the utxo with the largest value is taken).
        Returns a tuple (txid, n) referring to the created external utxo outpoint.
        """
        tx = self.create_self_transfer(fee_rate=0)["tx"]
        assert_greater_than_or_equal(tx.vout[0].nValue, amount + fee)
        # change output -> MiniWallet
        tx.vout[0].nValue -= amount + fee
        # arbitrary output -> to be returned
        tx.vout.append(CTxOut(amount, scriptPubKey))
        self.sign_tx(tx)
        txid = self.sendrawtransaction(from_node=from_node, tx_hex=tx.serialize().hex())
        return txid, len(tx.vout) - 1

    def send_self_transfer_multi(self, *, from_node, **kwargs):
        """Call create_self_transfer_multi and send the transaction."""
        tx = self.create_self_transfer_multi(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def create_self_transfer_multi(
        self,
        *,
        utxos_to_spend=None,
        num_outputs=1,
        amount_per_output=0,
        locktime=0,
        sequence=0,
        fee_per_output=1000,
        target_size=0,
        confirmed_only=False,
    ):
        """
        Create and return a transaction that spends the given UTXOs and creates a
        certain number of outputs with equal amounts. The output amounts can be
        set by amount_per_output or automatically calculated with a fee_per_output.
        """
        utxos_to_spend = utxos_to_spend or [
            self.get_utxo(confirmed_only=confirmed_only)
        ]
        sequence = (
            [sequence] * len(utxos_to_spend) if type(sequence) is int else sequence
        )
        assert_equal(len(utxos_to_spend), len(sequence))

        # Each input signs its own resolved coin, never a summed input value.
        for utxo in utxos_to_spend:
            self._input_values[(utxo["txid"], utxo["vout"])] = int(utxo["value"] * XEC)

        # calculate output amount
        inputs_value_total = sum(
            [self._currency.to_atoms(utxo["value"]) for utxo in utxos_to_spend]
        )
        outputs_value_total = inputs_value_total - fee_per_output * num_outputs
        amount_per_output = amount_per_output or (outputs_value_total // num_outputs)
        assert amount_per_output > 0
        outputs_value_total = amount_per_output * num_outputs
        fee = self._currency.from_atoms(inputs_value_total - outputs_value_total)

        # create tx
        tx = CTransaction()
        tx.vin = [
            CTxIn(
                COutPoint(int(utxo_to_spend["txid"], 16), utxo_to_spend["vout"]),
                nSequence=seq,
            )
            for utxo_to_spend, seq in zip(utxos_to_spend, sequence)
        ]
        tx.vout = [
            CTxOut(amount_per_output, bytearray(self._scriptPubKey))
            for _ in range(num_outputs)
        ]
        tx.nLockTime = locktime

        self.sign_tx(
            tx,
            sum(
                [
                    self._currency.to_atoms(utxo_to_spend["value"])
                    for utxo_to_spend in utxos_to_spend
                ]
            ),
        )

        if target_size and len(tx.serialize()) < target_size:
            # Native burn output padding; never append a legacy wire output.
            padding = CTxOut(0, b"\x6a")
            padding.nFlags = 2
            padding.tokenId = b"\x00" * 32
            padding.vBranches = [lotus_v2_branch_leaf(b"\x6a")]
            padding.vPaths = []
            tx.vout.append(padding)
            while len(tx.serialize()) < target_size:
                extra = deepcopy(padding)
                tx.vout.append(extra)
            self.sign_tx(tx)

        txid = tx.txid_hex
        return {
            "new_utxos": [
                self._create_utxo(
                    txid=txid,
                    vout=i,
                    value=self._currency.from_atoms(tx.vout[i].nValue),
                    height=0,
                    coinbase=False,
                    confirmations=0,
                )
                for i in range(len(tx.vout))
                if not tx.vout[i].nFlags & 2
            ],
            "fee": fee,
            "txid": txid,
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def create_self_transfer(
        self,
        *,
        fee_rate=None,
        fee=Decimal("0"),
        utxo_to_spend=None,
        locktime=0,
        sequence=0,
        target_size=0,
        confirmed_only=False,
    ):
        """Create and return a tx with the specified fee. If fee is 0, use fee_rate, where the resulting fee may be exact or at most one satoshi higher than needed."""
        utxo_to_spend = utxo_to_spend or self.get_utxo(confirmed_only=confirmed_only)
        if fee_rate is None:
            fee_rate = self._currency.from_atoms(300000)
        assert fee_rate >= 0
        assert fee >= 0

        # Native witnesses have fixed lengths, so an unsigned-value trial
        # gives the actual billable size before fee calculation.
        trial = self.create_self_transfer_multi(
            utxos_to_spend=[utxo_to_spend],
            locktime=locktime,
            sequence=sequence,
            fee_per_output=0,
            target_size=target_size,
        )
        size = len(trial["tx"].serialize())

        send_value = self._currency.round_down(
            utxo_to_spend["value"] - (fee or (fee_rate * (Decimal(size) / 1000)))
        )

        # create tx
        tx = self.create_self_transfer_multi(
            utxos_to_spend=[utxo_to_spend],
            locktime=locktime,
            sequence=sequence,
            amount_per_output=self._currency.to_atoms(send_value),
            target_size=target_size,
        )
        assert_equal(len(tx["tx"].serialize()), size)

        tx["new_utxo"] = tx.pop("new_utxos")[0]

        return tx

    def sendrawtransaction(self, *, from_node, tx_hex):
        txid = from_node.sendrawtransaction(tx_hex)
        self.scan_tx(from_node.decoderawtransaction(tx_hex))
        return txid

    def create_self_transfer_chain(self, *, chain_length, utxo_to_spend=None, **kwargs):
        """
        Create a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.
        """
        chaintip_utxo = utxo_to_spend or self.get_utxo()
        chain = []

        for _ in range(chain_length):
            tx = self.create_self_transfer(utxo_to_spend=chaintip_utxo, **kwargs)
            chaintip_utxo = tx["new_utxo"]
            chain.append(tx)

        return chain

    def send_self_transfer_chain(self, *, from_node, **kwargs):
        """Create and send a "chain" of chain_length transactions. The nth
        transaction in the chain is a child of the n-1th transaction and parent
        of the n+1th transaction.

        Returns a list of objects for each tx (see create_self_transfer_multi).
        """
        chain = self.create_self_transfer_chain(**kwargs)
        for t in chain:
            self.sendrawtransaction(from_node=from_node, tx_hex=t["hex"])

        return chain


def getnewdestination():
    """Generate a random destination and return the corresponding public key,
    scriptPubKey and address. Can be used when a random destination is
    needed, but no compiled wallet is available (e.g. as replacement to the
    getnewaddress/getaddressinfo RPCs)."""
    key = ECKey()
    key.generate()
    pubkey = key.get_pubkey().get_bytes()
    scriptpubkey = CScript(
        [OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG]
    )
    return pubkey, scriptpubkey, key_to_p2pkh(pubkey)


def address_to_scriptpubkey(address):
    """Converts a given address to the corresponding output script (scriptPubKey)."""
    payload, version = base58_to_byte(address)
    if version == 111:  # testnet pubkey hash
        return CScript([OP_DUP, OP_HASH160, payload, OP_EQUALVERIFY, OP_CHECKSIG])
    elif version == 196:  # testnet script hash
        return CScript([OP_HASH160, payload, OP_EQUAL])
    # TODO: also support other address formats
    else:
        assert False


def cashaddr_to_scriptpubkey(address: str) -> CScript:
    """Converts a given CashAddress to the corresponding output script (scriptPubKey)."""
    prefix, kind, addr_hash = cashaddr.decode(address)
    if kind == cashaddr.PUBKEY_TYPE:
        return CScript([OP_DUP, OP_HASH160, addr_hash, OP_EQUALVERIFY, OP_CHECKSIG])
    if kind == cashaddr.SCRIPT_TYPE:
        return CScript([OP_HASH160, addr_hash, OP_EQUAL])
    assert False
