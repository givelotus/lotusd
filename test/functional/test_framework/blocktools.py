# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

import struct
import time
import unittest
from typing import Optional, Union

from .key import ECKey
from .messages import (
    COIN,
    XEC,
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    ToHex,
)
from .script import (
    OP_1,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_RETURN,
    OP_TRUE,
    CScript,
    CScriptNum,
    CScriptOp,
)
from .txtools import pad_tx, sign_input
from .util import assert_equal, satoshi_round

# Genesis block data (regtest)
TIME_GENESIS_BLOCK = 1600000000
GENESIS_BLOCK_HASH = "106050de32db2a668422cc34aa0f96d739d4189b8e5d6e763deeca527bba9c9f"
GENESIS_BLOCK_HEADER = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000"
GENESIS_CB_TXID = "04749c2a27d0fe08665d29bca419b4e1077af2dc85b4ad439f88fc97c23d44a7"
GENESIS_CB_PK = (
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"
    "c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)
GENESIS_CB_SCRIPT_PUBKEY = CScript.fromhex(f"41{GENESIS_CB_PK}ac")
GENESIS_CB_SCRIPT_SIG = CScript(
    b"\x04\xff\xff\x00\x1d\x01\x04EThe Times 03/Jan/2009 Chancellor on brink of "
    b"second bailout for banks"
)

MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# Coinbase transaction outputs can only be spent after this number of new blocks
# (network rule)
COINBASE_MATURITY = 100

MIN_BLOCKS_TO_KEEP = 288

SUBSIDY = 260


_UNSET = object()


def create_block(
    hashprev: Optional[int] = None,
    coinbase: Optional[CTransaction] = None,
    height_or_ntime: Optional[int] = None,
    ntime: Any = _UNSET,
    *,
    height: Optional[int] = None,
    version: Optional[int] = None,
    tmpl: Optional[dict] = None,
    txlist: Optional[list] = None,
) -> CBlock:
    """Create a block (with regtest difficulty)."""
    block = CBlock()
    if tmpl is None:
        tmpl = {}
    if ntime is not _UNSET:
        if height is None:
            height = height_or_ntime
    else:
        if height_or_ntime is not None:
            if height is None and height_or_ntime < 100_000_000:
                height = height_or_ntime
                ntime = None
            else:
                ntime = height_or_ntime
        else:
            ntime = None
    block.nHeaderVersion = version or tmpl.get("version", 1)
    block.nTime = ntime or tmpl.get("curtime", int(time.time() + 600))
    block.hashPrevBlock = hashprev or int(tmpl["previousblockhash"], 0x10)
    if tmpl.get("bits") is not None:
        block.nBits = struct.unpack(">I", bytes.fromhex(tmpl["bits"]))[0]
    else:
        # difficulty retargeting is disabled in REGTEST chainparams
        block.nBits = 0x207FFFFF
    if height is not None:
        block.nHeight = height
    elif tmpl.get("height") is not None:
        block.nHeight = tmpl["height"]
    elif coinbase is not None and getattr(coinbase, "_height", None) is not None:
        block.nHeight = coinbase._height
    block.vtx.append(coinbase or create_coinbase(height=tmpl["height"]))
    if txlist:
        block.vtx.extend(txlist)
        make_conform_to_ctor(block)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.update_size()
    block.rehash_extended_metadata()
    block.calc_sha256()
    return block


def make_conform_to_ctor(block: CBlock):
    for tx in block.vtx:
        tx.rehash()
    block.vtx = [block.vtx[0]] + sorted(block.vtx[1:], key=lambda tx: tx.txid_hex)


def prepare_block(block: CBlock):
    make_conform_to_ctor(block)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.update_size()
    block.rehash_extended_metadata()
    block.solve()


def script_coinbase_height(height: int) -> CScript:
    if height <= 16:
        num = CScriptOp.encode_op_n(height)
    else:
        num = CScriptNum(height)
    return CScript([OP_RETURN, b'logos', num])


script_BIP34_coinbase_height = script_coinbase_height


def create_coinbase(
    height: int,
    pubkey: Optional[bytes] = None,
    *,
    script_pubkey: Optional[bytes] = None,
    nValue: int = SUBSIDY,
) -> CTransaction:
    """Create a coinbase transaction, assuming no miner fees.

    If pubkey is passed in, the coinbase output will be a P2PK output;
    otherwise an anyone-can-spend output."""
    coinbase = CTransaction()
    coinbase._height = height
    coinbase.vin.append(
        CTxIn(
            COutPoint(0, 0xFFFFFFFF), bytes(80), 0xFFFFFFFF
        )
    )
    op_return_output = CTxOut()
    op_return_output.scriptPubKey = script_coinbase_height(height)
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = int(nValue * COIN)
    if pubkey is not None:
        coinbaseoutput.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    elif script_pubkey is not None:
        coinbaseoutput.scriptPubKey = script_pubkey
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = [op_return_output, coinbaseoutput]

    coinbase.rehash()
    return coinbase


def create_tx_with_script(
    prevtx, n, script_sig=b"", *, amount, script_pub_key: Optional[CScript] = None
):
    """Return one-input, one-output transaction object
    spending the prevtx's n-th output with the given amount.

    Can optionally pass scriptPubKey and scriptSig, default is anyone-can-spend output.
    """
    tx = CTransaction()
    script_pub_key = script_pub_key or CScript()
    assert n < len(prevtx.vout)
    tx.vin.append(CTxIn(COutPoint(prevtx.txid_int, n), script_sig, 0xFFFFFFFF))
    tx.vout.append(CTxOut(amount, script_pub_key))
    pad_tx(tx)
    tx.rehash()
    return tx


def create_transaction(node, txid, to_address, *, amount, vout=0):
    """Return signed transaction spending the first output of the
    input txid. Note that the node must be able to sign for the
    output that is being spent, and the node must not be running
    multiple wallets.
    """
    raw_tx = create_raw_transaction(node, txid, to_address, amount=amount, vout=vout)
    tx = FromHex(CTransaction(), raw_tx)
    return tx


def create_raw_transaction(node, txid, to_address, *, amount, vout=0):
    """Return raw signed transaction spending the first output of the
    input txid. Note that the node must be able to sign for the
    output that is being spent, and the node must not be running
    multiple wallets.
    """
    rawtx = node.createrawtransaction(
        inputs=[{"txid": txid, "vout": vout}], outputs={to_address: amount}
    )
    signresult = node.signrawtransactionwithwallet(rawtx)
    assert_equal(signresult["complete"], True)
    return signresult["hex"]


def create_confirmed_utxos(test_framework, node, count, age=101, **kwargs):
    """
    Helper to create at least "count" utxos
    """
    to_generate = int(0.5 * count) + age
    while to_generate > 0:
        test_framework.generate(node, min(25, to_generate), **kwargs)
        to_generate -= 25
    utxos = node.listunspent()
    iterations = count - len(utxos)
    addr1 = node.getnewaddress()
    addr2 = node.getnewaddress()
    if iterations <= 0:
        return utxos
    for i in range(iterations):
        t = utxos.pop()
        inputs = []
        inputs.append({"txid": t["txid"], "vout": t["vout"]})
        outputs = {}
        outputs[addr1] = satoshi_round(t["amount"] / 2)
        outputs[addr2] = satoshi_round(t["amount"] / 2)
        raw_tx = node.createrawtransaction(inputs, outputs)
        ctx = FromHex(CTransaction(), raw_tx)
        fee = node.calculate_fee(ctx) // 2
        ctx.vout[0].nValue -= fee
        # Due to possible truncation, we go ahead and take another satoshi in
        # fees to ensure the transaction gets through
        ctx.vout[1].nValue -= fee + 1
        signed_tx = node.signrawtransactionwithwallet(ToHex(ctx))["hex"]
        node.sendrawtransaction(signed_tx)

    while node.getmempoolinfo()["size"] > 0:
        test_framework.generate(node, 1, **kwargs)

    utxos = node.listunspent()
    assert len(utxos) >= count
    return utxos


def mine_big_block(test_framework, node, utxos=None):
    # generate a 66k transaction,
    # and 14 of them is close to the 1MB block limit
    num = 14
    utxos = utxos if utxos is not None else []
    if len(utxos) < num:
        utxos.clear()
        utxos.extend(node.listunspent())
    send_big_transactions(node, utxos, num, 100)
    test_framework.generate(node, 1)


def send_big_transactions(node, utxos, num, fee_multiplier):
    from .cashaddr import decode

    txids = []
    padding = "1" * 512
    addrHash = decode(node.getnewaddress())[2]

    for _ in range(num):
        ctx = CTransaction()
        utxo = utxos.pop()
        txid = int(utxo["txid"], 16)
        ctx.vin.append(CTxIn(COutPoint(txid, int(utxo["vout"])), b""))
        ctx.vout.append(
            CTxOut(
                int(satoshi_round(utxo["amount"] * COIN)),
                CScript([OP_DUP, OP_HASH160, addrHash, OP_EQUALVERIFY, OP_CHECKSIG]),
            )
        )
        for i in range(0, 127):
            ctx.vout.append(CTxOut(0, CScript([OP_RETURN, bytes(padding, "utf-8")])))
        # Create a proper fee for the transaction to be mined
        ctx.vout[0].nValue -= int(fee_multiplier * node.calculate_fee(ctx))
        signresult = node.signrawtransactionwithwallet(ToHex(ctx), None, "NONE|FORKID")
        txid = node.sendrawtransaction(signresult["hex"], 0)
        txids.append(txid)
    return txids


class BlockTestMixin:
    """A mixin for functional test classes to factor some common code."""

    BlockNumber = Union[int, str]
    """Shortcut for type used for block numbers. Can be an int or a string when branch
    information is to be stored (e.g. "64a", "b56p2"...)"""

    blocks: dict[BlockNumber, CBlock] = {}

    tip: Optional[CBlock] = None

    genesis_hash = int(GENESIS_BLOCK_HASH, 16)

    block_heights: dict[int, int] = {genesis_hash: 0}
    """A sha256 to block height map"""

    coinbase_key: Optional[ECKey] = None
    """The key used to sign the coinbase transactions. If None, coinbase transactions
    will be anyone-can-spend.
    """

    coinbase_pubkey: Optional[bytes] = None

    # move the tip back to a previous block
    def move_tip(self, number: BlockNumber):
        self.tip = self.blocks[number]

    # adds transactions to the block and updates state
    def update_block(
        self,
        block_number: Union[int, str],
        new_transactions: list[CTransaction],
        reorder=True,
        *,
        nTime: Optional[int] = None,
    ) -> CBlock:
        block = self.blocks[block_number]
        block.vtx.extend(new_transactions)
        old_sha256 = block.hash_int
        if nTime is not None:
            block.nTime = nTime
        if reorder:
            make_conform_to_ctor(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.update_size()
        block.rehash_extended_metadata()
        block.solve()
        # Update the internal state just like in next_block
        self.tip = block
        if block.hash_int != old_sha256:
            self.block_heights[block.hash_int] = self.block_heights[old_sha256]
            del self.block_heights[old_sha256]
        self.blocks[block_number] = block
        return block

    def generate_coinbase_key(self):
        self.coinbase_key = ECKey()
        self.coinbase_key.generate()
        self.coinbase_pubkey = self.coinbase_key.get_pubkey().get_bytes()

    # sign a transaction, using the key we know about
    # this signs input 0 in tx, which is assumed to be spending output n in
    # spend_tx
    def sign_tx(self, tx: CTransaction, spend_tx: CTransaction):
        assert self.coinbase_key is not None
        out_idx = tx.vin[0].prevout.n
        scriptPubKey = bytearray(spend_tx.vout[out_idx].scriptPubKey)
        if scriptPubKey[0] == OP_TRUE:  # an anyone-can-spend
            tx.vin[0].scriptSig = CScript()
            return
        sign_input(
            tx,
            0,
            spend_tx.vout[out_idx].scriptPubKey,
            self.coinbase_key,
            spend_tx.vout[out_idx].nValue,
        )

    # this is a little handier to use than create_tx_with_script
    def create_tx(self, spend_tx, n, value: int, script: Optional[CScript] = None):
        script = script or CScript([OP_TRUE])
        return create_tx_with_script(spend_tx, n, amount=value, script_pub_key=script)

    def create_and_sign_transaction(
        self, spend_tx: CTransaction, value: int, script: Optional[CScript] = None
    ) -> CTransaction:
        script = script or CScript([OP_TRUE])
        out_idx = 1 if len(spend_tx.vout) > 1 and spend_tx.vout[0].nValue == 0 else 0
        tx = self.create_tx(spend_tx, out_idx, value, script)
        self.sign_tx(tx, spend_tx)
        tx.rehash()
        return tx

    def next_block(
        self,
        number: BlockNumber,
        *,
        additional_coinbase_value=0,
        script: Optional[CScript] = None,
        spend: Optional[CTransaction] = None,
        version=1,
        coinbase_time: Optional[int] = None,
    ) -> CBlock:
        """Create a new block building on the current tip, and advance the tip to it.
        The caller is responsible for broadcasting the generated block, either by storing
        the returned block or by immediately broadcasting self.tip after this method returns.
        """
        script = script or CScript([OP_TRUE])
        if self.tip is None:
            base_block_hash = self.genesis_hash
            block_time = coinbase_time or int(time.time()) + 1
        else:
            base_block_hash = self.tip.hash_int
            block_time = self.tip.nTime + 1
        # First create the coinbase
        height = self.block_heights[base_block_hash] + 1
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        coinbase.vout[1].nValue += additional_coinbase_value
        if spend is None:
            coinbase.rehash()
            block = create_block(base_block_hash, coinbase, block_time, version=version)
        else:
            out_idx = 1 if len(spend.vout) > 1 and spend.vout[0].nValue == 0 else 0
            # all but one satoshi to fees
            coinbase.vout[1].nValue += spend.vout[out_idx].nValue - 1
            coinbase.rehash()
            # spend 1 satoshi
            tx = self.create_tx(spend, out_idx, 1, script)
            self.sign_tx(tx, spend)
            tx.rehash()
            block = create_block(
                base_block_hash, coinbase, block_time, version=version, txlist=[tx]
            )
        block.nHeight = height
        prepare_block(block)
        self.tip = block
        self.block_heights[block.hash_int] = height
        assert number not in self.blocks
        self.blocks[number] = block
        return block


class TestFrameworkBlockTools(unittest.TestCase):
    def test_create_coinbase(self):
        height = 20
        coinbase_tx = create_coinbase(height=height)
        assert_equal(
            CScriptNum.decode(coinbase_tx.vout[0].scriptPubKey[len(b"_\x05logos") :]),
            height,
        )
