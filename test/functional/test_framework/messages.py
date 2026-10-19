# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin test framework primitive and message structures

CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives

msg_block, msg_tx, msg_headers, etc.:
    data structures that represent network messages

ser_*, deser_*: functions that handle serialization/deserialization.

Classes use __slots__ to ensure extraneous attributes aren't accidentally added
by tests, compromising their intended effect.
"""

import copy
import hashlib
import random
import socket
import time
import unittest
from base64 import b64decode, b64encode
from enum import IntEnum
from io import BytesIO
from typing import List, Optional

from test_framework.siphash import siphash256
from test_framework.util import assert_equal, uint256_hex

MAX_LOCATOR_SZ = 101
MAX_BLOCK_BASE_SIZE = 1000000
MAX_BLOOM_FILTER_SIZE = 36000
MAX_BLOOM_HASH_FUNCS = 50

# 1,000,000 XEC in satoshis (legacy BCHA)
COIN = 100000000
# 1 XEC in satoshis
XEC = 100
MAX_MONEY = 21000000 * COIN

# Maximum length of incoming protocol messages
MAX_PROTOCOL_MESSAGE_LENGTH = 2 * 1024 * 1024
MAX_HEADERS_RESULTS = 2000  # Number of headers sent in one getheaders result
MAX_INV_SIZE = 50000  # Maximum number of entries in an 'inv' protocol message

NODE_NETWORK = 1 << 0
NODE_GETUTXO = 1 << 1
NODE_BLOOM = 1 << 2
# NODE_WITNESS = (1 << 3)
# NODE_XTHIN = (1 << 4) # removed in v0.22.12
NODE_COMPACT_FILTERS = 1 << 6
NODE_NETWORK_LIMITED = 1 << 10
NODE_AVALANCHE = 1 << 24
NODE_UTXO_SHARD = 1 << 25
NODE_MERKLIX_EPOCH = 1 << 28

MSG_UNDEFINED = 0
MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4
MSG_AVA_PROOF = 0x1F000001
MSG_AVA_STAKE_CONTENDER = 0x1F000002
MSG_AVA_TREASURY_CONTENDER = 0x20000005
MSG_AVA_MEMPOOL_BATCH = 0x20000006
MSG_TYPE_MASK = 0xFFFFFFFF >> 2

FILTER_TYPE_BASIC = 0

# Serialization/deserialization tools


def sha256(s):
    return hashlib.new("sha256", s).digest()


def hash256(s):
    return sha256(sha256(s))


def ser_compact_size(size: int) -> bytes:
    if size < 253:
        r = size.to_bytes(1, "little")
    elif size < 0x10000:
        r = (253).to_bytes(1, "little") + size.to_bytes(2, "little")
    elif size < 0x100000000:
        r = (254).to_bytes(1, "little") + size.to_bytes(4, "little")
    else:
        r = (255).to_bytes(1, "little") + size.to_bytes(8, "little")
    return r


def deser_compact_size(f) -> int:
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def deser_string(f) -> bytes:
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s: bytes) -> bytes:
    return ser_compact_size(len(s)) + s


def deser_uint256(f):
    return int.from_bytes(f.read(32), "little")


def ser_uint256(u):
    return u.to_bytes(32, "little")


def uint256_from_str(s: bytes):
    return int.from_bytes(s[:32], "little")


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


# deser_function_name: Allow for an alternate deserialization function on the
# entries in the vector.
def deser_vector(f, c, deser_function_name=None):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector.
def ser_vector(v, ser_function_name=None):
    r = ser_compact_size(len(v))
    for i in v:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(v):
    r = ser_compact_size(len(v))
    for i in v:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v):
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r


def FromHex(obj, hex_string):
    """Deserialize from a hex string representation (eg from RPC)"""
    obj.deserialize(BytesIO(bytes.fromhex(hex_string)))
    return obj


def ToHex(obj):
    """Convert a binary-serializable object to hex
    (eg for submission via RPC)"""
    return obj.serialize().hex()


# Objects that map to bitcoind objects, which can be serialized/deserialized


class CAddress:
    __slots__ = ("net", "ip", "nServices", "port", "time", "wss_version")

    # see https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
    NET_IPV4 = 1
    # Not BIP155: a versioned wss:// endpoint. Version 1: "<name>[/<path>]",
    # dialed as wss://<name>:<port><path or /p2p/ws>. For NET_WSS, `ip` holds
    # the body: a str for version 1, bytes for other versions.
    NET_WSS = 0x10
    WSS_V1 = 1

    ADDRV2_NET_NAME = {NET_IPV4: "IPv4", NET_WSS: "WSS"}

    ADDRV2_ADDRESS_LENGTH = {NET_IPV4: 4}

    def __init__(self):
        self.time = 0
        self.nServices = 1
        self.net = self.NET_IPV4
        self.ip = "0.0.0.0"
        self.port = 0
        self.wss_version = self.WSS_V1

    def deserialize(self, f, *, with_time=True):
        """Deserialize from addrv1 format (pre-BIP155)"""
        if with_time:
            # VERSION messages serialize CAddress objects without time
            self.time = int.from_bytes(f.read(4), "little")
        self.nServices = int.from_bytes(f.read(8), "little")
        # We only support IPv4 which means skip 12 bytes and read the next 4 as
        # IPv4 address.
        f.read(12)
        self.net = self.NET_IPV4
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = int.from_bytes(f.read(2), "big")

    def serialize(self, *, with_time=True) -> bytes:
        """Serialize in addrv1 format (pre-BIP155)"""
        assert self.net == self.NET_IPV4
        return (
            # VERSION messages serialize CAddress objects without time
            (self.time.to_bytes(4, "little") if with_time else b"")
            + self.nServices.to_bytes(8, "little")
            + b"\x00" * 10
            + b"\xff" * 2
            + socket.inet_aton(self.ip)
            + self.port.to_bytes(2, "big")
        )

    def deserialize_v2(self, f):
        """Deserialize from addrv2 format (BIP155)"""
        self.time = int.from_bytes(f.read(4), "little")

        self.nServices = deser_compact_size(f)

        self.net = int.from_bytes(f.read(1), "little")
        assert self.net in (self.NET_IPV4, self.NET_WSS)

        address_length = deser_compact_size(f)
        if self.net == self.NET_WSS:
            payload = f.read(address_length)
            self.wss_version = payload[0]
            body = payload[1:]
            self.ip = body.decode("ascii") if self.wss_version == self.WSS_V1 else body
        else:
            assert address_length == self.ADDRV2_ADDRESS_LENGTH[self.net]
            self.ip = socket.inet_ntoa(f.read(4))

        self.port = int.from_bytes(f.read(2), "big")

    def serialize_v2(self) -> bytes:
        """Serialize in addrv2 format (BIP155)"""
        if self.net == self.NET_WSS:
            body = self.ip.encode("ascii") if isinstance(self.ip, str) else self.ip
            payload = bytes([self.wss_version]) + body
            return (
                self.time.to_bytes(4, "little")
                + ser_compact_size(self.nServices)
                + self.net.to_bytes(1, "little")
                + ser_compact_size(len(payload))
                + payload
                + self.port.to_bytes(2, "big")
            )
        assert self.net == self.NET_IPV4
        return (
            self.time.to_bytes(4, "little")
            + ser_compact_size(self.nServices)
            + self.net.to_bytes(1, "little")
            + ser_compact_size(self.ADDRV2_ADDRESS_LENGTH[self.net])
            + socket.inet_aton(self.ip)
            + self.port.to_bytes(2, "big")
        )

    def __repr__(self):
        return (
            f"CAddress(nServices={self.nServices} net={self.ADDRV2_NET_NAME[self.net]} "
            f"addr={self.ip} port={self.port})"
        )


class CInv:
    __slots__ = ("hash", "type")

    typemap = {
        MSG_UNDEFINED: "Error",
        MSG_TX: "TX",
        MSG_BLOCK: "Block",
        MSG_FILTERED_BLOCK: "filtered Block",
        MSG_CMPCT_BLOCK: "CompactBlock",
        MSG_AVA_PROOF: "avalanche proof",
        MSG_AVA_STAKE_CONTENDER: "avalanche stake contender",
        MSG_AVA_TREASURY_CONTENDER: "avalanche treasury contender",
        MSG_AVA_MEMPOOL_BATCH: "avalanche mempool batch",
    }

    def __init__(self, t=0, h=0):
        self.type = t
        self.hash = h

    def deserialize(self, f):
        self.type = int.from_bytes(f.read(4), "little", signed=True)
        self.hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.type.to_bytes(4, "little", signed=True) + ser_uint256(self.hash)

    def __repr__(self):
        return f"CInv(type={self.typemap[self.type]} hash={uint256_hex(self.hash)})"

    def __eq__(self, other):
        return (
            isinstance(other, CInv)
            and self.hash == other.hash
            and self.type == other.type
        )


class CBlockLocator:
    __slots__ = ("nVersion", "vHave")

    def __init__(self):
        self.vHave = []

    def deserialize(self, f):
        # Ignore version field.
        int.from_bytes(f.read(4), "little", signed=True)
        self.vHave = deser_uint256_vector(f)

    def serialize(self) -> bytes:
        # Bitcoin ABC ignores version field. Set it to 0.
        return (0).to_bytes(4, "little", signed=True) + ser_uint256_vector(self.vHave)

    def __repr__(self):
        return f"CBlockLocator(vHave={self.vHave!r})"


class COutPoint:
    __slots__ = ("txid", "n")

    def __init__(self, txid=0, n=0):
        self.txid = txid
        self.n = n

    def deserialize(self, f):
        self.txid = deser_uint256(f)
        self.n = int.from_bytes(f.read(4), "little")

    def serialize(self) -> bytes:
        return ser_uint256(self.txid) + self.n.to_bytes(4, "little")

    def __repr__(self):
        return f"COutPoint(txid={uint256_hex(self.txid)} n={self.n})"


class CTxIn:
    __slots__ = (
        "nSequence",
        "prevout",
        "scriptSig",
        "nFlags",
        "nPathIndex",
        "vWitnesses",
        "fHasCoinbaseData",
        "vCoinbaseData",
    )

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = int.from_bytes(f.read(4), "little")

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + ser_string(self.scriptSig)
            + self.nSequence.to_bytes(4, "little")
        )

    def __repr__(self):
        return (
            f"CTxIn(prevout={self.prevout!r} scriptSig={self.scriptSig.hex()} "
            f"nSequence={self.nSequence})"
        )


class CTxOut:
    __slots__ = ("nValue", "scriptPubKey", "nFlags", "tokenId", "vBranches", "vPaths")

    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = int.from_bytes(f.read(8), "little", signed=True)
        self.scriptPubKey = deser_string(f)

    def serialize(self) -> bytes:
        return self.nValue.to_bytes(8, "little", signed=True) + ser_string(
            self.scriptPubKey
        )

    def __repr__(self):
        return (
            f"CTxOut(nValue={self.nValue // XEC}.{self.nValue % XEC:02d} "
            f"scriptPubKey={self.scriptPubKey.hex()})"
        )


class CTransaction:
    __slots__ = (
        "nLockTime",
        "nVersion",
        "vin",
        "vout",
        "fHasV2Lock",
        "nV2Lock",
        "_height",
    )

    def __init__(self, tx=None):
        if tx is None:
            self.nVersion = 1
            self.vin = []
            self.vout = []
            self.nLockTime = 0
            self.fHasV2Lock = False
            self.nV2Lock = 0
            self._height = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.fHasV2Lock = getattr(tx, "fHasV2Lock", False)
            self.nV2Lock = getattr(tx, "nV2Lock", 0)
            self._height = getattr(tx, "_height", None)

    def deserialize(self, f):
        raw_version = int.from_bytes(f.read(4), "little")
        self.fHasV2Lock = False
        self.nV2Lock = 0
        if raw_version == 7:
            self.nVersion = 7
            self.fHasV2Lock = True
            self.nV2Lock = int.from_bytes(f.read(8), "little")
            self.nLockTime = (self.nV2Lock >> 8) & 0xFFFFFFFF
            in_count = int.from_bytes(f.read(2), "little")
            out_count = int.from_bytes(f.read(2), "little")
            self.vin = []
            for _ in range(in_count):
                txin = CTxIn()
                txin.prevout = COutPoint(
                    deser_uint256(f), int.from_bytes(f.read(4), "little")
                )
                txin.nSequence = int.from_bytes(f.read(4), "little")
                flags = int.from_bytes(f.read(1), "little")
                txin.nFlags = flags
                if flags == 1:
                    txin.nPathIndex = deser_compact_size(f)
                    wcount = deser_compact_size(f)
                    wits = []
                    for _ in range(wcount):
                        wscript = deser_string(f)
                        scount = deser_compact_size(f)
                        sibs = [f.read(32) for _ in range(scount)]
                        acount = deser_compact_size(f)
                        args = [deser_string(f) for _ in range(acount)]
                        wits.append((wscript, sibs, args))
                    txin.vWitnesses = wits
                    txin.scriptSig = wits[0][0] if wits else b""
                elif flags == 2:
                    has_cb = deser_compact_size(f)
                    cb_data = deser_string(f) if has_cb else b""
                    txin.fHasCoinbaseData = bool(has_cb)
                    txin.vCoinbaseData = cb_data
                    txin.scriptSig = cb_data
                    if txin.prevout.txid == 0 and txin.prevout.n == 0:
                        txin.prevout.n = 0xFFFFFFFF
                elif flags == 3:
                    wscript = deser_string(f)
                    scount = deser_compact_size(f)
                    sibs = [f.read(32) for _ in range(scount)]
                    acount = deser_compact_size(f)
                    args = [deser_string(f) for _ in range(acount)]
                    txin.vWitnesses = [(wscript, sibs, args)]
                    txin.scriptSig = wscript
                self.vin.append(txin)
            self.vout = []
            for _ in range(out_count):
                txout = CTxOut()
                oflags = int.from_bytes(f.read(1), "little")
                txout.nFlags = oflags
                txout.nValue = int.from_bytes(f.read(8), "little", signed=True)
                txout.tokenId = f.read(32) if (oflags & 1) else (b"\x00" * 32)
                bcount = deser_compact_size(f)
                txout.vBranches = [f.read(32) for _ in range(bcount)]
                pcount = deser_compact_size(f)
                paths = []
                for _ in range(pcount):
                    plen = deser_compact_size(f)
                    paths.append([deser_compact_size(f) for _ in range(plen)])
                txout.vPaths = paths
                txout.scriptPubKey = _lotus_v2_encode_output(
                    (oflags, txout.nValue, txout.tokenId, txout.vBranches, txout.vPaths)
                )
                self.vout.append(txout)
            return
        # Legacy grammar (version 1 or 2; the node refuses other versions).
        self.nVersion = raw_version
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = int.from_bytes(f.read(4), "little")

    def billable_size(self):
        """
        Returns the size used for billing the against the transaction
        """
        return len(self.serialize())

    def serialize(self) -> bytes:
        nver = self.nVersion & 0xFFFFFFFF
        if nver == 7:
            is_cb = len(self.vin) == 1 and (
                (self.vin[0].prevout.txid == 0 and self.vin[0].prevout.n == 0xFFFFFFFF)
                or getattr(self.vin[0], "nFlags", 0) == 2
            )
            if getattr(self, "fHasV2Lock", False):
                lock = self.nV2Lock
            elif is_cb or self.nLockTime == 0:
                lock = 0
            else:
                lock = (int(self.nLockTime) << 8) | (
                    1 if self.nLockTime < 500000000 else 2
                )
            res = bytearray()
            res += (7).to_bytes(4, "little")
            res += lock.to_bytes(8, "little")
            res += len(self.vin).to_bytes(2, "little")
            res += len(self.vout).to_bytes(2, "little")
            for txin in self.vin:
                flags = getattr(txin, "nFlags", 1)
                prev_n = (
                    0
                    if (
                        flags == 2
                        and txin.prevout.txid == 0
                        and txin.prevout.n == 0xFFFFFFFF
                    )
                    else (txin.prevout.n & 0xFFFFFFFF)
                )
                seq = 0xFFFFFFFF if flags == 2 else (txin.nSequence & 0xFFFFFFFF)
                res += ser_uint256(txin.prevout.txid)
                res += prev_n.to_bytes(4, "little")
                res += seq.to_bytes(4, "little")
                res.append(flags)
                if flags == 1:
                    res += ser_compact_size(getattr(txin, "nPathIndex", 0))
                    wits = getattr(
                        txin, "vWitnesses", [(bytes(txin.scriptSig) or b"\x4e", [], [])]
                    )
                    res += ser_compact_size(len(wits))
                    for script, sibs, args in wits:
                        res += ser_string(script)
                        res += ser_compact_size(len(sibs)) + b"".join(sibs)
                        res += ser_compact_size(len(args)) + b"".join(
                            ser_string(a) for a in args
                        )
                elif flags == 2:
                    cb_data = getattr(txin, "vCoinbaseData", bytes(txin.scriptSig))
                    has_cb = getattr(txin, "fHasCoinbaseData", len(cb_data) > 0)
                    res += ser_compact_size(1 if has_cb else 0)
                    if has_cb:
                        res += ser_string(cb_data)
                elif flags == 3:
                    wits = getattr(
                        txin, "vWitnesses", [(bytes(txin.scriptSig), [], [])]
                    )
                    script, sibs, args = wits[0]
                    res += ser_string(script)
                    res += ser_compact_size(len(sibs)) + b"".join(sibs)
                    res += ser_compact_size(len(args)) + b"".join(
                        ser_string(a) for a in args
                    )
            for txout in self.vout:
                res += _lotus_v2_encode_output(_lotus_v2_to_output(txout))
            return bytes(res)

        # Legacy grammar, as in eCash.
        return (
            nver.to_bytes(4, "little")
            + ser_vector(self.vin)
            + ser_vector(self.vout)
            + (self.nLockTime & 0xFFFFFFFF).to_bytes(4, "little")
        )

    @property
    def txid_hex(self) -> str:
        """Return txid as hex string."""
        txid_b, _ = lotus_v2_compute_tx_identities(self)
        return txid_b[::-1].hex()

    @property
    def txid_int(self) -> int:
        """Return txid as integer."""
        txid_b, _ = lotus_v2_compute_tx_identities(self)
        return uint256_from_str(txid_b)

    @property
    def txhash_hex(self) -> str:
        """Return txhash as hex string."""
        _, txhash_b = lotus_v2_compute_tx_identities(self)
        return txhash_b[::-1].hex()

    @property
    def txhash_int(self) -> int:
        """Return txhash as integer."""
        _, txhash_b = lotus_v2_compute_tx_identities(self)
        return uint256_from_str(txhash_b)

    def calc_sha256(self) -> int:
        return self.txid_int

    def is_valid(self):
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > MAX_MONEY:
                return False
        return True

    def __repr__(self):
        return (
            f"CTransaction(nVersion={self.nVersion} vin={self.vin!r} "
            f"vout={self.vout!r} nLockTime={self.nLockTime})"
        )


_BLAKE3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_BLAKE3_MSG_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _blake3_g(state: list, a: int, b: int, c: int, d: int, mx: int, my: int):
    state[a] = (state[a] + state[b] + mx) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 7)


def _blake3_compress(
    cv: list, block_words: list, counter: int, block_len: int, flags: int
) -> list:
    state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        _BLAKE3_IV[0],
        _BLAKE3_IV[1],
        _BLAKE3_IV[2],
        _BLAKE3_IV[3],
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len,
        flags,
    ]
    m = list(block_words)
    for r in range(7):
        _blake3_g(state, 0, 4, 8, 12, m[0], m[1])
        _blake3_g(state, 1, 5, 9, 13, m[2], m[3])
        _blake3_g(state, 2, 6, 10, 14, m[4], m[5])
        _blake3_g(state, 3, 7, 11, 15, m[6], m[7])
        _blake3_g(state, 0, 5, 10, 15, m[8], m[9])
        _blake3_g(state, 1, 6, 11, 12, m[10], m[11])
        _blake3_g(state, 2, 7, 8, 13, m[12], m[13])
        _blake3_g(state, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _BLAKE3_MSG_PERM]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state[:8]


def blake3_single_chunk(data: bytes) -> bytes:
    num_chunks = max(1, (len(data) + 1023) // 1024)
    cvs = []
    for c in range(num_chunks):
        chunk = data[c * 1024 : (c + 1) * 1024]
        cv = list(_BLAKE3_IV)
        num_blocks = max(1, (len(chunk) + 63) // 64)
        for b in range(num_blocks):
            blk = chunk[b * 64 : (b + 1) * 64]
            blk_len = len(blk)
            padded = blk + b"\x00" * (64 - blk_len)
            words = [
                int.from_bytes(padded[i * 4 : (i + 1) * 4], "little") for i in range(16)
            ]
            flags = (1 if b == 0 else 0) | (2 if b == num_blocks - 1 else 0)
            if num_chunks == 1 and b == num_blocks - 1:
                flags |= 8
            cv = _blake3_compress(cv, words, c, blk_len, flags)
        cvs.append(cv)
        total = c + 1
        while (
            (total & 1) == 0 and len(cvs) >= 2 and (total < num_chunks or len(cvs) > 2)
        ):
            right = cvs.pop()
            left = cvs.pop()
            cvs.append(_blake3_compress(list(_BLAKE3_IV), left + right, 0, 64, 4))
            total >>= 1
    while len(cvs) > 1:
        right = cvs.pop()
        left = cvs.pop()
        flags = 4 | (8 if len(cvs) == 0 else 0)
        cvs.append(_blake3_compress(list(_BLAKE3_IV), left + right, 0, 64, flags))
    return b"".join(w.to_bytes(4, "little") for w in cvs[0])


def lotus_v2_tagged_hash(tag: str, payload: bytes) -> bytes:
    return blake3_single_chunk(tag.encode("ascii") + b"\x00" + payload)


_BRANCH_LEAF_CACHE = {}


def lotus_v2_branch_leaf(script: bytes) -> bytes:
    cached = _BRANCH_LEAF_CACHE.get(script)
    if cached is not None:
        return cached
    res = lotus_v2_tagged_hash(
        "Lotus/v2/branch", b"\x00" + ser_compact_size(len(script)) + script
    )
    if len(_BRANCH_LEAF_CACHE) > 512:
        _BRANCH_LEAF_CACHE.clear()
    _BRANCH_LEAF_CACHE[script] = res
    return res


def lotus_v2_indexed_tree_root(leaves: list) -> bytes:
    if not leaves:
        return lotus_v2_tagged_hash("Lotus/v2/merkleidx", b"\x02")
    if len(leaves) == 1:
        return leaves[0]
    cur = list(leaves)
    layer = 0
    while len(cur) > 1:
        if len(cur) & 1:
            cur.append(b"\x00" * 32)
        nxt = []
        for i in range(0, len(cur), 2):
            nxt.append(
                lotus_v2_tagged_hash(
                    "Lotus/v2/merkleidx",
                    b"\x01" + layer.to_bytes(2, "little") + cur[i] + cur[i + 1],
                )
            )
        cur = nxt
        layer += 1
    return cur[0]


def _lotus_v2_tx_leaf(pair: tuple) -> bytes:
    txid, txhash = pair
    return lotus_v2_tagged_hash("Lotus/v2/txroot", b"\x00" + txid + txhash)


def _lotus_v2_tx_subtree_a(pairs: list, depth: int = 0) -> bytes:
    if not pairs:
        return lotus_v2_tagged_hash("Lotus/v2/txroot", b"\x02")
    if len(pairs) == 1:
        return _lotus_v2_tx_leaf(pairs[0])
    left = [p for p in pairs if ((p[0][depth // 8] >> (depth % 8)) & 1) == 0]
    right = [p for p in pairs if ((p[0][depth // 8] >> (depth % 8)) & 1) == 1]
    return lotus_v2_tagged_hash(
        "Lotus/v2/txroot",
        b"\x01"
        + depth.to_bytes(2, "little")
        + _lotus_v2_tx_subtree_a(left, depth + 1)
        + _lotus_v2_tx_subtree_a(right, depth + 1),
    )


def lotus_v2_transaction_root(pairs: list) -> bytes:
    if not pairs:
        return lotus_v2_tagged_hash("Lotus/v2/txroot", b"\x02")
    txids = [p[0] for p in pairs]
    if len(set(txids)) != len(txids):
        return b"\x00" * 32
    coinbase_leaf = _lotus_v2_tx_leaf(pairs[0])
    sub_a = _lotus_v2_tx_subtree_a(pairs[1:], 0)
    return lotus_v2_tagged_hash("Lotus/v2/txroot", b"\x03" + coinbase_leaf + sub_a)


def _lotus_v2_decode_output_bytes(raw: bytes):
    try:
        if len(raw) > 2186 or len(raw) < 11:
            return None
        flags = raw[0]
        if flags & 0xFC:
            return None
        pos = 9
        if flags & 1:
            if pos + 32 > len(raw):
                return None
            token_id = raw[pos : pos + 32]
            if token_id == b"\x00" * 32:
                return None
            pos += 32
        else:
            token_id = b"\x00" * 32
        bio = BytesIO(raw[pos:])
        bcount = deser_compact_size(bio)
        if bcount == 0 or bcount > 16:
            return None
        branches = []
        for _ in range(bcount):
            b = bio.read(32)
            if len(b) != 32 or b in branches:
                return None
            branches.append(b)
        pcount = deser_compact_size(bio)
        if (flags & 2) != 0:
            if pcount != 0:
                return None
        elif pcount == 0 or pcount > 16:
            return None
        paths = []
        for _ in range(pcount):
            plen = deser_compact_size(bio)
            if plen == 0 or plen > bcount:
                return None
            path = []
            for _ in range(plen):
                idx = deser_compact_size(bio)
                if idx >= bcount or (path and path[-1] >= idx):
                    return None
                path.append(idx)
            if paths and not (paths[-1] < path):
                return None
            paths.append(path)
        if bio.read(1) != b"":
            return None
        return (flags, token_id, branches, paths)
    except Exception:
        return None


def _lotus_v2_to_output(txout) -> tuple:
    val = max(0, int(txout.nValue))
    branches = getattr(txout, "vBranches", None)
    if branches:
        flags = getattr(txout, "nFlags", 0)
        token_id = getattr(txout, "tokenId", b"\x00" * 32)
        paths = getattr(txout, "vPaths", [])
        return (flags, val, token_id, branches, paths)
    spk = bytes(txout.scriptPubKey)
    if len(spk) >= 43:
        dec = _lotus_v2_decode_output_bytes(spk)
        if dec is not None:
            return (dec[0], val, dec[1], dec[2], dec[3])
        if spk[0] == 0x6A and len(spk) >= 44:
            dec = _lotus_v2_decode_output_bytes(spk[1:])
            if dec is not None:
                return (dec[0], val, dec[1], dec[2], dec[3])
    bleaf = lotus_v2_branch_leaf(spk)
    if len(spk) > 0 and spk[0] == 0x6A:
        return (2, val, b"\x00" * 32, [bleaf], [])
    return (0, val, b"\x00" * 32, [bleaf], [[0]])


def _lotus_v2_encode_output(out_tuple: tuple) -> bytes:
    flags, val, token_id, branches, paths = out_tuple
    r = bytearray()
    r.append(flags)
    r += val.to_bytes(8, "little")
    if flags & 1:
        r += token_id
    r += ser_compact_size(len(branches))
    for b in branches:
        r += b
    r += ser_compact_size(len(paths))
    for p in paths:
        r += ser_compact_size(len(p))
        for idx in p:
            r += ser_compact_size(idx)
    return bytes(r)


def lotus_v2_compute_tx_identities(tx) -> tuple:
    # A legacy (version 1 or 2) transaction is named by the SHA256d of its
    # serialization, both TxId and TxHash, as in eCash.
    if (tx.nVersion & 0xFFFFFFFF) != 7:
        h = hash256(tx.serialize())
        return (h, h)
    is_cb = len(tx.vin) == 1 and (
        (tx.vin[0].prevout.txid == 0 and tx.vin[0].prevout.n == 0xFFFFFFFF)
        or getattr(tx.vin[0], "nFlags", 0) == 2
    )
    if getattr(tx, "fHasV2Lock", False):
        lock = tx.nV2Lock
    elif is_cb or tx.nLockTime == 0:
        lock = 0
    else:
        lock = (int(tx.nLockTime) << 8) | (1 if tx.nLockTime < 500000000 else 2)

    v2_inputs = []
    for txin in tx.vin:
        prev_txid = ser_uint256(txin.prevout.txid)
        prev_index = txin.prevout.n & 0xFFFFFFFF
        seq = txin.nSequence & 0xFFFFFFFF
        nflags = getattr(txin, "nFlags", 0)
        if nflags != 0:
            flags = nflags
            path_index = getattr(txin, "nPathIndex", 0)
            witnesses = list(getattr(txin, "vWitnesses", []))
            has_cb = getattr(txin, "fHasCoinbaseData", False)
            cb_data = bytes(getattr(txin, "vCoinbaseData", b""))
            if flags == 2:
                seq = 0xFFFFFFFF
                if not has_cb and len(txin.scriptSig) > 0:
                    has_cb = True
                    cb_data = bytes(txin.scriptSig)
            elif flags == 1 and not witnesses:
                s = bytes(txin.scriptSig)
                witnesses = [(s if s else b"\x4e", [], [])]
        elif prev_txid == b"\x00" * 32 and prev_index == 0xFFFFFFFF:
            flags = 2
            prev_index = 0
            seq = 0xFFFFFFFF
            path_index = 0
            witnesses = []
            s = bytes(txin.scriptSig)
            has_cb = len(s) > 0
            cb_data = s
        else:
            flags = 1
            path_index = 0
            if seq != 0xFFFFFFFF and (seq & ~0x40FFFF):
                seq = 0xFFFFFFFF
            s = bytes(txin.scriptSig)
            witnesses = [(s if s else b"\x4e", [], [])]
            has_cb = False
            cb_data = b""
        v2_inputs.append(
            (prev_txid, prev_index, seq, flags, path_index, witnesses, has_cb, cb_data)
        )

    v2_outputs = [_lotus_v2_to_output(txout) for txout in tx.vout]

    valid_v2 = True
    if not v2_inputs or len(v2_inputs) > 65535 or len(v2_outputs) > 65535:
        valid_v2 = False
    if (lock & 0xFF) > 2 or ((lock & 0xFF) == 0 and lock != 0):
        valid_v2 = False
    seen_outpoints = set()
    has_spend = False
    has_coinbase = False
    mint_count = 0
    for (
        prev_txid,
        prev_index,
        seq,
        flags,
        path_index,
        witnesses,
        has_cb,
        cb_data,
    ) in v2_inputs:
        if (prev_txid, prev_index) in seen_outpoints:
            valid_v2 = False
            break
        seen_outpoints.add((prev_txid, prev_index))
        if flags == 1:
            has_spend = True
            if has_cb or cb_data or path_index >= 16 or not (1 <= len(witnesses) <= 16):
                valid_v2 = False
            if seq != 0xFFFFFFFF and (seq & ~0x40FFFF):
                valid_v2 = False
            for script, siblings, args in witnesses:
                if len(script) > 10000 or len(siblings) > 64 or len(args) > 65535:
                    valid_v2 = False
                for a in args:
                    if len(a) > 8192:
                        valid_v2 = False
        elif flags == 2:
            has_coinbase = True
            if seq != 0xFFFFFFFF or path_index != 0 or witnesses:
                valid_v2 = False
            if has_cb and not (1 <= len(cb_data) <= 8192):
                valid_v2 = False
            if not has_cb and cb_data:
                valid_v2 = False
        elif flags == 3:
            mint_count += 1
            if (
                has_cb
                or cb_data
                or prev_txid == b"\x00" * 32
                or prev_index != 0
                or seq != 0xFFFFFFFF
                or path_index != 0
                or len(witnesses) != 1
            ):
                valid_v2 = False
        else:
            valid_v2 = False
    if has_coinbase:
        if (
            len(v2_inputs) != 1
            or v2_inputs[0][3] != 2
            or lock != 0
            or not v2_outputs
            or any(o[0] & 1 for o in v2_outputs)
        ):
            valid_v2 = False
    elif not has_spend or mint_count > 65535:
        valid_v2 = False

    for o in v2_outputs:
        ow = _lotus_v2_encode_output(o)
        if len(ow) > 2186 or _lotus_v2_decode_output_bytes(ow) is None:
            valid_v2 = False

    if valid_v2:
        core_leaves = []
        full_leaves = []
        for (
            prev_txid,
            prev_index,
            seq,
            flags,
            path_index,
            witnesses,
            has_cb,
            cb_data,
        ) in v2_inputs:
            prefix = (
                prev_txid
                + prev_index.to_bytes(4, "little")
                + seq.to_bytes(4, "little")
                + bytes([flags])
            )
            if flags == 1:
                c_buf = bytearray(
                    prefix
                    + ser_compact_size(path_index)
                    + ser_compact_size(len(witnesses))
                )
                f_buf = bytearray(
                    prefix
                    + ser_compact_size(path_index)
                    + ser_compact_size(len(witnesses))
                )
                for script, siblings, args in witnesses:
                    w_base = (
                        ser_string(script)
                        + ser_compact_size(len(siblings))
                        + b"".join(siblings)
                    )
                    c_buf += w_base
                    f_buf += (
                        w_base
                        + ser_compact_size(len(args))
                        + b"".join(ser_string(a) for a in args)
                    )
                core_wire = bytes(c_buf)
                full_wire = bytes(f_buf)
            elif flags == 2:
                cb_part = ser_compact_size(1 if has_cb else 0) + (
                    ser_string(cb_data) if has_cb else b""
                )
                core_wire = prefix + cb_part
                full_wire = core_wire
            else:
                script, siblings, args = witnesses[0]
                w_base = (
                    ser_string(script)
                    + ser_compact_size(len(siblings))
                    + b"".join(siblings)
                )
                core_wire = prefix + w_base
                full_wire = (
                    prefix
                    + w_base
                    + ser_compact_size(len(args))
                    + b"".join(ser_string(a) for a in args)
                )
            core_leaves.append(lotus_v2_tagged_hash("Lotus/v2/inputcore", core_wire))
            full_leaves.append(lotus_v2_tagged_hash("Lotus/v2/inputfull", full_wire))
        out_leaves = []
        for o in v2_outputs:
            ow = _lotus_v2_encode_output(o)
            out_leaves.append(
                lotus_v2_tagged_hash("Lotus/v2/output", ser_compact_size(len(ow)) + ow)
            )
        in_root = lotus_v2_indexed_tree_root(core_leaves)
        full_in_root = lotus_v2_indexed_tree_root(full_leaves)
        out_root = lotus_v2_indexed_tree_root(out_leaves)
        hdr_core = (
            (7).to_bytes(4, "little")
            + lock.to_bytes(8, "little")
            + len(v2_inputs).to_bytes(2, "little")
            + len(v2_outputs).to_bytes(2, "little")
        )
        txid_b = bytearray(
            lotus_v2_tagged_hash(
                "Lotus/v2/txid", b"\x00" * 32 + hdr_core + in_root + out_root
            )
        )
        txhash_b = bytearray(
            lotus_v2_tagged_hash(
                "Lotus/v2/txhash", b"\x00" * 32 + hdr_core + full_in_root + out_root
            )
        )
        return (bytes(txid_b), bytes(txhash_b))

    # Not a well-formed V2 structure. The node refuses such a transaction (it
    # does not decode), so this name exists only on the Python side, for tests
    # that build one to send.
    fallback = lotus_v2_tagged_hash(
        "Lotus/v2/txid/nonstructural", b"\x00" * 32 + tx.serialize()
    )
    return (fallback, fallback)


# The block id commits to the network's chain id (raw bytes, as in
# chainparams). Regtest uses all zeros, which the framework assumes.
V2_REGTEST_CHAIN_ID = b"\x00" * 32
V2_TESTNET_CHAIN_ID = bytes.fromhex(
    "5f5e904cc5dfab62a8b62ee22551bca02e47a6d92d0de1f73c150e906bc3851b"
)


class CBlockHeader:
    __slots__ = (
        "hashPrevBlock",
        "nBits",
        "nTime",
        "nNonce",
        "nHeaderVersion",
        "nSize",
        "nHeight",
        "hashMerkleRoot",
        "hashStateRoot",
        "_auto_size",
    )

    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.hashPrevBlock = header.hashPrevBlock
            self.nBits = header.nBits
            self.nTime = header.nTime
            self.nNonce = header.nNonce
            self.nHeaderVersion = header.nHeaderVersion
            self.nSize = header.nSize
            self.nHeight = header.nHeight
            self.hashMerkleRoot = header.hashMerkleRoot
            self.hashStateRoot = header.hashStateRoot
            self._auto_size = getattr(header, "_auto_size", self.nSize)

    @property
    def nVersion(self) -> int:
        return self.nHeaderVersion

    @nVersion.setter
    def nVersion(self, val: int):
        self.nHeaderVersion = val

    def GetBlockTime(self) -> int:
        return self.nTime

    def SetBlockTime(self, val: int):
        self.nTime = int(val)

    def set_null(self):
        self.hashPrevBlock = 0
        self.nBits = 0
        self.nTime = 0
        self.nNonce = 0
        self.nHeaderVersion = 2
        self.nSize = 0
        self.nHeight = 0
        self.hashMerkleRoot = 0
        self.hashStateRoot = 0
        self._auto_size = 0

    def deserialize(self, f):
        self.hashPrevBlock = deser_uint256(f)
        self.nBits = int.from_bytes(f.read(4), "little")
        self.nTime = int.from_bytes(f.read(6), "little")
        self.nNonce = int.from_bytes(f.read(8), "little")
        self.nHeaderVersion = int.from_bytes(f.read(4), "little")
        self.nSize = int.from_bytes(f.read(8), "little")
        self.nHeight = int.from_bytes(f.read(8), "little")
        self.hashMerkleRoot = deser_uint256(f)
        self.hashStateRoot = deser_uint256(f)
        self._auto_size = self.nSize

    def serialize(self) -> bytes:
        return self._serialize_header()

    def _serialize_header(self) -> bytes:
        return (
            ser_uint256(self.hashPrevBlock)
            + (self.nBits & 0xFFFFFFFF).to_bytes(4, "little")
            + (self.nTime & 0xFFFFFFFFFFFF).to_bytes(6, "little")
            + (self.nNonce & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + (self.nHeaderVersion & 0xFFFFFFFF).to_bytes(4, "little")
            + (self.nSize & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + (self.nHeight & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            + ser_uint256(self.hashMerkleRoot)
            + ser_uint256(self.hashStateRoot)
        )

    def _hash_bytes(self, chain_id: bytes = V2_REGTEST_CHAIN_ID) -> bytes:
        hdr = self._serialize_header()
        body_hash = lotus_v2_tagged_hash("Lotus/v2/header/body", chain_id + hdr[50:134])
        work_hash = lotus_v2_tagged_hash("Lotus/v2/header/work", hdr[32:50] + body_hash)
        return lotus_v2_tagged_hash("Lotus/v2/blockid", hdr[0:32] + work_hash)

    @property
    def hash_hex(self) -> str:
        """Return block header hash as hex string."""
        return self._hash_bytes()[::-1].hex()

    def hash_hex_for_chain(self, chain_id: bytes) -> str:
        """Return the header hash as hex on the network with this chain id."""
        return self._hash_bytes(chain_id)[::-1].hex()

    @property
    def hash_int(self) -> int:
        """Return block header hash as integer."""
        return uint256_from_str(self._hash_bytes())

    @property
    def sha256(self) -> int:
        return self.hash_int

    @property
    def hash(self) -> str:
        return self.hash_hex

    def calc_sha256(self) -> int:
        return self.hash_int

    def __repr__(self):
        return (
            f"CBlockHeader(nHeaderVersion={self.nHeaderVersion} "
            f"hashPrevBlock={uint256_hex(self.hashPrevBlock)} "
            f"hashMerkleRoot={uint256_hex(self.hashMerkleRoot)} "
            f"hashStateRoot={uint256_hex(self.hashStateRoot)} "
            f"nTime={self.nTime} nBits={self.nBits:08x} "
            f"nNonce={self.nNonce:016x} nSize={self.nSize} nHeight={self.nHeight})"
        )


BLOCK_HEADER_SIZE = len(CBlockHeader().serialize())
assert_equal(BLOCK_HEADER_SIZE, 134)


class CBlock(CBlockHeader):
    __slots__ = ("vtx",)

    def __init__(self, header=None):
        super().__init__(header)
        self.vtx: List[CTransaction] = []

    def deserialize(self, f):
        super().deserialize(f)
        self.vtx = deser_vector(f, CTransaction)
        self._auto_size = self.nSize

    def serialize(self) -> bytes:
        return super().serialize() + ser_vector(self.vtx)

    def update_size(self):
        self.nSize = len(self.serialize())
        self._auto_size = self.nSize

    # Calculate the merkle root given a vector of transaction hashes
    def get_merkle_root(self, hashes):
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i + 1, len(hashes) - 1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        return uint256_from_str(hashes[0])

    def calc_merkle_root(self):
        if not self.vtx:
            return 0
        pairs = [lotus_v2_compute_tx_identities(tx) for tx in self.vtx]
        return uint256_from_str(lotus_v2_transaction_root(pairs))

    def is_valid(self):
        target = uint256_from_compact(self.nBits)
        if self.hash_int > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):
        if (
            self.nHeight == 0
            and self.vtx
            and getattr(self.vtx[0], "_height", None) is not None
        ):
            self.nHeight = self.vtx[0]._height
        if self.nSize == getattr(self, "_auto_size", 0):
            self.update_size()
        target = uint256_from_compact(self.nBits)
        while self.hash_int > target:
            self.nNonce += 1

    def __repr__(self):
        return (
            f"CBlock(nHeaderVersion={self.nHeaderVersion} "
            f"hashPrevBlock={uint256_hex(self.hashPrevBlock)} "
            f"hashMerkleRoot={uint256_hex(self.hashMerkleRoot)} "
            f"hashStateRoot={uint256_hex(self.hashStateRoot)} "
            f"nTime={self.nTime} nBits={self.nBits:08x} "
            f"nNonce={self.nNonce:016x} nSize={self.nSize} nHeight={self.nHeight} vtx={self.vtx!r})"
        )


class PrefilledTransaction:
    __slots__ = ("index", "tx")

    def __init__(self, index=0, tx=None):
        self.index = index
        self.tx = tx

    def deserialize(self, f):
        self.index = deser_compact_size(f)
        self.tx = CTransaction()
        self.tx.deserialize(f)

    def serialize(self) -> bytes:
        return ser_compact_size(self.index) + self.tx.serialize()

    def __repr__(self):
        return f"PrefilledTransaction(index={self.index}, tx={self.tx!r})"


# This is what we send on the wire, in a cmpctblock message.
class P2PHeaderAndShortIDs:
    __slots__ = (
        "header",
        "nonce",
        "prefilled_txn",
        "prefilled_txn_length",
        "shortids",
        "shortids_length",
    )

    def __init__(self):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids_length = 0
        self.shortids = []
        self.prefilled_txn_length = 0
        self.prefilled_txn = []

    def deserialize(self, f):
        self.header.deserialize(f)
        self.nonce = int.from_bytes(f.read(8), "little")
        self.shortids_length = deser_compact_size(f)
        for _ in range(self.shortids_length):
            # shortids are defined to be 6 bytes in the spec, so append
            # two zero bytes and read it in as an 8-byte number
            self.shortids.append(int.from_bytes(f.read(6) + b"\x00\x00", "little"))
        self.prefilled_txn = deser_vector(f, PrefilledTransaction)
        self.prefilled_txn_length = len(self.prefilled_txn)

    def serialize(self) -> bytes:
        return (
            self.header.serialize()
            + self.nonce.to_bytes(8, "little")
            + ser_compact_size(self.shortids_length)
            # We only want the first 6 bytes
            + b"".join(x.to_bytes(8, "little")[0:6] for x in self.shortids)
            + ser_vector(self.prefilled_txn)
        )

    def __repr__(self):
        return (
            f"P2PHeaderAndShortIDs(header={self.header!r}, nonce={self.nonce}, "
            f"shortids_length={self.shortids_length}, shortids={self.shortids!r}, "
            f"prefilled_txn_length={self.prefilled_txn_length}, "
            f"prefilledtxn={self.prefilled_txn!r}"
        )


def calculate_shortid(k0, k1, tx_hash):
    """Calculate the BIP 152-compact blocks shortid for a given
    transaction hash"""
    expected_shortid = siphash256(k0, k1, tx_hash)
    expected_shortid &= 0x0000FFFFFFFFFFFF
    return expected_shortid


# This version gets rid of the array lengths, and reinterprets the differential
# encoding into indices that can be used for lookup.
class HeaderAndShortIDs:
    __slots__ = ("header", "nonce", "prefilled_txn", "shortids")

    def __init__(self, p2pheaders_and_shortids=None):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids = []
        self.prefilled_txn = []

        if p2pheaders_and_shortids is not None:
            self.header = p2pheaders_and_shortids.header
            self.nonce = p2pheaders_and_shortids.nonce
            self.shortids = p2pheaders_and_shortids.shortids
            last_index = -1
            for x in p2pheaders_and_shortids.prefilled_txn:
                self.prefilled_txn.append(
                    PrefilledTransaction(x.index + last_index + 1, x.tx)
                )
                last_index = self.prefilled_txn[-1].index

    def to_p2p(self):
        ret = P2PHeaderAndShortIDs()
        ret.header = self.header
        ret.nonce = self.nonce
        ret.shortids_length = len(self.shortids)
        ret.shortids = self.shortids
        ret.prefilled_txn_length = len(self.prefilled_txn)
        ret.prefilled_txn = []
        last_index = -1
        for x in self.prefilled_txn:
            ret.prefilled_txn.append(
                PrefilledTransaction(x.index - last_index - 1, x.tx)
            )
            last_index = x.index
        return ret

    def get_siphash_keys(self):
        header_nonce = self.header.serialize()
        header_nonce += self.nonce.to_bytes(8, "little")
        hash_header_nonce_as_str = sha256(header_nonce)
        key0 = int.from_bytes(hash_header_nonce_as_str[0:8], "little")
        key1 = int.from_bytes(hash_header_nonce_as_str[8:16], "little")
        return [key0, key1]

    def initialize_from_block(self, block, nonce=0, prefill_list=None):
        if prefill_list is None:
            prefill_list = [0]
        self.header = CBlockHeader(block)
        self.nonce = nonce
        self.prefilled_txn = [
            PrefilledTransaction(i, block.vtx[i]) for i in prefill_list
        ]
        self.shortids = []
        [k0, k1] = self.get_siphash_keys()
        for i in range(len(block.vtx)):
            if i not in prefill_list:
                tx_hash = block.vtx[i].txhash_int
                self.shortids.append(calculate_shortid(k0, k1, tx_hash))

    def __repr__(self):
        return (
            f"HeaderAndShortIDs(header={self.header!r}, nonce={self.nonce}, "
            f"shortids={self.shortids!r}, prefilledtxn={self.prefilled_txn!r}"
        )


class BlockTransactionsRequest:
    __slots__ = ("blockhash", "indexes")

    def __init__(self, blockhash=0, indexes=None):
        self.blockhash = blockhash
        self.indexes = indexes if indexes is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        indexes_length = deser_compact_size(f)
        for _ in range(indexes_length):
            self.indexes.append(deser_compact_size(f))

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.blockhash)
            + ser_compact_size(len(self.indexes))
            + b"".join(ser_compact_size(x) for x in self.indexes)
        )

    # helper to set the differentially encoded indexes from absolute ones
    def from_absolute(self, absolute_indexes):
        self.indexes = []
        last_index = -1
        for x in absolute_indexes:
            self.indexes.append(x - last_index - 1)
            last_index = x

    def to_absolute(self):
        absolute_indexes = []
        last_index = -1
        for x in self.indexes:
            absolute_indexes.append(x + last_index + 1)
            last_index = absolute_indexes[-1]
        return absolute_indexes

    def __repr__(self):
        return (
            f"BlockTransactionsRequest(hash={uint256_hex(self.blockhash)} "
            f"indexes={self.indexes!r})"
        )


class BlockTransactions:
    __slots__ = ("blockhash", "transactions")

    def __init__(self, blockhash=0, transactions=None):
        self.blockhash = blockhash
        self.transactions = transactions if transactions is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        self.transactions = deser_vector(f, CTransaction)

    def serialize(self) -> bytes:
        return ser_uint256(self.blockhash) + ser_vector(self.transactions)

    def __repr__(self):
        return (
            f"BlockTransactions(hash={uint256_hex(self.blockhash)} "
            f"transactions={self.transactions!r})"
        )


class AvalancheStake:
    __slots__ = ("utxo", "amount", "height", "pubkey", "is_coinbase")

    def __init__(self, utxo=None, amount=0, height=0, pubkey=b"", is_coinbase=False):
        self.utxo: COutPoint = utxo or COutPoint()
        self.amount: int = amount
        """Amount in satoshis (int64)"""
        self.height: int = height
        """Block height containing this utxo (uint32)"""
        self.pubkey: bytes = pubkey
        """Public key"""

        self.is_coinbase: bool = is_coinbase

    def deserialize(self, f):
        self.utxo = COutPoint()
        self.utxo.deserialize(f)
        self.amount = int.from_bytes(f.read(8), "little", signed=True)
        height_ser = int.from_bytes(f.read(4), "little")
        self.is_coinbase = bool(height_ser & 1)
        self.height = height_ser >> 1
        self.pubkey = deser_string(f)

    def serialize(self) -> bytes:
        height_ser = self.height << 1 | int(self.is_coinbase)
        return (
            self.utxo.serialize()
            + self.amount.to_bytes(8, "little", signed=True)
            + height_ser.to_bytes(4, "little")
            + ser_compact_size(len(self.pubkey))
            + self.pubkey
        )

    def __repr__(self):
        return (
            f"AvalancheStake(utxo={self.utxo}, amount={self.amount},"
            f" height={self.height}, "
            f"pubkey={self.pubkey.hex()})"
        )


class AvalancheSignedStake:
    __slots__ = ("stake", "sig")

    def __init__(self, stake=None, sig=b""):
        self.stake: AvalancheStake = stake or AvalancheStake()
        self.sig: bytes = sig
        """Signature for this stake, bytes of length 64"""

    def deserialize(self, f):
        self.stake = AvalancheStake()
        self.stake.deserialize(f)
        self.sig = f.read(64)

    def serialize(self) -> bytes:
        return self.stake.serialize() + self.sig


class AvalancheProof:
    __slots__ = (
        "sequence",
        "expiration",
        "master",
        "stakes",
        "payout_script",
        "signature",
        "limited_proofid",
        "proofid",
    )

    def __init__(
        self,
        sequence=0,
        expiration=0,
        master=b"",
        signed_stakes=None,
        payout_script=b"",
        signature=b"",
    ):
        self.sequence: int = sequence
        self.expiration: int = expiration
        self.master: bytes = master

        self.stakes: List[AvalancheSignedStake] = signed_stakes or [
            AvalancheSignedStake()
        ]

        self.payout_script = payout_script
        self.signature = signature

        self.limited_proofid: int = None
        self.proofid: int = None
        self.compute_proof_id()

    def compute_proof_id(self):
        """Compute Bitcoin's 256-bit hash (double SHA-256) of the
        serialized proof data.
        """
        ss = self.sequence.to_bytes(8, "little")
        ss += self.expiration.to_bytes(8, "little", signed=True)
        ss += ser_string(self.payout_script)
        ss += ser_compact_size(len(self.stakes))
        # Use unsigned stakes
        for s in self.stakes:
            ss += s.stake.serialize()
        h = hash256(ss)
        self.limited_proofid = uint256_from_str(h)
        h += ser_string(self.master)
        h = hash256(h)
        # make it an int, for comparing with Delegation.proofid
        self.proofid = uint256_from_str(h)

    def get_score(self):
        return sum([stake.stake.amount for stake in self.stakes]) // 1000000

    def deserialize(self, f):
        self.sequence = int.from_bytes(f.read(8), "little")
        self.expiration = int.from_bytes(f.read(8), "little", signed=True)
        self.master = deser_string(f)
        self.stakes = deser_vector(f, AvalancheSignedStake)
        self.payout_script = deser_string(f)
        self.signature = f.read(64)
        self.compute_proof_id()

    def serialize(self) -> bytes:
        return (
            self.sequence.to_bytes(8, "little")
            + self.expiration.to_bytes(8, "little", signed=True)
            + ser_string(self.master)
            + ser_vector(self.stakes)
            + ser_string(self.payout_script)
            + self.signature
        )

    def __repr__(self):
        return (
            f"AvalancheProof(proofid={uint256_hex(self.proofid)}, "
            f"limited_proofid={uint256_hex(self.limited_proofid)}, "
            f"sequence={self.sequence}, "
            f"expiration={self.expiration}, "
            f"master={self.master.hex()}, "
            f"payout_script={self.payout_script.hex()}, "
            f"signature={b64encode(self.signature)}, "
            f"stakes={self.stakes})"
        )


class AvalanchePrefilledProof:
    __slots__ = ("index", "proof")

    def __init__(self, index=0, proof=None):
        self.index = index
        self.proof = proof or AvalancheProof()

    def deserialize(self, f):
        self.index = deser_compact_size(f)
        self.proof.deserialize(f)

    def serialize(self) -> bytes:
        return ser_compact_size(self.index) + self.proof.serialize()

    def __repr__(self):
        return f"AvalanchePrefilledProof(index={self.index}, proof={self.proof!r})"


class AvalanchePoll:
    __slots__ = ("round", "invs")

    def __init__(self, avaround=0, invs=None):
        self.round = avaround
        self.invs = invs if invs is not None else []

    def deserialize(self, f):
        self.round = int.from_bytes(f.read(8), "little", signed=True)
        self.invs = deser_vector(f, CInv)

    def serialize(self) -> bytes:
        return self.round.to_bytes(8, "little", signed=True) + ser_vector(self.invs)

    def __repr__(self):
        return f"AvalanchePoll(round={self.round}, invs={self.invs!r})"


class AvalancheVoteError(IntEnum):
    ACCEPTED = 0
    INVALID = 1
    PARKED = 2
    FORK = 3
    UNKNOWN = -1
    MISSING = -2
    PENDING = -3


class AvalancheProofVoteResponse(IntEnum):
    ACTIVE = 0
    REJECTED = 1
    IMMATURE = 2
    CONFLICT = 3
    UNKNOWN = -1


class AvalancheTxVoteError(IntEnum):
    ACCEPTED = 0
    INVALID = 1
    CONFLICTING = 2
    UNKNOWN = -1
    ORPHAN = -2


class AvalancheContenderVoteError(IntEnum):
    ACCEPTED = 0
    INVALID = 1
    UNKNOWN = -1
    PENDING = -2


class AvalancheVote:
    __slots__ = ("error", "hash")

    def __init__(self, e=0, h=0):
        self.error = e
        self.hash = h

    def deserialize(self, f):
        self.error = int.from_bytes(f.read(4), "little", signed=True)
        self.hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.error.to_bytes(4, "little", signed=True) + ser_uint256(self.hash)

    def __repr__(self):
        return f"AvalancheVote(error={self.error}, hash={uint256_hex(self.hash)})"


class AvalancheResponse:
    __slots__ = ("round", "cooldown", "votes")

    def __init__(self, avaround=0, cooldown=0, votes=None):
        self.round = avaround
        self.cooldown = cooldown
        self.votes = votes if votes is not None else []

    def deserialize(self, f):
        self.round = int.from_bytes(f.read(8), "little", signed=True)
        self.cooldown = int.from_bytes(f.read(4), "little", signed=True)
        self.votes = deser_vector(f, AvalancheVote)

    def serialize(self) -> bytes:
        return (
            self.round.to_bytes(8, "little", signed=True)
            + self.cooldown.to_bytes(4, "little", signed=True)
            + ser_vector(self.votes)
        )

    def get_hash(self):
        return hash256(self.serialize())

    def __repr__(self):
        return (
            f"AvalancheResponse(round={self.round}, cooldown={self.cooldown}, "
            f"votes={self.votes!r})"
        )


class TCPAvalancheResponse:
    __slots__ = ("response", "sig")

    def __init__(self, response: AvalancheResponse, sig=b"\0" * 64):
        self.response = response
        self.sig = sig

    def deserialize(self, f):
        self.response.deserialize(f)
        self.sig = f.read(64)

    def serialize(self) -> bytes:
        return self.response.serialize() + self.sig

    def __repr__(self):
        return f"TCPAvalancheResponse(response={self.response!r}, sig={self.sig})"


class AvalancheDelegationLevel:
    __slots__ = ("pubkey", "sig")

    def __init__(self, pubkey=b"", sig=b"\0" * 64):
        self.pubkey = pubkey
        self.sig = sig

    def deserialize(self, f):
        self.pubkey = deser_string(f)
        self.sig = f.read(64)

    def serialize(self) -> bytes:
        return ser_string(self.pubkey) + self.sig

    def __repr__(self):
        return f"AvalancheDelegationLevel(pubkey={self.pubkey.hex()}, sig={self.sig})"


class AvalancheDelegation:
    __slots__ = ("limited_proofid", "proof_master", "proofid", "levels")

    def __init__(self, limited_proofid=0, proof_master=b"", levels=None):
        self.limited_proofid: int = limited_proofid
        self.proof_master: bytes = proof_master
        self.levels: List[AvalancheDelegationLevel] = levels or []
        self.proofid: int = self.compute_proofid()

    def compute_proofid(self) -> int:
        return uint256_from_str(
            hash256(ser_uint256(self.limited_proofid) + ser_string(self.proof_master))
        )

    def deserialize(self, f):
        self.limited_proofid = deser_uint256(f)
        self.proof_master = deser_string(f)
        self.levels = deser_vector(f, AvalancheDelegationLevel)

        self.proofid = self.compute_proofid()

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.limited_proofid)
            + ser_string(self.proof_master)
            + ser_vector(self.levels)
        )

    def __repr__(self):
        return (
            "AvalancheDelegation("
            f"limitedProofId={uint256_hex(self.limited_proofid)}, "
            f"proofMaster={self.proof_master.hex()}, "
            f"proofid={uint256_hex(self.proofid)}, "
            f"levels={self.levels})"
        )

    def getid(self):
        h = ser_uint256(self.proofid)
        for level in self.levels:
            h = hash256(h + ser_string(level.pubkey))
        return h


class AvalancheHello:
    __slots__ = ("delegation", "sig", "max_elements")

    MAX_ELEMENT_POLL = 1024
    """Maximum number of items that can be polled at once.
    See AVALANCHE_MAX_ELEMENT_POLL in processor.h.
    """

    def __init__(
        self,
        delegation: AvalancheDelegation,
        sig=b"\0" * 64,
        max_elements=MAX_ELEMENT_POLL,
    ):
        self.delegation = delegation
        self.sig = sig
        self.max_elements = max_elements

    def deserialize(self, f):
        self.delegation.deserialize(f)
        self.sig = f.read(64)
        self.max_elements = int.from_bytes(f.read(4), "little")

    def serialize(self) -> bytes:
        return (
            self.delegation.serialize()
            + self.sig
            + self.max_elements.to_bytes(4, "little")
        )

    def __repr__(self):
        return f"AvalancheHello(delegation={self.delegation!r}, sig={self.sig}, max_elements={self.max_elements})"

    def get_sighash(self, node):
        b = self.delegation.getid()
        b += node.remote_nonce.to_bytes(8, "little")
        b += node.local_nonce.to_bytes(8, "little")
        b += node.remote_extra_entropy.to_bytes(8, "little")
        b += node.local_extra_entropy.to_bytes(8, "little")
        return hash256(b)


class CPartialMerkleTree:
    __slots__ = ("nTransactions", "vBits", "vHash")

    def __init__(self):
        self.nTransactions = 0
        self.vHash = []
        self.vBits = []

    def deserialize(self, f):
        self.nTransactions = int.from_bytes(f.read(4), "little", signed=True)
        self.vHash = deser_uint256_vector(f)
        vBytes = deser_string(f)
        self.vBits = []
        for i in range(len(vBytes) * 8):
            self.vBits.append(vBytes[i // 8] & (1 << (i % 8)) != 0)

    def serialize(self) -> bytes:
        vBytesArray = bytearray([0x00] * ((len(self.vBits) + 7) // 8))
        for i in range(len(self.vBits)):
            vBytesArray[i // 8] |= self.vBits[i] << (i % 8)
        return (
            self.nTransactions.to_bytes(4, "little", signed=True)
            + ser_uint256_vector(self.vHash)
            + ser_string(bytes(vBytesArray))
        )

    def __repr__(self):
        return (
            f"CPartialMerkleTree(nTransactions={self.nTransactions}, "
            f"Hash={self.vHash!r}, vBits={self.vBits!r})"
        )


class CMerkleBlock:
    __slots__ = ("header", "txn")

    def __init__(self):
        self.header = CBlockHeader()
        self.txn = CPartialMerkleTree()

    def deserialize(self, f):
        self.header.deserialize(f)
        self.txn.deserialize(f)

    def serialize(self) -> bytes:
        return self.header.serialize() + self.txn.serialize()

    def __repr__(self):
        return f"CMerkleBlock(header={self.header!r}, txn={self.txn!r})"


# Objects that correspond to messages on the wire


class msg_version:
    __slots__ = (
        "addrFrom",
        "addrTo",
        "nNonce",
        "relay",
        "nServices",
        "nStartingHeight",
        "nTime",
        "nVersion",
        "strSubVer",
        "nExtraEntropy",
    )
    msgtype = b"version"

    def __init__(self):
        self.nVersion = 0
        self.nServices = 0
        self.nTime = int(time.time())
        self.addrTo = CAddress()
        self.addrFrom = CAddress()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = ""
        self.nStartingHeight = -1
        self.relay = 0
        self.nExtraEntropy = random.getrandbits(64)

    def deserialize(self, f):
        self.nVersion = int.from_bytes(f.read(4), "little", signed=True)
        self.nServices = int.from_bytes(f.read(8), "little")
        self.nTime = int.from_bytes(f.read(8), "little", signed=True)
        self.addrTo = CAddress()
        self.addrTo.deserialize(f, with_time=False)

        self.addrFrom = CAddress()
        self.addrFrom.deserialize(f, with_time=False)
        self.nNonce = int.from_bytes(f.read(8), "little")
        self.strSubVer = deser_string(f).decode("utf-8")

        self.nStartingHeight = int.from_bytes(f.read(4), "little", signed=True)

        self.relay = int.from_bytes(f.read(1), "little")

        self.nExtraEntropy = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return (
            self.nVersion.to_bytes(4, "little", signed=True)
            + self.nServices.to_bytes(8, "little")
            + self.nTime.to_bytes(8, "little", signed=True)
            + self.addrTo.serialize(with_time=False)
            + self.addrFrom.serialize(with_time=False)
            + self.nNonce.to_bytes(8, "little")
            + ser_string(self.strSubVer.encode("utf-8"))
            + self.nStartingHeight.to_bytes(4, "little", signed=True)
            + self.relay.to_bytes(1, "little")
            + self.nExtraEntropy.to_bytes(8, "little")
        )

    def __repr__(self):
        return (
            f"msg_version(nVersion={self.nVersion} nServices={self.nServices} "
            f"nTime={self.nTime} addrTo={self.addrTo!r} addrFrom={self.addrFrom!r} "
            f"nNonce=0x{self.nNonce:016X} strSubVer={self.strSubVer} "
            f"nStartingHeight={self.nStartingHeight} relay={self.relay} "
            f"nExtraEntropy={self.nExtraEntropy})"
        )


class msg_verack:
    __slots__ = ()
    msgtype = b"verack"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_verack()"


class msg_addr:
    __slots__ = ("addrs",)
    msgtype = b"addr"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress)

    def serialize(self) -> bytes:
        return ser_vector(self.addrs)

    def __repr__(self):
        return f"msg_addr(addrs={self.addrs!r})"


class msg_addrv2:
    __slots__ = ("addrs",)
    msgtype = b"addrv2"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress, "deserialize_v2")

    def serialize(self) -> bytes:
        return ser_vector(self.addrs, "serialize_v2")

    def __repr__(self):
        return f"msg_addrv2(addrs={self.addrs!r})"


class msg_sendaddrv2:
    __slots__ = ()
    msgtype = b"sendaddrv2"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_sendaddrv2()"


class msg_inv:
    __slots__ = ("inv",)
    msgtype = b"inv"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        else:
            self.inv = inv

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self) -> bytes:
        return ser_vector(self.inv)

    def __repr__(self):
        return f"msg_inv(inv={self.inv!r})"


class msg_getdata:
    __slots__ = ("inv",)
    msgtype = b"getdata"

    def __init__(self, inv=None):
        self.inv = inv if inv is not None else []

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self) -> bytes:
        return ser_vector(self.inv)

    def __repr__(self):
        return f"msg_getdata(inv={self.inv!r})"


class msg_getblocks:
    __slots__ = ("locator", "hashstop")
    msgtype = b"getblocks"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.locator.serialize() + ser_uint256(self.hashstop)

    def __repr__(self):
        return (
            f"msg_getblocks(locator={self.locator!r} "
            f"hashstop={uint256_hex(self.hashstop)})"
        )


class msg_tx:
    __slots__ = ("tx",)
    msgtype = b"tx"

    def __init__(self, tx: Optional[CTransaction] = None):
        self.tx = tx or CTransaction()

    def deserialize(self, f):
        self.tx.deserialize(f)

    def serialize(self) -> bytes:
        return self.tx.serialize()

    def __repr__(self):
        return f"msg_tx(tx={self.tx!r})"


class msg_block:
    __slots__ = ("block",)
    msgtype = b"block"

    def __init__(self, block=None):
        if block is None:
            self.block = CBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self) -> bytes:
        return self.block.serialize()

    def __repr__(self):
        return f"msg_block(block={self.block!r})"


# for cases where a user needs tighter control over what is sent over the wire
# note that the user must supply the name of the msgtype, and the data
class msg_generic:
    __slots__ = "data"

    def __init__(self, msgtype, data=None):
        self.msgtype = msgtype
        self.data = data

    def serialize(self) -> bytes:
        return self.data

    def __repr__(self):
        return "msg_generic()"


class msg_getaddr:
    __slots__ = ()
    msgtype = b"getaddr"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_getaddr()"


class msg_ping:
    __slots__ = ("nonce",)
    msgtype = b"ping"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return self.nonce.to_bytes(8, "little")

    def __repr__(self):
        return f"msg_ping(nonce={self.nonce:08x})"


class msg_pong:
    __slots__ = ("nonce",)
    msgtype = b"pong"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return self.nonce.to_bytes(8, "little")

    def __repr__(self):
        return f"msg_pong(nonce={self.nonce:08x})"


class msg_mempool:
    __slots__ = ()
    msgtype = b"mempool"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_mempool()"


class msg_notfound:
    __slots__ = ("vec",)
    msgtype = b"notfound"

    def __init__(self, vec=None):
        self.vec = vec or []

    def deserialize(self, f):
        self.vec = deser_vector(f, CInv)

    def serialize(self) -> bytes:
        return ser_vector(self.vec)

    def __repr__(self):
        return f"msg_notfound(vec={self.vec!r})"


class msg_sendheaders:
    __slots__ = ()
    msgtype = b"sendheaders"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_sendheaders()"


# getheaders message has
# number of entries
# vector of hashes
# hash_stop (hash of last desired block header, 0 to get as many as possible)
class msg_getheaders:
    __slots__ = (
        "hashstop",
        "locator",
    )
    msgtype = b"getheaders"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.locator.serialize() + ser_uint256(self.hashstop)

    def __repr__(self):
        return (
            f"msg_getheaders(locator={self.locator!r}, "
            f"stop={uint256_hex(self.hashstop)})"
        )


# headers message has
# <count> <vector of block headers>
class msg_headers:
    __slots__ = ("headers",)
    msgtype = b"headers"

    def __init__(self, headers=None):
        self.headers = headers if headers is not None else []

    def deserialize(self, f):
        self.headers = deser_vector(f, CBlockHeader)

    def serialize(self) -> bytes:
        return ser_vector([CBlockHeader(header) for header in self.headers])

    def __repr__(self):
        return f"msg_headers(headers={self.headers!r})"


class msg_merkleblock:
    __slots__ = ("merkleblock",)
    msgtype = b"merkleblock"

    def __init__(self, merkleblock=None):
        if merkleblock is None:
            self.merkleblock = CMerkleBlock()
        else:
            self.merkleblock = merkleblock

    def deserialize(self, f):
        self.merkleblock.deserialize(f)

    def serialize(self) -> bytes:
        return self.merkleblock.serialize()

    def __repr__(self):
        return f"msg_merkleblock(merkleblock={self.merkleblock!r})"


class msg_filterload:
    __slots__ = ("data", "nHashFuncs", "nTweak", "nFlags")
    msgtype = b"filterload"

    def __init__(self, data=b"00", nHashFuncs=0, nTweak=0, nFlags=0):
        self.data = data
        self.nHashFuncs = nHashFuncs
        self.nTweak = nTweak
        self.nFlags = nFlags

    def deserialize(self, f):
        self.data = deser_string(f)
        self.nHashFuncs = int.from_bytes(f.read(4), "little")
        self.nTweak = int.from_bytes(f.read(4), "little")
        self.nFlags = int.from_bytes(f.read(1), "little")

    def serialize(self) -> bytes:
        return (
            ser_string(self.data)
            + self.nHashFuncs.to_bytes(4, "little")
            + self.nTweak.to_bytes(4, "little")
            + self.nFlags.to_bytes(1, "little")
        )

    def __repr__(self):
        return (
            f"msg_filterload(data={self.data}, nHashFuncs={self.nHashFuncs}, "
            f"nTweak={self.nTweak}, nFlags={self.nFlags})"
        )


class msg_filteradd:
    __slots__ = "data"
    msgtype = b"filteradd"

    def __init__(self, data):
        self.data = data

    def deserialize(self, f):
        self.data = deser_string(f)

    def serialize(self) -> bytes:
        return ser_string(self.data)

    def __repr__(self):
        return f"msg_filteradd(data={self.data})"


class msg_filterclear:
    __slots__ = ()
    msgtype = b"filterclear"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_filterclear()"


class msg_feefilter:
    __slots__ = ("feerate",)
    msgtype = b"feefilter"

    def __init__(self, feerate=0):
        self.feerate = feerate

    def deserialize(self, f):
        self.feerate = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return self.feerate.to_bytes(8, "little")

    def __repr__(self):
        return f"msg_feefilter(feerate={self.feerate:08x})"


class msg_sendcmpct:
    __slots__ = ("announce", "version")
    msgtype = b"sendcmpct"

    def __init__(self, announce=False, version=1):
        self.announce = announce
        self.version = version

    def deserialize(self, f):
        self.announce = bool(int.from_bytes(f.read(1), "little"))
        self.version = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return int(self.announce).to_bytes(1, "little") + self.version.to_bytes(
            8, "little"
        )

    def __repr__(self):
        return f"msg_sendcmpct(announce={self.announce}, version={self.version})"


# Nucleation relay capability flags (sendinvshort)
TXRELAY_INVSHORT = 1 << 0
TXRELAY_RECON = 1 << 1


class msg_sendinvshort:
    __slots__ = ("version", "flags")
    msgtype = b"sendinvshort"

    def __init__(self, version=1, flags=0):
        self.version = version
        self.flags = flags

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.flags = int.from_bytes(f.read(8), "little")

    def serialize(self) -> bytes:
        return self.version.to_bytes(4, "little") + self.flags.to_bytes(8, "little")

    def __repr__(self):
        return f"msg_sendinvshort(version={self.version}, flags={self.flags})"


class msg_invshort:
    """Short-id transaction announcements: epoch id and 8-byte short ids"""

    __slots__ = ("epoch_id", "short_ids")
    msgtype = b"invshort"

    def __init__(self, epoch_id=0, short_ids=None):
        self.epoch_id = epoch_id
        self.short_ids = short_ids or []

    def deserialize(self, f):
        self.epoch_id = deser_uint256(f)
        n = deser_compact_size(f)
        self.short_ids = [int.from_bytes(f.read(8), "little") for _ in range(n)]

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.epoch_id)
            + ser_compact_size(len(self.short_ids))
            + b"".join(s.to_bytes(8, "little") for s in self.short_ids)
        )

    def __repr__(self):
        return f"msg_invshort(epoch_id={self.epoch_id:064x}, n={len(self.short_ids)})"


class msg_getshorttx:
    """Request transactions by short id (scope, context, SipHash key, ids)"""

    __slots__ = ("scope", "context_id", "salt_k0", "salt_k1", "short_ids")
    msgtype = b"getshorttx"

    def __init__(self, scope=1, context_id=0, salt_k0=0, salt_k1=0, short_ids=None):
        self.scope = scope
        self.context_id = context_id
        self.salt_k0 = salt_k0
        self.salt_k1 = salt_k1
        self.short_ids = short_ids or []

    def deserialize(self, f):
        self.scope = int.from_bytes(f.read(1), "little")
        self.context_id = deser_uint256(f)
        self.salt_k0 = int.from_bytes(f.read(8), "little")
        self.salt_k1 = int.from_bytes(f.read(8), "little")
        n = deser_compact_size(f)
        self.short_ids = [int.from_bytes(f.read(8), "little") for _ in range(n)]

    def serialize(self) -> bytes:
        return (
            self.scope.to_bytes(1, "little")
            + ser_uint256(self.context_id)
            + self.salt_k0.to_bytes(8, "little")
            + self.salt_k1.to_bytes(8, "little")
            + ser_compact_size(len(self.short_ids))
            + b"".join(s.to_bytes(8, "little") for s in self.short_ids)
        )

    def __repr__(self):
        return f"msg_getshorttx(scope={self.scope}, n={len(self.short_ids)})"


class msg_cmpctblock:
    __slots__ = ("header_and_shortids",)
    msgtype = b"cmpctblock"

    def __init__(self, header_and_shortids=None):
        self.header_and_shortids = header_and_shortids

    def deserialize(self, f):
        self.header_and_shortids = P2PHeaderAndShortIDs()
        self.header_and_shortids.deserialize(f)

    def serialize(self) -> bytes:
        return self.header_and_shortids.serialize()

    def __repr__(self):
        return f"msg_cmpctblock(HeaderAndShortIDs={self.header_and_shortids!r})"


class msg_getblocktxn:
    __slots__ = ("block_txn_request",)
    msgtype = b"getblocktxn"

    def __init__(self):
        self.block_txn_request = None

    def deserialize(self, f):
        self.block_txn_request = BlockTransactionsRequest()
        self.block_txn_request.deserialize(f)

    def serialize(self) -> bytes:
        return self.block_txn_request.serialize()

    def __repr__(self):
        return f"msg_getblocktxn(block_txn_request={self.block_txn_request!r})"


class msg_blocktxn:
    __slots__ = ("block_transactions",)
    msgtype = b"blocktxn"

    def __init__(self):
        self.block_transactions = BlockTransactions()

    def deserialize(self, f):
        self.block_transactions.deserialize(f)

    def serialize(self) -> bytes:
        return self.block_transactions.serialize()

    def __repr__(self):
        return f"msg_blocktxn(block_transactions={self.block_transactions!r})"


class msg_getcfilters:
    __slots__ = ("filter_type", "start_height", "stop_hash")
    msgtype = b"getcfilters"

    def __init__(self, filter_type, start_height, stop_hash):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.start_height = int.from_bytes(f.read(4), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return (
            self.filter_type.to_bytes(1, "little")
            + self.start_height.to_bytes(4, "little")
            + ser_uint256(self.stop_hash)
        )

    def __repr__(self):
        return (
            f"msg_getcfilters(filter_type={self.filter_type:#x}, "
            f"start_height={self.start_height}, stop_hash={self.stop_hash:x})"
        )


class msg_cfilter:
    __slots__ = ("filter_type", "block_hash", "filter_data")
    msgtype = b"cfilter"

    def __init__(self, filter_type=None, block_hash=None, filter_data=None):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_data = filter_data

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.block_hash = deser_uint256(f)
        self.filter_data = deser_string(f)

    def serialize(self) -> bytes:
        return (
            self.filter_type.to_bytes(1, "little")
            + ser_uint256(self.block_hash)
            + ser_string(self.filter_data)
        )

    def __repr__(self):
        return (
            f"msg_cfilter(filter_type={self.filter_type:#x}, "
            f"block_hash={self.block_hash:x})"
        )


class msg_getcfheaders:
    __slots__ = ("filter_type", "start_height", "stop_hash")
    msgtype = b"getcfheaders"

    def __init__(self, filter_type, start_height, stop_hash):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.start_height = int.from_bytes(f.read(4), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return (
            self.filter_type.to_bytes(1, "little")
            + self.start_height.to_bytes(4, "little")
            + ser_uint256(self.stop_hash)
        )

    def __repr__(self):
        return (
            f"msg_getcfheaders(filter_type={self.filter_type:#x}, "
            f"start_height={self.start_height}, stop_hash={self.stop_hash:x})"
        )


class msg_cfheaders:
    __slots__ = ("filter_type", "stop_hash", "prev_header", "hashes")
    msgtype = b"cfheaders"

    def __init__(self, filter_type=None, stop_hash=None, prev_header=None, hashes=None):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.prev_header = prev_header
        self.hashes = hashes

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)
        self.prev_header = deser_uint256(f)
        self.hashes = deser_uint256_vector(f)

    def serialize(self) -> bytes:
        return (
            self.filter_type.to_bytes(1, "little")
            + ser_uint256(self.stop_hash)
            + ser_uint256(self.prev_header)
            + ser_uint256_vector(self.hashes)
        )

    def __repr__(self):
        return (
            f"msg_cfheaders(filter_type={self.filter_type:#x}, "
            f"stop_hash={self.stop_hash:x})"
        )


class msg_getcfcheckpt:
    __slots__ = ("filter_type", "stop_hash")
    msgtype = b"getcfcheckpt"

    def __init__(self, filter_type, stop_hash):
        self.filter_type = filter_type
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.filter_type.to_bytes(1, "little") + ser_uint256(self.stop_hash)

    def __repr__(self):
        return (
            f"msg_getcfcheckpt(filter_type={self.filter_type:#x}, "
            f"stop_hash={self.stop_hash:x})"
        )


class msg_cfcheckpt:
    __slots__ = ("filter_type", "stop_hash", "headers")
    msgtype = b"cfcheckpt"

    def __init__(self, filter_type=None, stop_hash=None, headers=None):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.headers = headers

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)
        self.headers = deser_uint256_vector(f)

    def serialize(self) -> bytes:
        return (
            self.filter_type.to_bytes(1, "little")
            + ser_uint256(self.stop_hash)
            + ser_uint256_vector(self.headers)
        )

    def __repr__(self):
        return (
            f"msg_cfcheckpt(filter_type={self.filter_type:#x}, "
            f"stop_hash={self.stop_hash:x})"
        )


class msg_avaproof:
    __slots__ = ("proof",)
    msgtype = b"avaproof"

    def __init__(self):
        self.proof = AvalancheProof()

    def deserialize(self, f):
        self.proof.deserialize(f)

    def serialize(self) -> bytes:
        return self.proof.serialize()

    def __repr__(self):
        return f"msg_avaproof(proof={self.proof!r})"


class msg_avapoll:
    __slots__ = ("poll",)
    msgtype = b"avapoll"

    def __init__(self):
        self.poll = AvalanchePoll()

    def deserialize(self, f):
        self.poll.deserialize(f)

    def serialize(self) -> bytes:
        return self.poll.serialize()

    def __repr__(self):
        return f"msg_avapoll(poll={self.poll!r})"


class msg_avaresponse:
    __slots__ = ("response",)
    msgtype = b"avaresponse"

    def __init__(self):
        self.response = AvalancheResponse()

    def deserialize(self, f):
        self.response.deserialize(f)

    def serialize(self) -> bytes:
        return self.response.serialize()

    def __repr__(self):
        return f"msg_avaresponse(response={self.response!r})"


class msg_tcpavaresponse:
    __slots__ = ("response",)
    msgtype = b"avaresponse"

    def __init__(self):
        self.response = TCPAvalancheResponse(AvalancheResponse())

    def deserialize(self, f):
        self.response.deserialize(f)

    def serialize(self) -> bytes:
        return self.response.serialize()

    def __repr__(self):
        return f"msg_tcpavaresponse(response={self.response!r})"


class msg_avahello:
    __slots__ = ("hello",)
    msgtype = b"avahello"

    def __init__(self):
        self.hello = AvalancheHello(AvalancheDelegation())

    def deserialize(self, f):
        self.hello.deserialize(f)

    def serialize(self) -> bytes:
        return self.hello.serialize()

    def __repr__(self):
        return f"msg_avahello(response={self.hello!r})"


class msg_getavaaddr:
    __slots__ = ()
    msgtype = b"getavaaddr"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_getavaaddr()"


class msg_getavaproofs:
    __slots__ = ()
    msgtype = b"getavaproofs"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self):
        return "msg_getavaproofs()"


class msg_avaproofs:
    __slots__ = ("key0", "key1", "shortids", "prefilled_proofs")
    msgtype = b"avaproofs"

    def __init__(self):
        self.key0 = 0
        self.key1 = 0
        self.shortids = []
        self.prefilled_proofs = []

    def deserialize(self, f):
        self.key0 = int.from_bytes(f.read(8), "little")
        self.key1 = int.from_bytes(f.read(8), "little")
        shortids_length = deser_compact_size(f)
        for _ in range(shortids_length):
            # shortids are defined to be 6 bytes in the spec, so append
            # two zero bytes and read it in as an 8-byte number
            self.shortids.append(int.from_bytes(f.read(6) + b"\x00\x00", "little"))

        # The indices are differentially encoded
        self.prefilled_proofs = deser_vector(f, AvalanchePrefilledProof)
        current_indice = -1
        for p in self.prefilled_proofs:
            current_indice += p.index + 1
            p.index = current_indice

    def serialize(self) -> bytes:
        r = self.key0.to_bytes(8, "little")
        r += self.key1.to_bytes(8, "little")
        r += ser_compact_size(len(self.shortids))
        for shortid in self.shortids:
            # We only want the first 6 bytes
            r += shortid.to_bytes(8, "little")[0:6]

        r += ser_compact_size(len(self.prefilled_proofs))
        if len(self.prefilled_proofs) < 1:
            return r

        # The indices are differentially encoded
        r += self.prefilled_proofs[0].serialize()
        for i in range(len(self.prefilled_proofs[1:])):
            r += ser_compact_size(
                self.prefilled_proofs[i + 1].index - self.prefilled_proofs[i].index - 1
            )
            r += self.prefilled_proofs[i].proof.serialize()

        return r

    def __repr__(self):
        return (
            f"msg_avaproofs(key0={self.key0}, key1={self.key1}, "
            f"len(shortids)={len(self.shortids)}, shortids={self.shortids}), "
            f"len(prefilled_proofs)={len(self.prefilled_proofs)}, "
            f"prefilled_proofs={self.prefilled_proofs})"
        )


class msg_avaproofsreq:
    __slots__ = "indices"
    msgtype = b"avaproofsreq"

    def __init__(self):
        self.indices = []

    def deserialize(self, f):
        indices_length = deser_compact_size(f)

        # The indices are differentially encoded
        current_indice = -1
        for _ in range(indices_length):
            current_indice += deser_compact_size(f) + 1
            self.indices.append(current_indice)

    def serialize(self) -> bytes:
        r = ser_compact_size(len(self.indices))

        if len(self.indices) < 1:
            return r

        # The indices are differentially encoded
        r += ser_compact_size(self.indices[0])
        for i in range(len(self.indices[1:])):
            r += ser_compact_size(self.indices[i + 1] - self.indices[i] - 1)

        return r

    def __repr__(self):
        return (
            f"msg_avaproofsreq(len(shortids)={len(self.indices)}, "
            f"indices={self.indices})"
        )


def blake3_keyed_single_chunk(key_32: bytes, data: bytes) -> bytes:
    assert len(key_32) == 32
    assert len(data) <= 1024
    key_words = [
        int.from_bytes(key_32[i * 4 : (i + 1) * 4], "little") for i in range(8)
    ]
    cv = list(key_words)
    num_blocks = max(1, (len(data) + 63) // 64)
    for b in range(num_blocks):
        blk = data[b * 64 : (b + 1) * 64]
        blk_len = len(blk)
        padded = blk + b"\x00" * (64 - blk_len)
        words = [
            int.from_bytes(padded[i * 4 : (i + 1) * 4], "little") for i in range(16)
        ]
        # 16 = KEYED_HASH, 1 = CHUNK_START, 2 = CHUNK_END, 8 = ROOT
        flags = 16 | (1 if b == 0 else 0) | (2 if b == num_blocks - 1 else 0)
        if b == num_blocks - 1:
            flags |= 8
        cv = _blake3_compress(cv, words, 0, blk_len, flags)
    return b"".join(w.to_bytes(4, "little") for w in cv)


class msg_avatreasury:
    __slots__ = ("prevblockhash", "outputs", "total_reward")
    msgtype = b"avatreasury"

    def __init__(self, prevblockhash=0, outputs=None, total_reward=0):
        self.prevblockhash = prevblockhash
        self.outputs = outputs if outputs is not None else []
        self.total_reward = total_reward

    def deserialize(self, f):
        self.prevblockhash = deser_uint256(f)
        self.outputs = deser_vector(f, CTxOut)
        self.total_reward = int.from_bytes(f.read(8), "little", signed=True)

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.prevblockhash)
            + ser_vector(self.outputs)
            + self.total_reward.to_bytes(8, "little", signed=True)
        )

    def contender_id(self) -> int:
        key = b"lotus.v2.ava.treasury_contender".ljust(32, b"\x00")
        payload = ser_uint256(self.prevblockhash) + ser_vector(self.outputs)
        return uint256_from_str(blake3_keyed_single_chunk(key, payload))

    def __repr__(self):
        return (
            f"msg_avatreasury(prevblockhash={self.prevblockhash:064x}, "
            f"outputs={self.outputs!r}, total_reward={self.total_reward})"
        )


class msg_avabatch:
    __slots__ = (
        "prev_block_hash",
        "epoch_seq",
        "parent_batch_id",
        "subtree_a_root",
        "utxo_root",
        "tx_count",
        "short_ids_hash",
    )
    msgtype = b"avabatch"

    def __init__(
        self,
        prev_block_hash=0,
        epoch_seq=1,
        parent_batch_id=0,
        subtree_a_root=0,
        utxo_root=0,
        tx_count=1,
        short_ids_hash=0,
    ):
        self.prev_block_hash = prev_block_hash
        self.epoch_seq = epoch_seq
        self.parent_batch_id = parent_batch_id
        self.subtree_a_root = subtree_a_root
        self.utxo_root = utxo_root
        self.tx_count = tx_count
        self.short_ids_hash = short_ids_hash

    def deserialize(self, f):
        self.prev_block_hash = deser_uint256(f)
        self.epoch_seq = int.from_bytes(f.read(4), "little")
        self.parent_batch_id = deser_uint256(f)
        self.subtree_a_root = deser_uint256(f)
        self.utxo_root = deser_uint256(f)
        self.tx_count = int.from_bytes(f.read(4), "little")
        self.short_ids_hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.prev_block_hash)
            + self.epoch_seq.to_bytes(4, "little")
            + ser_uint256(self.parent_batch_id)
            + ser_uint256(self.subtree_a_root)
            + ser_uint256(self.utxo_root)
            + self.tx_count.to_bytes(4, "little")
            + ser_uint256(self.short_ids_hash)
        )

    def batch_id(self) -> int:
        return uint256_from_str(
            lotus_v2_tagged_hash("lotus.v2.preconsensus.batch", self.serialize())
        )

    def __repr__(self):
        return (
            f"msg_avabatch(prev_block_hash={self.prev_block_hash:064x}, "
            f"epoch_seq={self.epoch_seq}, tx_count={self.tx_count})"
        )


class msg_getutxoroots:
    __slots__ = ("pivot_block_id",)
    msgtype = b"getutxoroots"

    def __init__(self, pivot_block_id: bytes = b"\x00" * 32):
        self.pivot_block_id = pivot_block_id

    def deserialize(self, f):
        self.pivot_block_id = f.read(32)

    def serialize(self) -> bytes:
        return self.pivot_block_id

    def __repr__(self):
        return f"msg_getutxoroots(pivot_block_id={self.pivot_block_id.hex()})"


class msg_utxoroots:
    __slots__ = ("raw_payload", "pivot_block_id", "height", "monetary_state", "shards")
    msgtype = b"utxoroots"

    def __init__(self):
        self.raw_payload = b""
        self.pivot_block_id = b"\x00" * 32
        self.height = 0
        self.monetary_state = b"\x00" * 56
        self.shards = []

    def deserialize(self, f):
        data = f.read()
        self.raw_payload = data
        self.pivot_block_id = data[:32]
        self.height = int.from_bytes(data[32:40], "little")
        self.monetary_state = data[40:96]
        self.shards = []
        offset = 96
        for _ in range(256):
            tag = data[offset]
            root = data[offset + 1 : offset + 33]
            self.shards.append((tag, root))
            offset += 33

    def serialize(self) -> bytes:
        if self.raw_payload:
            return self.raw_payload
        out = bytearray()
        out += self.pivot_block_id
        out += self.height.to_bytes(8, "little")
        out += self.monetary_state
        for tag, root in self.shards:
            out.append(tag)
            out += root
        return bytes(out)

    def __repr__(self):
        return f"msg_utxoroots(height={self.height}, pivot={self.pivot_block_id.hex()})"


class msg_getutxoshard:
    __slots__ = ("pivot_block_id", "prefix_depth", "prefix_bits")
    msgtype = b"getutxoshard"

    def __init__(
        self,
        pivot_block_id: bytes = b"\x00" * 32,
        prefix_depth: int = 8,
        prefix_bits: int = 0,
    ):
        self.pivot_block_id = pivot_block_id
        self.prefix_depth = prefix_depth
        self.prefix_bits = prefix_bits

    def deserialize(self, f):
        self.pivot_block_id = f.read(32)
        self.prefix_depth = int.from_bytes(f.read(1), "little")
        self.prefix_bits = int.from_bytes(f.read(2), "little")

    def serialize(self) -> bytes:
        return (
            self.pivot_block_id
            + self.prefix_depth.to_bytes(1, "little")
            + self.prefix_bits.to_bytes(2, "little")
        )

    def __repr__(self):
        return (
            f"msg_getutxoshard(pivot={self.pivot_block_id.hex()}, "
            f"depth={self.prefix_depth}, bits=0x{self.prefix_bits:04x})"
        )


class msg_utxoshard:
    __slots__ = ("raw_payload", "pivot_block_id", "prefix_depth", "prefix_bits")
    msgtype = b"utxoshard"

    def __init__(self, raw_payload: bytes = b""):
        self.raw_payload = raw_payload
        self.pivot_block_id = b"\x00" * 32
        self.prefix_depth = 8
        self.prefix_bits = 0

    def deserialize(self, f):
        data = f.read()
        self.raw_payload = data
        self.pivot_block_id = data[:32]
        self.prefix_depth = data[32]
        self.prefix_bits = int.from_bytes(data[33:35], "little")

    def serialize(self) -> bytes:
        return self.raw_payload

    def __repr__(self):
        return (
            f"msg_utxoshard(pivot={self.pivot_block_id.hex()}, "
            f"depth={self.prefix_depth}, bits=0x{self.prefix_bits:04x}, "
            f"bytes={len(self.raw_payload)})"
        )


class msg_getblockundo:
    __slots__ = ("block_id",)
    msgtype = b"getblockundo"

    def __init__(self, block_id: bytes = b"\x00" * 32):
        self.block_id = block_id

    def deserialize(self, f):
        self.block_id = f.read(32)

    def serialize(self) -> bytes:
        return self.block_id

    def __repr__(self):
        return f"msg_getblockundo(block_id={self.block_id.hex()})"


class msg_blockundo:
    __slots__ = ("raw_payload", "block_id", "parent_monetary_state")
    msgtype = b"blockundo"

    def __init__(self, raw_payload: bytes = b""):
        self.raw_payload = raw_payload
        self.block_id = b"\x00" * 32
        self.parent_monetary_state = b"\x00" * 56

    def deserialize(self, f):
        data = f.read()
        self.raw_payload = data
        self.block_id = data[:32]
        self.parent_monetary_state = data[32:88]

    def serialize(self) -> bytes:
        return self.raw_payload

    def __repr__(self):
        return (
            f"msg_blockundo(block_id={self.block_id.hex()}, "
            f"bytes={len(self.raw_payload)})"
        )


class TestFrameworkMessages(unittest.TestCase):
    def test_native_output_path_indices(self):
        branches = [b"\x11" * 32, b"\x22" * 32]
        wire = _lotus_v2_encode_output((0, 1234, b"\x00" * 32, branches, [[0], [0, 1]]))
        self.assertEqual(
            _lotus_v2_decode_output_bytes(wire),
            (0, b"\x00" * 32, branches, [[0], [0, 1]]),
        )
        malformed = _lotus_v2_encode_output((0, 1234, b"\x00" * 32, branches, [[1, 0]]))
        self.assertIsNone(_lotus_v2_decode_output_bytes(malformed))

    def test_native_batch_blake3_identifier_and_wire_round_trip(self):
        batch = msg_avabatch(
            prev_block_hash=int(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 16
            ),
            epoch_seq=42,
            parent_batch_id=int("11" * 32, 16),
            subtree_a_root=int("deadbeef" * 8, 16),
            utxo_root=int("aa" * 32, 16),
            tx_count=128,
            short_ids_hash=int("bb" * 32, 16),
        )
        # Same independently calculated vector as the native batch wire test.
        self.assertEqual(len(batch.serialize()), 168)
        self.assertEqual(
            f"{batch.batch_id():064x}",
            "cf456a4b7889237c3adace3e092fa4186c2c8c00642735c13eb8d80c7d977d46",
        )
        restored = msg_avabatch()
        restored.deserialize(BytesIO(batch.serialize()))
        self.assertEqual(restored.serialize(), batch.serialize())
        self.assertEqual(restored.batch_id(), batch.batch_id())
        restored.epoch_seq += 1
        self.assertNotEqual(restored.batch_id(), batch.batch_id())

    def test_avalanche_proof_serialization_round_trip(self):
        """Verify that an AvalancheProof object is unchanged after a round-trip
        of deserialization-serialization.
        """

        # Extracted from proof_tests.cpp
        proof_hex = (
            "d97587e6c882615796011ec8f9a7b1c621023beefdde700a6bc02036335b4df141"
            "c8bc67bb05a971f5ac2745fd683797dde30169a79ff23e1d58c64afad42ad81cff"
            "e53967e16beb692fc5776bb442c79c5d91de00cf21804712806594010038e168a3"
            "2102449fb5237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6"
            "804534ca1f5e22670be3df5cbd5957d8dd83d05c8f17eae391f0e7ffdce4fb3def"
            "adb7c079473ebeccf88c1f8ce87c61e451447b89c445967335ffd1aadef4299823"
            "21023beefdde700a6bc02036335b4df141c8bc67bb05a971f5ac2745fd683797dd"
            "e3ac7b0b7865200f63052ff980b93f965f398dda04917d411dd46e3c009a5fef35"
            "661fac28779b6a22760c00004f5ddf7d9865c7fead7e4a840b947939590261640f"
        )

        avaproof = FromHex(AvalancheProof(), proof_hex)
        self.assertEqual(ToHex(avaproof), proof_hex)

        self.assertEqual(
            uint256_hex(avaproof.proofid),
            "455f34eb8a00b0799630071c0728481bdb1653035b1484ac33e974aa4ae7db6d",
        )
        self.assertEqual(avaproof.sequence, 6296457553413371353)
        self.assertEqual(avaproof.expiration, -4129334692075929194)
        self.assertEqual(
            avaproof.master,
            bytes.fromhex(
                "023beefdde700a6bc02036335b4df141c8bc67bb05a971f5ac2745fd683797dde3"
            ),
        )
        # P2PK to master pubkey
        # We can't use a CScript() here because it would cause a circular
        # import
        self.assertEqual(
            avaproof.payout_script,
            bytes.fromhex(
                "21023beefdde700a6bc02036335b4df141c8bc67bb05a971f5ac2745fd683797dde3ac"
            ),
        )
        self.assertEqual(
            avaproof.signature,
            b64decode(
                "ewt4ZSAPYwUv+YC5P5ZfOY3aBJF9QR3UbjwAml/vNWYfrCh3m2oidgwAAE9d332YZcf+rX5KhAuUeTlZAmFkDw=="
            ),
        )

        self.assertEqual(len(avaproof.stakes), 1)
        self.assertEqual(
            avaproof.stakes[0].sig,
            b64decode(
                "RTTKH14iZwvj31y9WVfY3YPQXI8X6uOR8Of/3OT7Pe+tt8B5Rz6+zPiMH4zofGHkUUR7icRFlnM1/9Gq3vQpmA=="
            ),
        )
        self.assertEqual(
            f"{avaproof.stakes[0].stake.utxo.txid:x}",
            "915d9cc742b46b77c52f69eb6be16739e5ff1cd82ad4fa4ac6581d3ef29fa769",
        )
        self.assertEqual(avaproof.stakes[0].stake.utxo.n, 567214302)
        self.assertEqual(avaproof.stakes[0].stake.amount, 444638638000000)
        self.assertEqual(avaproof.stakes[0].stake.height, 1370779804)
        self.assertEqual(avaproof.stakes[0].stake.is_coinbase, False)
        self.assertEqual(
            avaproof.stakes[0].stake.pubkey,
            bytes.fromhex(
                "02449fb5237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce680"
            ),
        )

        msg_proof = msg_avaproof()
        msg_proof.proof = avaproof
        self.assertEqual(ToHex(msg_proof), proof_hex)
