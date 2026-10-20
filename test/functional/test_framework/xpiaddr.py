# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encode and decode Lotus V2 "xpi1..." addresses (doc/standards/xpiaddr.md).

A version 0 address carries one 32-byte branch root. Decoding returns
(hrp, root) and raises ValueError with a stable reason string.
"""

import json
import os
import unittest

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
REV = {c: i for i, c in enumerate(CHARSET)}

# cashaddr generator (k(x) = x^8 mod g(x) and its GF(32) multiples {2},{4},{8},{16})
GEN = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)

# Per-network checksum constants (40 bits). Fixed literals; see
# doc/standards/xpiaddr.md for how they were chosen.
K = {
    "xpi": 0xB70061479E,  # mainnet  (checksum symbols of an all-zero body would read "kuqxz3u7")
    "txpi": 0xADDA0F1635,  # testnet
    "rxpi": 0x8172B45D63,  # regtest
}

VERSION_ROOT = 0
BODY_LEN = 61  # 1 version + 52 payload + 8 checksum
PAYLOAD_LEN = 52


def polymod(symbols):
    c = 1
    for d in symbols:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= GEN[i]
    return c


def root_to_symbols(root):
    """32 bytes -> 52 five-bit symbols (big-endian bit order, 4 zero padding bits)."""
    acc = int.from_bytes(root, "big") << 4  # 260 bits
    return [(acc >> (5 * (51 - i))) & 31 for i in range(52)]


def symbols_to_root(symbols):
    """52 symbols -> 32 bytes; raises if the 4 padding bits are not zero."""
    acc = 0
    for s in symbols:
        acc = (acc << 5) | s
    if acc & 0xF:
        raise ValueError("nonzero padding")
    return (acc >> 4).to_bytes(32, "big")


def encode(hrp, root, address_type=0):
    if hrp not in K:
        raise ValueError("unknown prefix")
    if len(root) != 32:
        raise ValueError("root must be 32 bytes")
    if address_type not in (0, 1):
        raise ValueError("unknown version")
    data = [address_type] + root_to_symbols(root)
    mod = polymod(data + [0] * 8) ^ K[hrp]
    checksum = [(mod >> (5 * (7 - i))) & 31 for i in range(8)]
    return hrp + "1" + "".join(CHARSET[s] for s in data + checksum)


def decode_typed(addr, expected_hrp=None):
    """Returns (hrp, root).  Raises ValueError with a stable reason string.
    Callers strip surrounding whitespace and URI framing before calling."""
    # 1. case: all lower or all upper; normalize to lower.
    if addr != addr.lower() and addr != addr.upper():
        raise ValueError("mixed case")
    addr = addr.lower()
    # 2. split at the last '1' ('1' is not in the data alphabet).
    hrp, sep, body = addr.rpartition("1")
    if not sep or hrp not in K:
        raise ValueError("unknown prefix")
    if expected_hrp is not None and hrp != expected_hrp:
        raise ValueError("wrong network")
    # 3. fixed length.
    if len(body) != BODY_LEN:
        raise ValueError("bad length")
    # 4. alphabet.
    try:
        symbols = [REV[c] for c in body]
    except KeyError:
        raise ValueError("bad character")
    # 5. checksum.
    if polymod(symbols) != K[hrp]:
        raise ValueError("bad checksum")
    # 6. version.
    if symbols[0] not in (0, 1):
        raise ValueError("unknown version")
    # 7. payload (padding bits must be zero).
    return hrp, symbols[0], symbols_to_root(symbols[1 : 1 + PAYLOAD_LEN])


def decode(addr, expected_hrp=None):
    """Decode an explicit root; use decode_typed for template addresses."""
    hrp, address_type, payload = decode_typed(addr, expected_hrp)
    if address_type != 0:
        raise ValueError("not an explicit root")
    return hrp, payload


class TestFrameworkXpiAddr(unittest.TestCase):
    def test_vectors(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "src",
            "test",
            "data",
            "lotus_v2_address.json",
        )
        with open(path, encoding="utf8") as f:
            vectors = json.load(f)
        for hrp, value in vectors["constants"].items():
            self.assertEqual(K[hrp], int(value, 16))
        for v in vectors["valid"]:
            root = bytes.fromhex(v["root"])
            self.assertEqual(decode(v["address"]), (v["hrp"], root))
            self.assertEqual(encode(v["hrp"], root), v["address"].lower())
        for v in vectors["invalid"]:
            with self.assertRaises(ValueError) as cm:
                decode(v["address"])
            self.assertEqual(str(cm.exception), v["reason"])
