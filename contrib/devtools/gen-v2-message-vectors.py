#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see COPYING.
"""Independent hashlib/RFC6979/pure-Python secp oracle; public test keys only.

Run: PYTHONPATH=test/functional python3 contrib/devtools/gen-v2-message-vectors.py
Does not call the daemon or its cryptographic library. Not a wallet signer.
"""

import base64
import hashlib
import hmac
import json

from test_framework.address import base58_to_byte
from test_framework.key import SECP256K1, SECP256K1_G, SECP256K1_ORDER


def compact_size(value):
    if value < 253:
        return bytes([value])
    width = 2 if value <= 0xFFFF else 4 if value <= 0xFFFFFFFF else 8
    return bytes([{2: 253, 4: 254, 8: 255}[width]]) + value.to_bytes(width, "little")


def oracle(secret, message):
    order = SECP256K1_ORDER
    magic = b"Lotus Signed Message:\n"
    preimage = compact_size(len(magic)) + magic + b"\x01" + bytes(32)
    preimage += compact_size(len(message)) + message
    digest = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    # RFC6979 bits2octets followed by HMAC-SHA256 nonce generation.
    reduced = (int.from_bytes(digest, "big") % order).to_bytes(32, "big")
    key, value = bytes(32), b"\x01" * 32

    def hm(key, value):
        return hmac.new(key, value, hashlib.sha256).digest()

    # ABC distinguishes DER and recoverable ECDSA nonces with algo16.
    # src/secp256k1/src/modules/recovery/main_impl.h defines this exact label.
    material = secret + reduced + b"ECDSA+Recovery  "
    key = hm(key, value + b"\x00" + material)
    value = hm(key, value)
    key = hm(key, value + b"\x01" + material)
    value = hm(key, value)
    value = hm(key, value)
    nonce = int.from_bytes(value, "big")
    # These fixed vectors never take RFC6979's reject/retry branch.
    assert 0 < nonce < order
    x, y, _ = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, nonce)]))
    r = x % order
    s = (
        pow(nonce, -1, order)
        * (int.from_bytes(digest, "big") + int.from_bytes(secret, "big") * r)
    ) % order
    recovery = (y & 1) | ((x >= order) << 1)
    assert r and s
    if s > order // 2:
        s = order - s
        recovery ^= 1
    signature = bytes([31 + recovery]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "message_hex": message.hex(),
        "preimage_hex": preimage.hex(),
        "digest_hex": digest.hex(),
        "compact_base64": base64.b64encode(signature).decode(),
    }


if __name__ == "__main__":
    legacy_secret, _ = base58_to_byte(
        "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"
    )
    print(
        json.dumps(
            [
                oracle((1).to_bytes(32, "big"), b"  Lotus message\nwith whitespace\t"),
                oracle(legacy_secret[:32], b"This is just a test message"),
            ],
            indent=2,
        )
    )
