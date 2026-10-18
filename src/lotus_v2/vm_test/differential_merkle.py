#!/usr/bin/env python3
"""Independent Merkle-fold vectors for P03 c0/c1 native VM operations.

Usage: python3 differential_merkle.py NATIVE_RUNNER
"""

import hashlib
import random
import subprocess
import sys

from blake3 import blake3

runner = sys.argv[1]
rng = random.Random(0xC01C12026)
checked = 0


def n(value):
    return value.to_bytes(16, "little", signed=True)


def tagged(tag, payload):
    return blake3(tag + b"\x00" + payload).digest()


def pair_hash(algorithm, indexed, layer, left, right):
    if algorithm == 0:
        if indexed:
            return tagged(b"Lotus/v2/merkleidx",
                          b"\x01" + layer.to_bytes(2, "little") + left + right)
        return tagged(b"Lotus/v2/branch", b"\x01" + left + right)
    pair = left + right
    if algorithm == 1:
        return blake3(pair).digest()
    first = hashlib.sha256(pair).digest()
    return first if algorithm == 2 else hashlib.sha256(first).digest()


def check(op, args, expected):
    global checked
    script = bytes((op,))
    if expected is None:
        script += b"\x79\x4e"  # accepting an invalid proof would succeed
        status = "I"
    else:
        script += b"\x20" + expected + b"\x92\x4e"
        status = "S"
    actual = subprocess.check_output(
        [runner, "--charge-fields", script.hex(), "0", "0",
         *(arg.hex() for arg in args)], text=True).split()[0]
    if actual != status:
        raise SystemExit(f"{op:02x} {[a.hex() for a in args]} expected {expected.hex() if expected else None}: {status} != {actual}")
    checked += 1


for indexed in (False, True):
    for algorithm in range(4):
        for depth in range(7):
            for _ in range(12):
                leaf = rng.randbytes(32)
                siblings = [rng.randbytes(32) for _ in range(depth)]
                proof = b"".join(siblings)
                key = rng.randbytes(max(1, (depth + 7) // 8))
                acc = leaf
                for layer, sibling in enumerate(siblings):
                    if indexed:
                        right = bool((key[layer // 8] >> (layer % 8)) & 1)
                        left, other = (sibling, acc) if right else (acc, sibling)
                    else:
                        left, other = sorted((acc, sibling),
                                             key=lambda h: int.from_bytes(h, "little"))
                    acc = pair_hash(algorithm, indexed, layer, left, other)
                args = (leaf, key, proof, n(algorithm)) if indexed else (leaf, proof, n(algorithm))
                check(0xc1 if indexed else 0xc0, args, acc)

for algorithm in (-1, 4):
    check(0xc0, (bytes(32), b"", n(algorithm)), None)
    check(0xc1, (bytes(32), b"\x00", b"", n(algorithm)), None)
for leaf, proof in ((bytes(31), b""), (bytes(33), b""),
                    (bytes(32), b"\x00"), (bytes(32), bytes(33))):
    check(0xc0, (leaf, proof, n(0)), None)
for key, proof in ((b"", b""), (bytes(33), b""),
                   (b"\x00", bytes(32 * 9)), (b"\x00", b"\x00")):
    check(0xc1, (bytes(32), key, proof, n(0)), None)

print(f"{checked} independent Merkle vectors agree with native VM")
