#!/usr/bin/env python3
"""Independent P02 collapsed sparse-map vectors; blake3==1.0.11."""
import json

import blake3


def h(tag, value):
    return blake3.blake3(b"Lotus/v2/" + tag.encode() + b"\0" + value).digest()


def le(value, width):
    return value.to_bytes(width, "little")


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + le(n, 2)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + le(n, 4)
    return b"\xff" + le(n, 8)


TXID = bytes(range(32))
OUTPUT = b"\x00" + le(1000, 8) + b"\x01" + b"\x11" * 32 + b"\x01\x01\x00"


def coin(index, height=7, mtp=1234, coinbase=1):
    outpoint = TXID + le(index, 4)
    record = outpoint + cs(len(OUTPUT)) + OUTPUT + le(height, 8) + le(mtp, 8) + bytes([coinbase])
    key = bytearray(TXID)
    for i, byte in enumerate(le(index, 4)):
        key[28 + i] ^= byte
    key = bytes(key)
    leaf = h("utxo", b"\x00" + key + cs(len(record)) + record)
    return key, leaf, record


EMPTY = h("utxo", b"\x02")


def bit(key, depth):
    return (key[depth // 8] >> (depth % 8)) & 1


def tree(coins, depth=0):
    if not coins:
        return EMPTY
    if len(coins) == 1:
        return coins[0][1]
    left = [c for c in coins if not bit(c[0], depth)]
    right = [c for c in coins if bit(c[0], depth)]
    return h("utxo", b"\x01" + le(depth, 2) + tree(left, depth + 1) + tree(right, depth + 1))


def main():
    assert blake3.__version__ == "1.0.11"
    first = coin(0)
    same_prefix = 48
    assert all(bit(coin(same_prefix)[0], d) == bit(first[0], d) for d in range(228))
    assert bit(coin(same_prefix)[0], 228) != bit(first[0], 228)
    other_first_bit = 1
    assert bit(coin(other_first_bit)[0], 224) != bit(first[0], 224)
    second, third = coin(same_prefix), coin(other_first_bit)
    monetary = le(11, 8) + le(22, 8) + bytes(range(32)) + le(33, 8)
    chain = bytes(range(32, 64))
    root = tree([first, second, third])
    state = h("state", b"\x00" + chain + le(9, 8) + root + cs(len(monetary)) + monetary)
    print(json.dumps({
        "dependency": "python-blake3 1.0.11",
        "index_same_prefix": same_prefix,
        "index_other_first_bit": other_first_bit,
        "key_0": first[0].hex(),
        "coin_0": first[2].hex(),
        "leaf_0": first[1].hex(),
        "empty_root": EMPTY.hex(),
        "root_2_colliding_prefix": tree([first, second]).hex(),
        "root_3": root.hex(),
        "changed_metadata_root": tree([coin(0, 8), second, third]).hex(),
        "monetary": monetary.hex(),
        "state_root": state.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()
