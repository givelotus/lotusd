#!/usr/bin/env python3
"""Independent P01/P02 commitment vectors; requires blake3==1.0.11.

Run with the isolated environment documented in generate_vectors.py.
"""
import json

import blake3


def h(domain, value):
    return blake3.blake3(b"Lotus/v2/" + domain.encode() + b"\0" + value).digest()


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def branch_leaf(script):
    return h("branch", b"\0" + cs(len(script)) + script)


def branch_node(a, b):
    low, high = sorted((a, b), key=lambda x: int.from_bytes(x, "little"))
    return h("branch", b"\x01" + low + high)


def indexed(leaves):
    if not leaves:
        return h("merkleidx", b"\x02")
    cur = leaves[:]
    layer = 0
    while len(cur) > 1:
        if len(cur) & 1:
            cur.append(bytes(32))
        cur = [h("merkleidx", b"\x01" + layer.to_bytes(2, "little") + cur[i] + cur[i + 1])
               for i in range(0, len(cur), 2)]
        layer += 1
    return cur[0]


def subtree(pairs):
    if not pairs:
        return h("txroot", b"\x02")
    if len(pairs) == 1:
        return h("txroot", b"\x00" + pairs[0][0] + pairs[0][1])
    split = 1 << ((len(pairs) - 1).bit_length() - 1)
    return h("txroot", b"\x01" + subtree(pairs[:split]) + subtree(pairs[split:]))


def txroot(pairs):
    return h("txroot", b"\x03" + len(pairs).to_bytes(4, "little") + subtree(pairs))


def main():
    assert blake3.__version__ == "1.0.11"
    leaves = [h("inputcore", bytes([i])) for i in range(1, 6)]
    pairs = [(bytes([i]) * 32, bytes([i + 16]) * 32) for i in range(1, 6)]
    a = branch_leaf(b"\x51")
    b = branch_leaf(b"\x52")
    chain = bytes(range(32))
    header = bytes(range(32, 48))
    inroot = indexed(leaves[:3])
    outroot = indexed([h("output", b"\x03\x01\x02\x03")])
    payload = chain + header + inroot + outroot
    result = {
        "dependency": f"python-blake3 {blake3.__version__}",
        "branch_leaf_51": a.hex(),
        "branch_leaf_52": b.hex(),
        "branch_leaf_253": branch_leaf(bytes([0x51]) * 253).hex(),
        "branch_node": branch_node(a, b).hex(),
        "inputcore_leaf_01": leaves[0].hex(),
        "inputfull_leaf_01": h("inputfull", b"\x01").hex(),
        "owninput_domain_01": h("owninput", b"\x01").hex(),
        "sighash_domain_01": h("sighash", b"\x01").hex(),
        "output_leaf_010203": h("output", b"\x03\x01\x02\x03").hex(),
        "coinentry_mint": h("coinentry", b"\x00").hex(),
        "indexed_roots": [indexed(leaves[:n]).hex() for n in range(6)],
        "transaction_id": h("txid", payload).hex(),
        "transaction_hash": h("txhash", payload).hex(),
        "transaction_roots": [txroot(pairs[:n]).hex() for n in range(6)],
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
