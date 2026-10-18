#!/usr/bin/env python3
"""Reproduce test_header.cpp's P04 vectors with independent Python BLAKE3.

Install the pinned dependency into an isolated environment:
    python3 -m venv /tmp/lotus-v2-vector-venv
    /tmp/lotus-v2-vector-venv/bin/pip install blake3==1.0.11
    /tmp/lotus-v2-vector-venv/bin/python src/lotus_v2/generate_vectors.py
"""

import json

import blake3


def le(value: int, width: int) -> bytes:
    return value.to_bytes(width, "little")


def tagged(name: str, payload: bytes) -> bytes:
    return blake3.blake3(name.encode("ascii") + b"\0" + payload).digest()


def main() -> None:
    assert blake3.__version__ == "1.0.11", blake3.__version__
    chain_id = bytes(range(32))
    prev_id = bytes(range(32, 64))
    tx_root = bytes(range(64, 96))
    state_root = bytes(range(96, 128))
    bits = le(0x1D00FFFF, 4)
    time = le(0x010203040506, 6)
    body = (
        le(2, 4)
        + le(0x1122334455667788, 8)
        + le(0x99AABBCCDDEEFF00, 8)
        + tx_root
        + state_root
    )
    body_hash = tagged("Lotus/v2/header/body", chain_id + body)
    output = {
        "dependency": f"python-blake3 {blake3.__version__}",
        "chain_id": chain_id.hex(),
        "body_hash": body_hash.hex(),
        "cases": [],
    }
    for nonce in (0x08090A0B0C0D0E0F, 0x08090A0B0C0D0E10, 0xFFFFFFFFFFFFFFFF):
        work = bits + time + le(nonce, 8) + body_hash
        work_hash = tagged("Lotus/v2/header/work", work)
        block_id = tagged("Lotus/v2/blockid", prev_id + work_hash)
        header = prev_id + bits + time + le(nonce, 8) + body
        assert len(header) == 134
        output["cases"].append(
            {
                "nonce": nonce,
                "header": header.hex(),
                "work_hash": work_hash.hex(),
                "block_id": block_id.hex(),
            }
        )
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
