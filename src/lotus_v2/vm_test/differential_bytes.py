#!/usr/bin/env python3
"""Independent Python byte-operation oracle for the native P03 VM runner.

Usage: python3 differential_bytes.py NATIVE_RUNNER
Only test data and expected outputs are generated here; no reference VM code
is imported. The native script compares every output item byte-for-byte.
"""

import random
import subprocess
import sys

runner = sys.argv[1]
rng = random.Random(0xB17E2026)


def number(value):
    return value.to_bytes(16, "little", signed=True)


def min_signed_width(value):
    if value == 0:
        return 1
    raw = value.to_bytes((value.bit_length() + 8) // 8, "little", signed=True)
    w = len(raw)
    while w > 1:
        top = raw[w - 1]
        prev = raw[w - 2]
        if (top == 0x00 and (prev & 0x80) == 0) or (top == 0xff and (prev & 0x80) != 0):
            w -= 1
        else:
            break
    return w


def bin2num_expected(value):
    if len(value) > 1024:
        return None
    v = int.from_bytes(value, "little", signed=True) if value else 0
    w = max(16, min_signed_width(v))
    return (v.to_bytes(w, "little", signed=True),)


def push(data):
    if not data:
        return b"\x4c\x00"
    if len(data) <= 75:
        return bytes((len(data),)) + data
    if len(data) < 0xfd:
        return b"\x4c" + bytes((len(data),)) + data
    return b"\x4c\xfd" + len(data).to_bytes(2, "little") + data


def check(op, arguments, expected, *, bigint=False):
    script = bytes((op,))
    status = "I" if expected is None else "S"
    if expected is not None:
        for item in reversed(expected):
            script += push(item) + b"\x92"
        script += b"\x4e"
    cmd = [runner]
    if bigint:
        cmd.append("--bigint")
    cmd.extend([script.hex(), "0", "0", *(arg.hex() for arg in arguments)])
    output = subprocess.check_output(cmd, text=True).strip()
    if output != status:
        raise SystemExit(f"{op:02x} {arguments!r}: expected {status}, got {output}")


count = 0
for _ in range(100):
    value = rng.randbytes(rng.randrange(0, 65))
    index = rng.randrange(-2, len(value) + 3)
    check(0x89, (value, number(index)),
          (value[:index], value[index:]) if 0 <= index <= len(value) else None)
    count += 1

for _ in range(100):
    value = rng.choice((rng.randrange(-(1 << 16), 1 << 16),
                        -(1 << 127), (1 << 127) - 1))
    width = rng.randrange(0, 21)
    try:
        encoded = value.to_bytes(width, "little", signed=True)
    except OverflowError:
        encoded = None
    check(0x8a, (number(value), number(width)),
          (encoded,) if encoded is not None else None)
    count += 1

for _ in range(100):
    value = rng.randbytes(rng.randrange(0, 33))
    check(0x8b, (value,), bin2num_expected(value))
    count += 1

for _ in range(100):
    a = rng.randbytes(rng.randrange(0, 33))
    b = rng.randbytes(rng.randrange(0, 33))
    check(0x8d, (a,), (bytes(byte ^ 255 for byte in a),))
    w = max(len(a), len(b))
    pa = a.ljust(w, b"\x00")
    pb = b.ljust(w, b"\x00")
    for op in (0x8e, 0x8f, 0x90):
        function = {0x8e: lambda x, y: x & y,
                    0x8f: lambda x, y: x | y,
                    0x90: lambda x, y: x ^ y}[op]
        expected = (bytes(function(x, y) for x, y in zip(pa, pb)),)
        check(op, (a, b), expected)
    lower, higher = sorted((a, b), key=lambda data: (int.from_bytes(data, "little"), len(data)))
    check(0x93, (a, b), (lower, higher))
    count += 5

for _ in range(100):
    data = rng.randbytes(rng.randrange(0, 33))
    shift = rng.choice((rng.randrange(-300, 301), -(1 << 127)))
    bits = len(data) * 8
    value = int.from_bytes(data, "little")
    moved = ((value << shift) & ((1 << bits) - 1)) if shift >= 0 else value >> -shift
    expected = moved.to_bytes(len(data), "little")
    check(0x94, (data, number(shift)), (expected,))
    count += 1

# Wide / SIMD / 1024-byte byte-operation and zero-padding vectors
for w_a, w_b in ((16, 32), (32, 16), (17, 64), (64, 256), (256, 512), (512, 1024), (1024, 1024)):
    a = rng.randbytes(w_a)
    b = rng.randbytes(w_b)
    check(0x8d, (a,), (bytes(byte ^ 255 for byte in a),), bigint=True)
    w = max(len(a), len(b))
    pa = a.ljust(w, b"\x00")
    pb = b.ljust(w, b"\x00")
    check(0x8e, (a, b), (bytes(x & y for x, y in zip(pa, pb)),), bigint=True)
    check(0x8f, (a, b), (bytes(x | y for x, y in zip(pa, pb)),), bigint=True)
    check(0x90, (a, b), (bytes(x ^ y for x, y in zip(pa, pb)),), bigint=True)
    check(0x8b, (a,), bin2num_expected(a), bigint=True)
    count += 5
check(0x8b, (b"\x00" * 1025,), None, bigint=True)
count += 1

print(f"{count} independent byte-operation vectors agree with native VM")
