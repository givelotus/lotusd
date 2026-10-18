#!/usr/bin/env python3
"""Independent integer oracle for the native P03 arithmetic subset.

Usage: python3 differential_numeric.py NATIVE_RUNNER
Valid cases compare all sixteen result bytes. Invalid cases append DROP/ONE,
so an opcode accidentally accepting an invalid operand becomes a success.
No reference VM or floating-point arithmetic is used.
"""

import random
import subprocess
import sys

runner = sys.argv[1]
rng = random.Random(0xA1172026)
minimum = -(1 << 127)
maximum = (1 << 127) - 1
checked = 0


def number(value):
    assert minimum <= value <= maximum
    return value.to_bytes(16, "little", signed=True)


def check(op, arguments, expected):
    global checked
    script = bytes((op,))
    if expected is None:
        script += b"\x79\x4e"  # acceptance would yield clean true
        status = "I"
    else:
        script += b"\x10" + number(expected) + b"\x92\x4e"
        status = "S"
    result = subprocess.check_output(
        [runner, script.hex(), "0", "0", *(number(a).hex() for a in arguments)],
        text=True).strip()
    if result != status:
        raise SystemExit(f"{op:02x} {arguments}: expected {status}, got {result}")
    checked += 1


def divmod_expected(a, b):
    if b == 0 or (a == minimum and b == -1):
        return None, None
    magnitude = abs(a) // abs(b)
    quotient = -magnitude if (a < 0) != (b < 0) else magnitude
    return quotient, a - quotient * b


def mulpow2_expected(a, k):
    if a == 0 or k <= -128:
        return 0
    if k >= 128:
        return None
    if k >= 0:
        value = a * (1 << k)
    else:
        value = abs(a) >> -k
        if a < 0:
            value = -value
    return value if minimum <= value <= maximum else None


boundary = (minimum, minimum + 1, -(1 << 64), -129, -128, -7, -3, -2,
            -1, 0, 1, 2, 3, 7, 127, 128, (1 << 64), maximum - 1, maximum)
divisors = (minimum, -128, -7, -3, -2, -1, 0, 1, 2, 3, 7, 127, maximum)
exponents = (minimum, -1024, -129, -128, -127, -64, -1, 0, 1, 7,
             63, 126, 127, 128, 129, 1024, maximum)

for a in boundary:
    for b in divisors:
        quotient, remainder = divmod_expected(a, b)
        check(0xa1, (a, b), quotient)
        check(0xa2, (a, b), remainder)
    for k in exponents:
        check(0xa3, (a, k), mulpow2_expected(a, k))

for _ in range(300):
    a = rng.randrange(minimum, maximum + 1)
    b = rng.randrange(minimum, maximum + 1)
    quotient, remainder = divmod_expected(a, b)
    check(0xa1, (a, b), quotient)
    check(0xa2, (a, b), remainder)
    k = rng.choice((rng.randrange(-140, 141), rng.randrange(minimum, maximum + 1)))
    check(0xa3, (a, k), mulpow2_expected(a, k))

for a in (-2, -1, 0, 1, 2, minimum, maximum):
    for b in (-2, -1, 0, 1, 2, minimum, maximum):
        valid = a in (0, 1) and b in (0, 1)
        check(0xa4, (a, b), int(bool(a) and bool(b)) if valid else None)
        check(0xa5, (a, b), int(bool(a) or bool(b)) if valid else None)
        check(0xad, (a, b), min(a, b))
        check(0xae, (a, b), max(a, b))

for _ in range(200):
    values = (rng.randrange(minimum, maximum + 1) for _ in range(3))
    x, low, high = values
    check(0xaf, (x, low, high), int(low <= x < high))

for x, low, high in ((minimum, minimum, maximum),
                     (maximum, minimum, maximum),
                     (0, 1, 0),
                     (0, 0, 1)):
    check(0xaf, (x, low, high), int(low <= x < high))


def push_bytes(data):
    if len(data) <= 75:
        return bytes((len(data),)) + data
    if len(data) < 0xfd:
        return b"\x4c" + bytes((len(data),)) + data
    return b"\x4c\xfd" + len(data).to_bytes(2, "little") + data


def check_bigint(op, arg_bytes, expected_bytes):
    global checked
    script = bytes((op,))
    if expected_bytes is None:
        script += b"\x79\x4e"
        status = "I"
    else:
        script += push_bytes(expected_bytes) + b"\x92\x4e"
        status = "S"
    result = subprocess.check_output(
        [runner, "--bigint", script.hex(), "0", "0", *(a.hex() for a in arg_bytes)],
        text=True).strip()
    if result != status:
        raise SystemExit(f"bigint {op:02x}: expected {status}, got {result}")
    checked += 1


for w in (32, 64, 256, 512, 1024):
    w_min = -(1 << (8 * w - 1))
    w_max = (1 << (8 * w - 1)) - 1
    for _ in range(8):
        a = rng.randrange(w_min // 2, w_max // 2)
        b = rng.randrange(w_min // 4, w_max // 4) or 1
        a_b = a.to_bytes(w, "little", signed=True)
        b_b = b.to_bytes(w, "little", signed=True)
        check_bigint(0x9e, (a_b, b_b), (a + b).to_bytes(w, "little", signed=True))
        check_bigint(0x9f, (a_b, b_b), (a - b).to_bytes(w, "little", signed=True))
        q, r = divmod_expected(a, b)
        check_bigint(0xa1, (a_b, b_b), q.to_bytes(w, "little", signed=True))
        check_bigint(0xa2, (a_b, b_b), r.to_bytes(w, "little", signed=True))

print(f"{checked} independent arithmetic vectors agree with native VM")
