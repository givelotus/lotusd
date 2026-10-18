#!/usr/bin/env python3
"""Independent vectors for P03 b0-b4 (wide/unsigned math) and bd CHECKDATASIG.

Usage: python3 differential_wide.py NATIVE_RUNNER [PYTHON_REFERENCE_ROOT]

The oracle here uses only Python big integers, `decimal`, `math.isqrt`, the
published BIP340 CSV (bip340_test_vectors.csv, SHA-256 pinned below), the
RFC 6979 A.2.5 P-256 key/signatures, and a self-contained affine elliptic
curve implementation for ECDSA signing/verification (not OpenSSL or
libsecp256k1). With a reference root, every vector is also evaluated by the
Python reference VM and all three verdicts must agree.

Valid cases compare all result bytes with EQUALVERIFY; invalid cases drop the
results and push ONE, so an operation that wrongly accepts becomes success.
With a reference root, static charges under the illustrative 1+operand+result
schedule are compared as well. Profile 2 is strict prime-subgroup Ed25519.
"""

import hashlib
import math
import random
import subprocess
import sys
from decimal import Decimal, getcontext
from pathlib import Path

runner = sys.argv[1]
reference = None
charge_profile = None
reference_bigint = None
charge_profile_bigint = None
if len(sys.argv) >= 3:
    sys.path.insert(0, str(Path(sys.argv[2]).resolve()))
    from lotus_v2_reference.vm import (  # noqa: E402
        ASSIGNED, UnsupportedFeature, VMError, VMProfile, decode, evaluate,
        success_scan,
    )
    from lotus_v2_reference.vm_cost import static_size_cost  # noqa: E402
    reference = VMProfile(512, 8, 128, 16, 8, 256, 8, 100000, 1,
                          {op: 1 for op in ASSIGNED})
    reference_bigint = VMProfile(8192, 16, 2048, 32, 16, 16384, 8, 10_000_000, 1,
                                 {op: 1 for op in ASSIGNED})

    def price(operands, results):
        return 1 + sum(operands) + sum(results)

    charge_profile = VMProfile(512, 8, 128, 16, 8, 256, 8, 10_000_000, 1,
                               {op: price for op in ASSIGNED})
    charge_profile_bigint = VMProfile(8192, 16, 2048, 32, 16, 16384, 8, 10_000_000, 1,
                                      {op: price for op in ASSIGNED})

here = Path(__file__).resolve().parent
BIP340_CSV_SHA256 = "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d"
MIN = -(1 << 127)
MAX = (1 << 127) - 1
U_MAX = (1 << 128) - 1
rng = random.Random(0xB0B42026)
counts: dict[str, int] = {}


def n(value):
    assert MIN <= value <= MAX
    return value.to_bytes(16, "little", signed=True)


def u(value):
    assert 0 <= value <= U_MAX
    return value.to_bytes(16, "little")


def push(data):
    if not data:
        return b"\x4c\x00"
    if len(data) <= 75:
        return bytes((len(data),)) + data
    if len(data) < 0xfd:
        return b"\x4c" + bytes((len(data),)) + data
    return b"\x4c\xfd" + len(data).to_bytes(2, "little") + data


def run_reference(script, args, *, bigint=False):
    prof = reference_bigint if bigint else reference
    try:
        result = evaluate(script, tuple(args), prof)
        return "A" if result.automatic else "S"
    except UnsupportedFeature:
        return "U"
    except VMError:
        return "I"


def check(group, op, args, results, *, status=None, result_count=1, bigint=False):
    """results: tuple of expected stack items (deepest first) or None."""
    script = bytes((op,))
    if results is None:
        script += b"\x79" * result_count + b"\x4e"
        expected = status or "I"
    else:
        for item in reversed(results):
            script += push(item) + b"\x92"
        script += b"\x4e"
        expected = "S"
    flag = "--charge-bigint" if bigint else "--charge"
    output = subprocess.check_output(
        [runner, flag, script.hex(), "0", "0", *(a.hex() for a in args)],
        text=True).strip()
    actual, _, cost_text = output.partition(" ")
    if actual != expected:
        raise SystemExit(f"{group} {op:02x} {[a.hex() for a in args]}: "
                         f"oracle {expected}, native {output}")
    if reference is not None:
        python = run_reference(script, args, bigint=bigint)
        expected_py = "I" if expected == "E" else expected
        if python != expected_py and not (python == "U" and group in ("BIP340", "SELECTOR")):
            raise SystemExit(f"{group} {op:02x} {[a.hex() for a in args]}: "
                             f"oracle {expected_py}, Python reference {python}")
        cp = charge_profile_bigint if bigint else charge_profile
        try:
            if (len(script) > cp.max_script_bytes or
                    len(args) > cp.max_arguments or
                    any(len(item) > cp.max_element_bytes for item in args) or
                    sum(map(len, args)) > cp.max_vm_bytes or
                    len(args) > cp.max_stack_items):
                expected_cost = None
            elif success_scan(script, cp):
                expected_cost = len(script)
            else:
                ast = decode(script, cp)
                expected_cost = len(script) + static_size_cost(
                    ast, cp, initial_sizes=tuple(map(len, args)),
                    script_length=len(script), input_count=0,
                    output_count=0).cost
        except VMError:
            expected_cost = None
        actual_cost = None if cost_text == "-" else int(cost_text)
        if actual_cost != expected_cost:
            raise SystemExit(f"{group} {op:02x} {[a.hex() for a in args]}: "
                             f"cost Python {expected_cost}, native {output}")
    counts[group] = counts.get(group, 0) + 1


# ---------------------------------------------------------------- integers
U_BOUNDARY = (0, 1, 2, 3, (1 << 63), (1 << 64) - 1, 1 << 64, (1 << 64) + 1,
              (1 << 127) - 1, 1 << 127, (1 << 127) + 1, U_MAX - 1, U_MAX)


def u_random():
    return rng.choice((rng.getrandbits(128), rng.getrandbits(64),
                       U_MAX - rng.getrandbits(64), rng.getrandbits(8)))


def add_carry(a, b, c, w=16):
    total = a + b + c
    mask = (1 << (8 * w)) - 1
    return ((total & mask).to_bytes(w, "little"), n(total >> (8 * w)))


def sub_carry(a, b, c, w=16):
    mod = 1 << (8 * w)
    return (((a - b - c) % mod).to_bytes(w, "little"), n(int(a < b + c)))


def mul_wide(a, b, w=16):
    product = a * b
    mask = (1 << (8 * w)) - 1
    return ((product >> (8 * w)).to_bytes(w, "little"), (product & mask).to_bytes(w, "little"))


pairs = [(a, b) for a in U_BOUNDARY for b in U_BOUNDARY]
pairs += [(u_random(), u_random()) for _ in range(150)]
for a, b in pairs:
    for c in (0, 1):
        check("ADDCARRY", 0xb0, (u(a), u(b), n(c)), add_carry(a, b, c))
        check("SUBCARRY", 0xb1, (u(a), u(b), n(c)), sub_carry(a, b, c))
    check("MUL128_WIDE", 0xb2, (u(a), u(b)), mul_wide(a, b))

# Automatic zero-padding on short/mismatched byte widths in ADDCARRY, SUBCARRY, MUL128_WIDE
check("ADDCARRY", 0xb0, (u(1)[:15], u(1), n(0)), add_carry(1, 1, 0, 16))
check("ADDCARRY", 0xb0, (u(1), u(1) + b"\x00", n(0)), add_carry(1, 1, 0, 17))
check("ADDCARRY", 0xb0, (b"", u(1), n(1)), add_carry(0, 1, 1, 16))
check("SUBCARRY", 0xb1, (u(1)[:15], u(1), n(0)), sub_carry(1, 1, 0, 16))
check("SUBCARRY", 0xb1, (u(1), u(1) + b"\x00", n(0)), sub_carry(1, 1, 0, 17))
check("SUBCARRY", 0xb1, (b"", u(1), n(1)), sub_carry(0, 1, 1, 16))
check("MUL128_WIDE", 0xb2, (u(1)[:15], u(1)), mul_wide(1, 1, 16))
check("MUL128_WIDE", 0xb2, (u(1), u(1) + b"\x00"), mul_wide(1, 1, 17))

for op in (0xb0, 0xb1):
    group = "ADDCARRY" if op == 0xb0 else "SUBCARRY"
    for bad_carry in (-1, 2, 3, MAX, MIN):
        check(group, op, (u(1), u(1), n(bad_carry)), None, result_count=2)
    for args in ((u(1), u(1), n(0)[:15]), (u(1), n(0)), (n(0),)):
        check(group, op, args, None, result_count=2)
    check(group, op, (b"\x00" * 1025, u(1), n(0)), None, result_count=2, bigint=True)
for args in ((u(1),), ()):
    check("MUL128_WIDE", 0xb2, args, None, result_count=2)
check("MUL128_WIDE", 0xb2, (b"\x00" * 1025, u(1)), None, result_count=2, bigint=True)


def log2_q64(x):
    """Literal transcription of the P03 LOG2_Q64 recurrence."""
    e = x.bit_length() - 1
    k = max(127, e)
    z = x << (k - e)
    f = 0
    for _ in range(64):
        t = (z * z) >> k
        bit = 1 if t >= (1 << (k + 1)) else 0
        z = t >> 1 if bit else t
        f = 2 * f + bit
    return e * (1 << 64) + f


getcontext().prec = 140
LN2 = Decimal(2).ln()
max_log_gap = 0


def exact_floor_log2_q64(x):
    """floor(log2(x) * 2^64) via 140-digit decimal; None if too close to tie."""
    if x & (x - 1) == 0:
        return (x.bit_length() - 1) << 64
    scaled = Decimal(x).ln() / LN2 * (Decimal(2) ** 64)
    floor = int(scaled)
    if scaled - floor < Decimal(10) ** -40 or floor + 1 - scaled < Decimal(10) ** -40:
        return None
    return floor


log_inputs = {1, 2, 3, 5, 7, 10, 255, 256, 257, MAX, MAX - 1}
for k in range(1, 127):
    log_inputs.update({(1 << k) - 1, 1 << k, (1 << k) + 1})
log_inputs.update(rng.randrange(1, MAX + 1) for _ in range(200))
log_inputs.update(rng.randrange(1, 1 << rng.randrange(1, 127)) for _ in range(200))
for x in sorted(log_inputs):
    value = log2_q64(x)
    exact = exact_floor_log2_q64(x)
    if exact is not None:
        # The fixed recurrence truncates z each round, so it never exceeds the
        # exact floor and stays within a small number of 2^-64 units of it.
        assert value <= exact, (x, value, exact)
        max_log_gap = max(max_log_gap, exact - value)
        assert exact - value <= 64, (x, value, exact)
    check("LOG", 0xb3, (n(x),), (n(value),))
check("LOG", 0xb3, (n(1) + b"\x00",), (n(0),))
for bad in (0, -1, -2, MIN, MIN + 1):
    check("LOG", 0xb3, (n(bad),), None)
for args in ((n(1)[:15],), (b"",), ()):
    check("LOG", 0xb3, args, None)
check("LOG", 0xb3, (b"\x01" + b"\x00" * 1024,), None, bigint=True)

sqrt_inputs = {0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17, MAX, MAX - 1,
               math.isqrt(MAX) ** 2, math.isqrt(MAX) ** 2 - 1,
               (1 << 126), (1 << 126) - 1, (1 << 64), (1 << 64) - 1}
for k in range(1, 64):
    sqrt_inputs.update({k * k, k * k - 1, (1 << (2 * k)) - 1, (1 << (2 * k)) + 1})
sqrt_inputs.update(rng.randrange(0, MAX + 1) for _ in range(200))
sqrt_inputs.update(rng.randrange(0, 1 << 64) ** 2 for _ in range(50))
for x in sorted(v for v in sqrt_inputs if 0 <= v <= MAX):
    check("SQRT", 0xb4, (n(x),), (n(math.isqrt(x)),))
check("SQRT", 0xb4, (n(4) + b"\x00",), (n(2) + b"\x00",))
for bad in (-1, -4, MIN, MIN + 1):
    check("SQRT", 0xb4, (n(bad),), None)
for args in ((n(4)[:15],), ()):
    check("SQRT", 0xb4, args, None)
check("SQRT", 0xb4, (b"\x04" + b"\x00" * 1024,), None, bigint=True)


# ------------------------------------------------------------- signatures
class Curve:
    def __init__(self, name, p, a, b, gx, gy, order):
        self.name, self.p, self.a, self.b, self.n = name, p, a, b, order
        self.g = (gx, gy)
        assert self.on_curve(self.g)
        assert self.mul(order, self.g) is None

    def on_curve(self, point):
        x, y = point
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        (x1, y1), (x2, y2) = p1, p2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
        if p1 == p2:
            slope = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p)
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, self.p)
        x3 = (slope * slope - x1 - x2) % self.p
        return (x3, (slope * (x1 - x3) - y1) % self.p)

    def mul(self, k, point):
        result = None
        while k:
            if k & 1:
                result = self.add(result, point)
            point = self.add(point, point)
            k >>= 1
        return result

    def compress(self, point):
        return bytes((2 + (point[1] & 1),)) + point[0].to_bytes(32, "big")

    def lift_x(self, x):
        """Some y with (x, y) on the curve, or None (both p are 3 mod 4)."""
        rhs = (x * x * x + self.a * x + self.b) % self.p
        y = pow(rhs, (self.p + 1) // 4, self.p)
        return y if y * y % self.p == rhs else None

    def verify(self, key, sig, msg):
        """Oracle verdict: True/False, or None for a script error."""
        if len(key) != 33 or key[0] not in (2, 3) or len(sig) != 64:
            return None
        x = int.from_bytes(key[1:], "big")
        if x >= self.p:
            return None
        y = self.lift_x(x)
        if y is None:
            return None
        if (y & 1) != (key[0] & 1):
            y = self.p - y
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        if not (1 <= r < self.n and 1 <= s <= self.n // 2):
            return False
        e = int.from_bytes(msg, "big")
        w = pow(s, -1, self.n)
        point = self.add(self.mul(e * w % self.n, self.g),
                         self.mul(r * w % self.n, (x, y)))
        return point is not None and point[0] % self.n == r

    def sign_raw(self, d, msg, k):
        point = self.mul(k, self.g)
        r = point[0] % self.n
        s = pow(k, -1, self.n) * (int.from_bytes(msg, "big") + r * d) % self.n
        return r, s

    @staticmethod
    def pack(r, s):
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


P256 = Curve("P-256", 2**256 - 2**224 + 2**192 + 2**96 - 1,
             2**256 - 2**224 + 2**192 + 2**96 - 1 - 3,
             0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
             0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
             0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
             0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)
SECP = Curve("secp256k1", 2**256 - 2**32 - 977, 0, 7,
             0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
             0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def datasig(group, sig, msg, key, algorithm, verdict, status=None):
    args = (sig, msg, key, n(algorithm))
    if verdict is None:
        if (status is None and algorithm == 1 and len(msg) == 32 and
                len(key) == 33 and key[0] in (2, 3) and len(sig) == 64):
            status = "E"
        check(group, 0xbd, args, None, status=status)
    else:
        check(group, 0xbd, args, (n(int(verdict)),))


# BIP340 published vectors: profile 0 uses exact 32-byte messages, so other
# message sizes and invalid x-only keys are script errors.
csv_bytes = (here / "bip340_test_vectors.csv").read_bytes()
assert hashlib.sha256(csv_bytes).hexdigest() == BIP340_CSV_SHA256
for line in csv_bytes.decode().splitlines()[1:]:
    fields = line.split(",")
    index, key, msg, sig, result = (fields[0], bytes.fromhex(fields[2]),
                                    bytes.fromhex(fields[4]),
                                    bytes.fromhex(fields[5]), fields[6])
    comment = ",".join(fields[7:])
    if len(msg) != 32 or "public key" in comment:
        verdict = None
    else:
        verdict = result == "TRUE"
    datasig("BIP340", sig, msg, key, 0, verdict)
    if verdict:
        flipped = bytes((msg[0] ^ 1,)) + msg[1:]
        datasig("BIP340", sig, flipped, key, 0, False)
        datasig("BIP340", sig[:63], msg, key, 0, None)
        datasig("BIP340", sig + b"\x01", msg, key, 0, None)
        datasig("BIP340", sig, msg, b"\x02" + key, 0, None)
        # Same bytes under a different selector are not a BIP340 check.
        datasig("BIP340", sig, msg, key, 3, None)

# RFC 6979 A.2.5 (P-256, SHA-256): published r||s are standard ECDSA; this
# profile requires low-S, so the high-S "sample" signature is false and its
# negation n-s is true.
rfc_d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
rfc_q = P256.mul(rfc_d, P256.g)
assert rfc_q == (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
                 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
rfc_key = P256.compress(rfc_q)
for text, r, s in (
    (b"sample", 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
     0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
    (b"test", 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
     0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
):
    digest = hashlib.sha256(text).digest()
    low, high = (s, P256.n - s) if s <= P256.n // 2 else (P256.n - s, s)
    datasig("P256-RFC6979", P256.pack(r, low), digest, rfc_key, 1, True)
    datasig("P256-RFC6979", P256.pack(r, high), digest, rfc_key, 1, False)
    # Not hashed again: the SHA-256 of the digest is a different message.
    datasig("P256-RFC6979", P256.pack(r, low), hashlib.sha256(digest).digest(),
            rfc_key, 1, False)


def ecdsa_cases(curve, algorithm, count):
    group = f"ECDSA-{curve.name}"
    other = SECP if curve is P256 else P256
    for i in range(count):
        d = rng.randrange(1, curve.n)
        q = curve.mul(d, curve.g)
        key = curve.compress(q)
        msg = rng.choice((rng.randbytes(32), b"\xff" * 32, bytes(32),
                          curve.n.to_bytes(32, "big")))
        r, s = curve.sign_raw(d, msg, rng.randrange(1, curve.n))
        low = min(s, curve.n - s)
        sig = curve.pack(r, low)
        assert curve.verify(key, sig, msg) is True
        datasig(group, sig, msg, key, algorithm, True)
        datasig(group, curve.pack(r, curve.n - low), msg, key, algorithm, False)
        datasig(group, sig, bytes((msg[0] ^ 0x80,)) + msg[1:], key, algorithm,
                curve.verify(key, sig, bytes((msg[0] ^ 0x80,)) + msg[1:]))
        if i % 4 == 0:
            datasig(group, curve.pack(0, low), msg, key, algorithm, False)
            datasig(group, curve.pack(r, 0), msg, key, algorithm, False)
            datasig(group, curve.pack(curve.n, low), msg, key, algorithm, False)
            datasig(group, curve.pack(r + curve.n if r + curve.n < 2**256 else r,
                                      low), msg, key, algorithm,
                    False if r + curve.n < 2**256 else True)
            datasig(group, curve.pack(r, curve.n), msg, key, algorithm, False)
            datasig(group, sig[:63], msg, key, algorithm, None)
            datasig(group, sig + b"\x00", msg, key, algorithm, None)
            datasig(group, sig, msg[:31], key, algorithm, None)
            datasig(group, sig, msg + b"\x00", key, algorithm, None)
            datasig(group, sig, msg, key[1:], algorithm, None)        # x-only
            datasig(group, sig, msg, b"\x04" + key[1:], algorithm, None)
            datasig(group, sig, msg, bytes((key[0] ^ 1,)) + key[1:], algorithm,
                    curve.verify(bytes((key[0] ^ 1,)) + key[1:], sig, msg))
            # A key valid on the other curve, or a 32-byte x-only key.
            other_key = other.compress(other.mul(rng.randrange(1, other.n), other.g))
            datasig(group, sig, msg, other_key, algorithm,
                    curve.verify(other_key, sig, msg))
        # Boundary s exactly floor(n/2) (valid) and floor(n/2)+1 (high-S):
        # solve for the private key that makes the chosen s verify.
        if i % 8 == 0:
            for target, verdict in ((curve.n // 2, True), (curve.n // 2 + 1, False)):
                k = rng.randrange(1, curve.n)
                r = curve.mul(k, curve.g)[0] % curve.n
                e = int.from_bytes(msg, "big")
                d2 = (target * k - e) * pow(r, -1, curve.n) % curve.n
                key2 = curve.compress(curve.mul(d2, curve.g))
                sig2 = curve.pack(r, target)
                assert curve.verify(key2, sig2, msg) is verdict
                datasig(group, sig2, msg, key2, algorithm, verdict)


ecdsa_cases(P256, 1, 48)
ecdsa_cases(SECP, 3, 48)

# Invalid compressed keys: x >= p and x with no curve point are errors.
for curve, algorithm in ((P256, 1), (SECP, 3)):
    group = f"ECDSA-{curve.name}"
    sig = curve.pack(1, 1)
    x = curve.p + 1
    while x < 2**256 and curve.lift_x(x % curve.p) is None:
        x += 1
    if x < 2**256:
        datasig(group, sig, bytes(32), b"\x02" + x.to_bytes(32, "big"), algorithm, None)
    datasig(group, sig, bytes(32), b"\x02" + curve.p.to_bytes(32, "big"), algorithm, None)
    x = 1
    while curve.lift_x(x) is not None:
        x += 1
    datasig(group, sig, bytes(32), b"\x03" + x.to_bytes(32, "big"), algorithm, None)
    datasig(group, sig, bytes(32), bytes(33), algorithm, None)

# Strict prime-subgroup Ed25519. Identity satisfies [0]B = I + [h]I and must
# still be false. Torsion and S >= L are false. Non-canonical keys error.
ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = (-121665 * pow(121666, -1, ED_P)) % ED_P
ED_I = pow(2, (ED_P - 1) // 4, ED_P)


def ed_decode(encoded):
    if len(encoded) != 32:
        return None
    raw = int.from_bytes(encoded, "little")
    sign, y = raw >> 255, raw & ((1 << 255) - 1)
    if y >= ED_P:
        return None
    u, v = (y * y - 1) % ED_P, (ED_D * y * y + 1) % ED_P
    root = pow(u * pow(v, ED_P - 2, ED_P) % ED_P, (ED_P + 3) // 8, ED_P)
    squared = (v * root * root) % ED_P
    if squared == u:
        x = root
    elif squared == (-u) % ED_P:
        x = (root * ED_I) % ED_P
    else:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = ED_P - x
    return x, y


def ed_encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    product = (ED_D * x1 * x2 * y1 * y2) % ED_P
    return (
        ((x1 * y2 + y1 * x2) * pow(1 + product, -1, ED_P)) % ED_P,
        ((y1 * y2 + x1 * x2) * pow(1 - product, -1, ED_P)) % ED_P,
    )


def ed_mul(scalar, point):
    result = (0, 1)
    acc = point
    while scalar:
        if scalar & 1:
            result = ed_add(result, acc)
        acc = ed_add(acc, acc)
        scalar >>= 1
    return result


ED_B = ed_decode(bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"))
assert ED_B is not None


def ed_sign(secret, message, nonce):
    public = ed_encode(ed_mul(secret, ED_B))
    commitment = ed_encode(ed_mul(nonce, ED_B))
    challenge = int.from_bytes(
        hashlib.sha512(commitment + public + message).digest(), "little") % ED_L
    scalar = (nonce + challenge * secret) % ED_L
    return commitment + scalar.to_bytes(32, "little"), public


ed_msg = bytes(range(32))
openssl_pub = bytes.fromhex(
    "3f067e7a49d4c45ea20c02b956a13fcfdb7a561eb04f0ef38d91584185c14156")
openssl_sig = bytes.fromhex(
    "a56c91974ad4f6bb1aea3aeb41c4879abc74d4cd9a40b1cbb6115434359ed66a"
    "8ae2147268bf7f34e024082bc8f8c109c53b57363bccfcb84910bcce8549010d")
datasig("ED25519", openssl_sig, ed_msg, openssl_pub, 2, True)
datasig("ED25519", openssl_sig, bytes((ed_msg[0] ^ 1,)) + ed_msg[1:],
        openssl_pub, 2, False)
for bad_sig, bad_msg, bad_key in (
        (openssl_sig[:63], ed_msg, openssl_pub),
        (openssl_sig + b"\x00", ed_msg, openssl_pub),
        (openssl_sig, ed_msg[:31], openssl_pub),
        (openssl_sig, ed_msg + b"\x00", openssl_pub),
        (openssl_sig, ed_msg, openssl_pub[:31]),
        (openssl_sig, ed_msg, b"\x00" + openssl_pub),
        (openssl_sig, ed_msg, ED_P.to_bytes(32, "little")),
):
    datasig("ED25519", bad_sig, bad_msg, bad_key, 2, None)
identity = bytes.fromhex("01" + "00" * 31)
datasig("ED25519", openssl_sig, ed_msg, identity[:-1] + bytes((0x80,)), 2, None)
# S = 0 and R = A = identity meets the group equation and is still rejected.
datasig("ED25519", identity + bytes(32), ed_msg, identity, 2, False)
datasig("ED25519", bytes(64), ed_msg, bytes(32), 2, False)
base_point = ed_encode(ED_B)
datasig("ED25519", base_point + ED_L.to_bytes(32, "little"), ed_msg,
        base_point, 2, False)
lifted = bytearray(openssl_sig)
lifted[32:] = (int.from_bytes(openssl_sig[32:], "little") + ED_L).to_bytes(32, "little")
datasig("ED25519", bytes(lifted), ed_msg, openssl_pub, 2, False)
for _ in range(6):
    secret, nonce = rng.randrange(1, ED_L), rng.randrange(1, ED_L)
    message = rng.randbytes(32)
    signature, public = ed_sign(secret, message, nonce)
    datasig("ED25519", signature, message, public, 2, True)
    datasig("ED25519", signature, bytes((message[0] ^ 0x80,)) + message[1:],
            public, 2, False)
    over = bytearray(signature)
    over[32:] = (int.from_bytes(signature[32:], "little") + ED_L).to_bytes(32, "little")
    datasig("ED25519", bytes(over), message, public, 2, False)

# Selector framing: outside 0..3 is a script error, including after profile 2.
any_sig, any_key = bytes(64), b"\x02" + SECP.g[0].to_bytes(32, "big")
for algorithm in (-1, 4, 5, 255, MAX, MIN):
    datasig("SELECTOR", any_sig, bytes(32), any_key, algorithm, None)
# A 32-zero key is canonical torsion: false, not a script error.
datasig("SELECTOR", bytes(64), bytes(32), bytes(32), 2, False)
for sig, msg, key in ((b"", b"", b""), (bytes(64), bytes(31), bytes(32))):
    datasig("SELECTOR", sig, msg, key, 2, None)
check("SELECTOR", 0xbd, (bytes(64), bytes(32), any_key, n(0)[:15]), None)
check("SELECTOR", 0xbd, (bytes(32), any_key, n(3)), None)

# Big-int wide vectors across 32B, 64B, 256B, 1024B
for w in (32, 64, 256, 1024):
    a_val = rng.getrandbits(8 * w - 2) + 1
    b_val = rng.getrandbits(8 * (w // 2))
    a_u = a_val.to_bytes(w, "little")
    b_u = b_val.to_bytes(w // 2, "little")
    check("ADDCARRY", 0xb0, (a_u, b_u, n(1)), add_carry(a_val, b_val, 1, w), bigint=True)
    check("SUBCARRY", 0xb1, (a_u, b_u, n(0)), sub_carry(a_val, b_val, 0, w), bigint=True)
    check("MUL128_WIDE", 0xb2, (a_u, b_u), mul_wide(a_val, b_val, w), bigint=True)
    a_s = a_val.to_bytes(w, "little", signed=True)
    check("LOG", 0xb3, (a_s,), (n(log2_q64(a_val)),), bigint=True)
    check("SQRT", 0xb4, (a_s,), (math.isqrt(a_val).to_bytes(w, "little", signed=True),), bigint=True)

# Half-ULP LOG2_Q64 boundary checks for e > 127 (requires full k = max(127, e) precision)
for e_test, w_test in ((128, 32), (256, 64), (1024, 256)):
    root = math.isqrt(1 << (2 * e_test + 1))
    for candidate in (root, root + 1):
        c_bytes = candidate.to_bytes(w_test, "little", signed=True)
        check("LOG", 0xb3, (c_bytes,), (n(log2_q64(candidate)),), bigint=True)

total = sum(counts.values())
print(f"{total} independent wide-math/CHECKDATASIG vectors agree "
      f"({'native + Python reference' if reference else 'native'}): "
      + ", ".join(f"{k} {v}" for k, v in counts.items())
      + f"; max LOG2_Q64 gap below exact floor = {max_log_gap} units of 2^-64")
