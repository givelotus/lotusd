#!/usr/bin/env python3
"""Compare deterministic P03 core scripts with the independent Python VM.

Usage: python3 differential.py PYTHON_REFERENCE_ROOT NATIVE_RUNNER
The selected scripts avoid context-dependent opcodes and P05-only rejection.
"""
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from lotus_v2_reference.vm import (  # noqa: E402
    ASSIGNED, VMError, VMProfile, UnsupportedFeature, evaluate, number,
)

profile = VMProfile(512, 8, 128, 16, 8, 256, 8, 100000, 1,
                    {op: 1 for op in ASSIGNED})
runner = sys.argv[2]
fixed = [
    ("66615e4c", (), 0, 0), ("614e635e64", (), 0, 0),
    ("5e4cfd", (), 0, 0), ("015e4e91", (), 0, 0),
    ("0244", (), 0, 0), ("4cfd01005e", (), 0, 0),
    ("4c015e5e", (), 0, 0), ("4cfd", (), 0, 0),
    ("bd", (), 0, 0), ("0064", (), 0, 0),
    ("616a64", (), 0, 0), ("4e69610069646a", (), 0, 0),
    ("0069006900696a6a6a", (), 0, 0),
    ("4d4e9e00a6", (), 0, 0), ("00696a4e", (), 0, 0),
    ("4e69614e4e6b646a4e", (), 0, 0),
    ("c96979c969794e4f6b6a666a4e", (), 1, 0),
    ("4e7a91", (), 0, 0), ("4c004c00914e91", (), 0, 0),
    ("006179634e64", (), 0, 0),
    ("03616263b820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad91", (), 0, 0),
    ("03616263ba206437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d8591", (), 0, 0),
    ("61", (number(2),), 0, 0), ("98", (number(2**127-1),), 0, 0),
    ("4e4e", (), 0, 0), ("4e4e6b", (), 0, 0),
    ("89026263920161924e", (b"abc", number(1)), 0, 0),
]
stack_cases = (
    ((1, 2), 0x72, ()),
    ((1, 2), 0x73, (1, 2, 1, 2)),
    ((1, 2, 3), 0x74, (1, 2, 3, 1, 2, 3)),
    ((1, 2, 3, 4), 0x75, (1, 2, 3, 4, 1, 2)),
    ((1, 2, 3, 4, 5, 6), 0x76, (3, 4, 5, 6, 1, 2)),
    ((1, 2, 3, 4), 0x77, (3, 4, 1, 2)),
    ((1, 2), 0x78, (1, 2, 2)),
    ((1, 2), 0x79, (1,)),
    ((1, 2), 0x7a, (1, 2, 2)),
    ((1, 2), 0x7b, (2,)),
    ((1, 2), 0x7c, (1, 2, 1)),
    ((1, 2, 1), 0x7d, (1, 2, 1)),
    ((1, 2, 3, 2), 0x7e, (2, 3, 1)),
    ((1, 2, 3), 0x7f, (2, 3, 1)),
    ((1, 2), 0x80, (2, 1)),
    ((1, 2), 0x81, (2, 1, 2)),
)
for initial, op, expected in stack_cases:
    script = (bytes(0x4d + n for n in initial) + bytes((op,)) +
              b"".join(bytes((0x4d + n, 0x92)) for n in reversed(expected)) +
              b"\x4e")
    fixed.append((script.hex(), (), 0, 0))
rng = random.Random(0x1032026)
# Generated scripts produce a Boolean from arithmetic or byte equality,
# sometimes under one or two conditional frames.
for _ in range(256):
    a, b = rng.randrange(-12, 13), rng.randrange(-12, 13)
    opcode = rng.choice([0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3,
                         0xa4, 0xa5, 0xa6, 0xa8, 0xa9, 0xaa,
                         0xad, 0xae])
    prefix = (bytes((0x10,)) + number(a) + bytes((0x10,)) + number(b) +
              bytes((opcode,)))
    if opcode in (0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xad, 0xae):
        # Convert arbitrary arithmetic result to canonical Boolean.
        prefix += bytes((0x9d,))
    if rng.getrandbits(1):
        prefix += bytes((0x61, 0x4e, 0x63, 0x00, 0x64))
    fixed.append((prefix.hex(), (), 0, 0))

for _ in range(64):
    x, lo, hi = (rng.randrange(-12, 13) for _ in range(3))
    script = b"".join(bytes((0x10,)) + number(n) for n in (x, lo, hi))
    fixed.append(((script + b"\xaf").hex(), (), 0, 0))

for index, (script_hex, args, inputs, outputs) in enumerate(fixed):
    try:
        result = evaluate(bytes.fromhex(script_hex), args, profile,
                          input_count=inputs, output_count=outputs)
        expected = "A" if result.automatic else "S"
    except UnsupportedFeature:
        expected = "U"
    except VMError:
        expected = "I"
    actual = subprocess.check_output(
        [runner, script_hex, str(inputs), str(outputs), *(arg.hex() for arg in args)],
        text=True).strip()
    if actual != expected:
        raise SystemExit(f"case {index} {script_hex}: Python {expected}, native {actual}")
print(f"{len(fixed)} Python/native P03 core cases agree")
