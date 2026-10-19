#!/usr/bin/env python3
"""Compare the C++ P05 charge pass with the independent Python size pass.

Usage: python3 differential_cost.py PYTHON_REFERENCE_ROOT NATIVE_RUNNER
The 1+operand+result coefficients here are illustrative, not network params.
"""
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from lotus_v2_reference.vm import (  # noqa: E402
    ASSIGNED, VMError, VMProfile, decode, number, success_scan,
)
from lotus_v2_reference.vm_cost import static_size_cost  # noqa: E402


def price(operands, results):
    return 1 + sum(operands) + sum(results)


def profile(wide=False):
    return VMProfile(512, 8, 1024 if wide else 128, 16, 8,
                     2048 if wide else 256, 8, 10_000_000, 1,
                     {op: price for op in ASSIGNED})


cases = [
    ("03616263b8", (), 0, 0, False),
    ("b8", (), 0, 0, False),
    ("006101616308" + "62"*8 + "64b8", (), 0, 0, False),
    ("006179634e64", (), 0, 0, False),
    ("0061b8634e64", (), 0, 0, False),
    ("007d", (b"a"*3, b"b"*100), 0, 0, False),
    ("7d", (b"a"*3, b"b"*100, number(0)), 0, 0, False),
    ("4e69796a4e", (), 0, 0, False),
    ("4e697a6a", (), 0, 0, False),
    ("c969794e4e6b6a", (), 1, 0, False),
    ("c9694e4e6b6a", (), 1, 0, False),
    ("c969ca69796a796a", (), 3, 4, False),
    ("00e7", (), 0, 0, True),
    ("e7", (number(0),), 0, 0, True),
    ("f0", (), 0, 0, False),
    ("036162634e89", (), 0, 0, False),
    ("4e4f8a", (), 0, 0, False),
    ("01808b", (), 0, 0, False),
    ("01808d", (), 0, 0, False),
    ("018001408e", (), 0, 0, False),
    ("018001408f", (), 0, 0, False),
    ("0180014090", (), 0, 0, False),
    ("0180014093", (), 0, 0, False),
    ("01814e94", (), 0, 0, False),
    ("4e4fa1", (), 0, 0, False),
    ("4e4fa2", (), 0, 0, False),
    ("4e4fa3", (), 0, 0, False),
    ("4e4fa4", (), 0, 0, False),
    ("4e4fa5", (), 0, 0, False),
    ("4e4fad", (), 0, 0, False),
    ("4e4fae", (), 0, 0, False),
    ("4e4f50af", (), 0, 0, False),
    ("bb", (b"s"*64,b"k"*32), 1, 1, False),
    ("4ec2", (), 1, 1, False),
    ("5e4cfd", (), 0, 0, False),
    ("4cfd5e", (), 0, 0, False),
    ("0244", (), 0, 0, False),
    ("5e", (b"x"*129,), 0, 0, False),
    # Merkle: algorithm 0 is a 96-byte tagged preimage; 1–3 are 64-byte pairs.
    # A non-constant selector and an unknown proof use the four-way maximum.
    ("00c0", (b"\x11"*32, b"\x22"*64), 0, 0, False),
    ("4ec0", (b"\x11"*32, b"\x22"*64), 0, 0, False),
    ("4fc0", (b"\x11"*32, b"\x22"*64), 0, 0, False),
    ("50c0", (b"\x11"*32, b"\x22"*64), 0, 0, False),
    ("00c0", (b"\x11"*32, b""), 0, 0, False),
    ("c0", (b"\x11"*32, b"\x22"*64, number(0)), 0, 0, False),
    ("00c1", (b"\x11"*32, b"\x33"*32, b"\x22"*64), 0, 0, False),
    ("c0", (), 0, 0, False),
    ("c1", (), 0, 0, False),
    ("c969c06a", (), 2, 0, False),
    # Big-int size propagation and quadratic limb cost scaling (16B..1024B).
    ("8b", (b"\x01" * 64,), 0, 0, True),
    ("a0", (b"\x01" * 32, b"\x02" * 64), 0, 0, True),
    ("a1", (b"\x01" * 64, b"\x02" * 32), 0, 0, True),
    ("a2", (b"\x01" * 128, b"\x02" * 64), 0, 0, True),
    ("b0", (b"\x01" * 64, b"\x02" * 16, number(0)), 0, 0, True),
    ("b1", (b"\x01" * 32, b"\x02" * 64, number(1)), 0, 0, True),
    ("b2", (b"\x01" * 64, b"\x02" * 64), 0, 0, True),
    ("b3", (b"\x01" * 64,), 0, 0, True),
    ("b4", (b"\x01" * 64,), 0, 0, True),
    # 32-byte push immediately preceding NUM2BIN and PICK (non-16B literal).
    ("20" + "10" + "00" * 31 + "8a", (number(1),), 0, 0, True),
    ("20" + "00" * 32 + "7d", (number(1),), 0, 0, True),
    # Unknown-state quadratic ops include worst-case limb surcharge.
    ("79a0", (), 0, 0, True),
    ("79a1", (), 0, 0, True),
    ("79a2", (), 0, 0, True),
    ("79b2", (), 0, 0, True),
    ("79b3", (), 0, 0, True),
    ("79b4", (), 0, 0, True),
]
rng = random.Random(0x5052026)
for _ in range(256):
    a, b = rng.randrange(-12,13), rng.randrange(-12,13)
    op = rng.choice([0x9e,0x9f,0xa0,0xa6,0xa9,0xb8,0xba])
    script = bytes((0x10,)) + number(a)
    if op not in (0xb8,0xba): script += bytes((0x10,)) + number(b)
    script += bytes((op,))
    if rng.getrandbits(1): script += bytes((0x61,0x4e,0x63,0x00,0x64))
    cases.append((script.hex(), (), 0, 0, False))

arms = ("79", "4e", "b8", "4e7a", "4c00", "4e4e6b")
bodies = ("79", "7a", "4e4e6b", "794e4e6b", "00614e4e6b637964", "ca69796a79")
for _ in range(200):
    if rng.getrandbits(1):
        then_arm, else_arm = rng.choice(arms), rng.choice(arms)
        script = "0061" + then_arm + "63" + else_arm + "64b8"
        args = (b"x" * rng.randrange(0, 65),)
        inputs, outputs = 0, 0
    else:
        script = "c969" + rng.choice(bodies) + "6a4e"
        args = (b"x" * rng.randrange(0, 65),)
        inputs, outputs = rng.randrange(0, 5), rng.randrange(0, 5)
    cases.append((script, args, inputs, outputs, False))

for index, (script_hex, args, inputs, outputs, wide) in enumerate(cases):
    vm = profile(wide)
    script = bytes.fromhex(script_hex)
    try:
        if len(script) > vm.max_script_bytes or len(args) > vm.max_arguments or any(
            len(x) > vm.max_element_bytes for x in args
        ) or sum(map(len,args)) > vm.max_vm_bytes or len(args) > vm.max_stack_items:
            expected = None
        elif success_scan(script, vm):
            expected = len(script)
        else:
            ast = decode(script, vm)
            fields = {0xe7: (45,812)} if wide else None
            expected = len(script) + static_size_cost(
                ast, vm, initial_sizes=tuple(map(len,args)),
                script_length=len(script), input_count=inputs,
                output_count=outputs, field_sizes=fields).cost
    except VMError:
        expected = None
    flag = "--charge-fields" if wide else "--charge"
    output = subprocess.check_output(
        [sys.argv[2], flag, script_hex, str(inputs), str(outputs),
         *(arg.hex() for arg in args)], text=True).strip()
    actual = None if output.endswith(" -") else int(output.split()[1])
    if actual != expected:
        raise SystemExit(f"case {index} {script_hex}: Python {expected}, native {output}")
print(f"{len(cases)} Python/native P05 static charges agree")

# Authenticated output record (45-byte native output) and its path field.
# The runner builds the same shapes and derives sizes; no caller hint is passed.
from lotus_v2_reference.encoding import Output, Profile as OutputProfile, encode_output  # noqa: E402
from lotus_v2_reference.vm_context import InputView, InvocationContext  # noqa: E402
from lotus_v2_reference.vm_cost import bind_authenticated_field_sizes  # noqa: E402

derived_vm = VMProfile(512, 8, 8192, 16, 8, 16384, 8, 10_000_000, 1,
                       {op: price for op in ASSIGNED})
output_profile = OutputProfile(16, 16, 812, 8192)
derived_coin = Output(0, 1000, None, (b"\x55" * 32,), ((0,),))
derived_output = Output(0, 1000, None, (b"\x44" * 32,), ((0,),))
if len(encode_output(derived_output, output_profile)) != 45:
    raise SystemExit("native single-branch output is not 45 bytes")
derived_ctx = InvocationContext(
    (InputView(1, derived_coin),), (derived_output,), "spend", 0,
    derived_coin.branches[0], output_profile, 0, 0, None)
derived_fields = bind_authenticated_field_sizes(
    None, derived_ctx, max_element_bytes=derived_vm.max_element_bytes)
if derived_fields[0xe7] != (45,) or derived_fields[0xe6] != (2,):
    raise SystemExit(f"unexpected derived sizes {derived_fields}")


def agree_derived(script_hex, args):
    script = bytes.fromhex(script_hex)
    expected = len(script) + static_size_cost(
        decode(script, derived_vm), derived_vm,
        initial_sizes=tuple(map(len, args)), script_length=len(script),
        input_count=1, output_count=1, field_sizes=derived_fields).cost
    reported = subprocess.check_output(
        [sys.argv[2], "--charge-derived", script_hex, *(arg.hex() for arg in args)],
        text=True).strip()
    actual = None if reported.endswith(" -") else int(reported.split()[1])
    if actual != expected:
        raise SystemExit(f"derived {script_hex}: Python {expected}, native {reported}")


agree_derived("00e7", ())
agree_derived("00e6", (number(0),))
for quad_op, arity in ((0xa0, 2), (0xa1, 2), (0xa2, 2), (0xb2, 2), (0xb3, 1), (0xb4, 1)):
    op_bytes = bytes((quad_op,))
    known_1024 = static_size_cost(
        decode(op_bytes, derived_vm), derived_vm,
        initial_sizes=(1024,) * arity, script_length=1,
        input_count=0, output_count=0).cost
    unknown_cost = static_size_cost(
        decode(op_bytes, derived_vm), derived_vm,
        initial_sizes=(), script_length=1,
        input_count=0, output_count=0).cost
    if unknown_cost < known_1024:
        raise SystemExit(f"Unknown cost {unknown_cost} < Known 1024B cost {known_1024} for {quad_op:02x}")
print("derived output-record and path-field charges agree")
