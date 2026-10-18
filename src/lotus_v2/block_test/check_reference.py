#!/usr/bin/env python3
"""Differential ordinary-block roots and reject reasons.

Usage: check_reference.py NATIVE_TEST_EXE PATH_TO_lotus-v2-reference
The reference source is supplied explicitly; no source is copied into this tree.
This compares a standalone model. It does not mean lotusd parsed or accepted a block.
"""

import subprocess
import sys
from pathlib import Path

reference_root = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(reference_root))
sys.path.insert(0, str(reference_root / "tests"))
from test_block import reference_report  # noqa: E402

expected = reference_report()
result = subprocess.run([sys.argv[1], "--report"], text=True, capture_output=True, check=True)
actual = {}
for line in result.stdout.splitlines():
    key, value = line.split(" ", 1)
    actual[key] = value
missing = [key for key in expected if key not in actual and key not in
           ("over_root_unchanged", "bad_root_unchanged")]
if missing:
    raise SystemExit(f"native report missing {missing}")
compared = 0
for key, want in expected.items():
    if key in ("over_root_unchanged", "bad_root_unchanged"):
        continue
    got = actual[key]
    if got != want:
        raise SystemExit(f"{key}: native {got} != python {want}")
    compared += 1
print(f"{compared} Python/native ordinary-block fields matched")
