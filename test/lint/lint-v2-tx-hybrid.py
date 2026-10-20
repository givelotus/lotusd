#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Check that the removed hybrid-transaction forms do not come back.

A transaction is legacy (version 1 or 2) or V2 (version 7); other versions,
including the former wrapped versions 0x80000007 and 0xC0000007, do not
decode. This lint rejects, in src/ and test/functional/:
- the removed helpers AdaptLegacy, HasStructuralV2Identity and
  IsDisallowedNonV7Tx, and the reject reason bad-txns-non-v7-format;
- the wrapped version constants, except in tests that assert they do not
  decode.
"""

import re
import subprocess
import sys

FORBIDDEN = [
    (r"\bAdaptLegacy\b", "removed legacy adaptation"),
    (r"\bHasStructuralV2Identity\b", "removed hybrid identity test"),
    (r"\bIsDisallowedNonV7Tx\b", "removed non-v7 RPC refusal"),
    (r"bad-txns-non-v7-format", "removed non-v7 reject reason"),
    (r"\b0x[8C]0000007U?\b", "wrapped transaction version"),
]

# Tests that check the wrapped versions fail to decode.
WRAPPED_VERSION_TESTS = {
    "src/test/transaction_tests.cpp",
    "test/functional/feature_tx_version.py",
}

EXCLUDED_PREFIXES = (
    "src/leveldb/",
    "src/secp256k1/",
    "src/crc32c/",
    "src/lotus_v2/vendor/",
    "test/lint/lint-v2-tx-hybrid.py",
)


def main():
    files = subprocess.check_output(
        ["git", "ls-files", "--", "src", "test/functional"], text=True
    ).split()
    errors = []
    for path in files:
        if path.startswith(EXCLUDED_PREFIXES) or not path.endswith(
            (".cpp", ".h", ".py", ".rs")
        ):
            continue
        try:
            with open(path, encoding="utf8") as f:
                lines = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(lines, 1):
            for pattern, what in FORBIDDEN:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                if what == "wrapped transaction version" and (
                    path in WRAPPED_VERSION_TESTS
                ):
                    continue
                errors.append(f"{path}:{n}: {what}: {line.strip()}")
    for e in errors:
        print(e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
