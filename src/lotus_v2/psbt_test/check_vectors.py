#!/usr/bin/env python3
"""Check the C++ codec against independent specification schema fixtures.

Vector provenance: lotus-v2 specification commits d8a3b859 and 6305e947, examples/
psbt-profile-vectors.json. These shape-only fixtures do not authenticate
coins or demonstrate valid signatures or VM execution.
"""

import json
import subprocess
import sys
from pathlib import Path


def main():
    fixtures = json.loads(Path(__file__).with_name("profile_vectors.json").read_text())
    total = 0
    for kind in ("positive", "negative"):
        for fixture in fixtures[kind]:
            result = subprocess.run(
                [sys.argv[1], "--roundtrip", fixture["hex"]],
                capture_output=True,
                text=True,
                check=False,
            )
            if kind == "positive":
                assert result.returncode == 0, (fixture["name"], result.stderr)
                assert result.stdout.strip() == fixture.get(
                    "canonical_hex", fixture["hex"]
                ), fixture["name"]
            else:
                assert result.returncode != 0, fixture["name"]
            total += 1
    print(f"{total} independent native PSBT schema vectors passed")


if __name__ == "__main__":
    main()
