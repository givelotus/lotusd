#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compile the log-field key contract, including deliberate negative cases."""

import os
import shlex
import subprocess
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    requested = os.environ.get("CXX", "c++")
    compiler = [requested] if Path(requested).is_file() else shlex.split(requested)
    prefix = "#include <logging/fields.h>\nusing namespace BCLog;\n"
    cases = {
        "valid": "constexpr FieldKey<FieldType::STRING> key{FieldId::Addr};\n",
        "runtime_id": (
            "FieldKey<FieldType::STRING> key(FieldId id) { "
            "return FieldKey<FieldType::STRING>{id}; }\n"
        ),
        "wrong_type": "constexpr FieldKey<FieldType::STRING> key{FieldId::PeerId};\n",
        "out_of_range": (
            "constexpr FieldKey<FieldType::STRING> key{static_cast<FieldId>(65535)};\n"
        ),
    }
    with tempfile.TemporaryDirectory(prefix="log-key-contract-") as directory:
        for name, source in cases.items():
            path = Path(directory) / (name + ".cpp")
            path.write_text(prefix + source, encoding="utf-8")
            result = subprocess.run(
                compiler
                + ["-std=c++20", "-fsyntax-only", "-I" + str(root / "src"), str(path)],
                capture_output=True,
                text=True,
            )
            if name == "valid":
                passed = result.returncode == 0
            else:
                passed = (
                    result.returncode != 0 and "constant expression" in result.stderr
                )
            if not passed:
                print(f"Log key contract failed: {name}\n{result.stderr}")
                return 1
    print("Log field keys: valid literal accepted; runtime/type/range errors rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
