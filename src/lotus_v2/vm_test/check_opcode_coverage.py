#!/usr/bin/env python3
"""Check the pinned P03 opcode inventory against the native dispatch.

Optional arguments: path to the source opcodes.json snapshot, then native
lotus_v2_vm_runner. The runner check executes every unsupported assigned byte.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

here = Path(__file__).resolve().parent
inventory = json.loads((here / "opcode_coverage.json").read_text())
entries = inventory["entries"]
assert inventory["schema"] == "lotus/v2/native-vm-opcode-coverage/v1"
assert len(entries) == 225
assert len({entry["byte"] for entry in entries}) == 225
assert all(entry["status"] in {"push", "control", "implemented", "unsupported",
                               "invalid", "prefix"}
           for entry in entries)
# EMITLOG is assigned but invalid on-chain; EXT2 is the two-byte prefix.
assert [e["byte"] for e in entries if e["status"] == "invalid"] == ["6c"]
assert [e["byte"] for e in entries if e["status"] == "prefix"] == ["ff"]
success = sorted(set(range(256)) - {int(e["byte"], 16) for e in entries})
assert success == [0x5e, 0x5f, 0x67, 0x68, 0x6d, 0x6e, 0x6f,
                   *range(0x82, 0x88), 0x95, 0x96, 0x97, 0xb5, 0xb6, 0xb7,
                   0xc4, 0xc5, 0xc6, 0xc7, *range(0xf7, 0xff)]

if len(sys.argv) >= 2:
    spec_bytes = Path(sys.argv[1]).read_bytes()
    assert hashlib.sha256(spec_bytes).hexdigest() == inventory["spec_sha256"]
    spec = json.loads(spec_bytes)["opcodes"]
    assert [(item["byte"], item["name"], item["group"]) for item in spec] == [
        (item["byte"], item["name"], item["group"]) for item in entries]

source = (here.parent / "vm.cpp").read_text()
dispatch = source[source.index("                switch (op) {"):
                  source.index('                    default:\n                        throw VmFailure("assigned opcode not implemented"')]
cases = {int(value, 16) for value in re.findall(r"case 0x([0-9a-f]{2}):", dispatch)}
push = set(range(0x00, 0x5e))
control = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x69, 0x6a, 0x6b}
assert {int(e["byte"], 16) for e in entries if e["status"] == "push"} == push
assert {int(e["byte"], 16) for e in entries if e["status"] == "control"} == control
assert cases == {int(e["byte"], 16) for e in entries
                 if e["status"] == "implemented"} | {0x60, 0x65, 0x66, 0x6b}
assert 'throw VmFailure("assigned opcode not implemented",\n                                        true)' in source

if len(sys.argv) >= 3:
    runner = sys.argv[2]
    for entry in entries:
        if entry["status"] != "unsupported":
            continue
        output = subprocess.check_output([runner, entry["byte"], "0", "0"],
                                         text=True).strip()
        assert output == "U", (entry["byte"], output)

from collections import Counter
print("P03 assigned coverage:", dict(Counter(e["status"] for e in entries)))
