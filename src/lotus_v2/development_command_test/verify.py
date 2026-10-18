#!/usr/bin/env python3
"""Explicit offline daemon check using independently generated reference artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--daemon', type=Path, required=True)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--reference', type=Path, required=True)
p.add_argument('--first-block', type=Path, required=True)
p.add_argument('--work-dir', type=Path)
a = p.parse_args()
root = a.work_dir
if root is None:
    root = Path(tempfile.mkdtemp(prefix='lotus-v2-command-'))
else:
    root.mkdir()  # Never reuse/reset a prior run.
root = root.resolve()
reference = json.loads(a.reference.read_text())
manifest = a.manifest.resolve()
records = []

def run(label, args, expected=0, home=None, config=manifest):
    cmd = [str(a.daemon.resolve()), '-lotusv2development', str(config),
           str(home or root / 'home'), *args]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    records.append(dict(label=label, argv=cmd, exit=result.returncode,
                        stdout=result.stdout, stderr=result.stderr))
    (root / 'evidence.json').write_text(json.dumps(records, indent=2) + '\n')
    assert result.returncode == expected, records[-1]
    return json.loads(result.stdout) if result.stdout else None

initial = run('genesis', ['status'])
assert initial['tip'] == reference['genesis_id']
assert initial['state_root'] == reference['genesis_stateroot']
child = run('first-block', ['submit', str(a.first_block.resolve())])
assert child['accepted'] and child['height'] == 1
assert child['tip'] == reference['first_id']
assert child['state_root'] == reference['first_stateroot']
assert child['charges']['invocation'] == '0'
assert child['charges']['account'] == str(reference['block_cost'])
assert child['charges']['enforce'] == str(reference['block_cost'])
assert child['charges']['fees'] == '0'
assert int(child['charges']['subsidy']) - reference['payout'] == int(child['charges']['actual_underclaim'])
assert int(child['charges']['required_underclaim']) <= int(child['charges']['actual_underclaim'])
assert run('restart-child', ['status']) == {key: child[key] for key in initial}
parent = run('disconnect', ['disconnect', reference['first_id']])
assert all(parent[key] == value for key, value in initial.items())
assert run('restart-parent', ['status']) == initial
refused = run('genesis-guard', ['disconnect', reference['genesis_id']], 4)
assert refused['tip'] == initial['tip'] and 'cannot disconnect genesis' in refused['error']
bad = bytearray(a.first_block.read_bytes())
assert bad
bad[-1] ^= 1
(root / 'mutated.block').write_bytes(bad)
rejected = run('reject-body', ['submit', str(root / 'mutated.block')], 2)
assert not rejected['accepted'] and rejected['tip'] == initial['tip']
assert 'charges' not in rejected
assert run('restart-after-reject', ['status']) == initial
assert run('reconnect', ['submit', str(a.first_block.resolve())])['tip'] == child['tip']
legacy = root / 'legacy-looking'
legacy.mkdir()
(legacy / 'blocks').mkdir()
(legacy / 'wallet.dat').write_bytes(b'disposable legacy-looking test fixture')
before = hashlib.sha256((legacy / 'wallet.dat').read_bytes()).digest()
run('refuse-legacy-directory', ['status'], 1, home=legacy)
assert sorted(entry.name for entry in legacy.iterdir()) == ['blocks', 'wallet.dat']
assert hashlib.sha256((legacy / 'wallet.dat').read_bytes()).digest() == before
for label, change in [
    ('unknown-field', lambda m: m.update(unknown=1)),
    ('overflow', lambda m: m.update(future_window=str(1 << 64))),
    ('missing-cost', lambda m: m['opcode_costs'][0].__setitem__(0, 0)),
]:
    config = root / (label + '.json')
    value = json.loads(manifest.read_text())
    change(value)
    config.write_text(json.dumps(value))
    home = root / label
    run(label, ['status'], 1, home=home, config=config)
    assert not (home / 'chainstate-v2').exists()
print(f'Offline daemon checks passed; preserved evidence: {root}')
