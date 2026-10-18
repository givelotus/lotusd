#!/usr/bin/env python3
"""Explicitly translate the documented proposal artifacts; never select defaults."""
import argparse
import hashlib
import json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--parameters', type=Path, required=True)
p.add_argument('--reference', type=Path, required=True)
p.add_argument('--output-dir', type=Path, required=True)
p.add_argument('--max-steps', type=int, required=True, help='Explicit native host-work guard')
p.add_argument('--block-read-limit', type=int, required=True, help='Local command capacity, not consensus')
a = p.parse_args()
assert a.max_steps > 0 and a.block_read_limit > 0
raw = a.parameters.read_bytes()
r = json.loads(a.reference.read_text())
assert hashlib.sha256(raw).hexdigest() == r['parameter_sha256']
lines = raw.decode('ascii').splitlines()
assert lines[0] == 'Lotus/v2/development-profile/1'
values = dict(line.split('=', 1) for line in lines[1:])
assert len(values) == len(lines) - 1
n = lambda key: int(values[key])
assert n('tail_formula_version') == 1
assert n('genesis_tail') == n('initial_tail') and n('genesis_work') == n('initial_work')
seq = lambda names: [n(key) for key in names.split()]
manifest = dict(
    schema=2, tail_formula_version=1,
    header=dict(chain_id=r['chain_id'], genesis_id=r['genesis_id'],
                version=n('header_version'), time=n('genesis_time'), bits=n('genesis_bits'),
                pow_limit=r['pow_limit_le'], half_life=n('half_life_seconds'), spacing=n('spacing_seconds')),
    transaction_limits=seq('max_inputs max_outputs max_mints max_script_bytes max_arguments max_element_bytes max_branch_proof_depth'),
    vm_limits=seq('max_script_bytes max_arguments max_element_bytes max_stack_items max_altstack_items max_vm_bytes max_ast_depth') + [a.max_steps],
    invocation_limits=[str(n('max_invocation_cost')), str(n('max_block_invocation_sum')), n('structural_byte_cost')],
    opcode_costs=[list(map(int, values[f'opcode_{op:02x}'].split(',')))
                  if f'opcode_{op:02x}' in values else [0, 0, 0] for op in range(256)],
    field_sizes=[],
    monetary=seq('boot_shift tx_knee_shift ema_shift ema_min linear_shift quad_shift tail_min tail_max dust_limit min_fee_per_kb') + [n('genesis_tail'), n('genesis_work').to_bytes(32, 'little').hex()],
    initial_monetary=r['initial_state'], genesis=r['genesis_hex'],
    coinbase_maturity=n('coinbase_maturity'), dust_limit=n('dust_limit'),
    future_window=n('future_window_seconds'), block_read_limit=a.block_read_limit,
    outer_costs=seq('hash_base hash_byte resolve_byte asset_comparison'))
a.output_dir.mkdir()  # No overwrite or implicit fixture refresh.
(a.output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
(a.output_dir / 'first.block').write_bytes(bytes.fromhex(r['first_hex']))
print(a.output_dir)
