#!/usr/bin/env python3
"""Differential P05/P06/C16 arithmetic against the separate Python reference.

Usage: check_reference.py NATIVE_TEST_EXE PATH_TO_lotus-v2-reference
The reference source is supplied explicitly; no source is copied into this tree.
"""
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[2]).resolve()))
from lotus_v2_reference.monetary import MonetaryState, OrdinaryTx, Profile, absolute_tail, advance

P = Profile(2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, 9)
rng = random.Random(0xC16A06)
rows = []
expected = []
for _ in range(300):
    reserve = rng.randrange(0, 1000)
    prev_work = rng.randrange(1, 256)
    tail = absolute_tail(P, prev_work)
    if rng.randrange(5) == 0:
        tail += 1  # Checked redundant-cache rejection.
    ema = rng.randrange(0, 500)
    work = rng.randrange(1, 256)
    fee = rng.randrange(0, 800)
    size = rng.randrange(1, 500)
    tokens = rng.randrange(0, 5)
    explicit_burn = rng.randrange(0, 100)
    payout = rng.randrange(0, 2000)
    cb_burn = rng.randrange(0, 100)
    cb_bytes = rng.randrange(1, 500)
    prefix = rng.randrange(1, 8)
    account = rng.randrange(0, 70)
    enforce = account + rng.randrange(-3, 70)
    row = (reserve, tail, prev_work, ema, work, fee, size, tokens,
           explicit_burn, payout, cb_burn, cb_bytes, prefix, account, enforce)
    rows.append(row)
    try:
        tx = OrdinaryTx(fee + 100, 100, size, tokens, explicit_burn)
        result = advance(P, MonetaryState(reserve, tail, prev_work, ema),
                         work=work, transactions=(tx,),
                         coinbase_native_outputs=payout,
                         coinbase_native_burn=cb_burn,
                         coinbase_bytes=cb_bytes,
                         tx_frame_prefix_bytes=prefix,
                         account_block_cost=account,
                         enforce_block_cost=enforce)
        expected.append(" ".join(map(str, (
            result.state.bootstrap_reserve, result.state.tail_subsidy,
            result.state.prev_work, result.state.ema_block_cost,
            result.bootstrap_issued, result.subsidy, result.total_fees,
            result.token_burn, result.burned_fees, result.required_underclaim,
            result.actual_underclaim, result.spendable_supply_delta))))
    except ValueError:
        expected.append("ERR")

input_text = "".join(" ".join(map(str, row)) + "\n" for row in rows)
result = subprocess.run([sys.argv[1], "--vectors"], input=input_text,
                        text=True, capture_output=True, check=True)
actual = result.stdout.splitlines()
assert len(actual) == len(expected), (len(actual), len(expected), result.stderr)
for index, (got, want) in enumerate(zip(actual, expected)):
    if got != want:
        raise AssertionError(f"vector {index}: got {got!r}, want {want!r}; {rows[index]}")
accepted = sum(value != "ERR" for value in expected)
assert accepted >= 10, f"too few valid transitions: {accepted}"
print(f"{len(rows)} Python/native monetary differential vectors passed ({accepted} accepted)")
