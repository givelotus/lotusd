#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Interleaved A/B runs of bench_bitcoin microbenchmarks.

Each round runs every arm once, in order (A B A B ...), with the same
filter, and records each benchmark's median time per unit (ns) from
nanobench's JSON output. The table gives, per benchmark and arm, the
median over rounds and the range [min-max] of the rounds' values, plus
the ratio of each arm's median to the first arm's.

Example:
  ab_microbench.py --arm base=../base/build --arm patched=build \\
      --filter 'BlockMerkleRoot_.*' --rounds 7 --out merkle.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import abstats  # noqa: E402

BENCH_CANDIDATES = [
    "src/bench/bitcoin-bench",
    "src/bench/bench_bitcoin",
    "bin/bench_bitcoin",
]


def run_once(binary, extra, filt, min_time):
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out.json")
        cmd = [
            binary,
            f"-filter={filt}",
            f"-min_time={min_time}",
            f"-output_json={out}",
        ] + extra
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        with open(out, encoding="utf8") as f:
            data = json.load(f)
    res = {}
    for r in data["results"]:
        batch = r.get("batch", 1) or 1
        res[r["name"]] = r["median(elapsed)"] / batch * 1e9
    return res


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--arm",
        action="append",
        required=True,
        help="NAME=BUILD_DIR_OR_BINARY [extra bench args]; "
        "the first arm is the baseline",
    )
    p.add_argument("--filter", required=True, help="bench_bitcoin -filter regex")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument(
        "--min-time",
        type=int,
        default=200,
        help="bench_bitcoin -min_time per benchmark (ms)",
    )
    p.add_argument("--out", help="write raw samples and summary as JSON")
    args = p.parse_args()

    arms = []
    for spec in args.arm:
        name, path, extra = abstats.parse_arm(spec)
        arms.append((name, abstats.find_binary(path, BENCH_CANDIDATES), extra))

    samples = {}
    for rnd in range(args.rounds):
        for name, binary, extra in arms:
            res = run_once(binary, extra, args.filter, args.min_time)
            for bench, ns in res.items():
                samples.setdefault(bench, {a[0]: [] for a in arms})[name].append(ns)
            print(
                f"round {rnd + 1}/{args.rounds} {name}: "
                + ", ".join(f"{k}={v:.1f}" for k, v in sorted(res.items())),
                file=sys.stderr,
            )

    rows = abstats.summarize(samples)
    names = [a[0] for a in arms]
    print(abstats.render_table(rows, names, "ns/unit"))
    if args.out:
        abstats.write_results(
            args.out,
            {
                "arms": [{"name": n, "binary": b, "args": e} for n, b, e in arms],
                "filter": args.filter,
                "rounds": args.rounds,
                "min_time_ms": args.min_time,
                "unit": "ns per unit",
                "rows": rows,
            },
        )


if __name__ == "__main__":
    main()
