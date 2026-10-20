#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run relay_cluster.py for several variants, interleaved, and summarize.

Each variant is NAME=BINARY[@EXTRA-ARGS]; every round runs every variant
once, in order, so slow drift in machine load hits all variants alike.
Results go to --out (one JSON line per run) and a summary table (median
and range over rounds) is printed.

Example:
  contrib/bench/tx-relay/run_interleaved.py --build-dir build --rounds 3 \\
      --variant old=/path/old/bitcoind --variant new=build/src/bitcoind \\
      --out runs.jsonl -- --nodes 24 --outbound 8 --txs 300 --rate 20 \\
      --latency 10-80
"""

import argparse
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def summarize(runs):
    by = {}
    for r in runs:
        by.setdefault(r["variant"], []).append(r)
    rows = []
    for name, rs in by.items():

        def col(f):
            v = [f(r) for r in rs]
            return f"{statistics.median(v):.3f} [{min(v):.3f}-{max(v):.3f}]"

        p = lambda q, s: lambda r: r["propagation_seconds"][q][s]  # noqa: E731
        b = lambda k: lambda r: r["bytes_per_node_per_tx"][k]  # noqa: E731
        rows.append(
            [
                name,
                str(len(rs)),
                col(p("t50", "median")),
                col(p("t90", "median")),
                col(p("t99", "median")),
                col(p("t100", "median")),
                col(p("t100", "worst")),
                col(b("announce")),
                col(b("request")),
                col(b("body")),
                col(b("recon")),
                col(lambda r: r["bytes_per_node_per_tx_total"]),
                col(lambda r: r["bytes_per_node_per_tx_total"] / r["floor_bytes"]),
                col(
                    lambda r: (
                        (r["duplicate_bodies_metric"] or 0)
                        / max(1, r["bodies_received_metric"] or 1)
                    )
                ),
                col(lambda r: r["cpu_seconds_per_tx"] * 1000),
                col(lambda r: r["load_average"][0]),
                str(sum(not r["complete"] for r in rs)),
            ]
        )
    hdr = [
        "variant", "runs", "t50 s", "t90 s", "t99 s", "t100 s (median tx)",
        "t100 s (worst tx)", "announce B", "request B", "body B", "recon B",
        "total B/node/tx", "x floor", "dup bodies (metric)", "CPU ms/tx",
        "load", "incomplete",
    ]  # fmt: skip
    out = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--variant", action="append", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--out", required=True, help="JSON lines file (appended)")
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("cluster_args", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cluster_args = [a for a in args.cluster_args if a != "--"]

    runs = []
    if os.path.exists(args.out):
        with open(args.out, encoding="utf8") as f:
            runs = [json.loads(line) for line in f if line.strip()]
    if not args.summary_only:
        variants = []
        for v in args.variant:
            name, _, rest = v.partition("=")
            binary, _, extra = rest.partition("@")
            variants.append((name, binary, extra))
        for rnd in range(args.rounds):
            for name, binary, extra in variants:
                cmd = [
                    sys.executable,
                    os.path.join(HERE, "relay_cluster.py"),
                    f"--build-dir={args.build_dir}",
                    f"--bitcoind={binary}",
                    f"--extra-args={extra}",
                    f"--json={args.out}.last",
                    *cluster_args,
                ]
                print(f"round {rnd + 1}/{args.rounds}: {name}", file=sys.stderr)
                if os.path.exists(f"{args.out}.last"):
                    os.remove(f"{args.out}.last")
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0 or not os.path.exists(f"{args.out}.last"):
                    print(proc.stdout[-2000:], proc.stderr[-4000:], file=sys.stderr)
                    continue
                with open(f"{args.out}.last", encoding="utf8") as f:
                    r = json.load(f)
                r.update(variant=name, round=rnd, args=cluster_args)
                runs.append(r)
                with open(args.out, "a", encoding="utf8") as f:
                    f.write(json.dumps(r, sort_keys=True) + "\n")
    print(summarize([r for r in runs if r.get("variant")]))


if __name__ == "__main__":
    main()
