#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Interleaved A/B runner for flood.py.

Each round runs every configuration once, rotating the starting
configuration from round to round so slow drifts in machine load (shared
hosts) spread over all configurations. Every run is a fresh clone of the
fixture, so no run inherits a prior run's mempool. Host filesystem/page
caches are shared and are not flushed. Results are appended to
results.jsonl in --workdir (re-running resumes: completed (round, config)
pairs are skipped) and summarized as medians with min-max spread.

Configurations are NAME=BINARY_LABEL[:NODEARG,NODEARG...], e.g.

  ab.py --bitcoind base=/b0/src/bitcoind --bitcoind new=/b1/src/bitcoind \\
      --fixture FX --workdir OUT --rounds 5 \\
      --config base=base \\
      --config serial=new:-parallelmempool=0 \\
      --config par8=new:-parallelmempool=1,-parallelmempoolthreads=8

Use --summarize to print the table of an existing results.jsonl.
"""

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def parse_config(text, binaries):
    name, rest = text.split("=", 1)
    if ":" in rest:
        label, args = rest.split(":", 1)
        node_args = [a for a in args.split(",") if a]
    else:
        label, node_args = rest, []
    if label not in binaries:
        sys.exit(f"config {name}: unknown binary label {label}")
    return {"name": name, "binary": label, "node_args": node_args}


def load_results(path):
    out = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def fmt_spread(values, digits=0):
    if not values:
        return "-"
    med = statistics.median(values)
    lo, hi = min(values), max(values)
    f = f"{{:.{digits}f}}"
    return f"{f.format(med)} ({f.format(lo)}-{f.format(hi)})"


def summarize(results, config_order):
    by = {}
    for r in results:
        by.setdefault(r["config"], []).append(r)
    lines = [
        "| config | runs | complete | accepted tx/s (10-90%) | tx/s (all) "
        "| latency p50 ms | latency p99 ms | node CPU s | CPU us/tx "
        "| cs_main hold us/tx | cs_main wait us/tx | queue full events |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in config_order:
        rs = by.get(name, [])
        if not rs:
            continue
        valid = [r for r in rs if r.get("complete")]
        tps = [r["tps_10_90"] for r in valid if r.get("tps_10_90")]
        tps_all = [r["tps_total"] for r in valid if r.get("tps_total")]
        p50 = [r["latency"]["p50_ms"] for r in valid if r.get("latency")]
        p99 = [r["latency"]["p99_ms"] for r in valid if r.get("latency")]
        cpu = [r["node_cpu_s"] for r in valid if r.get("node_cpu_s")]
        cpu_per = [
            1e6 * r["node_cpu_s"] / r["accepted_zmq"]
            for r in valid
            if r.get("node_cpu_s") and r.get("accepted_zmq")
        ]
        hold = []
        full = []
        wait = []
        for r in valid:
            m = r.get("metrics", {})
            s = m.get("fullnode_mempool_admission_lock_hold_seconds_sum")
            c = m.get("fullnode_mempool_admission_lock_hold_seconds_count")
            if s is not None and c and r.get("metrics_complete"):
                hold.append(1e6 * s / r["accepted_zmq"])
            ws = m.get("fullnode_mempool_admission_lock_wait_seconds_sum")
            if ws is not None and r.get("metrics_complete"):
                wait.append(1e6 * ws / r["accepted_zmq"])
            q = m.get("fullnode_mempool_admission_queue_full_total")
            if q is not None:
                full.append(q)
        complete = sum(1 for r in valid if r.get("complete"))
        lines.append(
            f"| {name} | {len(rs)} | {complete}/{len(rs)} | {fmt_spread(tps)} "
            f"| {fmt_spread(tps_all)} | {fmt_spread(p50, 1)} | {fmt_spread(p99, 1)} "
            f"| {fmt_spread(cpu, 1)} | {fmt_spread(cpu_per, 1)} "
            f"| {fmt_spread(hold, 2) if hold else '-'} "
            f"| {fmt_spread(wait, 2) if wait else '-'} "
            f"| {fmt_spread(full) if full else '-'} |"
        )
    lines += [
        "",
        "Performance statistics include only complete runs; every incomplete run remains in the run/completion counts.",
    ]
    loads = [r["loadavg_start"][0] for r in results if r.get("loadavg_start")]
    if loads:
        lines.append("")
        lines.append(
            f"Host 1-minute load average at run start: median "
            f"{statistics.median(loads):.1f}, range {min(loads):.1f}-{max(loads):.1f} "
            f"on {results[0].get('host_cpus')} logical CPUs."
        )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        "--bitcoind", action="append", default=[], help="LABEL=PATH (repeatable)"
    )
    ap.add_argument(
        "--config",
        action="append",
        default=[],
        help="NAME=LABEL[:NODEARG,...] (repeatable)",
    )
    ap.add_argument("--fixture", type=Path)
    ap.add_argument("--workdir", type=Path, required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--peers", type=int, default=8)
    ap.add_argument("--mode", choices=("p2p", "rpc"), default="p2p")
    ap.add_argument("--rate", type=float, default=0.0)
    ap.add_argument("--no-relay", action="store_true")
    ap.add_argument("--unit-limit", type=int)
    ap.add_argument("--portseed", type=int, default=621)
    ap.add_argument("--libzmq")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--summarize", action="store_true")
    args = ap.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    results_path = args.workdir / "results.jsonl"
    binaries = {}
    for b in args.bitcoind:
        label, path = b.split("=", 1)
        binaries[label] = path
    configs = [parse_config(c, binaries) for c in args.config]
    order = [c["name"] for c in configs]

    if args.summarize:
        results = load_results(results_path)
        if not order:
            order = list(dict.fromkeys(r["config"] for r in results))
        print(summarize(results, order))
        return

    if not args.fixture or not configs:
        sys.exit("--fixture and at least one --config are required")
    done = {(r["round"], r["config"]) for r in load_results(results_path)}
    meta = {
        "binaries": binaries,
        "configs": configs,
        "peers": args.peers,
        "mode": args.mode,
        "rate": args.rate,
        "no_relay": args.no_relay,
        "fixture": str(args.fixture),
        "host_cpus": os.cpu_count(),
        "tool_sha256": {
            name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            for name in ("ab.py", "flood.py", "admission_common.py")
        },
        "binary_sha256": {
            k: hashlib.sha256(Path(v).read_bytes()).hexdigest()
            for k, v in binaries.items()
        },
        "fixture_sha256": hashlib.sha256(
            (args.fixture / "flood.jsonl").read_bytes()
        ).hexdigest(),
        "unit_limit": args.unit_limit,
        "timeout": args.timeout,
        "portseed": args.portseed,
    }
    config_path = args.workdir / "ab-config.json"
    if config_path.exists() and json.loads(config_path.read_text()) != meta:
        sys.exit("run provenance changed; choose a fresh --workdir")
    config_path.write_text(json.dumps(meta, indent=2) + "\n")

    for rnd in range(args.rounds):
        rotated = configs[rnd % len(configs) :] + configs[: rnd % len(configs)]
        for cfg in rotated:
            if (rnd, cfg["name"]) in done:
                continue
            run_dir = args.workdir / f"r{rnd}-{cfg['name']}"
            result_file = run_dir.with_suffix(".json")
            cmd = [
                sys.executable,
                str(HERE / "flood.py"),
                "--bitcoind",
                binaries[cfg["binary"]],
                "--fixture",
                str(args.fixture),
                "--workdir",
                str(run_dir),
                "--peers",
                str(args.peers),
                "--mode",
                args.mode,
                "--rate",
                str(args.rate),
                "--portseed",
                str(args.portseed),
                "--label",
                cfg["name"],
                "--timeout",
                str(args.timeout),
                "--result",
                str(result_file),
            ]
            if args.no_relay:
                cmd.append("--no-relay")
            if args.unit_limit:
                cmd += ["--unit-limit", str(args.unit_limit)]
            if args.libzmq:
                cmd += ["--libzmq", args.libzmq]
            for a in cfg["node_args"]:
                cmd.append(f"--node-arg={a}")
            print(f"round {rnd} {cfg['name']}: {' '.join(cmd)}", flush=True)
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL)
            if r.returncode != 0 or not result_file.exists():
                print(f"  FAILED (exit {r.returncode}); see {run_dir}", flush=True)
                res = {"complete": False, "runner_exitcode": r.returncode}
            else:
                res = json.loads(result_file.read_text())
            res["round"] = rnd
            res["config"] = cfg["name"]
            res.pop("timeline", None)
            with open(results_path, "a") as f:
                f.write(json.dumps(res) + "\n")
            print(
                f"  tps_10_90={res.get('tps_10_90')} p50={res.get('latency', {}).get('p50_ms')}ms "
                f"p99={res.get('latency', {}).get('p99_ms')}ms cpu={res.get('node_cpu_s')}s "
                f"complete={res.get('complete')}",
                flush=True,
            )
    table = summarize(load_results(results_path), order)
    (args.workdir / "SUMMARY.md").write_text(table + "\n")
    print(table)


if __name__ == "__main__":
    main()
