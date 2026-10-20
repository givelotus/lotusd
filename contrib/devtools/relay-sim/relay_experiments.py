"""Experiment tables behind the Nucleation relay plan (run: python3 relay_experiments.py [procs] [1-7|all])."""

import dataclasses
import multiprocessing
import sys

from relay_sim import Cfg, simulate


def table(title, cfgs, cols, procs=None):
    if procs is None:
        procs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    with multiprocessing.Pool(procs) as pool:
        rows = pool.map(simulate, cfgs)
    print(f"\n### {title}\n")
    hdr = [
        "config",
        "peers",
        "t50",
        "t90",
        "t99",
        "t100",
        "worst",
        "INV/n",
        "dupINV/n",
        "body/n",
        "dupbody/n",
        "recon/n",
        "bytes/node/tx (= MB/s at 1M TPS)",
    ] + (["origin found"] if "found" in cols else [])
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for c, m in rows:
        label = ", ".join(f"{k}={getattr(c, k)}" for k in cols if k != "found")
        vals = [
            label,
            f"{m['peers']:.0f}",
            f"{m['t50']:.2f}",
            f"{m['t90']:.2f}",
            f"{m['t99']:.2f}",
            f"{m['t100']:.2f}",
            f"{m['t100_max']:.2f}",
            f"{m['inv']:.1f}",
            f"{m['dup_inv']:.1f}",
            f"{m['body']:.2f}",
            f"{m['dup_body']:.2f}",
            f"{m['recon']:.3f}",
            f"{m['bytes']:.0f}",
        ]
        if "found" in cols:
            vals.append("-" if m["found"] is None else f"{m['found']:.0%}")
        print("| " + " | ".join(vals) + " |")
    sys.stdout.flush()


def main():
    B = Cfg()
    exp = sys.argv[2] if len(sys.argv) > 2 else "all"
    if exp in ("1", "all"):
        table(
            "1. Fan-out K x tick (16 peers, recon 1 s, 36-byte ids)",
            [
                dataclasses.replace(B, k=k, tick=t)
                for k in (4, 8, None)
                for t in (0, 0.01, 0.025, 0.05, 0.1)
            ],
            ["k", "tick", "found"],
        )
    if exp in ("2", "all"):
        table(
            "2. Peer count x fan-out (tick 25 ms)",
            [
                dataclasses.replace(B, outbound=o, k=k)
                for o in (8, 16, 24)
                for k in (4, 6, 8, 12, None)
            ],
            ["outbound", "k"],
        )
    if exp in ("3", "all"):
        table(
            "3. Reconciliation interval (K=4 and 8)",
            [
                dataclasses.replace(B, k=k, recon=r)
                for k in (4, 8)
                for r in (None, 0.25, 0.5, 1.0, 2.0)
            ],
            ["k", "recon"],
        )
    if exp in ("4", "all"):
        table(
            "4. Push bodies to P peers instead of announcing",
            [dataclasses.replace(B, k=k, push=p) for k in (4, 8) for p in (0, 1, 2, 4)],
            ["k", "push"],
        )
    if exp in ("5", "all"):
        table(
            "5. Wallet submits to m random nodes (K=8)",
            [dataclasses.replace(B, entries=m) for m in (1, 2, 3, 5)],
            ["entries"],
        )
    if exp in ("6", "all"):
        table(
            "6. Non-relaying nodes",
            [
                dataclasses.replace(B, k=k, dead=d)
                for d in (0.1, 0.3)
                for k in (4, 8, None)
            ],
            ["dead", "k"],
        )
    if exp in ("7", "all"):
        table(
            "7. Known-inventory suppression off/on (K=all and 8)",
            [
                dataclasses.replace(B, k=k, known=kn, tick=t)
                for k in (8, None)
                for kn in (False, True)
                for t in (0, 0.025)
            ],
            ["k", "known", "tick"],
        )


if __name__ == "__main__":
    main()
