#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shared helpers for the interleaved A/B drivers in this directory."""

import json
import os
import statistics


def find_binary(path, candidates):
    """path is a binary, or a build directory searched for candidates."""
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return os.path.abspath(path)
    for rel in candidates:
        p = os.path.join(path, rel)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.abspath(p)
    raise SystemExit(f"no executable found at {path} (tried {candidates})")


def parse_arm(spec):
    """NAME=PATH [extra args...] -> (name, path, [args])"""
    if "=" not in spec:
        raise SystemExit(f"--arm wants NAME=PATH [args], got {spec!r}")
    name, rest = spec.split("=", 1)
    parts = rest.split()
    return name, parts[0], parts[1:]


def summarize(samples):
    """samples: {metric: {arm: [values per round]}} -> rows"""
    rows = []
    for metric in sorted(samples):
        by_arm = samples[metric]
        row = {"metric": metric, "arms": {}}
        for arm, values in by_arm.items():
            if not values:
                continue
            row["arms"][arm] = {
                "n": len(values),
                "median": statistics.median(values),
                "min": min(values),
                "max": max(values),
                "values": values,
            }
        rows.append(row)
    return rows


def render_table(rows, arms, unit, baseline=None):
    """Markdown table: median [min-max] per arm, and median ratio to the
    baseline arm (the first arm unless given)."""
    baseline = baseline or arms[0]
    head = ["metric"] + [f"{a} median [min-max] ({unit})" for a in arms]
    head += [f"{a}/{baseline}" for a in arms if a != baseline]
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for row in rows:
        cells = [row["metric"]]
        for a in arms:
            s = row["arms"].get(a)
            cells.append(
                "-"
                if s is None
                else f"{s['median']:.4g} [{s['min']:.4g}-{s['max']:.4g}] n={s['n']}"
            )
        base = row["arms"].get(baseline)
        for a in arms:
            if a == baseline:
                continue
            s = row["arms"].get(a)
            if s is None or base is None or base["median"] == 0:
                cells.append("-")
            else:
                cells.append(f"{s['median'] / base['median']:.3f}")
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def write_results(path, payload):
    with open(path, "w", encoding="utf8") as f:
        json.dump(payload, f, indent=1, sort_keys=True)
        f.write("\n")
