#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Summarize a macOS `sample` call tree for one thread.

Prints inclusive sample counts per function (each function counted once per
stack, at its outermost frame) and self counts, as a share of the thread's
samples. Use it on the sample.txt that flood.py --sample-seconds writes.

Usage:
  sample_summary.py SAMPLE.txt [--thread b-msghand] [--top 40]
                   [--match REGEX ...]
"""

import argparse
import re
from collections import defaultdict

LINE = re.compile(
    r"^(?P<indent>[ +!:|]*)(?P<count>\d+) (?P<name>.*?)(\s+\(in [^)]*\).*)?$"
)


def short(name):
    name = re.sub(r"\(anonymous namespace\)::", "", name)
    name = re.sub(r"\[abi:[^\]]*\]", "", name)
    # drop argument lists, keep qualified name
    depth = 0
    out = []
    for ch in name:
        if ch == "(" and not out[-8:] == list("operator"):
            if depth == 0 and out:
                break
        out.append(ch)
    return "".join(out).strip()


def parse_thread(path, thread):
    lines = open(path).read().splitlines()
    start = None
    for i, line in enumerate(lines):
        if "Thread_" in line and thread in line:
            start = i
            break
    if start is None:
        raise SystemExit(f"thread {thread!r} not found")
    root = LINE.match(lines[start])
    total = int(root.group("count"))
    root_depth = len(root.group("indent"))
    nodes = []  # (depth, count, name)
    for line in lines[start + 1 :]:
        m = LINE.match(line)
        if not m:
            break
        depth = len(m.group("indent"))
        if depth <= root_depth:
            break
        nodes.append((depth, int(m.group("count")), short(m.group("name"))))
    return total, nodes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample")
    ap.add_argument("--thread", default="b-msghand")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--match", action="append", default=[])
    ap.add_argument("--callers", help="print the direct callers of FUNC")
    ap.add_argument(
        "--root",
        help="only count samples under frames named FUNC (shares are of those)",
    )
    args = ap.parse_args()
    total, nodes = parse_thread(args.sample, args.thread)
    if args.root:
        kept = []
        root_depth = None
        for depth, count, name in nodes:
            if root_depth is not None and depth <= root_depth:
                root_depth = None
            if root_depth is None and name == args.root:
                root_depth = depth
            if root_depth is not None:
                kept.append((depth, count, name))
        nodes = kept
        total = sum(c for d, c, n in nodes if n == args.root)
    inclusive = defaultdict(int)
    selfc = defaultdict(int)
    callers = defaultdict(int)
    stack = []  # (depth, name)
    for idx, (depth, count, name) in enumerate(nodes):
        while stack and stack[-1][0] >= depth:
            stack.pop()
        if name not in (n for _, n in stack):
            inclusive[name] += count
        if args.callers and name == args.callers and stack:
            callers[stack[-1][1]] += count
        # self = count - sum(direct children)
        direct = 0
        j = idx + 1
        child_depth = None
        while j < len(nodes) and nodes[j][0] > depth:
            if child_depth is None:
                child_depth = nodes[j][0]
            if nodes[j][0] == child_depth:
                direct += nodes[j][1]
            j += 1
        selfc[name] += count - direct
        stack.append((depth, name))
    print(f"thread {args.thread}: {total} samples")
    if args.callers:
        for k, v in sorted(callers.items(), key=lambda kv: -kv[1])[: args.top]:
            print(f"  {100.0 * v / total:6.1f}%  {k}")
        return
    if args.match:
        for pat in args.match:
            rx = re.compile(pat)
            hits = sorted(
                ((v, k) for k, v in inclusive.items() if rx.search(k)), reverse=True
            )
            for v, k in hits[:10]:
                print(f"  {100.0 * v / total:6.1f}%  {k}")
        return
    print("inclusive:")
    for k, v in sorted(inclusive.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"  {100.0 * v / total:6.1f}%  {k}")
    print("self:")
    for k, v in sorted(selfc.items(), key=lambda kv: -kv[1])[: args.top // 2]:
        print(f"  {100.0 * v / total:6.1f}%  {k}")


if __name__ == "__main__":
    main()
