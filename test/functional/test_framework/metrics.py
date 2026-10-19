#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Scrape and check a node's /metrics (-metrics), the Prometheus text format.

See doc/metrics.md for the naming scheme. Every series carries the constant
labels client and network (and any -metricslabel); lookups here match the
labels given and ignore the others, so tests need not repeat them.
"""

import http.client
import re

from .util import assert_equal, rpc_port

#: Prefix of every node metric name (METRICS_NAMESPACE in node/metrics.h)
NAMESPACE = "fullnode_"
#: Labels the node sets on every series
CONSTANT_LABELS = ("client", "network")

NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
LABEL = r'[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*"'
SAMPLE = re.compile(
    rf"^({NAME})(\{{{LABEL}(?:,{LABEL})*\}})? "
    r"(NaN|[+-]Inf|[-+]?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)$"
)
LABEL_PAIR = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def unescape(value):
    """A label value as given, from its escaped rendering"""
    return re.sub(r"\\(.)", lambda e: "\n" if e.group(1) == "n" else e.group(1), value)


def m(name):
    """Full name of a node metric: m("chain_tip_height")"""
    return NAMESPACE + name


def parse(text):
    """Parse and check an exposition; return ({(name, labels): value}, types).

    labels is the tuple of (name, value) pairs in the order rendered."""
    assert text.endswith("\n")
    types = {}
    samples = {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            assert re.match(rf"^# HELP {NAME} .+$", line), line
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind in ("counter", "gauge", "histogram"), line
            assert name not in types, f"duplicate TYPE {name}"
            types[name] = kind
            continue
        match = SAMPLE.match(line)
        assert match, f"bad sample line: {line!r}"
        name, labels, value = match.group(1), match.group(2) or "", match.group(3)
        family = name
        if name not in types:
            for suffix in ("_bucket", "_sum", "_count"):
                base = name[: -len(suffix)]
                if name.endswith(suffix) and types.get(base) == "histogram":
                    family = base
        assert family in types, f"sample before/without TYPE: {line}"
        if types[family] == "counter":
            assert name.endswith("_total"), name
        pairs = tuple((k, unescape(v)) for k, v in LABEL_PAIR.findall(labels))
        names = [k for k, _ in pairs]
        assert len(names) == len(set(names)), f"repeated label: {line}"
        key = (name, pairs)
        assert key not in samples, f"duplicate series {line}"
        samples[key] = float(value)
    # Histograms: cumulative buckets ending with +Inf == _count
    for name, kind in types.items():
        if kind != "histogram":
            continue
        series = {}
        for (n, labels), v in samples.items():
            if n == name + "_bucket":
                rest = tuple(p for p in labels if p[0] != "le")
                le = dict(labels)["le"]
                series.setdefault(rest, []).append(
                    (float("inf") if le == "+Inf" else float(le), v)
                )
        for rest, buckets in series.items():
            counts = [v for _, v in sorted(buckets)]
            assert counts == sorted(counts), f"{name} not cumulative"
            assert sorted(buckets)[-1][0] == float("inf")
            assert_equal(counts[-1], samples[(name + "_count", rest)])
            assert (name + "_sum", rest) in samples
    return samples, types


class Scrape:
    """One parsed scrape of /metrics"""

    def __init__(self, text):
        self.text = text
        self.samples, self.types = parse(text)

    def series(self, name, **labels):
        """[(labels dict, value)] of name's series matching labels"""
        return [
            (dict(ls), v)
            for (n, ls), v in self.samples.items()
            if n == name and all(dict(ls).get(k) == w for k, w in labels.items())
        ]

    def has(self, name, **labels):
        return bool(self.series(name, **labels))

    def total(self, name, **labels):
        """Sum of name's series matching labels (0 if none)"""
        return sum(v for _, v in self.series(name, **labels))

    def value(self, name, **labels):
        """The value of the one series of name matching labels"""
        found = self.series(name, **labels)
        assert_equal(len(found), 1)
        return found[0][1]

    def label_values(self, name, label):
        """Set of the values label takes in name's series"""
        return {ls[label] for ls, _ in self.series(name) if label in ls}

    def check_constant_labels(self, expected):
        """Every series carries exactly the expected constant labels, first"""
        n = len(expected)
        for (name, labels), _ in self.samples.items():
            assert_equal((name, tuple(labels[:n])), (name, tuple(expected.items())))


def request(port, path="/metrics", method="GET", headers=None, timeout=30):
    """(response, body) of an HTTP request to 127.0.0.1:port"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request(method, path, headers=headers or {})
    res = conn.getresponse()
    body = res.read().decode()
    conn.close()
    return res, body


def scrape(node):
    """Scrape a TestNode started with -metrics. Renderings are cached for a
    second (METRICS_MIN_SCRAPE_INTERVAL): wait past that to see changes."""
    res, body = request(rpc_port(node.index))
    assert_equal(res.status, 200)
    assert_equal(
        res.getheader("Content-Type"), "text/plain; version=0.0.4; charset=utf-8"
    )
    return Scrape(body)
