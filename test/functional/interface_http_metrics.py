#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test /metrics (-metrics): the Prometheus text format, values that change,
and access limited to -rpcallowip clients on the RPC listeners."""

import http.client
import re
import socket
import ssl
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port
from test_framework.wallet import MiniWallet

PUBLIC_PORT_INDEX = 41
NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
LABEL = r'[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*"'
SAMPLE = re.compile(
    rf"^({NAME})(\{{{LABEL}(?:,{LABEL})*\}})? "
    r"(NaN|[+-]Inf|[-+]?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)$"
)
LABEL_PAIR = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse(text):
    """Parse and check an exposition; return {(name, labels): value}."""
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
        m = SAMPLE.match(line)
        assert m, f"bad sample line: {line!r}"
        name, labels, value = m.group(1), m.group(2) or "", m.group(3)
        family = name
        if name not in types:
            for suffix in ("_bucket", "_sum", "_count"):
                base = name[: -len(suffix)]
                if name.endswith(suffix) and types.get(base) == "histogram":
                    family = base
        assert family in types, f"sample before/without TYPE: {line}"
        if types[family] == "counter":
            assert name.endswith("_total"), name
        key = (name, tuple(LABEL_PAIR.findall(labels)))
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
                    (float("inf") if le == "+Inf" else float(le), v))
        for rest, buckets in series.items():
            counts = [v for _, v in sorted(buckets)]
            assert counts == sorted(counts), f"{name} not cumulative"
            assert sorted(buckets)[-1][0] == float("inf")
            assert_equal(counts[-1], samples[(name + "_count", rest)])
            assert (name + "_sum", rest) in samples
    return samples


class HTTPMetricsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [
            [
                "-metrics",
                "-trustedproxy=127.0.0.1",
                f"-publicbind=127.0.0.1:{self.public_port}",
            ],
            # node1 peers with node0 over P2P WebSocket
            [f"-addnode=ws://127.0.0.1:{self.public_port}/p2p/ws"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        # node0's public listener first, so node1's first dial succeeds
        self.start_node(0)
        self.start_node(1)

    def request(self, port, path="/metrics", method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        conn.request(method, path, headers=headers or {})
        res = conn.getresponse()
        body = res.read().decode()
        conn.close()
        return res, body

    def scrape(self):
        res, body = self.request(rpc_port(0))
        assert_equal(res.status, 200)
        assert_equal(
            res.getheader("Content-Type"),
            "text/plain; version=0.0.4; charset=utf-8",
        )
        return parse(body)

    def total(self, samples, name, **labels):
        """Sum of a metric's series matching the given labels"""
        return sum(
            v
            for (n, ls), v in samples.items()
            if n == name and all(dict(ls).get(k) == w for k, w in labels.items())
        )

    def run_test(self):
        node = self.nodes[0]
        self.log.info("The exposition is well formed")
        samples = self.scrape()
        # The genesis block was connected at startup.
        connected = samples[("lotus_block_connect_seconds_count", ())]
        assert_equal(connected, 1)
        assert_equal(samples[("lotus_metrics_dropped_samples_total", ())], 0)
        assert_equal(samples[("lotus_chain_tip_height", ())], 0)
        assert_equal(samples[("lotus_initial_block_download", ())], 1)

        self.log.info("Peers: node1 over WebSocket, node1 over TCP")
        self.wait_until(
            lambda: self.total(
                self.scrape(), "lotus_peers", direction="inbound",
                transport="websocket") == 1
        )
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: self.total(
                self.scrape(), "lotus_peers", direction="outbound",
                transport="tcp") == 1
        )
        samples = self.scrape()
        assert_equal(self.total(samples, "lotus_p2p_websocket_peers"), 1)
        assert_equal(
            self.total(samples, "lotus_p2p_websocket_peers", tls="false"), 1)
        assert_equal(
            self.total(samples, "lotus_p2p_connections_total",
                       direction="inbound", transport="websocket"), 1)
        for name in ("lotus_p2p_received_messages_total",
                     "lotus_p2p_sent_messages_total"):
            assert self.total(samples, name, type="version") >= 2, name
        assert self.total(samples, "lotus_p2p_sent_bytes_total") > 0
        assert ("lotus_p2p_received_bytes_total", (("type", "other"),)) in samples

        self.log.info("Chain and mempool values change")
        wallet = MiniWallet(node)
        self.generate(wallet, 101)
        self.wait_until(
            lambda: self.scrape()[("lotus_block_connect_seconds_count", ())]
            == connected + 101
        )
        self.wait_until(
            lambda: self.scrape()[("lotus_initial_block_download", ())] == 0
        )
        samples = self.scrape()
        assert_equal(samples[("lotus_chain_tip_height", ())], 101)
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        assert_equal(samples[("lotus_chain_tip_timestamp_seconds", ())], tip_time)
        # Computed at scrape time; negative if the tip's timestamp is ahead
        # of the clock (quickly mined regtest blocks).
        age = samples[("lotus_chain_tip_age_seconds", ())]
        assert abs(age - (time.time() - tip_time)) < 30, age
        assert samples[("lotus_block_connect_seconds_sum", ())] > 0

        self.log.info("HTTP and RPC requests")
        node.getblockcount()
        self.request(rpc_port(0), path="/livez")
        with socket.create_connection(("127.0.0.1", rpc_port(0))) as raw:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw):
                pass
        time.sleep(1.1)  # past the rendering cache
        samples = self.scrape()
        assert self.total(samples, "lotus_http_requests_total",
                          endpoint="rpc", code="2xx") > 0
        assert self.total(samples, "lotus_http_requests_total",
                          endpoint="health", code="2xx") >= 1
        assert self.total(samples, "lotus_http_requests_total",
                          endpoint="metrics", code="2xx") >= 1
        assert self.total(samples, "lotus_http_request_duration_seconds_count",
                          endpoint="rpc") > 0
        assert_equal(
            self.total(samples, "lotus_http_tls_handshakes_total", result="ok"), 1)

        self.log.info("HEAD has the headers but no body; POST is refused")
        res, body = self.request(rpc_port(0), method="HEAD")
        assert_equal((res.status, body), (200, ""))
        res, _ = self.request(rpc_port(0), method="POST")
        assert_equal(res.status, 405)

        self.log.info("A client outside -rpcallowip is refused (resolved "
                      "through the trusted proxy's X-Forwarded-For)")
        res, body = self.request(
            rpc_port(0), headers={"X-Forwarded-For": "203.0.113.5"}
        )
        assert_equal(res.status, 403)
        assert "lotus_" not in body
        res, _ = self.request(
            rpc_port(0), headers={"X-Forwarded-For": "127.0.0.1"}
        )
        assert_equal(res.status, 200)

        self.log.info("Public listeners never serve metrics")
        res, body = self.request(self.public_port)
        assert_equal(res.status, 404)
        assert "lotus_" not in body

        self.log.info("Without -metrics there is no /metrics")
        res, _ = self.request(rpc_port(1))
        assert_equal(res.status, 404)


if __name__ == "__main__":
    HTTPMetricsTest().main()
