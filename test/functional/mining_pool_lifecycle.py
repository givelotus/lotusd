#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Node-owned pool runtime options, private routing and restart state."""

import base64
import http.client
import json
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, p2p_port
from test_framework.xpiaddr import encode


class MiningPoolLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(40)
        self.add_nodes(2, [[f"-publicbind=127.0.0.1:{self.public_port}"], []])
        with open(self.nodes[1].bitcoinconf, "a", encoding="utf-8") as config:
            config.write("\nminingpool=0\n")
        for node in self.nodes:
            with open(node.bitcoinconf, "a", encoding="utf-8") as config:
                config.write(f"\npooladdress={encode('rxpi', bytes(32), 0)}\n")
        self.start_nodes()

    def request(self, node, method, path, body=None, *, public=False):
        url = urllib.parse.urlparse(node.url)
        auth = base64.b64encode(f"{url.username}:{url.password}".encode()).decode()
        connection = http.client.HTTPConnection(
            url.hostname, self.public_port if public else url.port, timeout=15
        )
        connection.request(
            method,
            path,
            body,
            {"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        reply = connection.getresponse()
        status, payload = reply.status, reply.read()
        connection.close()
        return status, payload

    def run_test(self):
        a, b = self.nodes
        assert_equal(a.getpoolinfo()["enabled"], True)  # Default with RPC enabled.
        assert_equal(a.getpoolinfo()["pplns_window_max"], 1000)  # Shares, not blocks.
        calls = [
            ("getpoolinfo", []),
            ("getpoolworker", ["disabled"]),
            ("getminingjob", ["disabled"]),
            ("submitminingshare", ["1", "disabled", 0]),
        ]
        for name, args in calls:
            assert_raises_rpc_error(
                -1, "mining pool is disabled", getattr(b, name), *args
            )
        for method, route, body in [
            ("GET", "/pool/jobs", None),
            ("POST", "/pool/submit", "{}"),
            ("GET", "/pool/stats", None),
        ]:
            status, payload = self.request(b, method, route, body)
            assert_equal(status, 503)
            assert_equal(json.loads(payload)["error"], "mining-pool-disabled")
            status, _ = self.request(a, method, route, body, public=True)
            assert_equal(
                status, 404
            )  # Existing public-listener policy, even with auth.

        a.getminingjob("node-a")
        assert_equal(a.getpoolinfo()["active_workers"], 1)
        status, payload = self.request(a, "GET", "/pool/stats")
        assert_equal(status, 200)
        assert_equal(json.loads(payload)["active_workers"], 1)
        self.restart_node(1, ["-miningpool=1"])  # CLI overrides config opt-out.
        assert_equal(b.getpoolinfo()["enabled"], True)
        assert_equal(b.getpoolinfo()["active_workers"], 0)
        b.getminingjob("node-b")
        assert_equal(a.getpoolinfo()["active_workers"], 1)
        self.restart_node(0, [f"-publicbind=127.0.0.1:{self.public_port}"])
        assert_equal(
            a.getpoolinfo()["active_workers"], 0
        )  # Intentional in-memory reset.
        assert_equal(b.getpoolinfo()["active_workers"], 1)
        self.restart_node(1)  # Configuration opt-out takes effect again.
        assert_raises_rpc_error(-1, "mining pool is disabled", b.getpoolinfo)


if __name__ == "__main__":
    MiningPoolLifecycleTest().main()
