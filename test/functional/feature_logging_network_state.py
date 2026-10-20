#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual peer-networking RPC toggles keep typed bool and readable boolalpha."""

import base64
import http.client
import json
from urllib.parse import urlsplit

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NetworkStateLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-metrics=1"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        for active in (False, True):
            node.setnetworkactive(active)
            assert_equal(node.getnetworkinfo()["networkactive"], active)
        endpoint = urlsplit(node.url)
        credential = f"{endpoint.username}:{endpoint.password}".encode()
        authorization = base64.b64encode(credential).decode()
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port)
        connection.request(
            "GET", "/metrics", headers={"Authorization": f"Basic {authorization}"}
        )
        response = connection.getresponse()
        assert_equal(response.status, 200)
        assert response.getheader("Content-Type").startswith("text/plain")
        assert "# TYPE " in response.read().decode()
        connection.close()
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        states = [row for row in rows if row.get("event") == "network_active_set"]
        metrics = {row.get("event"): row for row in rows}["http_metrics_serving"]
        assert_equal(metrics["http_path"], "/metrics")
        assert_equal(
            metrics["message"], "Serving metrics at /metrics on the RPC listeners"
        )
        assert_equal(metrics["level"], "info")
        assert "fields_truncated" not in metrics
        assert "path" not in metrics
        assert len(states) >= 2
        for row, active in zip(states[-2:], (False, True)):
            assert type(row["network_active"]) is bool
            assert_equal(row["network_active"], active)
            assert_equal(row["source_function"], "SetNetworkActive")
            assert_equal(row["message"], f"SetNetworkActive: {str(active).lower()}")
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    NetworkStateLoggingTest().main()
