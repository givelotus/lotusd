#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""An owned loopback refusal keeps manual-connection diagnostics typed."""

import json
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class SocketFailureLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-avalanche=0"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        # A bound, non-listening TCP port times out on macOS. Close this
        # seed-owned port before connecting so the kernel refuses it instead.
        port = p2p_port(40)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", port))
        destination = f"127.0.0.1:{port}"
        node.addnode(destination, "onetry")
        self.wait_until(
            lambda: (
                f"connect() to {destination} failed" in node.debug_log_path.read_text()
            ),
            timeout=5,
        )
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        row = by_event["network_manual_connection_failed"]
        assert_equal(row["level"], "info")
        assert f"connect() to {destination} failed" in row["error"]
        assert_equal(row["message"], row["error"])
        assert "fields_truncated" not in row
        assert "peer_id" not in row


if __name__ == "__main__":
    SocketFailureLoggingTest().main()
