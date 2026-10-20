#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual public listener, worker counts and invalid configuration records."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class HTTPListenerLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []

    def setup_nodes(self):
        self.listener = f"127.0.0.1:{p2p_port(40)}"
        self.extra_args = [
            [
                "-logformat=json",
                "-rpcthreads=2",
                "-rpciothreads=1",
                "-p2pwebsocket=1",
                f"-publicbind={self.listener}",
            ]
        ]
        super().setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        for option in (
            "-publicbind=127.0.0.1",
            "-trustedproxy=invalid-owned-proxy",
            "-p2pwebsocketpath=/",
            "-publicfallback=127.0.0.1",
        ):
            node.assert_start_raises_init_error(
                extra_args=["-logformat=json", option],
                expected_msg="Error: Unable to start HTTP server. See debug log for details.",
                timeout=5,
            )
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        by_event = {row.get("event"): row for row in rows}
        started = by_event["http_worker_threads_started"]
        assert_equal(started["coroutine_worker_threads"], 2)
        assert_equal(started["io_threads"], 1)
        for key in ("coroutine_worker_threads", "io_threads"):
            assert isinstance(started[key], int)
        assert_equal(
            started["message"],
            "Starting HTTP server with 2 coroutine worker threads and 1 I/O threads",
        )
        public = by_event["public_listener_serving"]
        assert_equal(public["listen_address"], self.listener)
        assert_equal(public["public_prefixes"], "/p2p/ws")
        assert_equal(
            public["message"],
            f"Serving /p2p/ws on public listener {self.listener} (RPC, wallet and REST are not served there)",
        )
        assert "peer_address" not in public
        checks = (
            (
                "public_listener_port_missing",
                "listen_address",
                "127.0.0.1",
                "Error: -publicbind=127.0.0.1 needs an explicit port",
            ),
            (
                "trusted_proxy_invalid",
                "addr",
                "invalid-owned-proxy",
                "Error: invalid -trustedproxy 'invalid-owned-proxy' (an address or subnet, e.g. 10.0.0.0/8)",
            ),
            (
                "p2p_websocket_path_invalid",
                "http_path",
                "/",
                "Error: invalid -p2pwebsocketpath '/' (an absolute path such as /p2p/ws, not / and without query or trailing /)",
            ),
            (
                "public_fallback_invalid",
                "addr",
                "127.0.0.1",
                "Error: invalid -publicfallback '127.0.0.1' (host:port)",
            ),
        )
        for event, key, value, message in checks:
            row = by_event[event]
            assert_equal(row[key], value)
            assert_equal(row["message"], message)
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
            assert "path" not in row
        for row in (started, public):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    HTTPListenerLoggingTest().main()
