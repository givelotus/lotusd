#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -p2pwebsocketpath and -p2pwebsockettoken.

A node serving P2P WebSocket at a custom path behind a token answers every
request lacking the token exactly as it answers a request for an unknown
path, so the endpoint cannot be found by probing.
"""

import base64
import os
import re
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40
PATH = "/assets/live"
TOKENS = ["s3cret-Token_1", "other.2~"]


class P2PWebSocketTokenTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [
            [
                f"-publicbind=127.0.0.1:{self.public_port}",
                f"-p2pwebsocketpath={PATH}",
                *[f"-p2pwebsockettoken={t}" for t in TOKENS],
            ],
            [],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def request(self, target, headers=(), upgrade=True):
        """Send one request; return (status line, headers without Date, body)."""
        lines = [f"GET {target} HTTP/1.1", f"Host: 127.0.0.1:{self.public_port}"]
        if upgrade:
            key = base64.b64encode(os.urandom(16)).decode()
            lines += [
                "Upgrade: websocket",
                "Connection: Upgrade",
                f"Sec-WebSocket-Key: {key}",
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Protocol: p2p-zstd-v1",
            ]
        lines += list(headers)
        with socket.create_connection(("127.0.0.1", self.public_port)) as s:
            s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            head_lines = head.decode().split("\r\n")
            status, fields = head_lines[0], head_lines[1:]
            if status.split()[1] == "101":
                return status, [], b""
            length = 0
            for f in fields:
                if f.lower().startswith("content-length:"):
                    length = int(f.split(":", 1)[1])
            while len(body) < length:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
        fields = [f for f in fields if not f.lower().startswith("date:")]
        return status, fields, body

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        self.log.info("Without a valid token the endpoint looks like any unknown path")
        unknown = self.request("/no-such-page", upgrade=False)
        assert unknown[0].split()[1] in ("403", "404"), unknown[0]
        for target, headers, upgrade in (
            (PATH, (), False),
            (PATH, (), True),
            (PATH, ("Authorization: Bearer wrong",), True),
            (PATH, ("Cookie: t=wrong",), True),
            (PATH, (f"Authorization: Bearer {TOKENS[0]}",), False),
            ("/p2p/ws", (f"Authorization: Bearer {TOKENS[0]}",), True),
            ("/no-such-page", (), True),
        ):
            assert_equal(self.request(target, headers, upgrade), unknown)

        self.log.info("With a token (header or cookie) the upgrade succeeds")
        for headers in (
            (f"Authorization: Bearer {TOKENS[0]}",),
            (f"Cookie: a=b; t={TOKENS[1]}",),
        ):
            status = self.request(PATH, headers)[0]
            assert status.split()[1] == "101", (status, headers)
        self.wait_until(lambda: len(self.ws_peers(0)) == 0)

        self.log.info("A node dials ?token= URLs, sending the token as a header")
        url = f"wss://localhost:{self.public_port}{PATH}?token={TOKENS[0]}"
        with self.nodes[1].assert_debug_log(["?token=***"]):
            self.nodes[1].addnode(node=url, command="onetry")
            self.wait_until(lambda: len(self.ws_peers(0)) == 1)
        self.sync_blocks()
        with open(self.nodes[1].debug_log_path, encoding="utf8") as f:
            assert TOKENS[0] not in f.read()
        self.nodes[1].disconnectnode(nodeid=self.ws_peers(1)[0]["id"])
        self.wait_until(lambda: len(self.ws_peers(0)) == 0)

        self.log.info("...and gets nowhere with a wrong token")
        bad = f"wss://localhost:{self.public_port}{PATH}?token=wrong"
        with self.nodes[1].assert_debug_log(["WebSocket upgrade"]):
            self.nodes[1].addnode(node=bad, command="onetry")
        assert_equal(self.ws_peers(1), [])

        self.log.info("Invalid settings are startup errors")
        node0 = self.nodes[0]
        self.stop_node(0)
        for args, error in (
            (["-p2pwebsockettoken=x", "-externaldomain=example.org"],
             "-externaldomain cannot be combined"),
            (["-p2pwebsocketpath=/"], "Unable to start HTTP server"),
            (["-p2pwebsocketpath=relative"], "Unable to start HTTP server"),
            (["-p2pwebsockettoken=bad token"], "Unable to start HTTP server"),
        ):
            node0.assert_start_raises_init_error(
                args, re.escape(error), match=ErrorMatch.PARTIAL_REGEX
            )


if __name__ == "__main__":
    P2PWebSocketTokenTest().main()
