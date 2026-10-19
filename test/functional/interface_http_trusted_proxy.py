#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -trustedproxy (PROXY protocol, X-Forwarded-For) and health endpoints.

The node trusts 127.0.0.1 (standing in for a load balancer) and 10.0.0.0/8
(further balancer layers). Connections from ::1 stand in for anyone else.
"""

import base64
import json
import os
import socket
import struct
import urllib.parse

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40
V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def proxy_v2_tcp4(src, sport, dst="10.0.0.5", dport=10605):
    addrs = (
        socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">HH", sport, dport)
    )
    return V2_SIG + bytes([0x21, 0x11]) + struct.pack(">H", len(addrs)) + addrs


def upgrade(path="/p2p/ws", headers=()):
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: node",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: p2p-zstd-v1",
        *headers,
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def get(path, headers=()):
    lines = [f"GET {path} HTTP/1.1", "Host: node", "Connection: close", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


class HTTPTrustedProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.bind(("::1", 0))
        except OSError:
            raise SkipTest("needs IPv6 loopback (::1) for an untrusted client")

    def setup_network(self):
        self.port = p2p_port(PUBLIC_PORT_INDEX)
        self.args0 = [
            f"-publicbind=127.0.0.1:{self.port}",
            f"-publicbind=[::1]:{self.port}",
            "-trustedproxy=127.0.0.1",
            "-trustedproxy=10.0.0.0/8",
        ]
        self.extra_args = [self.args0, []]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def exchange(self, data, host="127.0.0.1", port=None, keep=False):
        """Send bytes, return (status line, body, socket if kept open)."""
        s = socket.create_connection((host, port or self.port), timeout=10)
        s.sendall(data)
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
        head, _, body = reply.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode()
        if keep:
            return status, body, s
        try:
            while chunk := s.recv(4096):
                body += chunk
        except OSError:
            pass
        s.close()
        return status, body, None

    def ws_peer_addr(self, data, host="127.0.0.1"):
        """Upgrade to P2P; return the address the node gives the peer."""
        before = {p["id"] for p in self.nodes[0].getpeerinfo()}
        status, _, s = self.exchange(data, host=host, keep=True)
        assert status.startswith("HTTP/1.1 101"), status
        self.wait_until(lambda: len(self.nodes[0].getpeerinfo()) > len(before))
        peer = [p for p in self.nodes[0].getpeerinfo() if p["id"] not in before][0]
        s.close()
        self.wait_until(
            lambda: peer["id"] not in {p["id"] for p in self.nodes[0].getpeerinfo()}
        )
        return peer["addr"]

    def run_test(self):
        self.log.info("PROXY v2 from a trusted balancer: the client's address")
        assert_equal(
            self.ws_peer_addr(proxy_v2_tcp4("203.0.113.7", 51000) + upgrade()),
            "203.0.113.7:51000",
        )
        self.log.info("PROXY v1, and a LOCAL v2 header (balancer health check)")
        v1 = b"PROXY TCP4 198.51.100.22 10.0.0.5 35646 10605\r\n"
        assert_equal(self.ws_peer_addr(v1 + upgrade()), "198.51.100.22:35646")
        local = V2_SIG + bytes([0x20, 0x00, 0x00, 0x00])
        assert self.ws_peer_addr(local + upgrade()).startswith("127.0.0.1:")
        self.log.info("No header from a trusted balancer is fine too")
        assert self.ws_peer_addr(upgrade()).startswith("127.0.0.1:")
        self.log.info("A PROXY header from anyone else is not believed")
        status, _, _ = self.exchange(v1 + upgrade(), host="::1")
        assert status.startswith("HTTP/1.1 400"), status

        self.log.info("X-Forwarded-For through two trusted layers")
        xff = "X-Forwarded-For: 1.1.1.1, 198.51.100.4, 10.0.0.9"
        assert self.ws_peer_addr(upgrade(headers=[xff])).startswith("198.51.100.4:")
        self.log.info("...combined with PROXY from the outer balancer")
        assert self.ws_peer_addr(
            proxy_v2_tcp4("10.0.3.3", 4000)
            + upgrade(headers=["X-Forwarded-For: 192.0.2.10"])
        ).startswith("192.0.2.10:")
        self.log.info("...and ignored from an untrusted client")
        assert self.ws_peer_addr(upgrade(headers=[xff]), host="::1").startswith(
            "[::1]:"
        )

        self.log.info("-rpcallowip applies to the resolved client")
        rpc = rpc_port(0)
        body = b'{"method":"getblockcount","params":[],"id":1}'

        def rpc_request(extra=()):
            # Credentials change on restart (a new cookie).
            url = urllib.parse.urlparse(self.nodes[0].url)
            auth = (
                "Authorization: Basic "
                + base64.b64encode(f"{url.username}:{url.password}".encode()).decode()
            )
            lines = [
                "POST / HTTP/1.1",
                "Host: node",
                "Connection: close",
                auth,
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
                *extra,
            ]
            return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

        assert_equal(self.exchange(rpc_request(), port=rpc)[0].split()[1], "200")
        status = self.exchange(rpc_request(["X-Forwarded-For: 203.0.113.9"]), port=rpc)[
            0
        ]
        assert_equal(status.split()[1], "403")
        self.restart_node(0, self.args0 + ["-rpcallowip=203.0.113.0/24"])
        status = self.exchange(rpc_request(["X-Forwarded-For: 203.0.113.9"]), port=rpc)[
            0
        ]
        assert_equal(status.split()[1], "200")

        self.log.info("/livez, /readyz and /healthz")
        status, body, _ = self.exchange(get("/livez"))
        assert_equal((status.split()[1], json.loads(body)), ("200", {"status": "ok"}))
        for path in ("/readyz", "/healthz"):
            status, body, _ = self.exchange(get(path))
            assert_equal(status.split()[1], "503")
            assert_equal(json.loads(body)["reason"], "initial block download")
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        status, body, _ = self.exchange(get("/readyz"))
        assert_equal(
            (status.split()[1], json.loads(body)["reason"]), ("503", "no peers")
        )
        self.connect_nodes(1, 0)
        status, body, _ = self.exchange(get("/readyz?verbose=1"))
        assert_equal((status.split()[1], json.loads(body)), ("200", {"status": "ok"}))
        status, body, _ = self.exchange(
            b"HEAD /livez HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        assert_equal((status.split()[1], body), ("200", b""))
        # Also on the RPC port, without credentials.
        assert_equal(self.exchange(get("/livez"), port=rpc)[0].split()[1], "200")

        self.log.info("A token bridge does not serve them, unless asked to")
        self.restart_node(0, self.args0 + ["-p2pwebsockettoken=t0k"])
        assert_equal(self.exchange(get("/livez"))[0].split()[1], "404")
        self.restart_node(0, self.args0 + ["-p2pwebsockettoken=t0k", "-httphealth=1"])
        assert_equal(self.exchange(get("/livez"))[0].split()[1], "200")

        self.log.info("An invalid -trustedproxy is a startup error")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-trustedproxy=not-a-subnet"],
            "Unable to start HTTP server",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == "__main__":
    HTTPTrustedProxyTest().main()
