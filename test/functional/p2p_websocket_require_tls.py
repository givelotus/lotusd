#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -p2prequiretls and unencrypted WebSocket under -onlynet=wss.

With -p2prequiretls, P2P WebSocket upgrades without TLS get the answer of
any unserved request (404, or the -publicfallback site) on the P2P port,
-publicbind listeners and the RPC port. Connections from a -trustedproxy
count as TLS when the proxy says the client used it: the nearest proxy's
X-Forwarded-Proto, or a PROXY v2 SSL TLV. Nothing else is believed.
"""

import socket
import ssl
import struct
import threading

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40
FALLBACK_PORT_INDEX = 41
FALLBACK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n"
    b"<html>welcome</html>"
)
PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def proxy_v2(src, dst, tlvs=b""):
    """A PROXY v2 header for TCP over IPv4 from src to dst ((ip, port))."""
    addrs = (
        socket.inet_aton(src[0])
        + socket.inet_aton(dst[0])
        + struct.pack(">HH", src[1], dst[1])
        + tlvs
    )
    return PROXY_V2_SIGNATURE + b"\x21\x11" + struct.pack(">H", len(addrs)) + addrs


# PP2_TYPE_SSL with PP2_CLIENT_SSL, a zero verify field and no sub-TLVs
SSL_TLV = b"\x20\x00\x05\x01\x00\x00\x00\x00"


def upgrade(port, *, tls=False, prefix=b"", headers=()):
    """Send a P2P WebSocket upgrade request; return the response status."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(prefix)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock)
    request = (
        "GET /p2p/ws HTTP/1.1\r\nHost: node.example\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: p2p-v2\r\n"
        + "".join(f"{h}\r\n" for h in headers)
        + "\r\n"
    )
    sock.sendall(request.encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()
    return int(data.split(b" ")[1]) if data else None


class FallbackSite:
    def __init__(self, port):
        self.server = socket.create_server(("127.0.0.1", port))
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(FALLBACK_RESPONSE)

    def stop(self):
        self.server.close()


class P2PWebSocketRequireTLSTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            raise SkipTest("websocket-client and zstandard are required")

    def public_port(self):
        return p2p_port(PUBLIC_PORT_INDEX)

    def restart(self, extra_args):
        self.restart_node(
            0, [f"-publicbind=127.0.0.1:{self.public_port()}"] + extra_args
        )

    def peers(self, n=0):
        return self.nodes[n].getpeerinfo()

    def wait_no_peers(self):
        self.wait_until(lambda: len(self.peers()) == 0)

    def accepted(self, status):
        """A 101 created a P2P peer: wait for it to go."""
        if status == 101:
            self.wait_no_peers()
        return status == 101

    def run_test(self):
        self.test_defaults()
        self.test_require_tls()
        self.test_trusted_proxy()
        self.test_untrusted_headers()
        self.test_fallback()
        self.test_onlynet_wss()

    def test_defaults(self):
        self.log.info("Default (-p2prequiretls=0): ws:// is accepted everywhere")
        self.restart([])
        for port in (p2p_port(0), self.public_port(), rpc_port(0)):
            assert self.accepted(upgrade(port))
            assert self.accepted(upgrade(port, tls=True))

    def test_require_tls(self):
        self.log.info("-p2prequiretls=1: wss:// connects, ws:// gets 404")
        from test_framework.p2p_websocket import P2PWebSocketClient

        self.restart(["-p2prequiretls=1"])
        for port in (p2p_port(0), self.public_port(), rpc_port(0)):
            assert_equal(upgrade(port), 404)
            assert self.accepted(upgrade(port, tls=True))
        assert_equal(self.peers(), [])
        for port in (p2p_port(0), self.public_port()):
            peer = P2PWebSocketClient(
                f"wss://127.0.0.1:{port}/p2p/ws",
                srcdir=self.config["environment"]["SRCDIR"],
            )
            peer.handshake()
            assert_equal([p["transport"] for p in self.peers()], ["wss"])
            peer.close()
            self.wait_no_peers()

    def test_trusted_proxy(self):
        self.log.info("A trusted proxy saying the client used TLS is believed")
        self.restart(["-p2prequiretls=1", "-trustedproxy=127.0.0.1"])
        public = self.public_port()
        dst = ("127.0.0.1", public)
        for port in (p2p_port(0), public):
            assert self.accepted(upgrade(port, headers=["X-Forwarded-Proto: https"]))
            # The nearest proxy's value (the last) counts.
            assert self.accepted(
                upgrade(port, headers=["X-Forwarded-Proto: http, https"])
            )
            assert_equal(upgrade(port, headers=["X-Forwarded-Proto: http"]), 404)
            assert_equal(upgrade(port, headers=["X-Forwarded-Proto: https, http"]), 404)
            assert_equal(upgrade(port), 404)
        self.log.info("... or with a PROXY v2 SSL TLV (on -publicbind)")
        client = ("203.0.113.7", 51000)
        assert self.accepted(upgrade(public, prefix=proxy_v2(client, dst, SSL_TLV)))
        assert_equal(upgrade(public, prefix=proxy_v2(client, dst)), 404)
        # Behind an L4 proxy, the HTTP comes from the (untrusted) client:
        # its X-Forwarded-Proto is not believed.
        assert_equal(
            upgrade(
                public,
                prefix=proxy_v2(client, dst),
                headers=["X-Forwarded-Proto: https"],
            ),
            404,
        )

    def test_untrusted_headers(self):
        self.log.info("The same headers from an untrusted address are refused")
        self.restart(["-p2prequiretls=1"])
        public = self.public_port()
        for port in (p2p_port(0), public):
            assert_equal(upgrade(port, headers=["X-Forwarded-Proto: https"]), 404)
        # A PROXY header is not even read from an untrusted address.
        status = upgrade(
            public,
            prefix=proxy_v2(("203.0.113.7", 51000), ("127.0.0.1", public), SSL_TLV),
        )
        assert status != 101
        assert_equal(self.peers(), [])

    def test_fallback(self):
        self.log.info("With -publicfallback, ws:// upgrades get the fallback site")
        fallback_port = p2p_port(FALLBACK_PORT_INDEX)
        site = FallbackSite(fallback_port)
        self.restart(["-p2prequiretls=1", f"-publicfallback=127.0.0.1:{fallback_port}"])
        for port in (p2p_port(0), self.public_port()):
            assert_equal(upgrade(port), 200)
            assert self.accepted(upgrade(port, tls=True))
        site.stop()

    def test_onlynet_wss(self):
        self.log.info("-onlynet=wss never dials raw P2P or unencrypted ws://")
        self.restart([])
        node1 = self.nodes[1]
        self.restart_node(1, ["-onlynet=wss"])
        with node1.assert_debug_log(["unencrypted ws:// needs network ipv4 or ipv6"]):
            node1.addnode(f"ws://127.0.0.1:{p2p_port(0)}/p2p/ws", "onetry")
        with node1.assert_debug_log(["plain P2P to network ipv4 is not allowed"]):
            node1.addnode(f"127.0.0.1:{p2p_port(0)}", "onetry")
        assert_equal(self.peers(1), [])
        node1.addnode(f"wss://127.0.0.1:{p2p_port(0)}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers(1)) == 1)
        assert_equal(self.peers(1)[0]["transport"], "wss")
        self.log.info("... while ws:// works without -onlynet")
        node1.disconnectnode(nodeid=self.peers(1)[0]["id"])
        self.wait_until(lambda: len(self.peers(1)) == 0)
        self.restart_node(1, [])
        node1.addnode(f"ws://127.0.0.1:{p2p_port(0)}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers(1)) == 1)
        assert_equal(self.peers(1)[0]["transport"], "ws")


if __name__ == "__main__":
    P2PWebSocketRequireTLSTest().main()
