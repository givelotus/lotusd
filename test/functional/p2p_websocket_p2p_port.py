#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test raw P2P and P2P over WebSocket sharing the P2P port.

Each connection on the P2P port is classified by its first bytes: a TLS
ClientHello or an HTTP GET goes to the WebSocket endpoint, anything else
(the network magic) is raw P2P, exactly as before. The P2P port serves only
the P2P WebSocket path: never JSON-RPC, REST, Chronik or health checks.
"""

import base64
import http.client
import socket
import ssl
import threading
import time

from test_framework.messages import msg_ping
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, get_auth_cookie, p2p_port, rpc_port

FALLBACK_PORT_INDEX = 41
FALLBACK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 20\r\n"
    b"Connection: close\r\n\r\n<html>welcome</html>"
)
HANDSHAKE_TIMEOUT = 3
# MAX_P2P_PORT_PENDING_PER_ADDR
MAX_PENDING_PER_ADDR = 8


class FallbackSite:
    """Answers every request with FALLBACK_RESPONSE."""

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


class P2PWebSocketP2PPortTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-p2pporthandshaketimeout={HANDSHAKE_TIMEOUT}", "-rest=1"],
            [],
            [],
            [],
        ]

    def setup_network(self):
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            raise SkipTest("websocket-client and zstandard are required")

    def ws_client(self, scheme, port=None, **kwargs):
        from test_framework.p2p_websocket import P2PWebSocketClient

        return P2PWebSocketClient(
            f"{scheme}://127.0.0.1:{port or p2p_port(0)}/p2p/ws",
            srcdir=self.config["environment"]["SRCDIR"],
            timeout=10,
            **kwargs,
        )

    def peers(self, n=0, transport=None):
        return [
            p
            for p in self.nodes[n].getpeerinfo()
            if transport is None or p["transport"] == transport
        ]

    def restart(self, extra_args):
        self.restart_node(
            0,
            [f"-p2pporthandshaketimeout={HANDSHAKE_TIMEOUT}", "-rest=1"] + extra_args,
        )

    def http_on_p2p_port(self, method, path, *, tls, body=None, headers=None):
        """Status of a request on the P2P port, or None if the connection
        was closed without an HTTP response."""
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                "127.0.0.1", p2p_port(0), timeout=10, context=ctx
            )
        else:
            conn = http.client.HTTPConnection("127.0.0.1", p2p_port(0), timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        except (http.client.RemoteDisconnected, ConnectionError):
            return None, b""
        finally:
            conn.close()

    def closed_within(self, sock, seconds):
        """Whether the node closes `sock` within `seconds`."""
        sock.settimeout(seconds)
        try:
            return sock.recv(1) == b""
        except TimeoutError:
            return False
        except ConnectionError:
            return True

    def run_test(self):
        self.test_all_transports_on_one_port()
        self.test_no_rpc_rest_chronik_on_p2p_port()
        self.test_fallback_site()
        self.test_raw_off()
        self.test_ws_off()
        self.test_slow_clients()

    def test_all_transports_on_one_port(self):
        node0 = self.nodes[0]
        self.log.info("A stock-style raw P2P peer proceeds as before")
        with node0.assert_debug_log(
            ["connection from 127.0.0.1"],
            unexpected_msgs=["is HTTP/TLS"],
        ):
            stock = node0.add_p2p_connection(P2PInterface())
            stock.sync_with_ping()
        assert_equal([p["transport"] for p in self.peers()], ["tcp"])
        node0.disconnect_p2ps()
        self.wait_until(lambda: len(self.peers()) == 0)

        self.log.info("Raw, ws:// and wss:// peers share the P2P port and sync")
        port = p2p_port(0)
        self.nodes[1].addnode(f"127.0.0.1:{port}", "onetry")
        self.nodes[2].addnode(f"ws://127.0.0.1:{port}/p2p/ws", "onetry")
        self.nodes[3].addnode(f"wss://127.0.0.1:{port}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers()) == 3)
        assert_equal(sorted(p["transport"] for p in self.peers()), ["tcp", "ws", "wss"])
        # With raw P2P on, a WebSocket peer on the P2P port is first a raw
        # P2P node, dropped when its first bytes are HTTP or TLS: it takes
        # a second node id.
        assert all(p["inbound"] for p in self.peers())
        for p in self.peers():
            # The address reached is the P2P port in every case.
            assert_equal(p["addrbind"], f"127.0.0.1:{port}")
        self.generate(node0, 1)
        self.sync_blocks()
        self.generate(self.nodes[3], 1)
        self.sync_blocks()
        for n in range(1, 4):
            for p in self.nodes[n].getpeerinfo():
                self.nodes[n].disconnectnode(nodeid=p["id"])
        self.wait_until(lambda: len(self.peers()) == 0)

        self.log.info("A Python WebSocket peer, ws:// and wss://")
        for scheme in ("ws", "wss"):
            peer = self.ws_client(scheme)
            assert_equal(peer.handshake().nStartingHeight, 2)
            peer.send_message(msg_ping(nonce=42))
            assert_equal(peer.wait_for(b"pong").nonce, 42)
            self.wait_until(lambda: len(self.peers(transport=scheme)) == 1)
            peer.close()
            self.wait_until(lambda: len(self.peers()) == 0)

    def test_no_rpc_rest_chronik_on_p2p_port(self):
        self.log.info("JSON-RPC, REST, Chronik and health are never served there")
        node0 = self.nodes[0]
        user, password = get_auth_cookie(node0.datadir, self.chain)
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        rpc_body = '{"method":"getblockcount","params":[],"id":1}'
        rpc_headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }
        # Control: the RPC port serves both.
        rpc = http.client.HTTPConnection("127.0.0.1", rpc_port(0), timeout=10)
        rpc.request("GET", "/rest/chaininfo.json")
        assert_equal(rpc.getresponse().status, 200)
        rpc.close()

        for tls in (False, True):
            for path in (
                "/rest/chaininfo.json",
                "/livez",
                "/healthz",
                "/chronik/blockchain-info",
                "/",
                "/p2p/ws",
            ):
                status, _ = self.http_on_p2p_port("GET", path, tls=tls)
                assert_equal(status, 404)
            status, body = self.http_on_p2p_port(
                "POST", "/", tls=tls, body=rpc_body, headers=rpc_headers
            )
            # Plain text that is not a GET is not HTTP to the P2P port: raw
            # P2P rejects it. Over TLS the request is read and refused.
            assert_equal(status, 404 if tls else None)
            assert b"result" not in body
        assert_equal(self.peers(), [])

    def test_fallback_site(self):
        self.log.info("-publicfallback answers the P2P port's unserved requests")
        fallback_port = p2p_port(FALLBACK_PORT_INDEX)
        site = FallbackSite(fallback_port)
        self.restart([f"-publicfallback=127.0.0.1:{fallback_port}"])
        for tls in (False, True):
            status, body = self.http_on_p2p_port("GET", "/", tls=tls)
            assert_equal((status, body), (200, b"<html>welcome</html>"))
            status, body = self.http_on_p2p_port("GET", "/rest/chaininfo.json", tls=tls)
            assert_equal((status, body), (200, b"<html>welcome</html>"))
        # The WebSocket endpoint is still the node's.
        peer = self.ws_client("wss")
        peer.handshake()
        peer.close()
        self.wait_until(lambda: len(self.peers()) == 0)
        site.stop()
        self.restart([])

    def test_raw_off(self):
        self.log.info("-p2prawlisten=0: raw P2P closed, WebSocket accepted")
        self.restart(["-p2prawlisten=0"])
        node0 = self.nodes[0]
        with node0.assert_debug_log(["raw P2P is not accepted"], timeout=10):
            # Closed after its version message: it may never look connected.
            raw = node0.add_p2p_connection(
                P2PInterface(), wait_for_connection=False, wait_for_verack=False
            )
        raw.wait_until(lambda: not raw.is_connected, check_connected=False)
        assert "version" not in raw.last_message
        node0.disconnect_p2ps()
        peer = self.ws_client("ws")
        peer.handshake()
        assert_equal([p["transport"] for p in self.peers()], ["ws"])
        # Neither the refused raw peer nor the WebSocket one passed through
        # a raw P2P node first: this is the first node.
        assert_equal(self.peers()[0]["id"], 0)
        peer.close()
        self.wait_until(lambda: len(self.peers()) == 0)
        self.nodes[2].addnode(f"wss://127.0.0.1:{p2p_port(0)}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers(transport="wss")) == 1)
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[0:3:2])
        self.nodes[2].disconnectnode(nodeid=self.nodes[2].getpeerinfo()[0]["id"])
        self.wait_until(lambda: len(self.peers()) == 0)

    def test_ws_off(self):
        self.log.info("-p2pwslisten=0: WebSocket refused, raw P2P accepted")
        import websocket

        self.restart(["-p2pwslisten=0"])
        node0 = self.nodes[0]
        for scheme in ("ws", "wss"):
            try:
                self.ws_client(scheme).close()
                raise AssertionError(f"{scheme}:// accepted with -p2pwslisten=0")
            except (
                websocket.WebSocketException,
                ConnectionError,
                ssl.SSLError,
            ):
                pass
        stock = node0.add_p2p_connection(P2PInterface())
        stock.sync_with_ping()
        assert_equal([p["transport"] for p in self.peers()], ["tcp"])
        node0.disconnect_p2ps()
        self.wait_until(lambda: len(self.peers()) == 0)

    def test_slow_clients(self):
        self.log.info("Silent and partial-header clients are closed at the deadline")
        self.restart(["-p2prawlisten=0"])
        port = p2p_port(0)
        silent = socket.create_connection(("127.0.0.1", port))
        partial_http = socket.create_connection(("127.0.0.1", port))
        partial_http.sendall(b"GET /p2p/ws HTTP/1.1\r\nHost: example\r\n")
        partial_tls = socket.create_connection(("127.0.0.1", port))
        partial_tls.sendall(b"\x16\x03\x01\x02\x00\x01")
        partial_get = socket.create_connection(("127.0.0.1", port))
        partial_get.sendall(b"GE")
        time.sleep(0.5)
        self.log.info("... and meanwhile a WebSocket peer still connects")
        peer = self.ws_client("ws")
        peer.handshake()
        start = time.time()
        for sock in (silent, partial_http, partial_tls, partial_get):
            assert self.closed_within(sock, HANDSHAKE_TIMEOUT + 5)
            sock.close()
        assert time.time() - start < HANDSHAKE_TIMEOUT + 5
        # The WebSocket peer is not subject to the deadline once upgraded.
        time.sleep(1)
        peer.send_message(msg_ping(nonce=7))
        assert_equal(peer.wait_for(b"pong").nonce, 7)
        peer.close()
        self.wait_until(lambda: len(self.peers()) == 0)

        self.log.info("Pending WebSocket connections are limited per address")
        held = []
        for _ in range(MAX_PENDING_PER_ADDR):
            s = socket.create_connection(("127.0.0.1", port))
            s.sendall(b"GET /p2p/ws HTTP/1.1\r\n")
            held.append(s)
        time.sleep(1)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.sendall(b"GET /p2p/ws HTTP/1.1\r\n")
        assert self.closed_within(extra, 2)
        extra.close()
        for s in held:
            assert not self.closed_within(s, 0.1)
        # Once they time out, the address can connect again.
        for s in held:
            assert self.closed_within(s, HANDSHAKE_TIMEOUT + 5)
            s.close()
        peer = self.ws_client("ws")
        peer.handshake()
        peer.close()

        self.log.info("With raw P2P on, a silent client is a raw P2P peer, as before")
        self.restart([])
        silent = socket.create_connection(("127.0.0.1", port))
        self.wait_until(lambda: len(self.peers()) == 1)
        assert_equal(self.peers()[0]["transport"], "tcp")
        time.sleep(HANDSHAKE_TIMEOUT + 1)
        assert_equal(len(self.peers()), 1)
        silent.close()
        self.wait_until(lambda: len(self.peers()) == 0)


if __name__ == "__main__":
    P2PWebSocketP2PPortTest().main()
