#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -publicfallback: requests the node does not serve on a -publicbind
listener (pages, probes, upgrades without the token) are answered by another
web server, byte for byte, over plain HTTP and over TLS."""

import base64
import os
import socket
import ssl
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40
FALLBACK_PORT_INDEX = 41
PATH = "/static/app"
TOKEN = "tok3n"
# Deliberately unusual header case and order: relayed unchanged.
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nserver: nginx\r\nX-Site: Fallback\r\n"
    b"Content-Type: text/html\r\nContent-Length: 20\r\nConnection: close\r\n\r\n"
    b"<html>welcome</html>"
)


class FallbackSite:
    """Answers every request with RESPONSE, recording what it received."""

    def __init__(self, port):
        self.requests = []
        self.lock = threading.Lock()
        self.server = socket.create_server(("127.0.0.1", port))
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def accept_loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value)
            while len(body) < length:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                body += chunk
            with self.lock:
                self.requests.append((head.decode(), body))
            conn.sendall(RESPONSE)

    def stop(self):
        try:
            self.server.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.server.close()


class HTTPPublicFallbackTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.fallback_port = p2p_port(FALLBACK_PORT_INDEX)
        self.site = FallbackSite(self.fallback_port)
        self.extra_args = [
            [
                f"-publicbind=127.0.0.1:{self.public_port}",
                f"-publicfallback=127.0.0.1:{self.fallback_port}",
                f"-p2pwebsocketpath={PATH}",
                f"-p2pwebsockettoken={TOKEN}",
            ],
            [],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def raw(self, request, tls=False):
        """Send raw request bytes; return everything received until close."""
        sock = socket.create_connection(("127.0.0.1", self.public_port))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname="example.org")
        with sock:
            sock.sendall(request)
            data = b""
            sock.settimeout(10)
            try:
                while chunk := sock.recv(65536):
                    data += chunk
                    if data.startswith(b"HTTP/1.1 101"):
                        break
            except (TimeoutError, ssl.SSLError, ConnectionResetError):
                pass
        return data

    def upgrade(self, target, auth=None):
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {target} HTTP/1.1",
            "Host: example.org",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Protocol: p2p-zstd-v1",
        ]
        if auth:
            lines.append(f"Authorization: Bearer {auth}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        for tls in (False, True):
            scheme = "https" if tls else "http"
            self.log.info(f"{scheme}: pages and probes get the fallback's bytes")
            for request in (
                b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
                b"GET /favicon.ico HTTP/1.0\r\n\r\n",
                b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n",
                self.upgrade(PATH),
                self.upgrade(PATH, auth="wrong"),
                self.upgrade("/p2p/ws", auth=TOKEN),
                b"GET " + PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n",
            ):
                assert_equal(self.raw(request, tls), RESPONSE)

            self.log.info(f"{scheme}: the request reaches the site as sent")
            body = os.urandom(200_000)
            with self.site.lock:
                self.site.requests.clear()
            request = (
                b"POST /upload?x=1 HTTP/1.1\r\nHost: example.org\r\n"
                b"X-Custom-CASE: kept\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
            assert_equal(self.raw(request, tls), RESPONSE)
            head, got = self.site.requests[0]
            assert head.startswith("POST /upload?x=1 HTTP/1.1\r\n"), head
            assert "\r\nX-Custom-CASE: kept\r\n" in head, head
            assert "\r\nX-Forwarded-For: 127.0.0.1\r\n" in head, head
            assert_equal(f"X-Forwarded-Proto: {scheme}" in head, True)
            assert_equal(got, body)

            self.log.info(f"{scheme}: an upgrade with the token is P2P")
            reply = self.raw(self.upgrade(PATH, auth=TOKEN), tls)
            assert reply.startswith(b"HTTP/1.1 101 "), reply[:40]

        self.log.info("Nodes dialing with the token still connect")
        url = f"wss://localhost:{self.public_port}{PATH}?token={TOKEN}"
        self.nodes[1].addnode(node=url, command="onetry")
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)

        self.log.info("With the site down, a bare 502")
        self.site.stop()
        reply = self.raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert reply.startswith(b"HTTP/1.1 502 "), reply[:40]

        self.log.info("An invalid -publicfallback is a startup error")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-publicfallback=nohostport"],
            "Unable to start HTTP server",
            match=ErrorMatch.PARTIAL_REGEX,
        )


if __name__ == "__main__":
    HTTPPublicFallbackTest().main()
