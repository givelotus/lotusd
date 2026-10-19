#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the configurations documented in doc/p2p-websocket.md, end to end.

- node0, bridge server: P2P WebSocket on -publicbind at a secret path behind
  a token, everything else answered by a fallback web site.
- node1, censored client: connects only to that bridge, through a SOCKS5
  proxy (standing in for Xray or Tor), with the bridge's key pinned; it does
  not listen, discover its address or contact seeds, and never connects
  directly.
- node2, public node behind a TLS proxy: -publicbind plus -externaldomain,
  advertising only the domain.
"""

import base64
import hashlib
import os
import shutil
import socket
import subprocess
import threading

from test_framework.forwarding_proxy import ForwardingSocks5Proxy
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

BRIDGE_PORT_INDEX = 40
PROXY_PORT_INDEX = 41
SITE_PORT_INDEX = 42
PUBLIC_PORT_INDEX = 43
PATH = "/assets/v2/stream"
TOKEN = "Zq0-recipe_token"
PAGE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n"
        b"Connection: close\r\n\r\n<html></html>")


def serve_page(port):
    """A web site answering every request with PAGE."""
    server = socket.create_server(("127.0.0.1", port))

    def loop():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(PAGE)

    threading.Thread(target=loop, daemon=True).start()
    return server


class P2PPrivacyRecipesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise SkipTest("openssl is not available")

    def spki_pin(self, cert_path):
        pub = subprocess.run(
            [self.openssl, "x509", "-in", cert_path, "-pubkey", "-noout"],
            check=True, capture_output=True,
        ).stdout
        der = subprocess.run(
            [self.openssl, "pkey", "-pubin", "-outform", "DER"],
            input=pub, check=True, capture_output=True,
        ).stdout
        return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")

    def setup_network(self):
        self.bridge_port = p2p_port(BRIDGE_PORT_INDEX)
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.site = serve_page(p2p_port(SITE_PORT_INDEX))
        self.proxy = ForwardingSocks5Proxy(p2p_port(PROXY_PORT_INDEX))
        self.add_nodes(self.num_nodes)

        # Recipe: bridge server.
        self.start_node(0, [
            f"-publicbind=127.0.0.1:{self.bridge_port}",
            f"-p2pwebsocketpath={PATH}",
            f"-p2pwebsockettoken={TOKEN}",
            f"-publicfallback=127.0.0.1:{p2p_port(SITE_PORT_INDEX)}",
        ])
        cert = os.path.join(self.nodes[0].datadir, self.chain, "node_tls_cert.pem")
        self.pin = self.spki_pin(cert)

        # Recipe: censored client using only the bridge, through a proxy.
        # (Without the test framework's bind= and connect=0 defaults.)
        conf = os.path.join(self.nodes[1].datadir, "bitcoin.conf")
        with open(conf, encoding="utf8") as f:
            lines = [line for line in f
                     if not line.startswith(("bind=", "connect="))]
        with open(conf, "w", encoding="utf8") as f:
            f.writelines(lines)
        url = f"wss://localhost:{self.bridge_port}{PATH}?token={TOKEN}#spki={self.pin}"
        self.start_node(1, [
            f"-connect={url}",
            f"-proxy=127.0.0.1:{p2p_port(PROXY_PORT_INDEX)}",
            "-listen=0", "-discover=0", "-dnsseed=0", "-fixedseeds=0",
            "-onlynet=wss",
        ])

        # Recipe: public node behind a TLS-terminating proxy.
        self.start_node(2, [
            f"-publicbind=127.0.0.1:{self.public_port}",
            "-externaldomain=node.example.org",
        ])

    def run_test(self):
        bridge, client, public = self.nodes

        self.log.info("Censored client: one pinned wss peer, via the proxy")
        self.wait_until(lambda: len(client.getpeerinfo()) == 1)
        peer = client.getpeerinfo()[0]
        assert_equal(peer["transport"], "wss")
        assert_equal(peer["websocket"]["pinned"], True)
        assert_equal(peer["websocket"]["alpn"], "http/1.1")
        with self.proxy.lock:
            # Names only (SOCKS5 address type 3): no local DNS lookup.
            assert_equal(set(self.proxy.requests), {(3, "localhost", self.bridge_port)})
        self.generate(bridge, 2, sync_fun=self.no_op)
        self.wait_until(lambda: client.getbestblockhash() == bridge.getbestblockhash())

        self.log.info("...it does not listen, advertise or learn its address")
        info = client.getnetworkinfo()
        assert_equal(info["localaddresses"], [])
        assert_equal(info["networkactive"], True)
        try:
            socket.create_connection(("127.0.0.1", p2p_port(1)), timeout=2).close()
            raise AssertionError("the client accepts P2P connections")
        except ConnectionRefusedError:
            pass
        with open(client.debug_log_path, encoding="utf8") as f:
            log = f.read()
        assert TOKEN not in log
        assert "Loading addresses from DNS seed" not in log

        self.log.info("...and fails closed without the proxy")
        self.proxy.stop()
        client.disconnectnode(nodeid=peer["id"])
        self.wait_until(lambda: client.getpeerinfo() == [])
        client.addnode(node=f"wss://localhost:{self.bridge_port}{PATH}?token={TOKEN}",
                       command="onetry")
        self.wait_until(lambda: client.getpeerinfo() == [], timeout=5)
        assert_equal(len([p for p in bridge.getpeerinfo() if p["inbound"]]), 0)

        self.log.info("Bridge server: visitors and probes see a web site")
        for request in (
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET {PATH} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode(),
            b"GET /p2p/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n",
        ):
            with socket.create_connection(("127.0.0.1", self.bridge_port)) as s:
                s.sendall(request)
                data = b""
                while chunk := s.recv(4096):
                    data += chunk
            assert_equal(data, PAGE)
        # Its own address is never advertised: no -externaldomain.
        assert_equal(bridge.getnetworkinfo()["localaddresses"], [])

        self.log.info("Public node: advertises the domain, not the listener")
        local = public.getnetworkinfo()["localaddresses"]
        assert_equal([(a["address"], a["port"]) for a in local], [("node.example.org", 443)])
        self.site.close()


if __name__ == "__main__":
    P2PPrivacyRecipesTest().main()
