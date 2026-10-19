#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the TLS profile of P2P WebSocket connections.

- The server selects ALPN http/1.1 when offered, and continues without ALPN
  otherwise.
- The dialer offers ALPN http/1.1 and sends SNI for host names (and warns
  when dialing an IP address).
"""

import os
import socket
import ssl
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40
CAPTURE_PORT_INDEX = 41


class ClientHelloCapture:
    """A TLS server recording what each client offered, then hanging up."""

    def __init__(self, port, cert, key):
        self.hellos = []
        self.lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.sni_callback = self.on_sni
        self.ctx = ctx
        self.server = socket.create_server(("127.0.0.1", port))
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def on_sni(self, sslobj, name, ctx):
        self.sni = name

    def accept_loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            self.sni = None
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    hello = {
                        "sni": self.sni,
                        "alpn": tls.selected_alpn_protocol(),
                    }
                with self.lock:
                    self.hellos.append(hello)
            except (ssl.SSLError, OSError):
                conn.close()

    def stop(self):
        self.server.close()


class P2PWebSocketTLSProfileTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [[f"-publicbind=127.0.0.1:{self.public_port}"], []]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def handshake(self, alpn):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        with socket.create_connection(("127.0.0.1", rpc_port(0))) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                return tls.selected_alpn_protocol()

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        self.log.info("The server selects http/1.1, and nothing else")
        assert_equal(self.handshake(["h2", "http/1.1"]), "http/1.1")
        assert_equal(self.handshake(["h2"]), None)
        assert_equal(self.handshake(None), None)

        self.log.info("Node to node, both sides agree on http/1.1")
        self.nodes[1].addnode(
            node=f"wss://localhost:{self.public_port}/p2p/ws", command="onetry"
        )
        self.wait_until(
            lambda: len(self.ws_peers(0)) == 1 and len(self.ws_peers(1)) == 1
        )
        assert_equal(self.ws_peers(0)[0]["websocket"]["alpn"], "http/1.1")
        assert_equal(self.ws_peers(1)[0]["websocket"]["alpn"], "http/1.1")

        # (The cipher order is checked by net_websocket_tests.)
        self.log.info("What the dialer offers: SNI and ALPN")
        datadir = os.path.join(self.nodes[0].datadir, self.chain)
        capture = ClientHelloCapture(
            p2p_port(CAPTURE_PORT_INDEX),
            os.path.join(datadir, "node_tls_cert.pem"),
            os.path.join(datadir, "node_tls_key.pem"),
        )
        url = f"wss://localhost:{p2p_port(CAPTURE_PORT_INDEX)}/p2p/ws"
        self.nodes[1].addnode(node=url, command="onetry")
        self.wait_until(lambda: len(capture.hellos) == 1)
        hello = capture.hellos[0]
        assert_equal(hello["sni"], "localhost")
        assert_equal(hello["alpn"], "http/1.1")

        self.log.info("Dialing an IP address sends no SNI, with a warning")
        ip_url = f"wss://127.0.0.1:{p2p_port(CAPTURE_PORT_INDEX)}/p2p/ws"
        with self.nodes[1].assert_debug_log(
            ["TLS to an IP address carries no server name"]
        ):
            self.nodes[1].addnode(node=ip_url, command="onetry")
            self.wait_until(lambda: len(capture.hellos) == 2)
        assert_equal(capture.hellos[1]["sni"], None)
        capture.stop()


if __name__ == "__main__":
    P2PWebSocketTLSProfileTest().main()
