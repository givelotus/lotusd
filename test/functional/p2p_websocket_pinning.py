#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test pinning wss:// peers to a public key (#spki= and -p2pwebsocketpin)."""

import base64
import os
import shutil
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40


class P2PWebSocketPinningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [[f"-publicbind=127.0.0.1:{self.public_port}"], []]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def url(self, scheme="wss", pin=None):
        u = f"{scheme}://localhost:{self.public_port}/p2p/ws"
        return u + (f"#spki={pin}" if pin else "")

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def connect(self, url):
        self.nodes[1].addnode(node=url, command="onetry")
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)
        peer = self.ws_peers(1)[0]
        return peer

    def disconnect_all(self):
        for p in self.ws_peers(1):
            self.nodes[1].disconnectnode(nodeid=p["id"])
        self.wait_until(lambda: len(self.ws_peers(1)) == 0)
        self.wait_until(lambda: len(self.ws_peers(0)) == 0)

    def refused(self, url, log):
        with self.nodes[1].assert_debug_log([log]):
            self.nodes[1].addnode(node=url, command="onetry")
        assert_equal(self.ws_peers(1), [])

    def run_test(self):
        node1 = self.nodes[1]

        self.log.info("Unpinned: the peer's key is reported, not pinned")
        peer = self.connect(self.url())
        spki = peer["websocket"]["peer_spki"]
        assert_equal(len(base64.urlsafe_b64decode(spki + "=")), 32)
        assert_equal(peer["websocket"]["pinned"], False)
        self.disconnect_all()

        self.log.info("A matching #spki= pin connects and is reported")
        peer = self.connect(self.url(pin=spki))
        assert_equal(peer["websocket"]["pinned"], True)
        self.disconnect_all()

        self.log.info("A wrong pin refuses the connection")
        wrong = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        self.refused(self.url(pin=wrong), "does not match the pinned key")

        self.log.info("A pin needs wss://")
        self.refused(self.url("ws", pin=spki), "a key pin needs wss://")

        self.log.info("-p2pwebsocketpin applies to every dial of that host")
        self.restart_node(1, [f"-p2pwebsocketpin=LocalHost={spki}"])
        peer = self.connect(self.url())
        assert_equal(peer["websocket"]["pinned"], True)
        self.disconnect_all()
        self.restart_node(1, [f"-p2pwebsocketpin=localhost={wrong}"])
        self.refused(self.url(), "does not match the pinned key")
        # A pin in the URL takes precedence over the configured one.
        peer = self.connect(self.url(pin=spki))
        assert_equal(peer["websocket"]["pinned"], True)
        self.disconnect_all()

        self.log.info("Invalid -p2pwebsocketpin values are startup errors")
        self.stop_node(1)
        for bad in ("localhost", "localhost=xyz", f"={spki}"):
            node1.assert_start_raises_init_error(
                [f"-p2pwebsocketpin={bad}"],
                "Unable to start the P2P WebSocket dialer",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        self.start_node(1)

        openssl = shutil.which("openssl")
        if not openssl:
            self.log.info("openssl not found: skipping the certificate re-issue check")
            return
        self.log.info("A certificate re-issued for the same key keeps the pin")
        datadir = os.path.join(self.nodes[0].datadir, self.chain)
        key = os.path.join(datadir, "node_tls_key.pem")
        cert = os.path.join(datadir, "reissued_cert.pem")
        subprocess.run(
            [
                openssl,
                "req",
                "-new",
                "-x509",
                "-key",
                key,
                "-subj",
                "/CN=other",
                "-days",
                "30",
                "-out",
                cert,
            ],
            check=True,
            capture_output=True,
        )
        self.restart_node(
            0,
            [
                f"-publicbind=127.0.0.1:{self.public_port}",
                f"-tlscert={cert}",
                f"-tlskey={key}",
            ],
        )
        peer = self.connect(self.url(pin=spki))
        assert_equal(peer["websocket"]["pinned"], True)


if __name__ == "__main__":
    P2PWebSocketPinningTest().main()
