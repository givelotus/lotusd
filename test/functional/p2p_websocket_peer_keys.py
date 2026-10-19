#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test inbound P2P WebSocket peers known by their TLS client key.

-p2pwebsocketpeer=[permissions@]<pin> grants permissions to an inbound wss://
peer presenting a client certificate with that key, and
-p2pwebsocketrequirecert drops WebSocket peers that are not listed.
"""

import base64
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40


class P2PWebSocketPeerKeysTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [self.server_args("-tlsmutual"), []]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def server_args(self, *extra):
        return [f"-publicbind=127.0.0.1:{self.public_port}", *extra]

    def url(self, scheme="wss"):
        return f"{scheme}://localhost:{self.public_port}/p2p/ws"

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def connect(self, scheme="wss"):
        self.nodes[1].addnode(node=self.url(scheme), command="onetry")
        self.wait_until(lambda: len(self.ws_peers(0)) == 1)
        return self.ws_peers(0)[0]

    def disconnect_all(self):
        for p in self.ws_peers(1):
            self.nodes[1].disconnectnode(nodeid=p["id"])
        self.wait_until(lambda: len(self.ws_peers(1)) == 0)
        self.wait_until(lambda: len(self.ws_peers(0)) == 0)

    def dropped(self, scheme, log):
        with self.nodes[0].assert_debug_log([log]):
            self.nodes[1].addnode(node=self.url(scheme), command="onetry")
        assert_equal(self.ws_peers(0), [])

    def run_test(self):
        node0 = self.nodes[0]

        self.log.info("-tlsmutual: the inbound peer's key is reported")
        peer = self.connect()
        spki = peer["websocket"]["peer_spki"]
        assert_equal(len(base64.urlsafe_b64decode(spki + "=")), 32)
        assert_equal(peer["websocket"]["pinned"], False)
        assert_equal(peer["permissions"], [])
        self.disconnect_all()
        other = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

        self.log.info("A listed key gets its permissions")
        self.restart_node(
            0, self.server_args(f"-p2pwebsocketpeer=noban,mempool@{spki}")
        )
        peer = self.connect()
        assert_equal(peer["websocket"]["pinned"], True)
        assert_equal(sorted(peer["permissions"]), ["download", "mempool", "noban"])
        self.disconnect_all()

        self.log.info("Without permissions@, the -whitelist defaults apply")
        # Standard base64 with padding is accepted and normalized.
        padded = base64.b64encode(base64.urlsafe_b64decode(spki + "=")).decode()
        self.restart_node(0, self.server_args(f"-p2pwebsocketpeer={padded}"))
        peer = self.connect()
        assert_equal(peer["websocket"]["pinned"], True)
        assert "noban" in peer["permissions"]
        self.disconnect_all()

        self.log.info("-p2pwebsocketrequirecert drops unlisted WebSocket peers")
        self.restart_node(
            0,
            self.server_args(f"-p2pwebsocketpeer={other}", "-p2pwebsocketrequirecert"),
        )
        self.dropped("wss", "its key is not listed in -p2pwebsocketpeer")
        self.dropped("ws", "no client certificate")
        # (Lotus v2 has no plain TCP peers: every peer needs a listed key,
        # hence wss://.)

        self.log.info("...and listed ones are accepted")
        self.restart_node(
            0,
            self.server_args(
                f"-p2pwebsocketpeer={other}",
                f"-p2pwebsocketpeer=relay@{spki}",
                "-p2pwebsocketrequirecert",
            ),
        )
        peer = self.connect()
        assert_equal(peer["websocket"]["pinned"], True)
        assert_equal(peer["permissions"], ["relay"])
        self.disconnect_all()

        self.log.info("Invalid settings are startup errors")
        self.stop_node(0)
        for args, error in (
            (["-p2pwebsocketrequirecert"], "needs at least one -p2pwebsocketpeer"),
            (["-p2pwebsocketpeer=xyz"], "Invalid public key in -p2pwebsocketpeer"),
            ([f"-p2pwebsocketpeer=bogus@{spki}"], "Invalid P2P permission"),
        ):
            node0.assert_start_raises_init_error(
                self.server_args(*args), error, match=ErrorMatch.PARTIAL_REGEX
            )


if __name__ == "__main__":
    P2PWebSocketPeerKeysTest().main()
