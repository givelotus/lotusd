#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test inbound P2P over WebSocket (/p2p/ws on the RPC port).

An independent Python peer (websocket-client + python-zstandard) connects
with each sub-protocol and completes the P2P handshake.
"""

import http.client
import os

from test_framework.messages import msg_ping
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, rpc_port


class P2PWebSocketInboundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            raise SkipTest("websocket-client and zstandard are required")

    def connect(self, scheme, subprotocols):
        from test_framework.p2p_websocket import P2PWebSocketClient

        return P2PWebSocketClient(
            f"{scheme}://127.0.0.1:{rpc_port(0)}/p2p/ws",
            subprotocols=subprotocols,
            srcdir=self.config["environment"]["SRCDIR"],
        )

    def ws_peers(self):
        return [p for p in self.nodes[0].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 10)

        for scheme, subprotocols, expected in [
            ("ws", ["p2p-zstd-v1", "p2p-zstd"], "p2p-zstd-v1"),
            ("ws", ["p2p-zstd"], "p2p-zstd"),
            ("ws", None, "none"),
            ("wss", ["p2p-zstd-v1", "p2p-zstd"], "p2p-zstd-v1"),
            ("wss", None, "none"),
        ]:
            self.log.info(f"{scheme}:// with {subprotocols} -> {expected}")
            peer = self.connect(scheme, subprotocols)
            assert_equal(peer.subprotocol or "none", expected)
            their_version = peer.handshake()
            assert_equal(their_version.nStartingHeight, 10)

            # A few pings: the handshake alone is too small for stream
            # compression without a dictionary to beat its own overhead
            # reliably (every message the node adds after verack shifts it).
            for i in range(10):
                ping = msg_ping(nonce=0x1234567890 + i)
                peer.send_message(ping)
                assert_equal(peer.wait_for(b"pong").nonce, 0x1234567890 + i)

            self.wait_until(lambda: len(self.ws_peers()) == 1)
            info = self.ws_peers()[0]
            assert_equal(info["transport"], scheme)
            assert_equal(info["inbound"], True)
            assert_equal(info["websocket"]["tls"], scheme == "wss")
            assert_equal(info["websocket"]["compression"], expected)
            assert_equal(info["subver"], "/p2p_websocket.py/")
            ws = info["websocket"]
            assert ws["payload_bytes_recv"] >= peer.payload_bytes_sent - 64
            if expected == "none":
                # Same bytes plus frame headers
                assert ws["wire_bytes_sent"] > ws["payload_bytes_sent"]
            else:
                assert ws["wire_bytes_sent"] < ws["payload_bytes_sent"]

            self.log.info("Closing the WebSocket disconnects the peer")
            peer.close()
            self.wait_until(lambda: len(self.ws_peers()) == 0)

        totals = node.getnettotals()["websocket"]
        assert totals["payload_bytes_recv"] > 0
        assert totals["wire_bytes_sent"] > 0

        self.log.info("The P2P node disconnecting closes the WebSocket")
        peer = self.connect("ws", ["p2p-zstd-v1"])
        peer.handshake()
        self.wait_until(lambda: len(self.ws_peers()) == 1)
        node.disconnectnode(nodeid=self.ws_peers()[0]["id"])
        import websocket

        try:
            while True:
                peer.recv_message()
        except (websocket.WebSocketConnectionClosedException, ConnectionError):
            pass

        self.log.info("The socketpair bridge (debug option) still works")
        self.restart_node(0, ["-p2pwebsocketbridge=1"])
        peer = self.connect("wss", ["p2p-zstd-v1"])
        peer.handshake()
        peer.send_message(msg_ping(nonce=7))
        assert_equal(peer.wait_for(b"pong").nonce, 7)
        self.wait_until(lambda: len(self.ws_peers()) == 1)
        peer.close()
        self.wait_until(lambda: len(self.ws_peers()) == 0)

        self.log.info("Without -p2pwebsocket, /p2p/ws is not served")
        # (Lotus v2: peers only connect over WebSocket, so a listening node
        # needs it.)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-p2pwslisten=0"],
            "Error: -p2pwslisten=0 needs -listen=0: peers can only connect "
            "over WebSocket",
        )
        conf = os.path.join(self.nodes[0].datadir, "lotusd.conf")
        with open(conf, encoding="utf8") as f:
            lines = [line for line in f if not line.startswith("bind=")]
        with open(conf, "w", encoding="utf8") as f:
            f.writelines(lines)
        self.start_node(0, ["-p2pwslisten=0", "-listen=0"])
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(0))
        conn.request(
            "GET",
            "/p2p/ws",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
        )
        assert_equal(conn.getresponse().status, 404)


if __name__ == "__main__":
    P2PWebSocketInboundTest().main()
