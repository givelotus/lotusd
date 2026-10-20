#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test P2P WebSockets between nodes over HTTP/2.

With HTTP/2 built and -http2 on, a node dialing wss:// offers ALPN h2 before
http/1.1; when the server selects h2 it opens the WebSocket with an RFC 8441
extended CONNECT. Either side with -http2=0 falls back to HTTP/1.1. Blocks
and large transactions cross the HTTP/2 flow control windows.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet import MiniWallet

PUBLIC_PORT_INDEX = 40


def public_port(i):
    return p2p_port(PUBLIC_PORT_INDEX + i)


class P2PWebSocketHTTP2Test(BitcoinTestFramework):
    num_nodes = 4
    setup_clean_chain = True
    topology = "none"
    requires = {"http2"}

    def set_test_params(self):
        self.extra_args = [
            # The server: HTTP/2 on, with the smallest windows so that
            # flow control is exercised
            [
                f"-publicbind=127.0.0.1:{public_port(0)}",
                "-http2streamwindow=65535",
                "-http2connwindow=65535",
            ],
            # Dialers: HTTP/2 on (default) without compression, so the
            # bytes on the wire are as many as the P2P bytes; and off
            ["-p2pwebsocketoffer=none"],
            ["-http2=0"],
            # A server with HTTP/2 off
            [f"-publicbind=127.0.0.1:{public_port(3)}", "-http2=0"],
        ]

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] == "wss"]

    def connect_ws(self, dialer, server_port):
        self.nodes[dialer].addnode(
            node=f"wss://localhost:{server_port}/p2p/ws", command="onetry"
        )

    def run_test(self):
        node0 = self.nodes[0]
        wallet = MiniWallet(node0)
        self.generate(wallet, 250, sync_fun=self.no_op)

        self.log.info("Both sides with HTTP/2: the WebSocket runs over h2")
        self.connect_ws(1, public_port(0))
        self.wait_until(
            lambda: len(self.ws_peers(1)) == 1 and len(self.ws_peers(0)) == 1
        )
        out = self.ws_peers(1)[0]
        inbound = self.ws_peers(0)[0]
        assert_equal(out["websocket"]["alpn"], "h2")
        assert_equal(inbound["websocket"]["alpn"], "h2")
        assert_equal(out["websocket"]["compression"], "none")
        assert_equal(inbound["websocket"]["compression"], "none")

        self.log.info("Initial block download over HTTP/2")
        self.sync_blocks([node0, self.nodes[1]], timeout=120)

        self.log.info("Large transactions and blocks cross the flow control windows")

        # About 85 kB each (policy forbids padding with OP_RETURNs), both
        # ways: the dialer's sends wait for the server's 64 KiB windows.
        def relay(sender, wal, receiver):
            txids = [
                wal.send_self_transfer_multi(from_node=sender, num_outputs=2500)["txid"]
                for _ in range(15)
            ]
            self.wait_until(
                lambda: set(txids) <= set(receiver.getrawmempool()), timeout=120
            )
            tip = self.generate(sender, 1, sync_fun=self.no_op)[0]
            self.wait_until(lambda: receiver.getbestblockhash() == tip, timeout=60)
            assert_equal(receiver.getrawmempool(), [])

        relay(node0, wallet, self.nodes[1])
        # The same coins, seen from the dialer (MiniWallet is deterministic)
        wallet1 = MiniWallet(self.nodes[1])
        wallet1.rescan_utxos()
        relay(self.nodes[1], wallet1, node0)
        info = self.ws_peers(1)[0]["websocket"]
        self.log.info(
            f"  dialer sent {info['wire_bytes_sent']} and received "
            f"{info['wire_bytes_recv']} WebSocket bytes"
        )
        assert info["wire_bytes_sent"] > 1_000_000
        assert info["wire_bytes_recv"] > 1_000_000

        self.log.info("Blocks relay the other way too")
        tip = self.generate(self.nodes[1], 2, sync_fun=self.no_op)[-1]
        self.wait_until(lambda: node0.getbestblockhash() == tip)

        self.log.info("Disconnecting ends the HTTP/2 tunnel on both sides")
        self.nodes[1].disconnectnode(nodeid=self.ws_peers(1)[0]["id"])
        self.wait_until(
            lambda: len(self.ws_peers(0)) == 0 and len(self.ws_peers(1)) == 0
        )

        self.log.info("A dialer with -http2=0 uses HTTP/1.1")
        self.connect_ws(2, public_port(0))
        self.wait_until(lambda: len(self.ws_peers(2)) == 1)
        assert_equal(self.ws_peers(2)[0]["websocket"]["alpn"], "http/1.1")
        self.wait_until(lambda: len(self.ws_peers(0)) == 1)
        assert_equal(self.ws_peers(0)[0]["websocket"]["alpn"], "http/1.1")
        self.sync_blocks([node0, self.nodes[2]], timeout=120)

        self.log.info("A server with -http2=0 makes an HTTP/2 dialer use HTTP/1.1")
        self.connect_ws(1, public_port(3))
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)
        assert_equal(self.ws_peers(1)[0]["websocket"]["alpn"], "http/1.1")
        self.sync_blocks([self.nodes[1], self.nodes[3]], timeout=120)


if __name__ == "__main__":
    P2PWebSocketHTTP2Test().main()
