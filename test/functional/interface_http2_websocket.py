#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test WebSockets over HTTP/2 (RFC 8441 extended CONNECT) on the node.

An independent client (Python h2, its own WebSocket framing and the test
framework's p2p-zstd implementation) opens the P2P WebSocket and Chronik's
WebSocket on HTTP/2 connections, next to ordinary requests on the same
connection, under the same access rules as HTTP/1.1 upgrades.
"""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40
TOKEN = "s3cret-token"


def public_port(i=0):
    return p2p_port(PUBLIC_PORT_INDEX + i)


class HTTP2WebSocketTest(BitcoinTestFramework):
    num_nodes = 2
    setup_clean_chain = True
    topology = "none"
    requires = {"http2"}

    def set_test_params(self):
        self.extra_args = [
            [f"-publicbind=127.0.0.1:{public_port()}", "-trustedproxy=127.0.0.1"],
            [f"-publicbind=127.0.0.1:{public_port(1)}", f"-p2pwebsockettoken={TOKEN}"],
        ]

    def setup_network(self):
        if self.is_chronik_compiled():
            self.extra_args[0].append("-chronik")
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        try:
            import zstandard  # noqa: F401
        except ImportError:
            from test_framework.test_framework import SkipTest

            raise SkipTest("python3 zstandard module not available.")

    def ws_peers(self, node):
        return [p for p in node.getpeerinfo() if p["transport"] == "wss"]

    def p2p(
        self, client, path="/p2p/ws", protocols=("p2p-zstd-v1", "p2p-zstd"), headers=()
    ):
        from test_framework.http2 import H2WebSocket
        from test_framework.p2p_websocket import P2PWebSocketClient

        ws = H2WebSocket(client, path, subprotocols=list(protocols), headers=headers)
        if ws.status != 200:
            return ws, None
        peer = P2PWebSocketClient(
            None, ws=ws, srcdir=self.config["environment"]["SRCDIR"]
        )
        return ws, peer

    def run_test(self):
        from test_framework.http2 import H2Client, H2WebSocket, basic_auth

        node = self.nodes[0]
        self.generate(node, 2, sync_fun=self.no_op)

        self.log.info("A CONNECT reset in its TLS record creates no P2P peer")
        c = H2Client("127.0.0.1", public_port())
        while not c.remote_settings_received:
            assert c.pump()
        sid = c.conn.get_next_available_stream_id()
        c.conn.send_headers(
            sid,
            [
                (":method", "CONNECT"),
                (":protocol", "websocket"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/p2p/ws"),
                ("sec-websocket-version", "13"),
            ],
        )
        c.conn.reset_stream(sid)
        c.flush()
        assert_equal(c.request("GET", "/livez").status, 200)
        assert_equal(self.ws_peers(node), [])
        c.close()

        for port, where in (
            (public_port(), "public listener"),
            (rpc_port(0), "RPC port"),
        ):
            self.log.info(f"P2P WebSocket over HTTP/2 on the {where}")
            c = H2Client("127.0.0.1", port)
            assert_equal(c.alpn, "h2")
            ws, peer = self.p2p(c)
            assert_equal(ws.status, 200)
            assert_equal(ws.getsubprotocol(), "p2p-zstd-v1")
            their = peer.handshake()
            assert_equal(their.nStartingHeight, node.getblockcount())
            self.wait_until(lambda: len(self.ws_peers(node)) == 1)
            info = self.ws_peers(node)[0]
            assert_equal(info["websocket"]["alpn"], "h2")
            assert_equal(info["websocket"]["tls"], True)
            assert_equal(info["websocket"]["compression"], "p2p-zstd-v1")

            self.log.info("  ... beside more streams on the same connection")
            ws2, peer2 = self.p2p(c, protocols=())
            assert_equal(ws2.status, 200)
            assert_equal(ws2.getsubprotocol(), None)
            peer2.handshake()
            self.wait_until(lambda: len(self.ws_peers(node)) == 2)
            if port == rpc_port(0):
                body = json.dumps({"method": "getblockcount", "id": 1}).encode()
                r = c.request(
                    "POST", "/", [("authorization", basic_auth(node.url))], body
                )
                assert_equal(json.loads(r.body)["result"], node.getblockcount())
            # Blocks relay over the tunnel.
            tip = self.generate(node, 1, sync_fun=self.no_op)[0]
            inv = peer.wait_for(b"inv")
            assert any(i.hash == int(tip, 16) for i in inv.inv)

            self.log.info("  ... the client ending the stream disconnects the peer")
            c.conn.end_stream(ws2.sid)
            c.flush()
            self.wait_until(lambda: len(self.ws_peers(node)) == 1)

            self.log.info("  ... the node disconnecting the peer ends the stream")
            node.disconnectnode(nodeid=self.ws_peers(node)[0]["id"])
            while ws.recv() != b"":
                pass
            # The WebSocket Close frame, then END_STREAM
            self.wait_until(
                lambda: (
                    c.pump(timeout=0.1)
                    and (
                        c.responses[ws.sid].ended
                        or c.responses[ws.sid].reset is not None
                    )
                )
            )
            self.wait_until(lambda: len(self.ws_peers(node)) == 0)
            c.close()

        self.log.info("Refusals match HTTP/1.1 upgrades")
        c = H2Client("127.0.0.1", public_port())
        assert_equal(H2WebSocket(c, "/rest/chaininfo.json").status, 404)
        assert_equal(H2WebSocket(c, "/p2p/wsx").status, 404)
        c2 = H2Client("127.0.0.1", rpc_port(0))
        # A client outside -rpcallowip (via the trusted proxy) on the RPC port
        ws = H2WebSocket(c2, "/p2p/ws", headers=[("x-forwarded-for", "192.0.2.7")])
        assert_equal(ws.status, 403)
        # ...is welcome on the public listener
        ws, peer = self.p2p(c, headers=[("x-forwarded-for", "192.0.2.7")])
        assert_equal(ws.status, 200)
        peer.handshake()
        self.wait_until(lambda: len(self.ws_peers(node)) == 1)
        assert_equal(self.ws_peers(node)[0]["addr"].split(":")[0], "192.0.2.7")
        ws.close()
        c.close()
        c2.close()

        self.log.info("Malformed extended CONNECTs")
        c = H2Client("127.0.0.1", public_port())
        while not c.remote_settings_received:
            assert c.pump()
        sid = c.conn.get_next_available_stream_id()
        c.conn.send_headers(
            sid,
            [
                (":method", "CONNECT"),
                (":protocol", "webtransport"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/p2p/ws"),
                ("sec-websocket-version", "13"),
            ],
        )
        c.flush()
        assert_equal(c.wait([sid])[0].status, 501)
        sid = c.conn.get_next_available_stream_id()
        c.conn.send_headers(
            sid,
            [
                (":method", "CONNECT"),
                (":protocol", "websocket"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/p2p/ws"),
            ],
        )
        c.flush()
        assert_equal(c.wait([sid])[0].status, 400)
        c.close()

        self.log.info("Upgrade tokens apply over HTTP/2")
        c = H2Client("127.0.0.1", public_port(1))
        assert_equal(H2WebSocket(c, "/p2p/ws").status, 404)
        ws, peer = self.p2p(c, headers=[("authorization", "Bearer wrong")])
        assert_equal(ws.status, 404)
        ws, peer = self.p2p(c, headers=[("authorization", f"Bearer {TOKEN}")])
        assert_equal(ws.status, 200)
        peer.handshake()
        self.wait_until(lambda: len(self.ws_peers(self.nodes[1])) == 1)
        ws, peer = self.p2p(c, headers=[("cookie", "a=b"), ("cookie", f"t={TOKEN}")])
        assert_equal(ws.status, 200)
        c.close()

        if self.is_chronik_compiled():
            self.log.info("Chronik's WebSocket over HTTP/2 on the public listener")
            from test_framework.chronik.client import pb

            c = H2Client("127.0.0.1", public_port())
            ws = H2WebSocket(c, "/chronik/ws")
            assert_equal(ws.status, 200)
            with node.assert_debug_log(["WS subscribe to blocks"]):
                ws.send_binary(pb.WsSub(blocks=pb.WsSubBlocks()).SerializeToString())
                # Let the node process it while we wait for the log line
                c.pump(timeout=1)
            tip = self.generate(node, 1, sync_fun=self.no_op)[0]
            msg = pb.WsMsg()
            msg.ParseFromString(ws.recv())
            assert_equal(msg.block.block_hash[::-1].hex(), tip)
            # Plain requests share the connection
            assert_equal(c.request("GET", "/chronik/blockchain-info").status, 200)
            ws.close()
            c.close()


if __name__ == "__main__":
    HTTP2WebSocketTest().main()
