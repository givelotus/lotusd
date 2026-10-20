#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the P2P transport listening options.

-listen is the master switch for inbound peers; -p2prawlisten (plain P2P)
and -p2pwslisten (P2P over WebSocket) select the
transports it accepts. A WebSocket-only node has no plain P2P listening
socket and never advertises an address for plain P2P.
"""

import http.client
import socket
import time

from test_framework.messages import CAddress, msg_getaddr
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port, rpc_port

UPGRADE_HEADERS = {
    "Connection": "Upgrade",
    "Upgrade": "websocket",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}

# As seen by the node: our address (through -trustedproxy) and its own
# address as we claim to see it. Both routable, so a node accepting plain
# P2P advertises the latter back to us.
PEER_IP = "1.2.3.4"
NODE_IP_SEEN = "5.6.7.8"
DOMAIN = "node0.example.com"
# WebSocket only. The test framework's configuration has bind=127.0.0.1,
# which is now a P2P port listener for WebSocket.
WS_ONLY = ["-p2prawlisten=0"]
# No transport: then -bind is refused. Without it, connect=0 in the test
# framework's configuration turns -listen off unless it is set.
NO_TRANSPORT = ["-p2prawlisten=0", "-p2pwslisten=0", "-nobind", "-listen=1"]


class P2PListenOptionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Connections are made by each subtest.
        self.setup_nodes()

    def skip_test_if_missing_module(self):
        try:
            import websocket  # noqa: F401
            import zstandard  # noqa: F401
        except ImportError:
            raise SkipTest("websocket-client and zstandard are required")

    def ws_client(self, port, **kwargs):
        from test_framework.p2p_websocket import P2PWebSocketClient

        return P2PWebSocketClient(
            f"ws://127.0.0.1:{port}/p2p/ws",
            srcdir=self.config["environment"]["SRCDIR"],
            **kwargs,
        )

    def plain_p2p_port_open(self, n):
        try:
            with socket.create_connection(("127.0.0.1", p2p_port(n)), timeout=5):
                return True
        except ConnectionRefusedError:
            return False

    def upgrade_status(self, n):
        conn = http.client.HTTPConnection("127.0.0.1", rpc_port(n), timeout=30)
        conn.request("GET", "/p2p/ws", headers=UPGRADE_HEADERS)
        status = conn.getresponse().status
        conn.close()
        return status

    def peers(self, n, transport=None):
        return [
            p
            for p in self.nodes[n].getpeerinfo()
            if transport is None or p["transport"] == transport
        ]

    def disconnect_all(self):
        for n in range(self.num_nodes):
            for p in self.nodes[n].getpeerinfo():
                self.nodes[n].disconnectnode(nodeid=p["id"])
        for n in range(self.num_nodes):
            self.wait_until(lambda n=n: len(self.nodes[n].getpeerinfo()) == 0)

    def self_advertisements(self, extra_args, *, until=None, window=3):
        """Restart node 0 with extra_args, connect a WebSocket peer that sees
        it as NODE_IP_SEEN, and collect the addresses it sends us. Stops
        `window` seconds after `until` matched (or after window seconds)."""
        import websocket

        # A public listener: the RPC port only serves -rpcallowip clients,
        # which our forwarded address is not.
        public_port = p2p_port(self.num_nodes)
        self.restart_node(
            0,
            ["-trustedproxy=127.0.0.1", f"-publicbind=127.0.0.1:{public_port}"]
            + extra_args,
        )
        # Out of initial block download: a node only advertises itself then.
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        peer = self.ws_client(public_port, header=[f"X-Forwarded-For: {PEER_IP}"])
        peer.handshake(addr_recv=(NODE_IP_SEEN, 8333), sendaddrv2=True)
        # Addresses are only relayed to inbound peers asking for them.
        peer.send_message(msg_getaddr())
        self.wait_until(lambda: len(self.peers(0, "ws")) == 1)
        assert_equal(self.peers(0, "ws")[0]["addr"].split(":")[0], PEER_IP)
        peer.ws.settimeout(0.5)
        seen = []
        deadline = time.time() + 30 if until else time.time() + window
        while time.time() < deadline:
            try:
                msgtype, msg = peer.recv_message()
            except websocket.WebSocketTimeoutException:
                continue
            if msgtype in (b"addr", b"addrv2"):
                seen.extend(msg.addrs)
                if until and any(until(a) for a in msg.addrs):
                    until = None
                    deadline = time.time() + window
        assert until is None, f"expected advertisement not seen: {seen}"
        peer.close()
        self.wait_until(lambda: len(self.peers(0)) == 0)
        return seen

    def run_test(self):
        self.test_defaults()
        self.test_websocket_only()
        self.test_no_plain_self_advertisement()
        self.test_onlynet_wss()
        self.test_listen_zero()
        self.test_option_errors()

    def test_defaults(self):
        self.log.info("Defaults: plain P2P and WebSocket are both accepted")
        node = self.nodes[0]
        assert self.plain_p2p_port_open(0)
        node.add_p2p_connection(P2PInterface())
        peer = self.ws_client(rpc_port(0))
        peer.handshake()
        self.wait_until(lambda: len(self.peers(0, "ws")) == 1)
        assert_equal(len(self.peers(0, "tcp")), 1)
        peer.close()
        node.disconnect_p2ps()
        self.wait_until(lambda: len(self.peers(0)) == 0)

    def test_websocket_only(self):
        self.log.info("-p2prawlisten=0: raw P2P peers are refused")
        self.restart_node(0, WS_ONLY)
        node0, node1 = self.nodes
        # The P2P port is bound for WebSocket, but closes raw P2P.
        assert self.plain_p2p_port_open(0)
        with node0.assert_debug_log(["raw P2P is not accepted"], timeout=10):
            raw = node0.add_p2p_connection(
                P2PInterface(), wait_for_connection=False, wait_for_verack=False
            )
        raw.wait_until(lambda: not raw.is_connected, check_connected=False)
        assert "version" not in raw.last_message
        node0.disconnect_p2ps()
        assert_equal(node0.getnetworkinfo()["localaddresses"], [])

        self.log.info("... but WebSocket peers connect and sync a block")
        node1.addnode(f"ws://127.0.0.1:{rpc_port(0)}/p2p/ws", "onetry")
        node1.addnode(f"wss://127.0.0.1:{p2p_port(0)}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers(0)) == 2)
        assert_equal(sorted(p["transport"] for p in self.peers(0)), ["ws", "wss"])
        assert all(p["inbound"] for p in self.peers(0))
        self.generate(node1, 1)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.disconnect_all()

        self.log.info("Neither transport: no listening socket at all")
        self.stop_node(0)
        self.start_node(0, NO_TRANSPORT)
        assert not self.plain_p2p_port_open(0)
        self.stop_node(
            0,
            expected_stderr="Warning: -p2prawlisten=0 and -p2pwslisten=0: no "
            "inbound P2P connections will be accepted, as with -listen=0",
        )
        self.start_node(0)

    def test_no_plain_self_advertisement(self):
        self.log.info(
            "Control: plain P2P on, the node advertises the address a peer saw"
        )
        # The test framework's configuration has discover=0.
        nodes_ip = self.self_advertisements(
            ["-discover=1"],
            until=lambda a: a.net == CAddress.NET_IPV4 and a.ip == NODE_IP_SEEN,
        )
        assert any(a.ip == NODE_IP_SEEN for a in nodes_ip)

        self.log.info("-p2prawlisten=0: only the -externaldomain is advertised")
        seen = self.self_advertisements(
            WS_ONLY + ["-discover=1", f"-externaldomain={DOMAIN}"],
            until=lambda a: a.net == CAddress.NET_WSS,
        )
        assert_equal([a.net for a in seen if a.net != CAddress.NET_WSS], [])
        assert_equal({a.ip for a in seen}, {DOMAIN})
        local = self.nodes[0].getnetworkinfo()["localaddresses"]
        assert_equal([a["address"] for a in local], [DOMAIN])

        self.log.info("-p2prawlisten=0 without -externaldomain: nothing")
        seen = self.self_advertisements(WS_ONLY + ["-discover=1"])
        assert_equal(seen, [])
        assert_equal(self.nodes[0].getnetworkinfo()["localaddresses"], [])

    def test_onlynet_wss(self):
        self.log.info("-onlynet=wss: no outbound plain P2P connections")
        node0, node1 = self.nodes
        self.restart_node(
            0,
            WS_ONLY
            + [
                "-onlynet=wss",
                f"-addnode=127.0.0.1:{p2p_port(1)}",
                f"-addnode=wss://127.0.0.1:{rpc_port(1)}/p2p/ws",
            ],
        )
        node0.addnode(f"127.0.0.1:{p2p_port(1)}", "onetry")
        self.wait_until(lambda: len(self.peers(0, "wss")) == 1)
        # Give the added-node thread a chance to try the plain address too.
        time.sleep(3)
        assert_equal([p["transport"] for p in self.peers(0)], ["wss"])
        assert not self.peers(0)[0]["inbound"]
        assert_equal(self.peers(1, "tcp"), [])
        self.generate(node1, 1)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.disconnect_all()

    def test_listen_zero(self):
        self.log.info("-listen=0 accepts no WebSocket peer, even with -p2pwslisten=1")
        import websocket

        self.restart_node(0, ["-listen=0", "-nobind", "-p2pwslisten=1"])
        assert not self.plain_p2p_port_open(0)
        try:
            self.ws_client(rpc_port(0))
            raise AssertionError("WebSocket peer accepted with -listen=0")
        except websocket.WebSocketBadStatusException as e:
            # As before these options: the endpoint exists, P2P does not
            # take peers.
            assert_equal(e.status_code, 503)
        assert_equal(self.peers(0), [])

    def test_option_errors(self):
        node = self.nodes[0]
        self.log.info("-p2pwslisten=0 stops serving /p2p/ws")
        for args, served in [(["-p2pwslisten=0"], False), (["-p2pwslisten=1"], True)]:
            self.restart_node(0, args)
            # A served endpoint answers a bare upgrade request instead of 404.
            assert_equal(self.upgrade_status(0) != 404, served)
        self.stop_node(0)

        self.log.info("Options needing raw P2P are refused")
        for args, needle in [
            (WS_ONLY + [f"-bind=127.0.0.1:{p2p_port(0) + 1}=onion"], "=onion"),
            (WS_ONLY + ["-externalip=1.2.3.4"], "-externalip advertises"),
            (WS_ONLY + ["-listenonion=1"], "-listenonion creates"),
            (
                NO_TRANSPORT + [f"-bind=127.0.0.1:{p2p_port(0)}"],
                "-bind and -whitebind",
            ),
            (
                NO_TRANSPORT + [f"-whitebind=noban@127.0.0.1:{p2p_port(0)}"],
                "-bind and -whitebind",
            ),
        ]:
            node.assert_start_raises_init_error(
                args, needle, match=ErrorMatch.PARTIAL_REGEX
            )

        self.log.info("No transport at all: allowed, with a warning")
        with node.assert_debug_log(["no inbound P2P connections will be accepted"]):
            self.start_node(0, NO_TRANSPORT)
        assert not self.plain_p2p_port_open(0)
        assert_equal(self.upgrade_status(0), 404)
        self.stop_node(
            0,
            expected_stderr="Warning: -p2prawlisten=0 and -p2pwslisten=0: no "
            "inbound P2P connections will be accepted, as with -listen=0",
        )
        self.start_node(0)


if __name__ == "__main__":
    P2PListenOptionsTest().main()
