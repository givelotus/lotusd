#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test WebSocket peer discovery and the non-default node-to-node modes.

- node1 (automatic outbound connections enabled) learns node0's
  -externaldomain (a NET_WSS address) over ADDRv2 through a TCP peer and
  then dials it on its own over wss://, without any -addnode.
- node2/node3 peer with node0 using p2p-zstd and no compression
  (-p2pwebsocketoffer), and node4 uses ws:// on node0's RPC port.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_port

PUBLIC_PORT_INDEX = 40


class P2PWebSocketDiscoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True

    def setup_network(self):
        public = p2p_port(PUBLIC_PORT_INDEX)
        url = f"wss://localhost:{public}/p2p/ws"
        self.extra_args = [
            [f"-publicbind=127.0.0.1:{public}", f"-externaldomain=localhost:{public}"],
            [],
            [f"-addnode={url}", "-p2pwebsocketoffer=p2p-zstd"],
            [f"-addnode={url}", "-p2pwebsocketoffer=none"],
            [f"-addnode=ws://127.0.0.1:{rpc_port(0)}/p2p/ws"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        # node1 makes automatic outbound connections (no connect=0).
        conf = os.path.join(self.nodes[1].datadir, "bitcoin.conf")
        with open(conf, encoding="utf8") as f:
            lines = [line for line in f if line.strip() != "connect=0"]
        with open(conf, "w", encoding="utf8") as f:
            f.writelines(lines)
        for i in range(1, self.num_nodes):
            self.start_node(i)
        # node1 first meets node0 over plain TCP.
        self.connect_nodes(1, 0)

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def run_test(self):
        node0, node1 = self.nodes[0], self.nodes[1]

        self.log.info("node1 learns the NET_WSS address of node0 over ADDRv2")
        self.generate(node0, 1, sync_fun=self.no_op)
        self.wait_until(
            lambda: any(
                a["network"] == "wss" and a["address"] == "localhost"
                for a in node1.getnodeaddresses(0)
            ),
            timeout=120,
        )

        self.log.info("...and dials it automatically over wss://")
        self.wait_until(lambda: len(self.ws_peers(1)) >= 1, timeout=120)
        auto = self.ws_peers(1)[0]
        assert_equal(auto["transport"], "wss")
        assert_equal(auto["inbound"], False)
        assert auto["connection_type"] in (
            "outbound-full-relay",
            "block-relay-only",
            "feeler",
        ), auto["connection_type"]
        assert_equal(auto["network"], "wss")
        assert_equal(auto["addr"], f"localhost:{p2p_port(PUBLIC_PORT_INDEX)}")

        self.log.info("Non-default modes node to node, and ws:// on the RPC port")
        expected = {
            2: ("wss", "p2p-zstd"),
            3: ("wss", "none"),
            4: ("ws", "p2p-zstd-v1"),
        }
        for n, (transport, compression) in expected.items():
            self.wait_until(lambda n=n: len(self.ws_peers(n)) == 1)
            peer = self.ws_peers(n)[0]
            assert_equal(peer["transport"], transport)
            assert_equal(peer["websocket"]["compression"], compression)
        tip = self.generate(node0, 1, sync_fun=self.no_op)[0]
        for n in expected:
            self.wait_until(lambda n=n: self.nodes[n].getbestblockhash() == tip)
        # The uncompressed peer's wire bytes exceed its payload (frame
        # headers only); the compressed ones are smaller.
        none_ws = self.ws_peers(3)[0]["websocket"]
        assert none_ws["wire_bytes_recv"] > none_ws["payload_bytes_recv"]
        zstd_ws = self.ws_peers(2)[0]["websocket"]
        assert zstd_ws["wire_bytes_recv"] < zstd_ws["payload_bytes_recv"]


if __name__ == "__main__":
    P2PWebSocketDiscoveryTest().main()
