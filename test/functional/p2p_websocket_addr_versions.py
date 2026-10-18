#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test versioned NET_WSS (0x10) addresses in ADDRv2 gossip.

- Version 1 carries a DNS name and optional path; the node stores it, relays
  it and dials wss://<name>:<port><path>.
- A later version is stored and relayed unchanged, so new formats spread
  through this node, but never dialed.
- Malformed payloads are dropped without penalizing the peer.
"""

import os
import time

from test_framework.messages import NODE_NETWORK, CAddress, msg_addrv2
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def wss(body, port, version=CAddress.WSS_V1):
    a = CAddress()
    a.time = int(time.time())
    a.nServices = NODE_NETWORK
    a.net = CAddress.NET_WSS
    a.wss_version = version
    a.ip = body
    a.port = port
    return a


class AddrReceiver(P2PInterface):
    def __init__(self):
        super().__init__(support_addrv2=True)
        self.received = []

    def on_addrv2(self, message):
        self.received.extend(message.addrs)


class P2PWebSocketAddrVersionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=addr@127.0.0.1"]]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        # Automatic outbound connections, to see what gets dialed.
        conf = os.path.join(self.nodes[0].datadir, "bitcoin.conf")
        with open(conf, encoding="utf8") as f:
            lines = [line for line in f if line.strip() != "connect=0"]
        with open(conf, "w", encoding="utf8") as f:
            f.writelines(lines)
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        with_path = wss("lotus-node.invalid/lotus/p2p", 8443)
        later = wss(b"\x00\xffsome future format", 9000, version=0x7f)
        malformed = [
            wss("bad name.invalid", 443),
            wss("x.invalid/p2p/ws", 443),  # the default path is implicit
            wss(b"x.invalid", 443, version=0),  # reserved version
        ]

        self.log.info("The node stores version 1 and later-version addresses")
        source = node.add_p2p_connection(P2PInterface(support_addrv2=True))
        receiver = node.add_p2p_connection(AddrReceiver())
        msg = msg_addrv2()
        msg.addrs = [with_path, later] + malformed
        source.send_and_ping(msg)
        known = {(a["port"], a.get("wss_version"), a.get("wss_path"), a["address"])
                 for a in node.getnodeaddresses(0, "wss")}
        assert (8443, 1, "/lotus/p2p", "lotus-node.invalid") in known, known
        assert any(port == 9000 and version == 0x7F for port, version, _, _ in known), known
        assert_equal(len(known), 2)
        assert_equal(len(node.getpeerinfo()), 2)  # nobody was disconnected

        self.log.info("...and relays both unchanged")
        node.setmocktime(int(time.time()) + 30 * 60)
        receiver.wait_until(lambda: len(receiver.received) >= 2)
        with p2p_lock:
            relayed = {(a.port, a.wss_version, a.ip) for a in receiver.received}
        assert_equal(relayed, {
            (8443, 1, "lotus-node.invalid/lotus/p2p"),
            (9000, 0x7F, b"\x00\xffsome future format"),
        })
        node.setmocktime(0)

        self.log.info("It dials version 1 at its path, never a later version")
        with node.assert_debug_log(
            ["trying WebSocket connection wss://lotus-node.invalid:8443/lotus/p2p"],
            unexpected_msgs=["trying WebSocket connection wss://wss-v127"],
            timeout=120,
        ):
            pass


if __name__ == "__main__":
    P2PWebSocketAddrVersionsTest().main()
