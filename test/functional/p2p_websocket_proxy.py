#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that ws:// and wss:// P2P dials never bypass -proxy or -onlynet."""

import time

from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40
PROXY_PORT_INDEX = 41


class P2PWebSocketProxyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        conf = Socks5Configuration()
        conf.addr = ("127.0.0.1", p2p_port(PROXY_PORT_INDEX))
        conf.unauth = True
        self.socks = Socks5Server(conf)
        self.socks.start()
        self.extra_args = [
            [f"-publicbind=127.0.0.1:{self.public_port}"],
            [f"-proxy=127.0.0.1:{p2p_port(PROXY_PORT_INDEX)}"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def ws_peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] != "tcp"]

    def try_dial(self, n, url, expected_log):
        with self.nodes[n].assert_debug_log([expected_log]):
            self.nodes[n].addnode(node=url, command="onetry")
        # Give a (wrong) direct connection time to show up.
        time.sleep(1)
        assert_equal(self.ws_peers(0), [])
        assert_equal(self.ws_peers(n), [])

    def run_test(self):
        url = f"wss://localhost:{self.public_port}/p2p/ws"

        self.log.info("With -proxy, a wss:// dial is refused, not made directly")
        self.try_dial(
            1, url, "WebSocket peers cannot be reached through -proxy yet"
        )
        assert self.socks.queue.empty()

        self.log.info("ws:// too")
        self.try_dial(
            1,
            f"ws://127.0.0.1:{self.public_port}/p2p/ws",
            "WebSocket peers cannot be reached through -proxy yet",
        )

        self.log.info("-onlynet without wss refuses WebSocket dials")
        self.restart_node(1, ["-onlynet=ipv4"])
        self.try_dial(1, url, "network wss is not reachable")

        self.log.info("Without either, the dial works")
        self.restart_node(1, [])
        self.nodes[1].addnode(node=url, command="onetry")
        self.wait_until(lambda: len(self.ws_peers(1)) == 1)

        self.socks.stop()


if __name__ == "__main__":
    P2PWebSocketProxyTest().main()
