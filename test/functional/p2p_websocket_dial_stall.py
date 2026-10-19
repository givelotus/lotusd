#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that an unresponsive WebSocket peer does not stall other dials.

Outbound connections are dialed on threads of their own: a peer that accepts
TCP and then never answers the WebSocket handshake (up to its 20 s deadline)
must not delay connections started after it. While it is pending it counts
as a connection: it is not dialed twice.
"""

import socket
import threading
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import p2p_port


class P2PWebSocketDialStallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0, node1 = self.nodes
        silent_port = p2p_port(40)
        silent = socket.create_server(("127.0.0.1", silent_port))
        accepted = []

        def accept():
            while True:
                try:
                    accepted.append(silent.accept()[0])
                except OSError:
                    return

        threading.Thread(target=accept, daemon=True).start()
        url = f"wss://127.0.0.1:{silent_port}/p2p/ws"

        self.log.info("A silent peer does not delay the next connection")
        start = time.time()
        node1.addnode(node=url, command="onetry")
        self.connect_nodes(1, 0)
        assert time.time() - start < 10, time.time() - start

        self.log.info("...and is dialed once while pending")
        node1.addnode(node=url, command="onetry")
        node1.addnode(node=url, command="onetry")
        time.sleep(1)
        assert len(accepted) == 1, len(accepted)
        silent.close()
        for s in accepted:
            s.close()


if __name__ == "__main__":
    P2PWebSocketDialStallTest().main()
