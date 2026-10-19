#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the test framework's P2P-over-WebSocket transport against a node.

P2PInterface connections normally use the raw P2P protocol. With
P2P_TRANSPORT = "websocket" they speak P2P over /p2p/ws instead; here they
connect to a -publicbind listener and exchange the usual messages,
including a large one.
"""

from test_framework import p2p
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import msg_block, msg_ping
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port

PUBLIC_PORT_INDEX = 40


class P2PWebSocketFrameworkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-publicbind=127.0.0.1:{p2p_port(PUBLIC_PORT_INDEX)}"]]

    def run_test(self):
        node = self.nodes[0]
        transport = p2p.P2P_TRANSPORT
        p2p.P2P_TRANSPORT = "websocket"
        try:
            self.log.info("A P2PInterface connects over WebSocket")
            peer = node.add_p2p_connection(
                P2PInterface(), dstport=p2p_port(PUBLIC_PORT_INDEX)
            )
            info = node.getpeerinfo()[0]
            assert_equal(info["transport"], "ws")
            assert_equal(info["websocket"]["compression"], "none")
            peer.send_and_ping(msg_ping(nonce=1))

            self.log.info("...and relays a block to the node")
            tip = int(node.getbestblockhash(), 16)
            height = node.getblockcount() + 1
            block_time = node.getblock(node.getbestblockhash())["time"] + 1
            block = create_block(tip, create_coinbase(height), block_time)
            block.solve()
            peer.send_and_ping(msg_block(block))
            assert_equal(node.getbestblockhash(), block.hash_hex)
            node.disconnect_p2ps()
        finally:
            p2p.P2P_TRANSPORT = transport


if __name__ == "__main__":
    P2PWebSocketFrameworkTest().main()
