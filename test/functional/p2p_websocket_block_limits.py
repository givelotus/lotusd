#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Configured large blocks traverse WebSocket; smaller peers keep strict caps."""

from abc_p2p_fullblocktest import FullBlockTest, PreviousSpendableOutput
from test_framework.p2p import NetworkThread, P2PDataStore, P2PInterface
from test_framework.util import assert_equal


class WebSocketBlockLimitsTest(FullBlockTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 2
        self.extra_args = [["-excessiveblocksize=100000000"], []]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node, default_node = self.nodes
        peer = node.add_p2p_connection(P2PDataStore())
        self.genesis_hash = int(node.getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0
        maturity = [self.next_block(i) for i in range(100)]
        peer.send_blocks_and_test(maturity, node, timeout=120)
        self.log.info("A configured valid 100 MB block is accepted over WebSocket")
        block = self.next_block(
            "configured-limit",
            spend=PreviousSpendableOutput(maturity[0].vtx[0], 0),
            block_size=100000000,
        )
        assert_equal(len(block.serialize()), 100000000)
        peer.send_blocks_and_test([block], node, timeout=180)
        assert_equal(node.getbestblockhash(), block.hash_hex)
        assert_equal(node.getblock(block.hash_hex)["size"], 100000000)

        self.log.info(
            "The default peer rejects an oversized frame header before its body"
        )
        small_peer = default_node.add_p2p_connection(P2PInterface())
        limit = default_node.getexcessiveblock()["excessiveBlockSize"] + 256 * 1024 + 24
        header = b"\x82\xff" + (limit + 1).to_bytes(8, "big") + b"\x00" * 4
        with default_node.assert_debug_log(["WebSocket peer error: message too large"]):
            NetworkThread.network_event_loop.call_soon_threadsafe(
                lambda: small_peer._transport.write(header)
            )
            small_peer.wait_for_disconnect()

        self.log.info("Ordinary P2P message limits remain independent of the block cap")
        invalid_peer = default_node.add_p2p_connection(P2PInterface())

        class OversizedTx:
            msgtype = b"tx"

            def serialize(self):
                return b"\x00" * (2 * 1024 * 1024 + 1)

        with default_node.assert_debug_log(["Header error: Size too large"]):
            invalid_peer.send_without_ping(OversizedTx())
            invalid_peer.wait_for_disconnect()


if __name__ == "__main__":
    WebSocketBlockLimitsTest().main()
