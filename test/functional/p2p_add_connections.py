#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test add_outbound_p2p_connection test framework functionality"""

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, check_node_connections


class P2PFeelerReceiver(P2PInterface):
    def on_version(self, message):
        # The bitcoind node closes feeler connections as soon as a version
        # message is received from the test framework. Don't send any responses
        # to the node's version message since the connection will already be
        # closed.
        pass


class P2PAddConnections(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        # Don't connect the nodes

    def run_test(self):
        self.p2p_idx = [0] * self.num_nodes

        def add_outbounds(node, quantity, conn_type, **kwargs):
            for _ in range(quantity):
                self.log.debug(
                    f"Node {node.index}, {conn_type}: {self.p2p_idx[node.index]}")
                node.add_outbound_p2p_connection(
                    P2PInterface(),
                    p2p_idx=self.p2p_idx[node.index],
                    connection_type=conn_type,
                    **kwargs,
                )
                self.p2p_idx[node.index] += 1

        self.log.info("Add 8 outbounds to node 0")
        add_outbounds(self.nodes[0], 8, "outbound-full-relay")

        self.log.info("Add 2 block-relay-only connections to node 0")
        add_outbounds(self.nodes[0], 2, "block-relay-only")

        self.log.info("Add 2 block-relay-only connections to node 1")
        add_outbounds(self.nodes[1], 2, "block-relay-only")

        self.log.info("Add 5 inbound connections to node 1")
        for i in range(5):
            self.log.info(f"inbound: {i}")
            self.nodes[1].add_p2p_connection(P2PInterface())

        self.log.info("Add 8 outbounds to node 1")
        add_outbounds(self.nodes[1], 8, "outbound-full-relay")

        self.log.info("Check the connections opened as expected")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=10)
        check_node_connections(node=self.nodes[1], num_in=5, num_out=10)

        self.log.info("Disconnect p2p connections & try to re-open")
        self.nodes[0].disconnect_p2ps()
        self.p2p_idx[0] = 0
        check_node_connections(node=self.nodes[0], num_in=0, num_out=0)

        self.log.info("Add 8 outbounds to node 0")
        add_outbounds(self.nodes[0], 8, "outbound-full-relay")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=8)

        self.log.info("Add 2 block-relay-only connections to node 0")
        add_outbounds(self.nodes[0], 2, "block-relay-only")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=10)

        self.log.info("Restart node 0 and try to reconnect to p2ps")
        self.restart_node(0)
        self.p2p_idx[0] = 0

        self.log.info("Add 4 outbounds to node 0")
        add_outbounds(self.nodes[0], 4, "outbound-full-relay")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=4)

        self.log.info("Add 2 block-relay-only connections to node 0")
        add_outbounds(self.nodes[0], 2, "block-relay-only")
        check_node_connections(node=self.nodes[0], num_in=0, num_out=6)

        check_node_connections(node=self.nodes[1], num_in=5, num_out=10)

        self.log.info("Add 1 feeler connection to node 0")
        feeler_conn = self.nodes[0].add_outbound_p2p_connection(
            P2PFeelerReceiver(), p2p_idx=self.p2p_idx[0], connection_type="feeler")

        # Feeler connection is closed
        assert not feeler_conn.is_connected

        # Verify version message received
        assert_equal(feeler_conn.message_count["version"], 1)
        # Feeler connections do not request tx relay
        assert_equal(feeler_conn.last_message["version"].relay, 0)


if __name__ == '__main__':
    P2PAddConnections().main()
