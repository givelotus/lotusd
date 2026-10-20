#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pinned WebTransport P2P, block/transaction relay, close and reconnect."""

import hashlib
import socket
import ssl
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port
from test_framework.wallet import MiniWallet


class WebTransportBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-p2pwebtransport=1", "-debug=webtransport"]] * 2

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean(
            "ENABLE_WEBTRANSPORT", fallback=False
        ):
            raise SkipTest("WebTransport was not compiled")

    def setup_network(self):
        self.extra_args[1] = [
            *self.extra_args[1],
            "-listen=0",
            f"-p2pwebtransportbind=127.0.0.1:{p2p_port(1)}",
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        # The framework's clean config binds TCP loopback by default;
        # stock -listen=0 correctly rejects that combination.
        config = Path(self.nodes[1].datadir) / "bitcoin.conf"
        config.write_text(
            "\n".join(
                line
                for line in config.read_text().splitlines()
                if line != "bind=127.0.0.1"
            )
            + "\n"
        )
        self.start_nodes()
        # An explicit WebTransport bind cannot override -listen=0.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", p2p_port(1)))

    def peers(self, index):
        return [
            p
            for p in self.nodes[index].getpeerinfo()
            if p["transport"] == "webtransport"
        ]

    def url(self):
        cert = Path(self.nodes[0].datadir) / self.chain / "node_tls_cert.pem"
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        return f"wt://127.0.0.1:{p2p_port(0)}/p2p/wt#cert={digest}"

    def connect(self):
        self.nodes[1].addnode(self.url(), "onetry")
        self.wait_until(lambda: len(self.peers(0)) == len(self.peers(1)) == 1)
        self.wait_until(lambda: self.peers(1)[0]["version"] != 0)
        assert_equal(self.peers(1)[0]["webtransport"]["pinned"], True)
        assert_equal(self.peers(0)[0]["inbound"], True)

    def run_test(self):
        self.connect()
        wallet = MiniWallet(self.nodes[0])
        self.generate(wallet, 101, sync_fun=self.no_op)
        self.sync_blocks()
        txid = wallet.send_self_transfer(from_node=self.nodes[0])["txid"]
        self.wait_until(lambda: txid in self.nodes[1].getrawmempool())
        with self.nodes[0].assert_debug_log(["WebTransport session"]):
            self.nodes[1].disconnectnode(nodeid=self.peers(1)[0]["id"])
            self.wait_until(lambda: not self.peers(0) and not self.peers(1))
        self.connect()
        self.nodes[1].ping()
        self.wait_until(lambda: "pingtime" in self.peers(1)[0])


if __name__ == "__main__":
    WebTransportBasicTest().main()
