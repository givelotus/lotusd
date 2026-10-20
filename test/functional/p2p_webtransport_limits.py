#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""WT per-IP admission, always-Retry, pre-TLS bans and bounded metrics."""

import hashlib
import http.client
import ssl
from pathlib import Path

from interface_http_metrics import parse
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port, rpc_port


class WebTransportLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        self.setup_clean_chain = True
        self.extra_args = [
            [
                "-p2pwebtransport=1",
                "-p2pwebtransportmaxperip=4",
                "-p2pwebtransportmaxhandshaking=8",
                "-p2pwebtransportretry=always",
                "-metrics",
                "-debug=webtransport",
            ],
        ] + [["-p2pwebtransport=1", "-listen=0"] for _ in range(5)]

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean(
            "ENABLE_WEBTRANSPORT", fallback=False
        ):
            raise SkipTest("WebTransport was not compiled")

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        for node in self.nodes[1:]:
            config = Path(node.datadir) / "bitcoin.conf"
            config.write_text(
                "\n".join(
                    line
                    for line in config.read_text().splitlines()
                    if line != "bind=127.0.0.1"
                )
                + "\n"
            )
        self.start_nodes()

    def peers(self, index):
        return [
            p
            for p in self.nodes[index].getpeerinfo()
            if p["transport"] == "webtransport"
        ]

    def scrape(self):
        connection = http.client.HTTPConnection("127.0.0.1", rpc_port(0), timeout=10)
        connection.request("GET", "/metrics")
        response = connection.getresponse()
        body = response.read().decode()
        connection.close()
        assert_equal(response.status, 200)
        return parse(body)

    def total(self, name, **labels):
        return sum(
            value
            for (metric, fields), value in self.scrape().items()
            if metric == name
            and all(dict(fields).get(k) == v for k, v in labels.items())
        )

    def connect(self, index, url):
        self.nodes[index].addnode(url, "onetry")
        self.wait_until(lambda: len(self.peers(index)) == 1)
        self.wait_until(lambda: self.peers(index)[0]["version"] != 0)
        assert_equal(self.peers(index)[0]["webtransport"]["pinned"], True)

    def run_test(self):
        server = self.nodes[0]
        cert = Path(server.datadir) / self.chain / "node_tls_cert.pem"
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        url = f"wt://127.0.0.1:{p2p_port(0)}/p2p/wt#cert={digest}"
        self.log.info("Four native peers connect through QUIC Retry address validation")
        for index in range(1, 5):
            self.connect(index, url)
        self.wait_until(lambda: len(self.peers(0)) == 4)
        assert self.total("fullnode_p2p_wt_retry_sent_total") >= 4
        assert self.total("fullnode_p2p_wt_handshakes_total", result="success") >= 4
        assert (
            self.total(
                "fullnode_p2p_connections_total",
                direction="inbound",
                transport="webtransport",
            )
            >= 4
        )
        self.wait_until(
            lambda: (
                self.total(
                    "fullnode_p2p_wt_connections", dir="inbound", state="established"
                )
                == 4
            )
        )

        self.log.info("A fifth source-port from the same IP cannot evade the limit")
        self.nodes[5].addnode(url, "onetry")
        self.wait_until(
            lambda: self.total("fullnode_p2p_wt_rejected_total", reason="per_ip") > 0
        )
        assert_equal(len(self.peers(0)), 4)
        assert_equal(self.peers(5), [])
        self.stop_node(5)  # Interrupt its bounded explicit dial instead of waiting10s.

        self.log.info("A banned source is rejected before a new TLS handshake")
        completed = self.total("fullnode_p2p_wt_handshakes_total", result="success")
        server.setban("127.0.0.1", "add")
        self.wait_until(lambda: not self.peers(0))
        self.start_node(5)
        self.nodes[5].addnode(url, "onetry")
        self.wait_until(
            lambda: self.total("fullnode_p2p_wt_rejected_total", reason="banned") > 0
        )
        assert_equal(
            self.total("fullnode_p2p_wt_handshakes_total", result="success"), completed
        )
        assert_equal(self.peers(5), [])
        self.stop_node(5)
        server.clearbanned()
        self.wait_until(
            lambda: (
                self.total(
                    "fullnode_p2p_wt_connections", dir="inbound", state="closing"
                )
                == 0
            )
        )
        self.start_node(5)
        self.connect(5, url)
        tip = self.generate(server, 1, sync_fun=self.no_op)[0]
        self.wait_until(lambda: self.nodes[5].getbestblockhash() == tip)
        assert (
            self.total(
                "fullnode_p2p_wt_bytes_total", dir="outbound", **{"class": "block"}
            )
            > 0
        )
        self.wait_until(lambda: self.total("fullnode_p2p_wt_rtt_seconds_count") > 0)

        self.log.info("All fixed-cardinality WT metric families are exposed")
        names = {name for name, _ in self.scrape()}
        for name in [
            "connections",
            "handshakes_total",
            "retry_sent_total",
            "stateless_reset_sent_total",
            "rejected_total",
            "bytes_total",
            "blocked_total",
            "lost_packets_total",
            "rtt_seconds_count",
            "fallback_total",
            "split_total",
        ]:
            assert "fullnode_p2p_wt_" + name in names, name


if __name__ == "__main__":
    WebTransportLimitsTest().main()
