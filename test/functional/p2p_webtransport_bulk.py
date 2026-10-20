#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bulk preference keeps interactive and explicitly selected WT peers."""

import hashlib
import ssl
import time
from pathlib import Path

from p2p_webtransport_fallback import (
    NODE_WEBTRANSPORT,
    PUBLIC_PORT_INDEX,
    WebTransportFallbackTest,
)
from test_framework.messages import NODE_AVALANCHE, NODE_NETWORK, CAddress, msg_addrv2
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal, p2p_port


class WebTransportBulkTest(WebTransportFallbackTest):
    def announce_services(self, services):
        source = self.nodes[1].add_p2p_connection(P2PInterface(support_addrv2=True))
        address = CAddress()
        address.net = CAddress.NET_WSS
        address.wss_version = CAddress.WSS_V1
        address.ip = "localhost"
        address.port = p2p_port(PUBLIC_PORT_INDEX)
        address.time = int(time.time())
        address.nServices = services
        message = msg_addrv2()
        message.addrs = [address]
        source.send_and_ping(message)

    def wait_transport(self, transport):
        self.wait_until(
            lambda: any(
                peer["transport"] == transport and peer["version"]
                for peer in self.outbound()
            ),
            timeout=30,
        )
        info = self.nodes[1].getwebtransportinfo()
        assert_equal(info["negative_cache"], 0)
        assert_equal(sum(info["fallback"].values()), 0)

    def run_test(self):
        server, client = self.nodes
        # Exercise service-hint routing with full-relay connections. The server
        # has no Avalanche proof, so an Avalanche-only outbound would correctly
        # reject its version message independently of transport selection.
        args = self.extra_args[1] + ["-p2pwebtransportbulk=0", "-avalanche=0"]
        services = NODE_NETWORK | NODE_WEBTRANSPORT
        self.log.info("Bulk disabled uses WSS directly without a failed UDP attempt")
        self.restart_fresh_client("bulk-block", args)
        with client.assert_debug_log(
            [
                f"trying WebSocket connection wss://localhost:{p2p_port(PUBLIC_PORT_INDEX)}"
            ],
            unexpected_msgs=["trying WebTransport connection"],
        ):
            self.announce_services(services)
            self.wait_transport("wss")

        self.log.info("An Avalanche service hint retains automatic WT preference")
        self.restart_fresh_client("bulk-avalanche", args)
        self.announce_services(services | NODE_AVALANCHE)
        self.wait_transport("webtransport")

        self.log.info("Explicit only policy overrides bulk preference")
        self.restart_fresh_client("bulk-only", args + ["-p2pwebtransportdial=only"])
        self.announce_services(services)
        self.wait_transport("webtransport")

        self.log.info("An explicit pinned wt URL also overrides bulk preference")
        self.restart_fresh_client("bulk-url", args)
        certificate = Path(server.datadir) / self.chain / "node_tls_cert.pem"
        digest = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(certificate.read_text())
        ).hexdigest()
        client.addnode(
            f"wt://localhost:{p2p_port(PUBLIC_PORT_INDEX)}/p2p/wt#cert={digest}",
            "onetry",
        )
        self.wait_until(
            lambda: any(
                not peer["inbound"]
                and peer["transport"] == "webtransport"
                and peer["version"]
                for peer in client.getpeerinfo()
            )
        )
        peer = next(peer for peer in client.getpeerinfo() if not peer["inbound"])
        assert_equal(peer["webtransport"]["pinned"], True)
        assert_equal(peer["webtransport"]["peer_cert_fingerprint"], digest)


if __name__ == "__main__":
    WebTransportBulkTest().main()
