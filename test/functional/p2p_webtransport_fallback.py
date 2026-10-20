#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Automatic WT discovery, bounded failure cache and proxy-safe wss fallback."""

import select
import socket
import time
from contextlib import ExitStack
from pathlib import Path

from test_framework.messages import NODE_NETWORK, CAddress, msg_addrv2
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port

NODE_WEBTRANSPORT = 1 << 26
PUBLIC_PORT_INDEX = 40


class WebTransportFallbackTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean(
            "ENABLE_WEBTRANSPORT", fallback=False
        ):
            raise SkipTest("WebTransport was not compiled")

    def setup_network(self):
        self.extra_args = [
            [
                "-p2pwebtransport=1",
                f"-p2pwebtransportbind=127.0.0.1:{p2p_port(0)}",
                f"-p2pwebtransportbind=127.0.0.1:{p2p_port(PUBLIC_PORT_INDEX)}",
                f"-p2pwebtransportbind=[::1]:{p2p_port(PUBLIC_PORT_INDEX)}",
                f"-publicbind=127.0.0.1:{p2p_port(PUBLIC_PORT_INDEX)}",
                f"-externaldomain=localhost:{p2p_port(PUBLIC_PORT_INDEX)}",
            ],
            [
                "-p2pwebtransport=1",
                "-p2pwebtransporttimeout=500",
                "-debug=net",
                "-whitelist=addr@127.0.0.1",
            ],
        ]

        self.add_nodes(self.num_nodes, self.extra_args)
        config = Path(self.nodes[1].datadir) / "bitcoin.conf"
        config.write_text(
            "\n".join(
                line for line in config.read_text().splitlines() if line != "connect=0"
            )
            + "\n"
        )
        self.start_nodes()

    def announce(self, source=None):
        if source is None:
            source = self.nodes[1].add_p2p_connection(P2PInterface(support_addrv2=True))
        address = CAddress()
        address.net = CAddress.NET_WSS
        address.wss_version = CAddress.WSS_V1
        address.ip = "localhost"
        address.port = p2p_port(PUBLIC_PORT_INDEX)
        address.time = int(time.time())
        address.nServices = NODE_NETWORK | NODE_WEBTRANSPORT
        message = msg_addrv2()
        message.addrs = [address]
        source.send_and_ping(message)
        return source

    def outbound(self):
        return [
            peer
            for peer in self.nodes[1].getpeerinfo()
            if not peer["inbound"]
            and peer["addr"] == f"localhost:{p2p_port(PUBLIC_PORT_INDEX)}"
        ]

    def clear_client_addresses(self, suffix):
        peers = Path(self.nodes[1].datadir) / self.chain / "peers.dat"
        if peers.exists():
            peers.rename(peers.with_name(f"peers.before-{suffix}.dat"))

    def restart_fresh_client(self, suffix, args):
        self.stop_node(1)
        self.clear_client_addresses(suffix)
        self.start_node(1, args)

    def run_test(self):
        server, client = self.nodes
        self.log.info("Advertise only a real, derivable UDP listener")
        assert int(server.getnetworkinfo()["localservices"], 16) & NODE_WEBTRANSPORT
        assert client.getwebtransportinfo()["enabled"]
        self.log.info("An advertised endpoint establishes automatic WT first")
        self.announce()
        self.wait_until(
            lambda: any(
                p["transport"] == "webtransport" and p["version"]
                for p in self.outbound()
            ),
            timeout=30,
        )
        self.stop_node(1)
        self.clear_client_addresses("successful-wt")
        self.stop_node(0)
        with ExitStack() as stack:
            sockets = []
            for family, host in [
                (socket.AF_INET, "127.0.0.1"),
                (socket.AF_INET6, "::1"),
            ]:
                sock = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, p2p_port(PUBLIC_PORT_INDEX)))
                sock.setblocking(False)
                sockets.append(sock)
            self.start_node(0)
            self.start_node(1)
            assert (
                not int(server.getnetworkinfo()["localservices"], 16)
                & NODE_WEBTRANSPORT
            )
            # An old or false service advertisement is untrusted input. The
            # restarted server no longer advertises unavailable UDP itself.
            packet_times = []

            def drain():
                for sock in select.select(sockets, [], [], 0)[0]:
                    while True:
                        try:
                            sock.recvfrom(65536)
                            packet_times.append(time.monotonic())
                        except BlockingIOError:
                            break

            source = self.announce()

            def connected():
                drain()
                return any(
                    p["transport"] == "wss" and p["version"] for p in self.outbound()
                )

            self.wait_until(connected, timeout=30)
            assert packet_times, "Automatic WT was not attempted"
            # Measure from the actual first UDP packet, excluding addrman
            # selection/startup delay. The configured attempt budget is 500ms.
            assert time.monotonic() - packet_times[0] < 1.5
            info = client.getwebtransportinfo()
            assert_equal(info["negative_cache"], 1)
            assert info["fallback"]["timeout"] >= 1, info
            failures = info["fallback"]
            self.log.info("Negative cache skips another UDP attempt on reconnect")
            self.announce(source)  # Refresh the untrusted bit after version processing.
            client.disconnectnode(nodeid=self.outbound()[0]["id"])
            self.wait_until(lambda: not self.outbound())
            # Let the canceled QUIC connection leave the engine before measuring.
            time.sleep(0.2)
            drain()
            packet_times.clear()
            self.wait_until(connected, timeout=30)
            assert_equal(packet_times, [])
            assert_equal(client.getwebtransportinfo()["fallback"], failures)
            source.peer_disconnect()

            self.log.info("A name/network proxy prevents all automatic UDP")
            self.restart_fresh_client(
                "proxy", self.extra_args[1] + ["-proxy=127.0.0.1:1"]
            )
            drain()
            packet_times.clear()
            with client.assert_debug_log(
                [
                    f"trying WebSocket connection wss://localhost:{p2p_port(PUBLIC_PORT_INDEX)}"
                ],
                unexpected_msgs=["trying WebTransport connection"],
                timeout=15,
            ):
                self.announce()
            time.sleep(1)
            drain()
            assert_equal(packet_times, [])
            assert_equal(client.getwebtransportinfo()["negative_cache"], 0)
            assert_equal(sum(client.getwebtransportinfo()["fallback"].values()), 0)
            assert_equal(self.outbound(), [])

            self.log.info("WT-only discovery records failure and never falls back")
            self.restart_fresh_client(
                "only", self.extra_args[1] + ["-p2pwebtransportdial=only"]
            )
            self.announce()
            self.wait_until(
                lambda: client.getwebtransportinfo()["negative_cache"] == 1, timeout=30
            )
            assert_equal(self.outbound(), [])
            assert client.getwebtransportinfo()["fallback"]["timeout"] >= 1


if __name__ == "__main__":
    WebTransportFallbackTest().main()
