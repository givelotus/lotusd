#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test /metrics (-metrics): the Prometheus text format, values that change,
and access limited to -rpcallowip clients on the RPC listeners."""

import re
import socket
import ssl
import time

from test_framework.metrics import NAMESPACE, m, request, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
    rpc_port,
)
from test_framework.wallet import MiniWallet

PUBLIC_PORT_INDEX = 41


class HTTPMetricsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.public_port = p2p_port(PUBLIC_PORT_INDEX)
        self.extra_args = [
            [
                "-metrics",
                "-metricslabel=region=test-1",
                '-metricslabel=role=edge "a\\b"',
                "-trustedproxy=127.0.0.1",
                f"-publicbind=127.0.0.1:{self.public_port}",
            ],
            # node1 peers with node0 over P2P WebSocket
            [f"-addnode=ws://127.0.0.1:{self.public_port}/p2p/ws"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
        # node0's public listener first, so node1's first dial succeeds
        self.start_node(0)
        self.start_node(1)

    def request(self, port, path="/metrics", method="GET", headers=None):
        return request(port, path, method, headers)

    def scrape(self):
        return scrape(self.nodes[0])

    def total(self, samples, name, **labels):
        """Sum of a metric's series matching the given labels"""
        return samples.total(name, **labels)

    def run_test(self):
        node = self.nodes[0]
        self.log.info("The exposition is well formed")
        samples = self.scrape()
        # The genesis block was connected at startup.
        connected = samples.value(m("block_connect_seconds_count"))
        assert_equal(connected, 1)
        assert_equal(samples.value(m("metrics_dropped_samples_total")), 0)
        assert_equal(samples.value(m("log_dropped_lines_total")), 0)
        assert_equal(samples.value(m("log_journal_failures_total")), 0)
        assert_equal(samples.value(m("chain_tip_height")), 0)
        assert_equal(samples.value(m("initial_block_download")), 1)
        assert samples.value("process_start_time_seconds") > 1e9

        self.log.info("Names are namespaced; every series has the constant labels")
        assert "lotus_" not in samples.text
        for name in samples.types:
            assert name.startswith((NAMESPACE, "process_")), name
        samples.check_constant_labels(
            {
                "client": "ecashd",
                "network": "ecash-regtest",
                "region": "test-1",
                "role": 'edge "a\\b"',
            }
        )
        assert 'role="edge \\"a\\\\b\\""' in samples.text
        version = node.getnetworkinfo()["version"]
        info = samples.series(m("build_info"))
        assert_equal(len(info), 1)
        labels, value = info[0]
        assert_equal(value, 1)
        assert_equal(
            labels["version"],
            f"{version // 1000000}.{version // 10000 % 100}.{version // 100 % 100}",
        )
        assert "commit" in labels

        self.log.info("Peers: both native connections use WebSocket")
        self.wait_until(
            lambda: (
                self.total(
                    self.scrape(),
                    m("peers"),
                    direction="inbound",
                    transport="ws",
                )
                == 1
            )
        )
        self.connect_nodes(0, 1)
        self.wait_until(
            lambda: (
                self.total(
                    self.scrape(), m("peers"), direction="outbound", transport="ws"
                )
                == 1
            )
        )
        samples = self.scrape()
        assert_equal(self.total(samples, m("p2p_websocket_peers")), 2)
        assert_equal(self.total(samples, m("p2p_websocket_peers"), tls="false"), 2)
        # The WebSocket peer's handshake is timed under transport="ws"
        assert (
            self.total(
                samples,
                m("p2p_handshake_seconds_count"),
                direction="inbound",
                transport="ws",
            )
            >= 1
        )
        assert_equal(
            self.total(
                samples,
                m("p2p_connections_total"),
                direction="inbound",
                transport="ws",
            ),
            1,
        )
        assert_equal(self.total(samples, m("peers"), transport="tcp"), 0)
        assert_equal(
            self.total(
                samples,
                m("p2p_connections_total"),
                direction="outbound",
                transport="ws",
            ),
            1,
        )
        for name in (
            m("p2p_received_messages_total"),
            m("p2p_sent_messages_total"),
        ):
            assert self.total(samples, name, type="version") >= 2, name
        assert self.total(samples, m("p2p_sent_bytes_total")) > 0
        assert samples.has(m("p2p_received_bytes_total"), type="other")

        self.log.info("Chain and mempool values change")
        wallet = MiniWallet(node)
        self.generate(wallet, 101)
        self.wait_until(
            lambda: (
                self.scrape().value(m("block_connect_seconds_count")) == connected + 101
            )
        )
        self.wait_until(lambda: self.scrape().value(m("initial_block_download")) == 0)
        samples = self.scrape()
        assert_equal(samples.value(m("chain_tip_height")), 101)
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        assert_equal(samples.value(m("chain_tip_timestamp_seconds")), tip_time)
        # Computed at scrape time; negative if the tip's timestamp is ahead
        # of the clock (quickly mined regtest blocks).
        age = samples.value(m("chain_tip_age_seconds"))
        assert abs(age - (time.time() - tip_time)) < 30, age
        assert samples.value(m("block_connect_seconds_sum")) > 0
        # Message handling is timed for 1 message in 16.
        assert self.total(samples, m("p2p_message_handling_seconds_count")) > 0
        assert_equal(samples.value(m("mempool_transactions")), 0)
        tx = wallet.send_self_transfer(from_node=node)
        self.wait_until(lambda: self.scrape().value(m("mempool_transactions")) == 1)
        assert_equal(self.scrape().value(m("mempool_bytes")), len(tx["hex"]) // 2)
        self.generate(node, 1)
        self.wait_until(lambda: self.scrape().value(m("mempool_transactions")) == 0)

        self.log.info("Block coin prefetch")
        # Blocks so far had at most two transactions: below the prefetch's
        # minimum, so none was prefetched.
        samples = self.scrape()
        assert_equal(samples.value(m("block_prefetch_started_total")), 0)
        assert_equal(samples.value(m("block_prefetch_dropped_total")), 0)
        assert_equal(samples.value(m("block_prefetch_errors_total")), 0)
        for _ in range(10):
            wallet.send_self_transfer(from_node=node)
        self.generate(node, 1)
        self.wait_until(
            lambda: (
                self.scrape().value(m("block_prefetch_duration_seconds_count"))
                == 1
            )
        )
        samples = self.scrape()
        assert_equal(samples.value(m("block_prefetch_started_total")), 1)
        assert_equal(samples.value(m("block_prefetch_errors_total")), 0)
        # Spends of coins created in the same block are not read.
        assert 1 <= samples.value(m("block_prefetch_outpoints_total")) <= 10

        self.log.info("HTTP and RPC requests")
        # Baselines exclude completed setup RPCs and the one-second scrape cache.
        time.sleep(1.1)
        before_rpc = self.scrape()
        height = node.getblockcount()  # Native async actor.
        node.getrpcinfo()  # Async dispatcher wrapping a synchronous actor.
        assert_raises_rpc_error(-8, "Block height out of range", node.getblockhash, -1)
        node.waitforblockheight(height + 1, 100)  # Actual coroutine suspension.
        self.request(rpc_port(0), path="/livez")
        with socket.create_connection(("127.0.0.1", rpc_port(0))) as raw:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw):
                pass
        time.sleep(1.1)  # past the rendering cache
        samples = self.scrape()
        assert (
            self.total(samples, m("http_requests_total"), endpoint="rpc", code="2xx")
            > 0
        )
        assert (
            self.total(samples, m("http_requests_total"), endpoint="health", code="2xx")
            >= 1
        )
        assert (
            self.total(
                samples, m("http_requests_total"), endpoint="metrics", code="2xx"
            )
            >= 1
        )
        assert (
            self.total(
                samples, m("http_request_duration_seconds_count"), endpoint="rpc"
            )
            > 0
        )
        assert_equal(
            self.total(samples, m("http_tls_handshakes_total"), result="ok"), 1
        )
        for method in (
            "getblockcount",
            "getrpcinfo",
            "getblockhash",
            "waitforblockheight",
        ):
            name = m("rpc_request_duration_seconds_count")
            assert_equal(
                self.total(samples, name, method=method),
                self.total(before_rpc, name, method=method) + 1,
            )
        # The timer covers the await lifetime, not only initial dispatch.
        name = m("rpc_request_duration_seconds_sum")
        assert (
            self.total(samples, name, method="waitforblockheight")
            - self.total(before_rpc, name, method="waitforblockheight")
        ) >= 0.075
        # Only methods that were called have series.
        assert_equal(
            self.total(samples, m("rpc_request_duration_seconds_count"), method="stop"),
            0,
        )
        assert not any(
            n.startswith(m("rpc_request")) and ("method", "stop") in ls
            for n, ls in samples.samples
        )

        self.log.info("HEAD has the headers but no body; POST is refused")
        res, body = self.request(rpc_port(0), method="HEAD")
        assert_equal((res.status, body), (200, ""))
        res, _ = self.request(rpc_port(0), method="POST")
        assert_equal(res.status, 405)

        self.log.info(
            "A client outside -rpcallowip is refused (resolved "
            "through the trusted proxy's X-Forwarded-For)"
        )
        res, body = self.request(
            rpc_port(0), headers={"X-Forwarded-For": "203.0.113.5"}
        )
        assert_equal(res.status, 403)
        assert NAMESPACE not in body
        res, _ = self.request(rpc_port(0), headers={"X-Forwarded-For": "127.0.0.1"})
        assert_equal(res.status, 200)

        self.log.info("Public listeners never serve metrics")
        res, body = self.request(self.public_port)
        assert_equal(res.status, 404)
        assert NAMESPACE not in body

        self.log.info("Without -metrics there is no /metrics")
        res, _ = self.request(rpc_port(1))
        assert_equal(res.status, 404)

        self.log.info("Invalid or reserved -metricslabel names are refused")
        self.stop_node(1)
        for arg, error in (
            ("network=x", 'the label "network" is set by the node'),
            ("client=x", 'the label "client" is set by the node'),
            ("9x=y", "is not a valid label name"),
            ("__x=y", "is not a valid label name"),
            ("le=y", "is not a valid label name"),
            ("novalue", "expected <name>=<value>"),
            ("a=", "the value must be 1 to 128 bytes"),
            # The name of a metric's own label
            ("type=x", 'label name "type" is used by a metric'),
        ):
            self.nodes[1].assert_start_raises_init_error(
                ["-metrics", f"-metricslabel={arg}"],
                re.escape(error),
                match=ErrorMatch.PARTIAL_REGEX,
            )


if __name__ == "__main__":
    HTTPMetricsTest().main()
