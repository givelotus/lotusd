#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Browser certificate overlap, stable key, public discovery and live reload."""

import hashlib
import http.client
import json
import ssl
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, p2p_port, rpc_port


class WebTransportBrowserCertificateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        if not self.config["components"].getboolean(
            "ENABLE_WEBTRANSPORT", fallback=False
        ):
            raise SkipTest("WebTransport was not compiled")

    def setup_network(self):
        self.public_port = p2p_port(40)
        self.extra_args = [
            [
                "-p2pwebtransport=1",
                "-p2pwebtransportbrowsercert=1",
                f"-publicbind=127.0.0.1:{self.public_port}",
            ],
            ["-p2pwebtransport=1", "-listen=0"],
        ]
        self.add_nodes(self.num_nodes, self.extra_args)
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

    def request(self, port, path="/p2p/wt/info", method="GET"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, headers, body

    def peers(self, index):
        return [
            p
            for p in self.nodes[index].getpeerinfo()
            if p["transport"] == "webtransport"
        ]

    def connect(self, certificate_hash):
        self.nodes[1].addnode(
            f"wt://127.0.0.1:{p2p_port(0)}/p2p/wt#cert={certificate_hash}", "onetry"
        )
        self.wait_until(
            lambda: len(self.peers(1)) == 1 and self.peers(1)[0]["version"] != 0
        )
        assert_equal(
            self.peers(1)[0]["webtransport"]["peer_cert_fingerprint"], certificate_hash
        )

    def run_test(self):
        server = self.nodes[0]
        directory = Path(server.datadir) / self.chain
        key = directory / "node_tls_key.pem"
        normal_cert = directory / "node_tls_cert.pem"
        browser_cert = directory / "node_wt_cert.pem"
        original_key, original_normal = key.read_bytes(), normal_cert.read_bytes()
        self.log.info(
            "Public discovery publishes current and next hashes without private counters"
        )
        first = server.getwebtransportinfo()
        assert_equal(first["enabled"], True)
        assert_equal(first["browsercert"], True)
        assert_equal(first["protocols"], ["p2p-v1"])
        assert_equal(first["h3_service"], "webtransport-p2p")
        assert_equal(len(first["cert_sha256"]), 2)
        assert first["cert_sha256"][0] != first["cert_sha256"][1]

        def digest():
            return hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(browser_cert.read_text())
            ).hexdigest()

        assert_equal(first["cert_sha256"][0], digest())
        decoded = ssl._ssl._test_decode_cert(str(browser_cert))
        assert_equal(
            ssl.cert_time_to_seconds(decoded["notAfter"])
            - ssl.cert_time_to_seconds(decoded["notBefore"]),
            10 * 86400,
        )
        status, headers, body = self.request(self.public_port)
        assert_equal(status, 200)
        assert_equal(headers["Cache-Control"], "no-store")
        assert_equal(headers["Access-Control-Allow-Origin"], "*")
        assert "Alt-Svc" not in headers
        public = json.loads(body)
        assert_equal(public["cert_sha256"], first["cert_sha256"])
        for private in ("negative_cache", "fallback", "connections"):
            assert private not in public
        assert_equal(self.request(self.public_port, method="HEAD")[2], b"")
        assert_equal(self.request(self.public_port, method="POST")[0], 405)
        assert_equal(self.request(self.public_port, "/p2p/wt/info?test=1")[0], 200)
        assert_equal(
            self.request(self.public_port, "/p2p/wt/info?test=1", "POST")[0], 405
        )
        for path in ("/", "/metrics", "/p2p/wt/info/extra", "/p2p/wt/infoevil"):
            assert_equal(self.request(self.public_port, path)[0], 404)
        assert "Alt-Svc" not in self.request(rpc_port(0))[1]
        self.connect(first["cert_sha256"][0])

        self.log.info(
            "Restart recovers both hashes; mocktime rollover promotes the published successor"
        )
        self.stop_node(0)
        self.start_node(0)
        self.wait_until(lambda: not self.peers(1))
        assert_equal(server.getwebtransportinfo()["cert_sha256"], first["cert_sha256"])
        server.setmocktime(int(time.time()) + 6 * 86400)
        rotated = server.getwebtransportinfo()
        assert_equal(rotated["cert_sha256"][0], first["cert_sha256"][1])
        assert rotated["cert_sha256"][1] not in first["cert_sha256"]
        assert_equal(rotated["cert_sha256"][0], digest())
        assert_equal(rotated["spki"], first["spki"])
        assert_equal(key.read_bytes(), original_key)
        assert_equal(normal_cert.read_bytes(), original_normal)
        # Native pinned TLS confirms that the engine refreshes its actual leaf
        # immediately. Browser validity against real time is a separate manual
        # gate; this fixture advances only the node's mock clock.
        self.connect(rotated["cert_sha256"][0])
        assert_equal(
            json.loads(self.request(self.public_port)[2])["cert_sha256"],
            rotated["cert_sha256"],
        )


if __name__ == "__main__":
    WebTransportBrowserCertificateTest().main()
