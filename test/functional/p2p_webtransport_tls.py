#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""WebTransport certificate pin mismatch and certificate replacement."""

import hashlib
import shutil
import ssl
import subprocess
import time
from pathlib import Path

from p2p_webtransport_basic import WebTransportBasicTest
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal


class WebTransportTLSTest(WebTransportBasicTest):
    def skip_test_if_missing_module(self):
        super().skip_test_if_missing_module()
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise SkipTest("openssl not available")

    def run_test(self):
        bad_url = self.url().split("#")[0] + "#cert=" + "00" * 32
        with self.nodes[1].assert_debug_log(["does not match the pinned hash"]):
            self.nodes[1].addnode(bad_url, "onetry")
        assert_equal(self.peers(1), [])
        self.connect()
        old_peer = self.peers(1)[0]
        old_fingerprint = old_peer["webtransport"]["peer_cert_fingerprint"]
        directory = Path(self.nodes[0].datadir) / self.chain
        cert, key = directory / "replacement.pem", directory / "replacement.key"
        subprocess.run(
            [
                self.openssl,
                "req",
                "-new",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "10",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
        expected = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(cert.read_text())
        ).hexdigest()
        # Reload is checked once per minute on the engine thread. Existing
        # sessions retain their original identity; new sessions use the files.
        cert.replace(directory / "node_tls_cert.pem")
        key.replace(directory / "node_tls_key.pem")
        time.sleep(61)
        assert_equal(
            self.peers(1)[0]["webtransport"]["peer_cert_fingerprint"], old_fingerprint
        )
        self.nodes[1].disconnectnode(nodeid=old_peer["id"])
        self.wait_until(lambda: not self.peers(0) and not self.peers(1))
        self.connect()
        assert_equal(
            self.peers(1)[0]["webtransport"]["peer_cert_fingerprint"], expected
        )


if __name__ == "__main__":
    WebTransportTLSTest().main()
