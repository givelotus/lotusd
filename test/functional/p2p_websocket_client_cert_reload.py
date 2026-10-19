#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Outbound wss dials reload client keys, retaining old sessions and bad-file fallback."""
import base64
import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, rpc_port


class ClientCertificateReloadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [["-tlsmutual"], [], ["-tlsmutual"]]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def skip_test_if_missing_module(self):
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise SkipTest("openssl not available")

    def issue(self, path):
        cert, key = path / "rotated.pem", path / "rotated.key"
        subprocess.run([self.openssl, "req", "-new", "-x509", "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                        "-subj", "/CN=rotated.example", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True)
        pubkey = subprocess.run([self.openssl, "x509", "-pubkey", "-noout", "-in", str(cert)],
                                check=True, capture_output=True).stdout
        der = subprocess.run([self.openssl, "pkey", "-pubin", "-outform", "DER"],
                             input=pubkey, check=True, capture_output=True).stdout
        return cert.read_bytes(), key.read_bytes(), base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")

    def peers(self, n):
        return [p for p in self.nodes[n].getpeerinfo() if p["transport"] == "wss"]

    def dial(self, n):
        self.nodes[1].addnode(f"wss://localhost:{rpc_port(n)}/p2p/ws", "onetry")
        self.wait_until(lambda: len(self.peers(n)) == 1)
        return self.peers(n)[0]["websocket"]["peer_spki"]

    def disconnect_second(self):
        self.nodes[2].disconnectnode(nodeid=self.peers(2)[0]["id"])
        self.wait_until(lambda: not self.peers(2))
        self.wait_until(lambda: len(self.peers(1)) == 1)

    def replace(self, path, contents):
        tmp = path.with_suffix(".replacement")
        tmp.write_bytes(contents)
        os.replace(tmp, path)

    def run_test(self):
        old = self.dial(0)
        assert old
        retained = self.peers(0)[0]["id"]
        client_dir = Path(self.nodes[1].datadir) / self.chain
        cert, key = client_dir / "node_tls_cert.pem", client_dir / "node_tls_key.pem"
        replacement_cert, replacement_key, expected = self.issue(client_dir)
        assert old != expected
        self.replace(cert, replacement_cert)
        self.replace(key, replacement_key)
        time.sleep(1.1)  # Same mtime-check cadence as the inbound TLS listener.
        assert_equal(self.dial(2), expected)
        # Rotation must not disconnect or mutate the already established session.
        assert_equal(self.peers(0)[0]["id"], retained)
        assert_equal(self.peers(0)[0]["websocket"]["peer_spki"], old)
        received_ping = self.peers(0)[0].get("bytesrecv_per_msg", {}).get("ping", 0)
        self.nodes[1].ping()
        self.wait_until(lambda: self.peers(0)[0].get("bytesrecv_per_msg", {}).get("ping", 0) > received_ping)
        self.disconnect_second()

        self.log.info("A mismatched certificate/key retains the last good identity")
        third_cert, third_key, third_spki = self.issue(client_dir)
        self.replace(cert, third_cert)
        time.sleep(1.1)
        assert_equal(self.dial(2), expected)
        self.disconnect_second()
        self.replace(key, third_key)
        time.sleep(1.1)
        assert_equal(self.dial(2), third_spki)
        assert_equal(self.peers(0)[0]["id"], retained)
        assert_equal(self.peers(0)[0]["websocket"]["peer_spki"], old)


if __name__ == "__main__":
    ClientCertificateReloadTest().main()
