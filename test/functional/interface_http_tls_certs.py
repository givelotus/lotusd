#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test generated TLS certificates and reloading -tlscert/-tlskey.

- The generated certificate names nothing node-specific, is valid for 90
  days, uses -externaldomain when set, and is renewed (same key) when it
  nears expiry.
- A replaced -tlscert/-tlskey is picked up without a restart.
"""

import os
import shutil
import ssl
import subprocess
import time

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, rpc_port


class HTTPTLSCertsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.openssl = shutil.which("openssl")
        if not self.openssl:
            raise SkipTest("openssl is not available")

    def ossl(self, *args, stdin=None):
        return subprocess.run(
            [self.openssl, *args],
            input=stdin,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def served_pem(self):
        return ssl.get_server_certificate(("127.0.0.1", rpc_port(0)))

    def subject_cn(self, pem):
        out = self.ossl(
            "x509", "-noout", "-subject", "-nameopt", "multiline", stdin=pem
        )
        return out.split("commonName", 1)[1].split("=", 1)[1].strip()

    def days_left(self, pem):
        for days in range(0, 400):
            try:
                self.ossl("x509", "-noout", "-checkend", str(days * 86400), stdin=pem)
            except subprocess.CalledProcessError:
                return days
        return 400

    def pubkey(self, pem):
        return self.ossl("x509", "-noout", "-pubkey", stdin=pem)

    def issue(self, key, cert, cn, days, new_key=False):
        if new_key:
            self.ossl(
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                key,
            )
        tmp = cert + ".tmp"
        self.ossl(
            "req",
            "-new",
            "-x509",
            "-key",
            key,
            "-subj",
            f"/CN={cn}",
            "-days",
            str(days),
            "-out",
            tmp,
        )
        os.replace(tmp, cert)

    def run_test(self):
        node = self.nodes[0]
        datadir = os.path.join(node.datadir, self.chain)
        cert = os.path.join(datadir, "node_tls_cert.pem")
        key = os.path.join(datadir, "node_tls_key.pem")

        self.log.info("Generated certificate: neutral name, 90 days")
        pem = self.served_pem()
        with open(cert, encoding="utf8") as f:
            assert_equal(self.pubkey(f.read()), self.pubkey(pem))
        cn = self.subject_cn(pem)
        text = self.ossl("x509", "-noout", "-text", stdin=pem)
        for word in ("bitcoin", "localhost", "127.0.0.1", "ecash", "lotus"):
            assert word not in text.lower(), word
        assert "." in cn and cn == cn.lower(), cn
        assert_equal(f"DNS:{cn}" in text, True)
        assert self.days_left(pem) in (89, 90), self.days_left(pem)
        original_key = self.pubkey(pem)

        self.log.info("...kept across restarts")
        self.restart_node(0)
        assert_equal(self.subject_cn(self.served_pem()), cn)

        self.log.info("-externaldomain names the certificate; the key stays")
        self.restart_node(0, ["-externaldomain=Node.Example.org:443"])
        pem = self.served_pem()
        assert_equal(self.subject_cn(pem), "node.example.org")
        assert_equal(self.pubkey(pem), original_key)

        self.log.info("A certificate near expiry is renewed with the same key")
        self.stop_node(0)
        self.issue(key, cert, "node.example.org", days=10)
        with node.assert_debug_log(["Renewed TLS certificate"]):
            self.start_node(0, ["-externaldomain=node.example.org"])
        pem = self.served_pem()
        assert self.days_left(pem) in (89, 90)
        assert_equal(self.pubkey(pem), original_key)

        self.log.info("An old 'bitcoind node' certificate gets a neutral name")
        self.stop_node(0)
        self.issue(key, cert, "bitcoind node", days=1000)
        self.start_node(0)
        pem = self.served_pem()
        assert self.subject_cn(pem) != "bitcoind node"
        assert_equal(self.pubkey(pem), original_key)

        self.log.info("A replaced -tlscert/-tlskey is used without a restart")
        own_cert = os.path.join(datadir, "own_cert.pem")
        own_key = os.path.join(datadir, "own_key.pem")
        self.issue(own_key, own_cert, "one.example.net", days=30, new_key=True)
        self.restart_node(0, [f"-tlscert={own_cert}", f"-tlskey={own_key}"])
        assert_equal(self.subject_cn(self.served_pem()), "one.example.net")
        with node.assert_debug_log(["Reloaded TLS certificate"]):
            # A new key and certificate, as an ACME client would write them.
            new_key = own_key + ".next"
            self.issue(
                new_key, own_cert + ".next", "two.example.net", days=30, new_key=True
            )
            os.replace(new_key, own_key)
            os.replace(own_cert + ".next", own_cert)
            self.wait_until(
                lambda: self.subject_cn(self.served_pem()) == "two.example.net"
            )

        self.log.info("A broken replacement keeps the working certificate")
        with node.assert_debug_log(["unable to load TLS certificate"]):
            with open(own_cert, "w", encoding="utf8") as f:
                f.write("not a certificate\n")
            # Files are rechecked at most once a second, on new connections;
            # meanwhile and afterwards handshakes get the previous certificate.
            for _ in range(25):
                assert_equal(self.subject_cn(self.served_pem()), "two.example.net")
                time.sleep(0.1)
        assert_equal(self.subject_cn(self.served_pem()), "two.example.net")


if __name__ == "__main__":
    HTTPTLSCertsTest().main()
