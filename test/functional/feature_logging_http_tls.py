#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real certificate generation, renewal and bad-file startup diagnostics."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class HTTPTLSLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-externaldomain=logging-one.example.org"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.restart_node(
            0, ["-logformat=json", "-externaldomain=logging-two.example.org"]
        )
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        missing_cert = node.chain_path / "owned-missing-cert.pem"
        missing_key = node.chain_path / "owned-missing-key.pem"
        assert not missing_cert.exists() and not missing_key.exists()
        # Short relative inputs exercise a complete record separately from the
        # correctly marked overflow of two long absolute temporary paths.
        node.assert_start_raises_init_error(
            extra_args=[
                "-logformat=json",
                f"-tlscert={missing_cert.name}",
                f"-tlskey={missing_key.name}",
            ],
            expected_msg="Error: Unable to start HTTP server. See debug log for details.",
            timeout=5,
            cwd=node.chain_path,
        )
        log = node.debug_log_path.read_text()
        assert "BEGIN PRIVATE KEY" not in log
        assert "BEGIN EC PRIVATE KEY" not in log
        assert "BEGIN CERTIFICATE" not in log
        rows = [json.loads(line) for line in log.splitlines() if line.strip()]
        issued = [row for row in rows if row.get("event") == "tls_certificate_issued"]
        assert_equal(len(issued), 2)
        certificate = str(node.chain_path / "node_tls_cert.pem")
        for row, action, name in zip(
            issued,
            ("Generated", "Renewed"),
            ("logging-one.example.org", "logging-two.example.org"),
        ):
            assert_equal(row["certificate_action"], action)
            assert_equal(row["certificate_path"], certificate)
            assert_equal(row["server_name"], name)
            assert_equal(row["certificate_validity_days"], 90)
            assert isinstance(row["certificate_validity_days"], int)
            assert_equal(
                row["message"],
                f"{action} TLS certificate {certificate} for {name} (valid 90 days)",
            )
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        enabled = [row for row in rows if row.get("event") == "rpc_tls_enabled"]
        assert_equal(len(enabled), 2)
        for row in enabled:
            assert_equal(row["certificate_path"], certificate)
            assert_equal(
                row["message"], f"TLS enabled on the RPC port using {certificate}"
            )
        failed = next(
            row for row in rows if row.get("event") == "tls_certificate_load_failed"
        )
        assert_equal(failed["certificate_path"], missing_cert.name)
        assert_equal(failed["key_path"], missing_key.name)
        assert isinstance(failed["error"], str) and failed["error"]
        assert_equal(
            failed["message"],
            f"Error: unable to load TLS certificate {missing_cert.name} / key {missing_key.name}: {failed['error']}",
        )
        assert_equal(failed["level"], "info")
        assert "fields_truncated" not in failed


if __name__ == "__main__":
    HTTPTLSLoggingTest().main()
