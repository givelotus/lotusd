#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Actual early crypto startup copies its implementation label before return."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CryptoStartupLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-par=1"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        cookie_path = node.chain_path / ".cookie"
        cookie = cookie_path.read_text()
        assert cookie.startswith("__cookie__:")
        self.stop_node(0)
        # These paths and marker belong only to this isolated test datadir.
        missing_cookie = node.chain_path / "missing-cookie-parent" / "auth"
        init_error = "Error: Unable to start HTTP server. See debug log for details."
        node.assert_start_raises_init_error(
            extra_args=[*self.extra_args[0], f"-rpccookiefile={missing_cookie}"],
            expected_msg=init_error,
            timeout=5,
        )
        blocked_cookie = node.chain_path / "cookie-destination-directory"
        blocked_cookie.mkdir()
        (blocked_cookie / "owned-marker").write_text("keep this directory nonempty")
        node.assert_start_raises_init_error(
            extra_args=[*self.extra_args[0], f"-rpccookiefile={blocked_cookie}"],
            expected_msg=init_error,
            timeout=5,
        )
        log = node.debug_log_path.read_text()
        assert cookie not in log
        assert "__cookie__:" not in log
        rows = [json.loads(line) for line in log.splitlines() if line.strip()]
        by_event = {row.get("event"): row for row in rows}
        generated = by_event["rpc_cookie_generated"]
        assert_equal(generated["path"], str(cookie_path))
        assert_equal(
            generated["message"], f"Generated RPC authentication cookie {cookie_path}"
        )
        opened = by_event["rpc_cookie_open_failed"]
        assert_equal(opened["path"], str(missing_cookie) + ".tmp")
        assert_equal(
            opened["message"],
            f"Unable to open cookie authentication file {missing_cookie}.tmp for writing",
        )
        renamed = by_event["rpc_cookie_rename_failed"]
        assert_equal(renamed["source_path"], str(blocked_cookie) + ".tmp")
        assert_equal(renamed["destination_path"], str(blocked_cookie))
        assert "path" not in renamed
        assert_equal(
            renamed["message"],
            f"Unable to rename cookie authentication file {blocked_cookie}.tmp to {blocked_cookie}",
        )
        for row in (generated, opened, renamed):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
            assert "cookie" not in row
            assert "password" not in row
        selected = by_event["sha256_implementation_selected"]
        implementation = selected["sha256_implementation"]
        assert isinstance(implementation, str) and implementation
        assert_equal(
            selected["message"], f"Using the '{implementation}' SHA256 implementation"
        )
        assert_equal(selected["level"], "info")
        assert "fields_truncated" not in selected
        workers = by_event["script_verification_workers"]
        assert_equal(workers["script_worker_threads"], 0)
        assert isinstance(workers["script_worker_threads"], int)
        assert_equal(
            workers["message"], "Script verification uses 0 additional threads"
        )
        assert_equal(workers["level"], "info")
        assert "fields_truncated" not in workers
        # Architecture/capability guards are unchanged. These optional branches
        # are absent on macOS arm64, and this test does not force CPU features.
        for event, text in (
            ("entropy_rdseed_enabled", "Using RdSeed as additional entropy source"),
            ("entropy_rdrand_enabled", "Using RdRand as an additional entropy source"),
        ):
            if event in by_event:
                row = by_event[event]
                assert_equal(row["message"], text)
                assert_equal(row["level"], "info")
                assert "fields_truncated" not in row
                assert "value" not in row


if __name__ == "__main__":
    CryptoStartupLoggingTest().main()
