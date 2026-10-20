#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Shutdown logs preserve levels and text with typed function/error snapshots."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ShutdownLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-pid=structured-shutdown.pid"]]

    def records(self):
        # Only read after shutdown has flushed the logger and closed the file.
        return [
            json.loads(line)
            for line in self.nodes[0].debug_log_path.read_text().splitlines()
            if line.strip()
        ]

    def run_test(self):
        node = self.nodes[0]
        pid_path = node.chain_path / "structured-shutdown.pid"
        assert pid_path.is_file()
        pid_path.unlink()
        self.stop_node(0)
        records = self.records()
        for event, message in (
            ("node_shutdown_started", "Shutdown: In progress..."),
            ("node_shutdown_completed", "Shutdown: done"),
            (
                "node_shutdown_pid_file_missing",
                "Shutdown: Unable to remove PID file: File does not exist",
            ),
        ):
            row = next(row for row in records if row.get("event") == event)
            assert_equal(row["source_function"], "Shutdown")
            assert_equal(row["message"], message)
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        rpc = next(row for row in records if row.get("event") == "rpc_service_stopped")
        assert_equal(rpc["message"], "RPC stopped.")
        assert_equal(rpc["level"], "debug")
        assert_equal(rpc["category"], "rpc")

        # Replace only this isolated test node's PID path with a nonempty
        # directory, so fs::remove exercises its existing exception branch.
        self.start_node(0)
        pid_path.unlink()
        pid_path.mkdir()
        blocker = pid_path / "owned-test-file"
        blocker.write_text("shutdown logger fixture")
        self.stop_node(0)
        blocker.unlink()
        pid_path.rmdir()
        failed = next(
            row
            for row in self.records()
            if row.get("event") == "node_shutdown_pid_file_remove_failed"
        )
        assert_equal(failed["level"], "warning")
        assert_equal(failed["source_function"], "Shutdown")
        assert isinstance(failed["error"], str) and failed["error"]
        assert_equal(
            failed["message"], f"Shutdown: Unable to remove PID file: {failed['error']}"
        )
        assert "fields_truncated" not in failed


if __name__ == "__main__":
    ShutdownLoggingTest().main()
