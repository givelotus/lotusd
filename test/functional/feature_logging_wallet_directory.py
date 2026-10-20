#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Wallet startup and an owned unreadable directory retain nonfatal behavior."""

import json
import os

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal


class WalletDirectoryLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    requires = {"wallet"}
    extra_args = [["-logformat=json"]]

    def run_test(self):
        if os.name == "nt" or os.geteuid() == 0:
            raise SkipTest("This permission control needs a non-root POSIX process")
        node = self.nodes[0]
        self.stop_node(0)
        directory = node.chain_path / "owned-wallet-dir"
        directory.mkdir()
        blocked = directory / "blocked"
        blocked.mkdir()
        self.start_node(0, ["-logformat=json", f"-walletdir={directory}"])
        assert_equal(node.listwalletdir(), {"wallets": []})
        blocked.chmod(0)
        try:
            # A directory scan failure remains nonfatal and returns no wallet;
            # no wallet files, keys or database records are fabricated.
            assert_equal(node.listwalletdir(), {"wallets": []})
        finally:
            blocked.chmod(0o700)
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        selected = events["wallet_directory_selected"]
        assert_equal(selected["directory"], str(directory))
        assert_equal(selected["message"], f"Using wallet directory {directory}")
        scanned = events["wallet_directory_scan_failed"]
        assert_equal(scanned["source_function"], "ListWalletDir")
        assert_equal(scanned["path"], str(blocked))
        assert isinstance(scanned["error"], str) and scanned["error"]
        assert_equal(
            scanned["message"],
            f"ListWalletDir: Error scanning {blocked}: {scanned['error']}",
        )
        for row in (selected, scanned):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    WalletDirectoryLoggingTest().main()
