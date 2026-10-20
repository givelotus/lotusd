#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Database restart preserves typed paths and existing public XOR key diagnostics."""

import json
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class DatabaseWrapperLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-debug=leveldb"]]

    def run_test(self):
        node = self.nodes[0]
        # Exercise real persistence and restart before any typed-schema assertions.
        self.generate(node, 1)
        tip = node.getbestblockhash()
        assert node.verifychain(4, 0)
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), tip)
        assert node.verifychain(4, 0)
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        openings = [r for r in records if r.get("event") == "database_open_started"]
        assert openings
        for row in openings:
            assert Path(row["path"]).is_absolute()
            assert_equal(row["message"], f"Opening libmdbx in {row['path']}")
            assert_equal(row["level"], "info")
        completions = [r for r in records if r.get("event") == "database_open_finished"]
        assert_equal(len(completions), len(openings))
        for row in completions:
            assert_equal(row["message"], "Opened libmdbx successfully")
            assert_equal(row["level"], "info")
        created = [
            r for r in records if r.get("event") == "database_obfuscation_key_created"
        ]
        selected = [
            r for r in records if r.get("event") == "database_obfuscation_key_selected"
        ]
        assert created and selected
        for row in created + selected:
            key = row["obfuscation_key"]
            assert type(key) is str and len(key) == 16
            assert bytes.fromhex(key).hex() == key
            assert Path(row["path"]).is_absolute()
            prefix = (
                "Wrote new obfuscate key for"
                if row["event"] == "database_obfuscation_key_created"
                else "Using obfuscation key for"
            )
            assert_equal(row["message"], f"{prefix} {row['path']}: {key}")
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
        # A freshly created persistent key must be selected again after restart.
        for row in created:
            matches = [r for r in selected if r["path"] == row["path"]]
            assert len(matches) >= 2
            assert all(r["obfuscation_key"] == row["obfuscation_key"] for r in matches)


if __name__ == "__main__":
    DatabaseWrapperLoggingTest().main()
