#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the storage metrics at /metrics: MDBX database sizes and commit
latency, per database."""

import time

from test_framework.metrics import m, scrape
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

DATABASES = {
    "chainstate",
    "block_index",
    "txindex",
    "blockfilterindex",
    "coinstatsindex",
    "other",
}


class StorageMetricsTest(BitcoinTestFramework):
    num_nodes = 1
    extra_args = [
        ["-metrics", "-txindex", "-coinstatsindex", "-blockfilterindex"],
    ]

    def run_test(self):
        node = self.nodes[0]
        self.wait_until(lambda: all(i["synced"] for i in node.getindexinfo().values()))
        before = scrape(node)
        assert_equal(before.label_values(m("db_size_bytes"), "db"), DATABASES)
        assert_equal(before.label_values(m("db_commit_seconds_count"), "db"), DATABASES)

        self.log.info("Indexes commit per block; a flush commits the chainstate")
        self.generate(node, 5)
        self.wait_until(lambda: all(i["synced"] for i in node.getindexinfo().values()))
        node.gettxoutsetinfo()  # flushes the chainstate and the block index
        time.sleep(1.05)  # past the rendering cache
        s = scrape(node)
        for db in ("chainstate", "block_index", "txindex", "coinstatsindex"):
            name = m("db_commit_seconds_count")
            assert s.value(name, db=db) > before.value(name, db=db), db
            assert s.value(m("db_size_bytes"), db=db) > 0, db
        assert s.value(m("db_commit_seconds_sum"), db="txindex") > 0
        assert s.value(m("db_commit_seconds_count"), db="blockfilterindex") > 0
        assert_equal(s.value(m("db_commit_seconds_count"), db="other"), 0)


if __name__ == "__main__":
    StorageMetricsTest().main()
