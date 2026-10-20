#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Read a real config include and preserve its exact filename diagnostic."""

import json
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ConfigIncludeLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        node = self.nodes[0]
        included = Path(node.datadir) / "typed-logging-extra.conf"
        included.write_text("uacomment=typed-log-include\n", encoding="utf8")
        with Path(node.bitcoinconf).open("a", encoding="utf8") as config:
            config.write("includeconf=typed-logging-extra.conf\n")
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert "typed-log-include" in node.getnetworkinfo()["subversion"]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        event = next(row for row in rows if row.get("event") == "config_include_loaded")
        assert_equal(event["name"], "typed-logging-extra.conf")
        assert_equal(
            event["message"], "Included configuration file typed-logging-extra.conf"
        )
        assert_equal(event["level"], "info")
        assert "fields_truncated" not in event


if __name__ == "__main__":
    ConfigIncludeLoggingTest().main()
