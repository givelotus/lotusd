#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Load the real upstream AS-map fixture through a path needing fs::quoted."""

import json
import shutil
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

ASMAP_VERSION = "fec61fa21a9f46f3b17bdcd660d7f4cd90b966aad3aec593c99b35f0aca15853"


class ASMapLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json"]]

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        node = self.nodes[0]
        self.asmap_path = Path(node.datadir) / 'asmap&"fixture.raw'
        fixture = Path(__file__).resolve().parents[2] / "src/test/data/asmap.raw"
        shutil.copyfile(fixture, self.asmap_path)
        node.extra_args.append("-asmap=" + str(self.asmap_path))
        self.start_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        opened = events["asmap_file_opened"]
        assert_equal(opened["path"], str(self.asmap_path))
        assert_equal(opened["asmap_length_bytes"], self.asmap_path.stat().st_size)
        assert isinstance(opened["asmap_length_bytes"], int)
        quoted = '"' + str(self.asmap_path).replace("&", "&&").replace('"', '&"') + '"'
        assert_equal(
            opened["message"], f"Opened asmap file {quoted} (59 bytes) from disk"
        )
        selected = events["asmap_version_selected"]
        assert_equal(selected["asmap_hash"], ASMAP_VERSION)
        assert_equal(
            selected["message"], f"Using asmap version {ASMAP_VERSION} for IP bucketing"
        )
        for event in (opened, selected):
            assert_equal(event["level"], "info")
            assert "fields_truncated" not in event


if __name__ == "__main__":
    ASMapLoggingTest().main()
