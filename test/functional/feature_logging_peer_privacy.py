#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Real outbound handshakes keep logips privacy in typed fields and text."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class PeerPrivacyLoggingTest(BitcoinTestFramework):
    num_nodes = 2
    setup_clean_chain = True
    topology = "none"
    wallet_names = []
    extra_args = [
        ["-logformat=json", "-logips=0"],
        ["-logformat=json", "-logips=0"],
    ]

    def run_test(self):
        expected = []
        for logips in (False, True):
            if logips:
                self.start_nodes(
                    [
                        ["-logformat=json", "-logips=1"],
                        ["-logformat=json", "-logips=0"],
                    ]
                )
            self.connect_nodes(0, 1)
            peers = [p for p in self.nodes[0].getpeerinfo() if not p["inbound"]]
            assert_equal(len(peers), 1)
            expected.append(peers[0])
            for node in self.nodes:
                assert_equal(node.getblockcount(), 0)
            self.stop_nodes()
        by_event = {}
        for line in self.nodes[0].debug_log_path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                by_event.setdefault(row.get("event"), []).append(row)
        rows = by_event["peer_outbound_connected"]
        assert_equal(len(rows), 2)
        for row, peer, logips in zip(rows, expected, (False, True), strict=True):
            for field in ("version", "height", "peer_id"):
                assert type(row[field]) is int
            assert_equal(row["version"], peer["version"])
            assert_equal(row["height"], peer["startingheight"])
            assert_equal(row["peer_id"], peer["id"])
            assert_equal(row["conn_type"], peer["connection_type"])
            suffix = f", peeraddr={peer['addr']}" if logips else ""
            assert_equal(row["peer_address_suffix"], suffix)
            assert_equal(row["addr"], peer["addr"] if logips else "")
            assert_equal(
                row["message"],
                f"New outbound peer connected: version: {peer['version']}, "
                f"blocks={peer['startingheight']}, peer={peer['id']}{suffix} "
                f"({peer['connection_type']})",
            )
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row
            if not logips:
                assert peer["addr"] not in json.dumps(row)
                assert "peeraddr=" not in row["message"]


if __name__ == "__main__":
    PeerPrivacyLoggingTest().main()
