#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Address-manager events retain bucket types and persistence behavior."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AddrmanLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-debug=addrman"]]

    def run_test(self):
        node = self.nodes[0]
        address, port = "250.1.1.1", 10605
        assert_equal(node.addpeeraddress(address, port, True), {"success": True})
        peers = node.getnodeaddresses(count=0)
        assert_equal(len(peers), 1)
        assert_equal((peers[0]["address"], peers[0]["port"]), (address, port))
        self.restart_node(0)
        peers = node.getnodeaddresses(count=0)
        assert_equal(len(peers), 1)
        assert_equal((peers[0]["address"], peers[0]["port"]), (address, port))
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        endpoint = f"{address}:{port}"
        added = next(
            row for row in records if row.get("event") == "addrman_address_added_new"
        )
        assert_equal(added["addr"], endpoint)
        assert_equal(added["mapped_as"], 0)
        for field in ("new_bucket_index", "new_bucket_position"):
            assert type(added[field]) is int and added[field] >= 0
        assert_equal(
            added["message"],
            f"Added {endpoint} mapped to AS0 to "
            f"new[{added['new_bucket_index']}][{added['new_bucket_position']}]",
        )
        counts = next(
            row for row in records if row.get("event") == "addrman_addresses_added"
        )
        assert_equal(counts["addr"], address)
        for field, expected in (
            ("count", 1),
            ("candidate_count", 1),
            ("tried_address_count", 0),
            ("new_address_count", 1),
        ):
            assert type(counts[field]) is int
            assert_equal(counts[field], expected)
        moved = next(
            row for row in records if row.get("event") == "addrman_address_moved_tried"
        )
        assert_equal(moved["addr"], endpoint)
        assert_equal(moved["mapped_as"], 0)
        for field in ("tried_bucket_index", "tried_bucket_position"):
            assert type(moved[field]) is int and moved[field] >= 0
        returned = [
            row
            for row in records
            if row.get("event") == "addrman_getaddr_finished" and row["count"] == 1
        ]
        assert len(returned) >= 2
        for row in (added, counts, moved, *returned):
            assert_equal(row["level"], "debug")
            assert_equal(row["category"], "addrman")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    AddrmanLoggingTest().main()
