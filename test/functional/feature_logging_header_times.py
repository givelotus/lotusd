#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Opt-in header-time persistence handles an owned missing index and truncation."""

import json
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class HeaderTimeLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-persistrecentheaderstime=1"]]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        self.stop_node(0)  # A genesis-only chain cannot provide twenty headers.
        self.start_node(0)
        tip = self.generatetoaddress(
            node, 20, node.get_deterministic_priv_key().address
        )[-1]
        assert_equal(node.getblockcount(), 20)
        self.stop_node(0)
        times = node.chain_path / "headerstime.dat"
        saved = times.read_bytes()
        version, count = struct.unpack("<QQ", saved[:16])
        assert_equal(count, 20)
        assert_equal(len(saved), 16 + 20 * (32 + 8))
        unknown = "34" * 32
        assert unknown != tip
        # Preserve the actual file's version. Only this owned diagnostic file
        # references an unknown index; no block or chainstate is fabricated.
        times.write_bytes(
            struct.pack("<QQ", version, 1) + bytes.fromhex(unknown)[::-1] + b"\0" * 8
        )
        self.start_node(0)
        assert_equal(node.getblockcount(), 20)
        assert_equal(node.getbestblockhash(), tip)
        self.stop_node(0)
        times.write_bytes(b"\1")
        self.start_node(0)
        assert_equal(node.getblockcount(), 20)
        assert_equal(node.getbestblockhash(), tip)
        self.stop_node(0)
        rows = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        events = {row.get("event"): row for row in rows}
        missing = events["header_times_dump_index_missing"]
        assert_equal(missing["count"], 1)
        assert type(missing["count"]) is int
        assert_equal(
            missing["message"],
            "Missing block index, stopping the headers time dumping after 1 blocks.",
        )
        dumped = events["header_times_dumped"]
        assert_equal(dumped["count"], 20)
        assert type(dumped["count"]) is int
        assert_equal(dumped["path"], str(times))
        assert_equal(
            dumped["message"],
            f"Successfully dumped the last 20 headers time to {times}.",
        )
        index = events["header_times_load_index_missing"]
        assert_equal(index["block_hash"], unknown)
        assert_equal(index["count"], 0)
        assert type(index["count"]) is int
        assert_equal(
            index["message"],
            f"Missing index for block {unknown}, stopping the headers time loading after 0 blocks.",
        )
        failed = events["header_times_load_failed"]
        assert isinstance(failed["error"], str) and failed["error"]
        assert_equal(
            failed["message"],
            f"Failed to read the headers time file data on disk: {failed['error']}.",
        )
        for row in (missing, dumped, index, failed):
            assert_equal(row["level"], "info")
            assert "fields_truncated" not in row


if __name__ == "__main__":
    HeaderTimeLoggingTest().main()
