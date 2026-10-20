#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Address/ban database logs preserve recovery, typed values and filesystem quoting."""

import json

from feature_addrman import write_addrman
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def quoted_path(value):
    # Exact fs::quoted convention, including its nonstandard '&' escape.
    return '"' + value.replace("&", "&&").replace('"', '&"') + '"'


class AddressDatabaseLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    disable_autoconnect = False
    extra_args = [["-logformat=json", "-dnsseed=0", "-fixedseeds=0", "-discover=0"]]

    def records(self):
        # All callers stop the node first, so the async worker has flushed.
        return [
            json.loads(line)
            for line in self.nodes[0].debug_log_path.read_text().splitlines()
            if line.strip()
        ]

    def exercise_database_workload(self):
        node = self.nodes[0]
        peers = node.chain_path / "peers.dat"
        banlist = node.chain_path / "banlist.json"
        self.stop_node(0)

        # Exercise legacy format rejection and its existing .bak recovery.
        write_addrman(peers, lowest_compatible=111)
        future_bytes = peers.read_bytes()
        invalid_subnet = 'not&"a_subnet'
        entries = [
            {"version": 2, "address": "192.0.2.0/24", "banned_until": 2**40},
            {"version": 1, "address": invalid_subnet, "banned_until": 2**40},
            {"version": 1, "address": "198.51.100.0/24", "banned_until": 1},
            {"version": 1, "address": "203.0.113.0/24", "banned_until": 2**40},
        ]
        for entry in entries:
            entry["ban_created"] = 0
        banlist.write_text(json.dumps({"banned_nets": entries}))
        self.start_node(0)
        assert_equal(node.getnodeaddresses(), [])
        banned = node.listbanned()
        assert_equal(len(banned), 1)
        assert_equal(banned[0]["address"], "203.0.113.0/24")
        self.stop_node(0)
        assert_equal(peers.with_suffix(".dat.bak").read_bytes(), future_bytes)

        # Invalid JSON exercises ReadSettings' error, then an invalid value
        # type exercises BanMapFromJson's separate caught exception.
        banlist.write_text("{")
        self.start_node(0)
        assert_equal(node.listbanned(), [])
        self.stop_node(0)
        banlist.write_text(json.dumps({"banned_nets": 123}))
        self.start_node(0)
        assert_equal(node.listbanned(), [])

        # Faults affect only this node's owned test files. A nonempty banlist
        # directory prevents WriteSettings; a nonempty peers.dat directory
        # reaches SerializeFileDB's existing rename failure at shutdown.
        banlist.unlink()
        banlist.mkdir()
        ban_blocker = banlist / "owned-test-file"
        ban_blocker.write_text("block write")
        node.setban("192.0.2.1", "add")
        assert_equal(len(node.listbanned()), 1)
        peers.unlink()
        peers.mkdir()
        peer_blocker = peers / "owned-test-file"
        peer_blocker.write_text("block rename")
        self.stop_node(0)
        ban_blocker.unlink()
        banlist.rmdir()
        peer_blocker.unlink()
        peers.rmdir()
        return peers, banlist, invalid_subnet

    def run_test(self):
        # The whole workload runs before schema assertions, so the same test
        # against the old binary is a meaningful before control for recovery.
        peers, banlist, invalid_subnet = self.exercise_database_workload()
        records = self.records()

        def event(name):
            return next(row for row in records if row.get("event") == name)

        missing = event("address_database_file_missing")
        assert_equal(missing["path"], str(peers))
        assert_equal(
            missing["message"],
            f"Creating peers.dat because the file was not found ({quoted_path(str(peers))})",
        )
        legacy = event("ban_database_legacy_file_unavailable")
        legacy_path = str(banlist.with_suffix(".dat"))
        assert_equal(legacy["path"], legacy_path)
        assert_equal(
            legacy["message"], f"Missing or invalid file {quoted_path(legacy_path)}"
        )
        future = event("address_database_version_unsupported")
        assert_equal(future["path"], str(peers))
        assert_equal(
            future["message"],
            "Creating new peers.dat because the file version was not compatible "
            f"({quoted_path(str(peers))}). Original backed up to peers.dat.bak",
        )
        loaded = event("address_database_loaded")
        assert type(loaded["count"]) is int
        assert_equal(loaded["count"], 0)
        assert type(loaded["database_operation_ms"]) is int
        assert_equal(
            loaded["message"],
            f"Loaded 0 addresses from peers.dat  {loaded['database_operation_ms']}ms",
        )
        anchors = event("anchor_database_loaded")
        assert_equal(anchors["count"], 0)
        assert_equal(anchors["name"], "anchors.dat")
        assert "path" not in anchors  # Filename is not claimed to be a full path.
        assert_equal(anchors["message"], 'Loaded 0 addresses from "anchors.dat"')
        version = event("ban_database_entry_version_unsupported")
        assert type(version["version"]) is int
        assert_equal(version["version"], 2)
        assert_equal(
            version["message"], "Dropping entry with unknown version (2) from ban list"
        )
        invalid = event("ban_database_entry_subnet_invalid")
        assert_equal(invalid["subnet"], invalid_subnet)
        assert_equal(
            invalid["message"],
            f"Dropping entry with unparseable address or subnet ({invalid_subnet}) from ban list",
        )
        removed = event("ban_database_entry_removed")
        assert_equal(removed["subnet"], "198.51.100.0/24")
        assert_equal(removed["level"], "debug")
        assert_equal(removed["category"], "net")
        assert_equal(
            removed["message"], "Removed banned node address/subnet: 198.51.100.0/24"
        )
        for name, prefix in (
            ("ban_database_loaded", "Loaded"),
            ("ban_database_flush_finished", "Flushed"),
        ):
            row = event(name)
            assert type(row["count"]) is int
            assert type(row["database_operation_ms"]) is int
            assert row["message"].startswith(f"{prefix} {row['count']} banned node")
            assert row["message"].endswith(f"  {row['database_operation_ms']}ms")
            assert_equal(row["level"], "debug")
            assert_equal(row["category"], "net")
        assert_equal(event("ban_database_recreated")["level"], "info")
        for name, prefix in (
            ("ban_database_load_failed", "Cannot load banlist"),
            ("ban_database_parse_failed", "Cannot parse banlist"),
        ):
            row = event(name)
            assert_equal(row["path"], str(banlist))
            assert isinstance(row["error"], str) and row["error"]
            assert_equal(row["message"], f"{prefix} {banlist}: {row['error']}")
            assert_equal(row["level"], "info")
        write = event("ban_database_write_failed")
        assert_equal(write["level"], "error")
        assert isinstance(write["error"], str) and write["error"]
        assert_equal(write["message"], write["error"])
        rename = event("address_database_rename_failed")
        assert_equal(rename["level"], "error")
        assert_equal(rename["source_function"], "SerializeFileDB")
        assert_equal(rename["message"], "SerializeFileDB: Rename-into-place failed")
        assert all(
            "fields_truncated" not in row
            for row in records
            if row.get("event", "").startswith(
                ("ban_database_", "address_database_", "anchor_database_")
            )
        )


if __name__ == "__main__":
    AddressDatabaseLoggingTest().main()
