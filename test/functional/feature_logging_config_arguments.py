#!/usr/bin/env python3
# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Configuration diagnostics keep their displayed strings and typed option names."""

import json

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ConfigArgumentLoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True
    wallet_names = []
    extra_args = [["-logformat=json", "-noblocksonly=0"]]

    def run_test(self):
        node = self.nodes[0]
        # Complete a harmless restart with an unknown persistent setting before
        # typed-schema checks. The unknown key must retain its normal behavior.
        assert_equal(node.getnetworkinfo()["networkactive"], True)
        self.stop_node(0)
        settings = node.chain_path / "settings.json"
        settings.write_text(json.dumps({"unknown-logging-fixture": "safe"}))
        self.start_node(0)
        assert_equal(node.getnetworkinfo()["networkactive"], True)
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_path.read_text().splitlines()
            if line.strip()
        ]
        double = next(
            row
            for row in records
            if row.get("event") == "config_double_negative_interpreted"
        )
        assert_equal(double["config_option"], "blocksonly")
        assert_equal(double["value"], "0")
        assert_equal(double["level"], "info")
        assert_equal(
            double["message"],
            "Warning: parsed potentially confusing double-negative -blocksonly=0",
        )
        arguments = [
            row for row in records if row.get("event") == "config_argument_displayed"
        ]
        assert arguments
        for row in arguments:
            for name in (
                "log_prefix",
                "config_section_prefix",
                "config_option",
                "value",
            ):
                assert type(row[name]) is str
            assert_equal(
                row["message"],
                f"{row['log_prefix']} {row['config_section_prefix']}"
                f"{row['config_option']}={row['value']}",
            )
            assert_equal(row["level"], "info")
        unknown = next(
            row
            for row in records
            if row.get("event") == "config_settings_option_unknown"
        )
        assert_equal(unknown["config_option"], "unknown-logging-fixture")
        displayed = next(
            row
            for row in records
            if row.get("event") == "config_settings_argument_displayed"
            and row.get("config_option") == "unknown-logging-fixture"
        )
        assert_equal(displayed["value"], '"safe"')
        assert_equal(
            displayed["message"],
            'Setting file arg: unknown-logging-fixture = "safe"',
        )


if __name__ == "__main__":
    ConfigArgumentLoggingTest().main()
