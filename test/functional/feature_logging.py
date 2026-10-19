# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test debug logging."""

import json
import os
import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class LoggingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def relative_log_path(self, name):
        return os.path.join(self.nodes[0].datadir, self.chain, name)

    def run_test(self):
        # test default log file name
        default_log_path = self.relative_log_path("debug.log")
        assert os.path.isfile(default_log_path)
        # The test framework runs nodes with -logthreadnames: lines name
        # their thread.
        with open(default_log_path, encoding="utf-8") as f:
            assert any("Z [init] " in line for line in f)

        # test alternative log file name in datadir
        self.restart_node(0, ["-debuglogfile=foo.log"])
        assert os.path.isfile(self.relative_log_path("foo.log"))

        # test alternative log file name outside datadir
        tempname = os.path.join(self.options.tmpdir, "foo.log")
        self.restart_node(0, [f"-debuglogfile={tempname}"])
        assert os.path.isfile(tempname)

        # check that invalid log (relative) will cause error
        invdir = self.relative_log_path("foo")
        invalidname = os.path.join("foo", "foo.log")
        self.stop_node(0)
        exp_stderr = r"Error: Could not open debug log file \S+$"
        self.nodes[0].assert_start_raises_init_error(
            [f"-debuglogfile={invalidname}"], exp_stderr, match=ErrorMatch.FULL_REGEX
        )
        assert not os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (relative) works after path exists
        self.stop_node(0)
        os.mkdir(invdir)
        self.start_node(0, [f"-debuglogfile={invalidname}"])
        assert os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (absolute) will cause error
        self.stop_node(0)
        invdir = os.path.join(self.options.tmpdir, "foo")
        invalidname = os.path.join(invdir, "foo.log")
        self.nodes[0].assert_start_raises_init_error(
            [f"-debuglogfile={invalidname}"], exp_stderr, match=ErrorMatch.FULL_REGEX
        )
        assert not os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that invalid log (absolute) works after path exists
        self.stop_node(0)
        os.mkdir(invdir)
        self.start_node(0, [f"-debuglogfile={invalidname}"])
        assert os.path.isfile(os.path.join(invdir, "foo.log"))

        # check that -nodebuglogfile disables logging
        self.stop_node(0)
        os.unlink(default_log_path)
        assert not os.path.isfile(default_log_path)
        self.start_node(0, ["-nodebuglogfile"])
        assert not os.path.isfile(default_log_path)

        # just sanity check no crash here
        self.restart_node(0, [f"-debuglogfile={os.devnull}"])

        self.test_text_source_locations()
        self.test_json_format()

    def assert_no_absolute_source_paths(self, log_path):
        src = os.path.join(self.config["environment"]["SRCDIR"], "src") + os.sep
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                assert src not in line, line

    def test_text_source_locations(self):
        self.log.info("-logsourcelocations shows source-relative paths")
        self.restart_node(0, ["-logsourcelocations", "-debuglogfile=src.log"])
        self.stop_node(0)
        log_path = self.relative_log_path("src.log")
        self.assert_no_absolute_source_paths(log_path)
        with open(log_path, encoding="utf-8") as f:
            assert any("[src/init.cpp:" in line for line in f)

    def test_json_format(self):
        self.log.info("Test -logformat=json")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-logformat=xml"],
            "Error: Invalid -logformat 'xml' (valid values: text, json)",
        )
        json_log_path = self.relative_log_path("json.log")
        self.start_node(
            0,
            [
                "-logformat=json",
                "-debuglogfile=json.log",
                "-debug=net",
                "-logsourcelocations",
            ],
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        records = []
        with open(json_log_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    # Every line is one JSON object
                    records.append(json.loads(line))
        assert len(records) > 20
        for r in records:
            assert set(r) >= {
                "ts",
                "level",
                "category",
                "thread",
                "file",
                "line",
                "func",
                "msg",
            }, r
            assert r["level"] in ("trace", "debug", "info", "warning", "error")
            assert isinstance(r["line"], int)
            assert not r["msg"].endswith("\n")
        msgs = [r["msg"] for r in records]
        # Lines logged before the log file was opened are buffered and
        # written in the selected format too.
        assert any(m.startswith("Bitcoin ABC version") for m in msgs)
        assert any("UpdateTip: new best=" in m and "height=1 " in m for m in msgs)
        assert any(r["category"] == "net" and r["level"] == "debug" for r in records)
        assert any(r["thread"] == "init" for r in records)
        # Source files are relative to the source tree (compile-time
        # -fmacro-prefix-map), like "src/init.cpp".
        assert any(r["file"] == "src/init.cpp" for r in records)
        assert all(not os.path.isabs(r["file"]) for r in records)
        self.assert_no_absolute_source_paths(json_log_path)
        assert any(
            r["category"] == "none" and r["level"] == "info" for r in records
        )

        self.log.info("Init errors are logged at error level")
        # An error after the log file is open: the P2P port is taken.
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        self.nodes[0].assert_start_raises_init_error(
            [
                "-logformat=json",
                "-debuglogfile=err.log",
                "-listen=1",
                f"-bind=127.0.0.1:{port}",
            ],
            match=ErrorMatch.PARTIAL_REGEX,
            expected_msg="Error: Unable to bind to 127.0.0.1:",
        )
        busy.close()
        with open(self.relative_log_path("err.log"), encoding="utf-8") as f:
            errors = [
                r
                for r in map(json.loads, filter(str.strip, f))
                if r["msg"].startswith("Error: Unable to bind")
            ]
        assert_equal(len(errors), 1)
        assert_equal(errors[0]["level"], "error")


if __name__ == "__main__":
    LoggingTest().main()
