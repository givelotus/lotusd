# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test debug logging."""

import json
import os
import shlex
import socket
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


class LoggingTest(BitcoinTestFramework):
    num_nodes = 1
    setup_clean_chain = True

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
        self.test_logfmt_format()
        self.test_gcp_format()
        self.test_ecs_format()
        self.test_syslog_format()
        self.test_text_priority()
        self.test_json_aux_only()
        self.test_framework_fields()

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

    def test_logfmt_format(self):
        self.log.info("Test -logformat=logfmt through the actual file sink")
        self.restart_node(
            0, ["-logformat=logfmt", "-debuglogfile=logfmt.log", "-logsourcelocations"]
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        records = []
        with open(self.relative_log_path("logfmt.log"), encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    records.append(
                        dict(word.split("=", 1) for word in shlex.split(line))
                    )
        assert len(records) > 20
        for record in records:
            assert set(record) >= {
                "time",
                "level",
                "category",
                "thread",
                "message",
                "source_file",
                "source_line",
                "source_function",
            }, record
            assert record["source_line"].isdigit(), record
        assert any(record["message"].startswith("Lotus version") for record in records)

    def test_gcp_format(self):
        self.restart_node(
            0, ["-logformat=json-gcp", "-debuglogfile=gcp.log", "-logsourcelocations"]
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        with open(self.relative_log_path("gcp.log"), encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        assert len(records) > 20
        for record in records:
            assert record["severity"] in {"DEBUG", "INFO", "WARNING", "ERROR"}
            assert "level" not in record
            assert isinstance(record["time"], str)
            location = record["logging.googleapis.com/sourceLocation"]
            assert set(location) == {"file", "line", "function"}
            assert isinstance(location["line"], str)
        assert any(record["message"].startswith("Lotus version") for record in records)

    def test_ecs_format(self):
        self.restart_node(
            0,
            [
                "-logformat=json-ecs",
                "-debuglogfile=ecs.log",
                "-logsourcelocations",
                "-logtimestamps=0",
            ],
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        with open(self.relative_log_path("ecs.log"), encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        assert len(records) > 20
        for record in records:
            assert record["ecs.version"] == "8.11.0"
            assert isinstance(record["@timestamp"], str)
            assert set(record) >= {
                "log.level",
                "log.logger",
                "message",
                "process.thread.name",
                "log.origin.file.name",
                "log.origin.file.line",
                "log.origin.function",
            }
            assert isinstance(record["log.origin.file.line"], int)
            assert "source" not in record
        assert any(record["message"].startswith("Lotus version") for record in records)

    def test_syslog_format(self):
        self.log.info("Test RFC 5424 file output")
        self.restart_node(
            0,
            [
                "-logformat=syslog",
                "-debuglogfile=syslog.log",
                "-logsourcelocations",
            ],
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        records = []
        with open(self.relative_log_path("syslog.log"), encoding="utf-8") as stream:
            for line in filter(str.strip, stream):
                header, payload = line.split("\ufeff", 1)
                fields = header.split()
                assert fields[0] in ("<27>1", "<28>1", "<30>1", "<31>1")
                assert len(fields) == 7
                assert fields[2:] == ["-"] * 5
                records.append(json.loads(payload))
        assert len(records) > 20
        assert any(record["message"].startswith("Lotus version") for record in records)
        assert any(record["message"] == "Shutdown: done" for record in records)

    def test_text_priority(self):
        self.log.info("Test opt-in text priority prefix")
        self.restart_node(
            0,
            [
                "-logformat=text",
                "-logtextpriority",
                "-debuglogfile=priority.log",
            ],
        )
        self.generate(self.nodes[0], 1)
        self.stop_node(0)
        with open(self.relative_log_path("priority.log"), encoding="utf-8") as stream:
            lines = [line for line in stream if line.strip()]
        assert len(lines) > 20
        assert all(line[:3] in ("<3>", "<4>", "<6>", "<7>") for line in lines)
        assert any(
            line.startswith("<6>") and "Shutdown: done" in line for line in lines
        )
        self.restart_node(0, ["-logformat=text", "-debuglogfile=priority-default.log"])
        self.stop_node(0)
        with open(
            self.relative_log_path("priority-default.log"), encoding="utf-8"
        ) as stream:
            lines = [line for line in stream if line.strip()]
        assert lines and all(not line.startswith("<") for line in lines)

    def test_json_aux_only(self):
        self.log.info("An auxiliary JSON sink keeps logging enabled on its own")
        path = self.relative_log_path("aux-only.jsonl")
        self.stop_node(0)
        default_log = self.relative_log_path("debug.log")
        if os.path.exists(default_log):
            os.unlink(default_log)
        self.start_node(
            0,
            [
                "-nodebuglogfile",
                "-printtoconsole=0",
                f"-debuglogjsonfile={path}",
            ],
        )
        height = self.nodes[0].getblockcount() + 1
        with self.nodes[0].assert_debug_log(
            [
                {"source": {"function": "UpdateTipLog"}},
            ]
        ):
            self.generate(self.nodes[0], 1)
        self.stop_node(0)
        assert not os.path.exists(default_log)
        with open(path, encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        assert any(
            "UpdateTip: new best=" in record["message"]
            and f"height={height} " in record["message"]
            for record in records
        )
        assert any(record["message"] == "Shutdown: done" for record in records)

    def test_framework_fields(self):
        self.log.info("Framework dictionary matching and final drop counter")
        self.restart_node(0, [])
        node = self.nodes[0]
        with node.assert_debug_log(
            [
                {"source": {"file": "src/validation.cpp", "function": "UpdateTipLog"}},
                "UpdateTip: new best=",
            ]
        ):
            self.generate(node, 1)
        with node.wait_for_debug_log(
            [
                {"source": {"function": "UpdateTipLog"}},
                b"UpdateTip: new best=",
            ]
        ):
            self.generate(node, 1)
        self.stop_node(0)
        records = [
            json.loads(line)
            for line in node.debug_log_json_path.read_text().splitlines()
        ]
        summaries = [r for r in records if r.get("event") == "logger_shutdown"]
        assert summaries and summaries[-1]["dropped_lines"] == 0

    def test_json_format(self):
        self.log.info("Test -logformat=json")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            ["-logformat=xml"],
            "Error: Invalid -logformat 'xml' (valid values: text, logfmt, json, json-gcp, json-ecs, syslog"
            + (", journald" if sys.platform == "linux" else "")
            + ")",
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
                "time",
                "level",
                "category",
                "thread",
                "message",
                "source",
            }, r
            assert set(r["source"]) == {"file", "line", "function"}, r
            assert r["level"] in ("trace", "debug", "info", "warning", "error")
            assert isinstance(r["source"]["line"], int)
            # The bare name: no return type, no parameters
            function = r["source"]["function"]
            assert not function.startswith(("void ", "bool ", "static ")), r
            assert function.endswith("operator()") or not function.endswith(")"), r
            assert not r["message"].endswith("\n")
        msgs = [r["message"] for r in records]
        # Lines logged before the log file was opened are buffered and
        # written in the selected format too.
        assert any(m.startswith("Lotus version") for m in msgs)
        assert any("UpdateTip: new best=" in m and "height=1 " in m for m in msgs)
        assert any(r["category"] == "net" and r["level"] == "debug" for r in records)
        assert any(r["thread"] == "init" for r in records)
        # Source files are relative to the source tree (compile-time
        # -fmacro-prefix-map), like "src/init.cpp".
        assert any(r["source"]["file"] == "src/init.cpp" for r in records)
        assert all(not os.path.isabs(r["source"]["file"]) for r in records)
        self.assert_no_absolute_source_paths(json_log_path)
        assert any(r["category"] == "none" and r["level"] == "info" for r in records)

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
                if r["message"].startswith("Error: Unable to bind")
            ]
        assert_equal(len(errors), 1)
        assert_equal(errors[0]["level"], "error")


if __name__ == "__main__":
    LoggingTest().main()
