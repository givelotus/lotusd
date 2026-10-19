# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_framework.test_node import TestNode


class AsyncLogDeadlineTests(unittest.TestCase):
    def exercise(self, helper, messages):
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / "debug.log"
            logfile.touch()
            clock = [0.0]

            def fail(message):
                raise AssertionError(message)

            node = SimpleNamespace(
                timeout_factor=1,
                debug_log_path=logfile,
                debug_log_size=lambda **kwargs: logfile.stat().st_size,
                _raise_assertion_error=fail,
            )

            def drain(_interval):
                logfile.write_text("expected asynchronous line\n")
                clock[0] += 0.05

            with (
                patch("test_framework.test_node.time.time", lambda: clock[0]),
                patch("test_framework.test_node.time.sleep", drain),
            ):
                with helper(node, messages, timeout=2):
                    # The action takes longer than the logging wait budget.
                    # The logger drains only after the action returns.
                    clock[0] = 3.0

    def test_assert_deadline_starts_after_action(self):
        self.exercise(TestNode.assert_debug_log, ["expected asynchronous line"])

    def test_wait_deadline_starts_after_action(self):
        self.exercise(TestNode.wait_for_debug_log, [b"expected asynchronous line"])


class StructuredLogTests(unittest.TestCase):
    def test_nested_fields_match_one_record(self):
        from test_framework.log_messages import has_message

        self.assertTrue(
            has_message(
                {"source": {"line": 7}},
                "",
                [{"source": {"line": 7, "file": "net.cpp"}}],
            )
        )
        self.assertFalse(
            has_message(
                {"peer_id": 7, "bytes": 42}, "", [{"peer_id": 7}, {"bytes": 42}]
            )
        )
        self.assertFalse(has_message({"peer_id": 1}, "", [{"peer_id": True}]))

    def test_complete_json_lines_only(self):
        from test_framework.log_messages import read_records

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_bytes(b'{"height":7}\n{"height":')
            self.assertEqual(read_records(path), [{"height": 7}])
            path.write_bytes(b"not-json\n")
            with self.assertRaises(ValueError):
                read_records(path)

    def test_drop_check_lifetimes_and_missing_counter(self):
        from test_framework.log_messages import assert_no_drops

        with self.assertRaisesRegex(AssertionError, "Missing logger_shutdown"):
            assert_no_drops([], require_summary=True)
        with self.assertRaisesRegex(AssertionError, "dropped 3"):
            assert_no_drops([{"event": "logger_shutdown", "dropped_lines": 3}])
        with self.assertRaisesRegex(AssertionError, "Invalid"):
            assert_no_drops([{"event": "logger_shutdown", "dropped_lines": False}])
        with self.assertRaisesRegex(AssertionError, "Logger dropped lines"):
            assert_no_drops(
                [
                    {
                        "message": "Logging could not keep up: 2 debug/info log lines were dropped (2 in total)."
                    }
                ]
            )
        assert_no_drops(
            [{"event": "logger_shutdown", "dropped_lines": 0}], require_summary=True
        )
        assert_no_drops(
            [], require_summary=False
        )  # An expected crash cannot report a final counter.

    def test_process_offset_excludes_earlier_drops(self):
        from test_framework.log_messages import assert_no_drops, read_records

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_text('{"event":"logger_shutdown","dropped_lines":10}\n')
            start = path.stat().st_size
            with path.open("a") as stream:
                stream.write('{"event":"logger_shutdown","dropped_lines":0}\n')
            assert_no_drops(read_records(path, start), require_summary=True)

    def exercise(self, helper, expected):
        with tempfile.TemporaryDirectory() as directory:
            text = Path(directory) / "debug.log"
            records = Path(directory) / "debug-framework.jsonl"
            text.touch()
            records.touch()

            def fail(message):
                raise AssertionError(message)

            node = SimpleNamespace(
                timeout_factor=1,
                debug_log_path=text,
                debug_log_json_path=records,
                debug_log_size=lambda **kwargs: text.stat().st_size,
                _raise_assertion_error=fail,
            )
            with helper(node, expected):
                text.write_text("historical human message\n")
                records.write_text(
                    '{"event":"peer_connected","peer_id":7,"source":{"file":"net.cpp","line":42}}\n'
                )

    def test_assert_accepts_fields_and_substring(self):
        self.exercise(
            TestNode.assert_debug_log,
            [
                "historical human message",
                {"event": "peer_connected", "peer_id": 7, "source": {"line": 42}},
            ],
        )

    def test_wait_accepts_fields_and_bytes(self):
        self.exercise(
            TestNode.wait_for_debug_log, [b"historical human message", {"peer_id": 7}]
        )


class StructuredLogPathTests(unittest.TestCase):
    def exercise(self, helper):
        with tempfile.TemporaryDirectory() as directory:
            text = Path(directory) / "debug.log"
            text.touch()
            old = Path(directory) / "old.jsonl"
            old.write_text('{"message":"earlier process"}\n' * 20)
            new = Path(directory) / "new.jsonl"

            def fail(message):
                raise AssertionError(message)

            node = SimpleNamespace(
                timeout_factor=1,
                debug_log_path=text,
                debug_log_json_path=old,
                debug_log_size=lambda **kwargs: 0,
                _raise_assertion_error=fail,
            )
            with helper(node, [{"event": "startup"}], timeout=0):
                # Starting a node with an explicit sidecar path updates it
                # during the context. The previous file's offset cannot apply.
                node.debug_log_json_path = new
                new.write_text('{"event":"startup"}\n')

    def test_assert_matches_new_process_path(self):
        self.exercise(TestNode.assert_debug_log)

    def test_wait_matches_new_process_path(self):
        self.exercise(TestNode.wait_for_debug_log)


class StructuredLogWithoutTextTests(unittest.TestCase):
    def exercise(self, helper):
        with tempfile.TemporaryDirectory() as directory:
            text = Path(directory) / "debug.log"  # Deliberately never created.
            records = Path(directory) / "debug-framework.jsonl"

            def fail(message):
                raise AssertionError(message)

            node = SimpleNamespace(
                timeout_factor=1,
                debug_log_path=text,
                debug_log_json_path=records,
                _raise_assertion_error=fail,
            )
            node.debug_log_size = lambda **kwargs: TestNode.debug_log_size(
                node, **kwargs
            )
            with helper(node, [{"event": "json_only"}], timeout=0):
                records.write_text('{"event":"json_only"}\n')

    def test_assert_uses_json_without_text_file(self):
        self.exercise(TestNode.assert_debug_log)

    def test_wait_uses_json_without_text_file(self):
        self.exercise(TestNode.wait_for_debug_log)


class AsyncLogBoundaryTests(unittest.TestCase):
    def fixture(self, helper, *, expect_stale=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "debug.log"
            path.touch()
            calls = []

            def append(message):
                with path.open("a") as stream:
                    stream.write(message + "\n")

            def flush():
                calls.append(True)
                append("stale forbidden message")

            def fail(message):
                raise AssertionError(message)

            node = SimpleNamespace(
                timeout_factor=1,
                debug_log_path=path,
                debug_log_size=lambda **kwargs: path.stat().st_size,
                _raise_assertion_error=fail,
                rpc_connected=True,
                rpc=SimpleNamespace(logging=flush),
            )
            expected = [b"stale forbidden message"] if expect_stale else ["new action"]
            kwargs = {} if expect_stale else {"unexpected_msgs": ["stale forbidden"]}
            with helper(node, expected, timeout=0, **kwargs):
                # Without the entry barrier, the previous action's queued
                # message becomes visible inside this action's capture.
                if not calls:
                    append("stale forbidden message")
                if not expect_stale:
                    append("new action")
            self.assertEqual(calls, [True])

    def test_assert_excludes_previous_action(self):
        self.fixture(TestNode.assert_debug_log)

    def test_wait_does_not_match_previous_action(self):
        with self.assertRaisesRegex(AssertionError, "[Mm]issing"):
            self.fixture(TestNode.wait_for_debug_log, expect_stale=True)


if __name__ == "__main__":
    unittest.main()
