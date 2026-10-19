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
