#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""How test_runner.py reports test jobs: console lines, failure details,
the end-of-run summary and JSON lines (see README-runner-output.md)."""

import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from collections import deque
from typing import IO, Any, Dict, Iterable, List, Optional

from .results import FAILED, PASSED, SKIPPED, JobResult, parse_job_name

GLYPHS = {PASSED: "✓", SKIPPED: "○"}

# Lines of the framework log and of each node's log shown for a failure
FRAMEWORK_LOG_LINES = 40
NODE_LOG_LINES = 20
NODE_LOG_PATTERN = re.compile(r"\b(warning|error)\b", re.IGNORECASE)
# Where the framework logs the exception that failed the test; the failure
# block shows the traceback once, then the log lines leading up to it
FRAMEWORK_LOG_FAILURE = re.compile(
    r"TestFramework \(ERROR\): (Unexpected exception|Called Process failed)"
)


def glyph(status: str) -> str:
    return GLYPHS.get(status, "✖")


def finish_line(result: JobResult) -> str:
    """One line for a finished test."""
    line = f"{glyph(result.status)} {result.name}  {result.duration:.0f} s"
    if result.status not in (PASSED, SKIPPED, FAILED):
        line += f"  ({result.status})"
    if result.status == SKIPPED and result.skip_reason:
        line += f"  (skipped: {result.skip_reason})"
    return line


def last_lines(path: str, count: int, pattern=None, stop=None) -> List[str]:
    """The last `count` lines of a file (matching `pattern`, if given), up to
    the first line matching `stop`, if given."""
    try:
        with open(path, encoding="utf8", errors="replace") as f:
            lines = []
            for line in f:
                if stop and stop.search(line):
                    break
                if not pattern or pattern.search(line):
                    lines.append(line.rstrip("\n"))
            return list(deque(lines, count))
    except OSError:
        return []


def rerun_command(result: JobResult, tests_dir: str) -> str:
    """The command that runs this test job again on its own."""
    _, variant, args = parse_job_name(result.name)
    if variant:
        args = [f"--variant={variant}"] + args
    return " ".join([os.path.join(tests_dir, result.file)] + args + ["--nocleanup"])


def failure_block(result: JobResult, tests_dir: str) -> str:
    """What a developer needs to look into a failed test."""
    out = [f"✖ {result.name} {result.status} after {result.duration:.0f} s"]
    failure = result.failure or {}
    if failure.get("traceback"):
        out += ["", failure["traceback"].rstrip()]
    elif failure.get("message"):
        out += ["", failure["message"]]
    if result.stderr_tail and failure.get("type") != "stderr":
        out += ["", "stderr (last lines):"] + result.stderr_tail.splitlines()[-40:]
    stop = FRAMEWORK_LOG_FAILURE if failure.get("traceback") else None
    framework_log = last_lines(result.framework_log, FRAMEWORK_LOG_LINES, stop=stop)
    if framework_log:
        where = "before the failure" if stop else "last"
        out += ["", f"{result.framework_log} ({len(framework_log)} lines {where}):"]
        out += framework_log
    for log in result.node_logs:
        lines = last_lines(log, NODE_LOG_LINES, NODE_LOG_PATTERN)
        if lines:
            out += ["", f"{log} (last {len(lines)} warnings/errors):"] + lines
    out += ["", f"Test directory: {result.tmpdir}"]
    out += [f"Rerun: {rerun_command(result, tests_dir)}"]
    combine = os.path.join(tests_dir, "combine_logs.py")
    out += [f"Logs:  {combine} '{result.tmpdir}'"]
    return "\n".join(out)


def summary(results: Iterable[JobResult], tests_dir: str, slowest: int = 10) -> str:
    """Slowest tests and every failure, for the end of the run."""
    results = list(results)
    out = []
    timed = sorted(
        (r for r in results if r.status != SKIPPED),
        key=lambda r: r.duration,
        reverse=True,
    )[:slowest]
    if timed:
        out.append(f"Slowest {len(timed)} tests:")
        out += [f"  {r.duration:7.1f} s  {r.name}" for r in timed]
    failed = [r for r in results if not r.was_successful]
    if failed:
        out.append(f"{len(failed)} failed:")
        for r in sorted(failed, key=lambda r: r.name):
            out.append(f"  {r.name} ({r.status})")
            out.append(f"    rerun: {rerun_command(r, tests_dir)}")
    return "\n".join(out)


class StatusLine:
    """A single updating line on a terminal: progress, failures and the
    tests still running."""

    def __init__(self, stream: IO[str], total: int):
        self.stream = stream
        self.total = total
        self.enabled = stream.isatty()
        self.shown = False

    def show(self, done: int, failed: int, running: List[str]):
        if not self.enabled:
            return
        width = shutil.get_terminal_size((100, 20)).columns
        line = f"[{done}/{self.total}] failed={failed} running: {', '.join(running)}"
        if len(line) > width - 1:
            line = line[: width - 2] + "…"
        self.stream.write("\r\x1b[2K" + line)
        self.stream.flush()
        self.shown = True

    def clear(self):
        if self.shown:
            self.stream.write("\r\x1b[2K")
            self.stream.flush()
            self.shown = False


class JsonLines:
    """Writes one JSON object per event to a file."""

    def __init__(self, stream: IO[str]):
        self.stream = stream

    def write(self, event: str, **fields):
        fields.update({"event": event, "schema": 1})
        self.stream.write(json.dumps(fields, sort_keys=True) + "\n")
        self.stream.flush()


def open_jsonl(path: Optional[str]) -> Optional[JsonLines]:
    if path is None:
        return None
    if path == "-":
        return JsonLines(sys.stdout)
    return JsonLines(open(path, "w", encoding="utf8"))


class TestReporting(unittest.TestCase):
    def make_result(self, **kwargs):
        fields: Dict[str, Any] = {
            "name": "x_test.py --opt",
            "file": "x_test.py",
            "status": FAILED,
        }
        fields.update(kwargs)
        return JobResult(**fields)

    def test_finish_line(self):
        self.assertEqual(
            finish_line(self.make_result(status=PASSED, duration=3.2)),
            "✓ x_test.py --opt  3 s",
        )
        self.assertIn(
            "(skipped: no wallet)",
            finish_line(self.make_result(status=SKIPPED, skip_reason="no wallet")),
        )
        self.assertIn("(timeout)", finish_line(self.make_result(status="timeout")))

    def test_failure_block(self):
        tmpdir = tempfile.mkdtemp(prefix="reporting_unit_")
        self.addCleanup(shutil.rmtree, tmpdir)
        framework_log = os.path.join(tmpdir, "test_framework.log")
        with open(framework_log, "w", encoding="utf8") as f:
            f.write("".join(f"line {i}\n" for i in range(100)))
            f.write("TestFramework (ERROR): Unexpected exception\nTB again\n")
        node_log = os.path.join(tmpdir, "node0", "regtest", "debug.log")
        os.makedirs(os.path.dirname(node_log))
        with open(node_log, "w", encoding="utf8") as f:
            f.write("all fine\nsomething Warning here\nan ERROR there\nfine\n")
        result = self.make_result(
            failure={"type": "AssertionError", "message": "m", "traceback": "TB"},
            framework_log=framework_log,
            node_logs=[node_log],
            tmpdir=tmpdir,
        )
        block = failure_block(result, "/tests")
        self.assertIn("TB", block)
        self.assertIn("line 99", block)
        self.assertIn("40 lines before the failure", block)
        self.assertNotIn("TB again", block)
        self.assertNotIn("line 59\n", block)
        self.assertIn("something Warning here", block)
        self.assertIn("an ERROR there", block)
        self.assertNotIn("all fine", block)
        self.assertIn("Rerun: /tests/x_test.py --opt --nocleanup", block)

    def test_summary(self):
        results = [
            self.make_result(name="a.py", status=PASSED, duration=5),
            self.make_result(name="b.py", status=FAILED, duration=9),
            self.make_result(name="c.py", status=SKIPPED, duration=0),
        ]
        text = summary(results, "/tests")
        self.assertIn("Slowest 2 tests:", text)
        self.assertLess(text.index("b.py"), text.index("a.py"))
        self.assertIn("1 failed:", text)
        self.assertIn("rerun: /tests/x_test.py --nocleanup", text)

    def test_rerun_variant(self):
        result = self.make_result(name="x_test.py[cli] --opt")
        self.assertEqual(
            rerun_command(result, "/t"), "/t/x_test.py --variant=cli --opt --nocleanup"
        )

    def test_json_lines(self):
        path = os.path.join(tempfile.mkdtemp(prefix="reporting_unit_"), "out.jsonl")
        self.addCleanup(shutil.rmtree, os.path.dirname(path))
        writer = open_jsonl(path)
        assert writer is not None
        writer.write("finish", result=self.make_result().to_dict())
        writer.stream.close()
        with open(path, encoding="utf8") as f:
            event = json.loads(f.readline())
        self.assertEqual(event["event"], "finish")
        self.assertEqual(event["schema"], 1)
        self.assertEqual(JobResult.from_dict(event["result"]).name, "x_test.py --opt")
