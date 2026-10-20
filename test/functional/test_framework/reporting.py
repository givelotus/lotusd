#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""How test_runner.py reports test jobs: console lines, failure details,
the end-of-run summary and JSON lines (see README-runner-output.md)."""

import dataclasses
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from typing import IO, Any, Dict, Iterable, List, Optional, Tuple

from . import timeline
from .results import FAILED, PASSED, SKIPPED, JobResult, parse_job_name

GLYPHS = {PASSED: "✓", SKIPPED: "○"}

# Lines of the merged log timeline shown for a failure
TIMELINE_LINES = 40


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


def rerun_command(result: JobResult, tests_dir: str) -> str:
    """The command that runs this test job again on its own."""
    _, variant, args = parse_job_name(result.name)
    if variant:
        args = [f"--variant={variant}"] + args
    return " ".join([os.path.join(tests_dir, result.file)] + args + ["--nocleanup"])


def failure_timeline(result: JobResult) -> Tuple[List[str], str, bool]:
    """The end of the test's merged log timeline, up to the failure (the
    framework's logged exception, when the test failed with one), read from
    the end of each log; then the whole timeline written to
    <tmpdir>/combined.log (text) and <tmpdir>/timeline.jsonl (JSON lines;
    its path goes in result.timeline). Returns the excerpt's lines, the
    text log's path ("" if it could not be written), and whether the
    failure was found."""
    if not result.tmpdir or not os.path.isdir(result.tmpdir):
        return [], "", False
    stop = bool((result.failure or {}).get("traceback"))
    lines, found = timeline.failure_excerpt(
        result.tmpdir, TIMELINE_LINES, stop_at_failure=stop
    )
    try:
        path = timeline.write_combined_log(result.tmpdir)
    except OSError:
        path = ""
    try:
        result.timeline = timeline.write_timeline(result.tmpdir)
    except OSError:
        pass
    return lines, path, found


def failure_block(
    result: JobResult,
    tests_dir: str,
    details: Optional[Tuple[List[str], str, bool]] = None,
) -> str:
    """What a developer needs to look into a failed test: the traceback, the
    end of the merged log timeline (framework and nodes, by time) up to the
    failure, and how to rerun it. `details` is what failure_timeline()
    returned; without it, failure_timeline() is called (and writes the
    timeline files)."""
    out = [f"✖ {result.name} {result.status} after {result.duration:.0f} s"]
    failure = result.failure or {}
    if failure.get("traceback"):
        out += ["", failure["traceback"].rstrip()]
    elif failure.get("message"):
        out += ["", failure["message"]]
    if result.stderr_tail and failure.get("type") != "stderr":
        out += ["", "stderr (last lines):"] + result.stderr_tail.splitlines()[-40:]
    lines, combined_log, found = details or failure_timeline(result)
    if lines:
        where = "up to the failure" if found else "at the end"
        out += ["", f"Log timeline, last {len(lines)} lines {where}:"] + lines
    out += ["", f"Test directory: {result.tmpdir}"]
    out += [f"Rerun: {rerun_command(result, tests_dir)}"]
    if combined_log:
        out += [f"Log:   {combined_log}"]
    if result.timeline:
        out += [f"       {result.timeline}"]
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


# What each of the framework's phases is shown as
PHASE_LABELS = {
    "chain_init": "setting up chain",
    "network_setup": "starting nodes",
    "body": "running",
    "final_stop": "stopping nodes",
    "cleanup": "cleaning up",
}


@dataclasses.dataclass
class RunningJob:
    """What the live status shows about a test that is running."""

    name: str
    start: float
    phase: str = "starting"
    last_log: str = ""

    def update(self, event: Dict[str, Any]):
        if event.get("event") == "phase":
            self.phase = PHASE_LABELS.get(event["phase"], event["phase"])
        elif event.get("event") == "log":
            lines = str(event.get("message", "")).strip().splitlines()
            if lines:
                self.last_log = lines[0]


def fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 1, 0)] + "…"


def render_status(
    done: int,
    total: int,
    failed: int,
    running: List[RunningJob],
    width: int,
    height: int,
    now: float,
) -> List[str]:
    """The live status: a summary line, then a line per running test (its
    phase, time so far and latest log line), within width x height."""
    lines = [
        fit(f"[{done}/{total}] {failed} failed, {len(running)} running", width - 1)
    ]
    rows = max(height - 3, 1)
    jobs = sorted(running, key=lambda job: job.start)
    shown = jobs if len(jobs) <= rows else jobs[: rows - 1]
    name_width = min(max((len(job.name) for job in shown), default=0), 40)
    for job in shown:
        elapsed = f"{now - job.start:4.0f} s"
        line = f"  {fit(job.name, name_width):<{name_width}}  {job.phase:<16} {elapsed}"
        if job.last_log:
            line += f"  {job.last_log}"
        lines.append(fit(line, width - 1))
    if len(shown) < len(jobs):
        lines.append(f"  … and {len(jobs) - len(shown)} more")
    return lines


class LiveStatus:
    """The bottom of an interactive terminal: the live status, redrawn as
    tests progress. Clear it before printing anything else."""

    def __init__(self, stream: IO[str], total: int):
        self.stream = stream
        self.total = total
        self.enabled = stream.isatty()
        self.lines = 0

    def show(self, done: int, failed: int, running: List[RunningJob]):
        if not self.enabled:
            return
        size = shutil.get_terminal_size((100, 24))
        lines = render_status(
            done,
            self.total,
            failed,
            running,
            size.columns,
            size.lines,
            time.time(),
        )
        self.clear()
        self.stream.write("".join(line + "\n" for line in lines))
        self.stream.flush()
        self.lines = len(lines)

    def clear(self):
        if self.lines:
            # Back to the first line of the status, and erase to the end
            self.stream.write(f"\x1b[{self.lines}F\x1b[J")
            self.stream.flush()
            self.lines = 0


class JsonLines:
    """Writes one JSON object per event to a file."""

    def __init__(self, stream: IO[str]):
        self.stream = stream

    def write(self, event: str, **fields):
        fields.update({"event": event, "schema": 1})
        self.stream.write(json.dumps(fields, sort_keys=True) + "\n")
        self.stream.flush()


def open_jsonl(path: Optional[str]) -> Optional[JsonLines]:
    """JSON lines to the file at `path`. For "-", to standard output, which
    then has only JSON lines: everything else written there (by this process
    or the processes it starts) goes to standard error instead."""
    if path is None:
        return None
    if path == "-":
        sys.stdout.flush()
        stream = os.fdopen(os.dup(1), "w", encoding="utf8")
        os.dup2(2, 1)
        return JsonLines(stream)
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
        stamp = "2026-10-19T12:00:{:02d}.{:06d}Z"
        framework_log = os.path.join(tmpdir, "test_framework.log")
        with open(framework_log, "w", encoding="utf8") as f:
            f.write(
                "".join(
                    f"{stamp.format(1, i)} TestFramework (INFO): line {i}\n"
                    for i in range(100)
                )
            )
            f.write(
                f"{stamp.format(3, 0)} TestFramework (ERROR): Unexpected exception\n"
                "TB again\n"
                f"{stamp.format(5, 0)} TestFramework (INFO): Not stopping nodes\n"
            )
        node_log = os.path.join(tmpdir, "node0", "regtest", "debug.log")
        os.makedirs(os.path.dirname(node_log))
        with open(node_log, "w", encoding="utf8") as f:
            f.write(
                f"{stamp.format(2, 0)} [net:warning] something here\n"
                f"{stamp.format(4, 0)} after the failure\n"
            )
        result = self.make_result(
            failure={"type": "AssertionError", "message": "m", "traceback": "TB"},
            framework_log=framework_log,
            node_logs=[node_log],
            tmpdir=tmpdir,
        )
        block = failure_block(result, "/tests")
        self.assertIn("\nTB\n", block)
        self.assertIn("Log timeline, last 40 lines up to the failure:", block)
        self.assertIn("test   12:00:01.000099 line 99", block)
        self.assertIn("node0  12:00:02.000000 WARNING [net] something here", block)
        self.assertIn("test   12:00:03.000000 ERROR Unexpected exception", block)
        self.assertNotIn("TB again", block)
        self.assertNotIn("line 61\n", block)
        self.assertIn("line 62\n", block)
        self.assertNotIn("after the failure", block)
        self.assertNotIn("combine_logs.py", block)
        self.assertIn("Rerun: /tests/x_test.py --opt --nocleanup", block)
        combined = os.path.join(tmpdir, "combined.log")
        self.assertIn(f"Log:   {combined}", block)
        with open(combined, encoding="utf8") as f:
            text = f.read()
        self.assertIn("TB again", text)
        self.assertIn("after the failure", text)
        self.assertEqual(result.timeline, os.path.join(tmpdir, "timeline.jsonl"))
        self.assertIn(f"       {result.timeline}", block)
        self.assertGreater(timeline.check_timeline(result.timeline), 100)
        # Without a traceback (e.g. a timeout): the end of the timeline
        result.failure = {"type": "timeout", "message": "stopped", "traceback": ""}
        block = failure_block(result, "/tests")
        self.assertIn("last 40 lines at the end:", block)
        self.assertIn("Not stopping nodes", block)
        # No test directory at all
        result.tmpdir = os.path.join(tmpdir, "missing")
        self.assertNotIn("Log", failure_block(result, "/tests"))

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

    def test_render_status(self):
        jobs = [
            RunningJob("b_test.py", start=90),
            RunningJob("a_test.py[variant]", start=80),
        ]
        jobs[0].update({"event": "phase", "phase": "network_setup"})
        jobs[1].update({"event": "phase", "phase": "body"})
        jobs[1].update({"event": "log", "message": "Mine blocks\nmore"})
        lines = render_status(3, 10, 1, jobs, width=80, height=24, now=100)
        self.assertEqual(lines[0], "[3/10] 1 failed, 2 running")
        # Oldest first, with phase, time so far and the latest log line
        self.assertEqual(
            lines[1], "  a_test.py[variant]  running            20 s  Mine blocks"
        )
        self.assertEqual(lines[2], "  b_test.py           starting nodes     10 s")
        # Within the terminal
        narrow = render_status(3, 10, 1, jobs, width=30, height=24, now=100)
        self.assertTrue(all(len(line) <= 29 for line in narrow))
        short = render_status(3, 10, 1, jobs * 5, width=80, height=6, now=100)
        self.assertEqual(len(short), 4)
        self.assertEqual(short[-1], "  … and 8 more")

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
        self.assertEqual(event["result"]["schema"], 2)
        self.assertEqual(JobResult.from_dict(event["result"]).name, "x_test.py --opt")
