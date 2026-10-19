#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run one functional test job in a worker process and report a JobResult.

The test runner starts run_job() as a multiprocessing "spawn" process per
job. The worker becomes the leader of its own process group (so the runner
can stop it and every bitcoind it started), sends the test's own stdout and
stderr to files in the job's directory, runs the test class with the job's
arguments, and sends the JobResult back over the connection.

While the test runs, the worker also sends its progress over the connection:
{"event": "phase", "phase": name} as each phase starts, and {"event": "log",
...} for each line the test logs at INFO or above.
"""

import glob
import importlib.util
import logging
import multiprocessing
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
import traceback
import unittest

from .discovery import module_name
from .results import CRASHED, FAILED, PASSED, SKIPPED, TIMEOUT, JobResult, tail
from .test_framework import TEST_EXIT_PASSED, TEST_EXIT_SKIPPED


def load_class(tests_dir, file, class_name):
    path = os.path.join(tests_dir, file)
    spec = importlib.util.spec_from_file_location(module_name(file), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, class_name)


class Progress:
    """Sends messages to the test runner; the test's threads all log."""

    def __init__(self, conn):
        self.conn = conn
        self.lock = threading.Lock()

    def send(self, message):
        with self.lock:
            try:
                self.conn.send(message)
            except (OSError, ValueError):
                # The runner is gone: let the test finish anyway
                pass

    def phase(self, name):
        self.send({"event": "phase", "phase": name})


class ProgressLogHandler(logging.Handler):
    """Forwards the test's log lines at INFO and above."""

    def __init__(self, progress):
        super().__init__(logging.INFO)
        self.progress = progress

    def emit(self, record):
        try:
            message = record.getMessage()
        except Exception:
            return
        self.progress.send(
            {
                "event": "log",
                "time": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": message,
            }
        )


def read(path):
    try:
        with open(path, encoding="utf8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def result_from_output(job, status, exit_code, start, test=None):
    """Build the JobResult from the job's captured output (and the test
    instance, when the test ran)."""
    stdout = read(job["stdout_path"])
    stderr = read(job["stderr_path"])
    result = JobResult(
        name=job["name"],
        file=job["file"],
        class_name=job["class_name"],
        variant=job.get("variant", ""),
        status=status,
        exit_code=exit_code,
        start_time=start,
        duration=time.time() - start,
        tmpdir=job["tmpdir"],
        framework_log=os.path.join(job["tmpdir"], "test_framework.log"),
        stdout_tail=tail(stdout),
        stderr_tail=tail(stderr),
        stderr_nonempty=stderr != "",
    )
    if test is not None:
        result.skip_reason = test.skip_reason
        result.failure = test.failure
        result.phases = list(test._phases)
    # (The framework clears test.nodes on shutdown: find the logs on disk.)
    result.node_logs = sorted(
        glob.glob(os.path.join(job["tmpdir"], "node*", "*", "debug.log"))
    )
    return result


def run_job(job, conn):
    """Process entry point (multiprocessing target)."""
    start = time.time()
    if hasattr(os, "setpgrp"):
        os.setpgrp()
    # The test's output, and that of anything it starts, goes to files.
    for fd, path in ((1, job["stdout_path"]), (2, job["stderr_path"])):
        f = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.dup2(f, fd)
        os.close(f)
    os.environ.update(job.get("env", {}))
    progress = Progress(conn)
    logging.getLogger("TestFramework").addHandler(ProgressLogHandler(progress))
    try:
        cls = load_class(job["tests_dir"], job["file"], job["class_name"])
        sys.argv = [os.path.join(job["tests_dir"], job["file"])] + job["argv"]
        test = cls(argv=job["argv"])
        test.on_phase = progress.phase
        exit_code = test.main(exit_process=False)
    except BaseException as e:
        # The test could not even be set up (import error, bad arguments...)
        sys.stdout.flush()
        sys.stderr.flush()
        result = result_from_output(job, FAILED, None, start)
        if isinstance(e, SystemExit):
            # e.g. argparse, which already explained the error on stderr
            result.failure = {
                "type": "SystemExit",
                "message": f"the test exited with code {e.code} before running",
                "traceback": "",
            }
        else:
            result.failure = {
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc(),
            }
        progress.send(result.to_dict())
        os._exit(1)
    sys.stdout.flush()
    sys.stderr.flush()
    if exit_code == TEST_EXIT_PASSED:
        status = PASSED
    elif exit_code == TEST_EXIT_SKIPPED:
        status = SKIPPED
    else:
        status = FAILED
    result = result_from_output(job, status, exit_code, start, test)
    # As before: a passing test that wrote to stderr fails.
    if status == PASSED and result.stderr_nonempty:
        result.status = FAILED
        result.failure = {
            "type": "stderr",
            "message": "the test wrote to stderr",
            "traceback": result.stderr_tail,
        }
    progress.send(result.to_dict())
    os._exit(exit_code)


def run_in_process(job, timeout=None, on_progress=None):
    """Run a test job (see test_framework/worker.py) in a new process.

    Calls on_progress(message) for each progress message. Returns the
    JobResult. A worker that dies without reporting a result is
    "crashed"; one still running after `timeout` seconds is stopped (with
    every process it started) and "timeout"."""
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    process = ctx.Process(target=run_job, args=(job, sender))
    start = time.time()
    process.start()
    sender.close()
    result = None
    timed_out = False
    while result is None:
        if receiver.poll(0.2):
            try:
                message = receiver.recv()
            except EOFError:
                break
            if "event" not in message:
                result = JobResult.from_dict(message)
            elif on_progress is not None:
                on_progress(message)
        elif not process.is_alive() and not receiver.poll(0):
            break
        elif timeout is not None and time.time() - start > timeout:
            timed_out = True
            break
    if timed_out:
        stop_process_group(process.pid, signal.SIGTERM)
        process.join(10)
    process.join(60)
    # Kill whatever is left in the worker's process group, e.g. the nodes of
    # a failed test.
    stop_process_group(process.pid, signal.SIGKILL)
    process.join()
    if result is None:
        result = result_from_output(
            job, TIMEOUT if timed_out else CRASHED, process.exitcode, start
        )
        result.failure = {
            "type": "timeout" if timed_out else "crash",
            "message": (
                f"stopped after {timeout} s"
                if timed_out
                else f"the worker exited ({process.exitcode}) without a result"
            ),
            "traceback": result.stderr_tail,
        }
    return result


def stop_process_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


class TestWorker(unittest.TestCase):
    """Run small node-less tests in worker processes."""

    TEST = """
import os, time
from test_framework.test_framework import BitcoinTestFramework, SkipTest

class Case(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def setup_network(self):
        pass

    def run_test(self):
        action = os.environ["WORKER_UNIT_ACTION"]
        print("hello from the test")
        self.log.info("working on it")
        if action == "fail":
            raise AssertionError("boom")
        if action == "skip":
            raise SkipTest("not today")
        if action == "stderr":
            import sys
            sys.stderr.write("unexpected\\n")
        if action == "crash":
            os._exit(3)
        if action == "hang":
            time.sleep(600)
"""

    def run_action(self, action, timeout=None, on_progress=None):
        workdir = tempfile.mkdtemp(prefix="worker_unit_")
        self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
        with open(os.path.join(workdir, "case_test.py"), "w", encoding="utf8") as f:
            f.write(self.TEST)
        configfile = os.path.join(workdir, "config.ini")
        with open(configfile, "w", encoding="utf8") as f:
            f.write(
                "[environment]\nBUILDDIR=" + workdir + "\nEXEEXT=\nEMULATOR=\n"
                "PACKAGE_BUGREPORT=\n[components]\n"
            )
        tmpdir = os.path.join(workdir, "tmp")
        job = {
            "name": "case_test.py",
            "file": "case_test.py",
            "class_name": "Case",
            "tests_dir": workdir,
            "argv": [f"--configfile={configfile}", f"--tmpdir={tmpdir}"],
            "tmpdir": tmpdir,
            "stdout_path": f"{tmpdir}.stdout",
            "stderr_path": f"{tmpdir}.stderr",
            "env": {"WORKER_UNIT_ACTION": action},
        }
        return run_in_process(job, timeout, on_progress)

    def test_passed(self):
        result = self.run_action("pass")
        self.assertEqual(result.status, PASSED)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hello from the test", result.stdout_tail)
        self.assertIn("body", [p["name"] for p in result.phases])

    def test_progress(self):
        events = []
        self.run_action("pass", on_progress=events.append)
        phases = [e["phase"] for e in events if e["event"] == "phase"]
        self.assertEqual(phases[:3], ["chain_init", "network_setup", "body"])
        logs = [e for e in events if e["event"] == "log"]
        self.assertIn("working on it", [e["message"] for e in logs])
        self.assertTrue(all(e["level"] != "DEBUG" for e in logs))

    def test_failed(self):
        result = self.run_action("fail")
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.failure["type"], "AssertionError")
        self.assertEqual(result.failure["message"], "boom")

    def test_skipped(self):
        result = self.run_action("skip")
        self.assertEqual(result.status, SKIPPED)
        self.assertEqual(result.skip_reason, "not today")

    def test_stderr_fails_a_passing_test(self):
        result = self.run_action("stderr")
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.failure["type"], "stderr")

    def test_crashed(self):
        result = self.run_action("crash")
        self.assertEqual(result.status, CRASHED)
        self.assertEqual(result.exit_code, 3)

    def test_timeout(self):
        start = time.time()
        result = self.run_action("hang", timeout=3)
        self.assertEqual(result.status, TIMEOUT)
        self.assertLess(time.time() - start, 30)
