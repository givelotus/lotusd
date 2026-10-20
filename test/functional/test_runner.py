#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2017 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run regression test suite.

This module calls down into individual test cases via subprocess. It will
forward all unrecognized arguments onto the individual test scripts.

For a description of arguments recognized by test scripts, see
`test/functional/test_framework/test_framework.py:BitcoinTestFramework.main`.

"""

import argparse
import configparser
import datetime
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from collections import deque
from queue import Empty, Queue
from typing import Any, Dict, NamedTuple, Set, Tuple

from test_framework import reporting, worker
from test_framework.results import FAILED, PASSED, SKIPPED, JobResult, parse_job_name
from test_framework.util import MAX_NODES, PORT_RANGE

# Formatting. Default colors to empty strings.
BOLD, GREEN, RED, GREY = ("", ""), ("", ""), ("", ""), ("", "")
try:
    # Make sure python thinks it can write unicode to its stdout
    "\u2713".encode("utf_8").decode(sys.stdout.encoding)
    TICK = "✓ "
    CROSS = "✖ "
    CIRCLE = "○ "
except UnicodeDecodeError:
    TICK = "P "
    CROSS = "x "
    CIRCLE = "o "

if os.name != "nt" or sys.getwindowsversion() >= (10, 0, 14393):  # type: ignore
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4
        STD_OUTPUT_HANDLE = -11
        STD_ERROR_HANDLE = -12
        # Enable ascii color control to stdout
        stdout = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        stdout_mode = ctypes.c_int32()
        kernel32.GetConsoleMode(stdout, ctypes.byref(stdout_mode))
        kernel32.SetConsoleMode(
            stdout, stdout_mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )
        # Enable ascii color control to stderr
        stderr = kernel32.GetStdHandle(STD_ERROR_HANDLE)
        stderr_mode = ctypes.c_int32()
        kernel32.GetConsoleMode(stderr, ctypes.byref(stderr_mode))
        kernel32.SetConsoleMode(
            stderr, stderr_mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )
    # primitive formatting on supported
    # terminal via ANSI escape sequences:
    BOLD = ("\033[0m", "\033[1m")
    GREEN = ("\033[0m", "\033[0;32m")
    RED = ("\033[0m", "\033[0;31m")
    GREY = ("\033[0m", "\033[1;30m")

TEST_EXIT_PASSED = 0
TEST_EXIT_SKIPPED = 77

TEST_FRAMEWORK_MODULES = [
    "log_match",
    "address",
    "blocktools",
    "discovery",
    "merkle",
    "reporting",
    "messages",
    "muhash",
    "p2p_websocket",
    "results",
    "script",
    "test_framework",
    "test_node",
    "timeline",
    "txtools",
    "util",
    "worker",
]

NON_TESTS = {
    # These are python files that live in the functional tests directory, but
    # are not test scripts.
    "combine_logs.py",
    "create_cache.py",
    # A standalone benchmark script, run by hand
    "lotus_v2_loopback_tps_stress.py",
    "test_runner.py",
}

EXTRA_PRIVILEGES_TESTS = [
    # These tests can only run with extra privileges.
    # Their durations are not recorded because they are not designed to run
    # in the same context as the other tests.
    "interface_usdt_net.py",
    "interface_usdt_utxocache.py",
    "interface_usdt_validation.py",
    "feature_bind_port_externalip.py",
    "feature_bind_port_discover.py",
]

DEFAULT_TEST_TIMEOUT = 20 * 60
DEFAULT_JOBS = os.cpu_count() or 1

SETUP_SCRIPTS_SUBDIR = "setup_scripts"


def bold(text) -> str:
    return f"{BOLD[1]}{text}{BOLD[0]}"


def running_setup_script(test_list):
    return len(test_list) == 1 and test_list[0].startswith(
        os.path.join(SETUP_SCRIPTS_SUBDIR, "")
    )


class TestCase:
    """
    Data structure to hold and run information necessary to launch a test case.
    """

    def __init__(
        self,
        test_num,
        test_case,
        tests_dir,
        tmpdir,
        failfast_event,
        flags=None,
        spec=None,
        timeout=None,
    ):
        self.tests_dir = tests_dir
        self.tmpdir = tmpdir
        self.test_case = test_case
        self.test_num = test_num
        self.failfast_event = failfast_event
        self.flags = flags
        # The test's discovery spec (test_framework/discovery.py), if any:
        # discovered tests run in a worker process, see run_in_worker().
        self.spec = spec
        # Seconds before the test is stopped, or None
        self.timeout = timeout
        # Called with the test's progress messages (see worker.py)
        self.on_progress = None

    def run(self, slot):
        """Run the test in pool slot `slot` (0 to jobs-1), which gives it its
        port range: tests running at the same time never share one."""
        if self.failfast_event.is_set():
            return TestResult(self.test_num, self.test_case, "", "Skipped", 0, "", "")

        portseed_arg = [f"--portseed={slot}"]
        file, variant, args = parse_job_name(self.test_case)
        test_argv = [file] + ([f"--variant={variant}"] if variant else []) + args
        testname = re.sub(".py$", "", file)
        testdir = os.path.join(f"{self.tmpdir}", f"{testname}_{self.test_num}")
        tmpdir_arg = [f"--tmpdir={testdir}"]
        argv = test_argv[1:] + self.flags + portseed_arg + tmpdir_arg
        if self.spec is not None and not running_setup_script([testname]):
            return self.run_in_worker(file, argv, testdir, variant)

        log_stdout = tempfile.SpooledTemporaryFile(max_size=2**16)
        log_stderr = tempfile.SpooledTemporaryFile(max_size=2**16)
        start_time = time.time()
        process = subprocess.Popen(
            [sys.executable, os.path.join(self.tests_dir, test_argv[0])] + argv,
            universal_newlines=True,
            stdout=sys.stdout if running_setup_script([testname]) else log_stdout,
            stderr=log_stderr,
        )

        process.wait()
        log_stdout.seek(0), log_stderr.seek(0)
        [stdout, stderr] = [
            log.read().decode("utf-8") for log in (log_stdout, log_stderr)
        ]
        log_stdout.close(), log_stderr.close()
        if process.returncode == TEST_EXIT_PASSED and stderr == "":
            status = "Passed"
        elif process.returncode == TEST_EXIT_SKIPPED:
            status = "Skipped"
        else:
            status = "Failed"

        return TestResult(
            self.test_num,
            self.test_case,
            testdir,
            status,
            time.time() - start_time,
            stdout,
            stderr,
        )

    def run_in_worker(self, file, argv, testdir, variant=None):
        job = {
            "name": self.test_case,
            "file": file,
            "variant": variant or "",
            "class_name": self.spec["class_name"],
            "tests_dir": self.tests_dir,
            "argv": argv,
            "tmpdir": testdir,
            # Next to the test's directory, which the test creates itself
            "stdout_path": f"{testdir}.stdout",
            "stderr_path": f"{testdir}.stderr",
        }
        result = worker.run_in_process(job, self.timeout, self.on_progress)
        status = {"passed": "Passed", "skipped": "Skipped"}.get(result.status, "Failed")
        stdout = worker.read(job["stdout_path"])
        stderr = worker.read(job["stderr_path"])
        if result.status in ("timeout", "crashed"):
            stderr += f"\n{result.failure['message']}\n"
        test_result = TestResult(
            self.test_num,
            self.test_case,
            testdir,
            status,
            result.duration,
            stdout,
            stderr,
        )
        test_result.job_result = result
        return test_result


def test_timeout(seconds, passon_args):
    """The per-test timeout in seconds, or None: `seconds` times the tests'
    --timeout-factor (0 disables, as it does for the tests)."""
    factor = 1.0
    for arg in passon_args:
        if arg.startswith("--timeout-factor="):
            factor = float(arg.split("=", 1)[1])
    if seconds == 0 or factor == 0:
        return None
    return seconds * factor


def on_ci():
    return os.getenv("TRAVIS") == "true" or os.getenv("TEAMCITY_VERSION") is not None


def main():
    # Read config generated by configure.
    config = configparser.ConfigParser()
    configfile = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "..", "config.ini"
    )
    config.read_file(open(configfile, encoding="utf8"))

    src_dir = config["environment"]["SRCDIR"]
    # Test modules need it to import (test_framework/cdefs.py), also in the
    # worker processes that run them.
    os.environ["SRCDIR"] = src_dir
    build_dir = config["environment"]["BUILDDIR"]
    tests_dir = os.path.join(src_dir, "test", "functional")

    # SRCDIR must be set for cdefs.py to find and parse consensus.h
    os.environ["SRCDIR"] = src_dir

    # Parse arguments and pass through unrecognised args
    parser = argparse.ArgumentParser(
        add_help=False,
        usage="%(prog)s [test_runner.py options] [script options] [scripts]",
        description=__doc__,
        epilog="""
    Help text and arguments for individual test script:""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--combinedlogslen",
        "-c",
        type=int,
        default=0,
        metavar="n",
        help=(
            "On failure, print a log (of length n lines) to "
            "the console, combined from the test framework "
            "and all test nodes."
        ),
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="generate a basic coverage report for the RPC interface",
    )
    parser.add_argument(
        "--exclude", "-x", help="specify a comma-separated-list of scripts to exclude."
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help=(
            "also run the extended tests (those that declare `extended`); tests"
            " named on the command line always run"
        ),
    )
    parser.add_argument(
        "--help", "-h", "-?", action="store_true", help="print help text and exit"
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=DEFAULT_JOBS,
        help="how many test scripts to run in parallel.",
    )
    parser.add_argument(
        "--keepcache",
        "-k",
        action="store_true",
        help=(
            "the default behavior is to flush the cache directory on startup."
            " --keepcache retains the cache from the previous testrun."
        ),
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="only print results summary and failure logs",
    )
    parser.add_argument(
        "--tmpdirprefix",
        "-t",
        default=os.path.join(build_dir, "test", "tmp"),
        help="Root directory for datadirs",
    )
    parser.add_argument(
        "--failfast",
        action="store_true",
        help="stop execution after the first test failure",
    )
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=DEFAULT_TEST_TIMEOUT,
        help=(
            "Stop a test, and every process it started, after this many seconds"
            " (multiplied by --timeout-factor, if given). 0 disables. Default:"
            " %(default)s"
        ),
    )
    parser.add_argument(
        "--phase-report",
        action="store_true",
        help=(
            "Record each test's phase timings (cache copy, node start/stop, test"
            " body, cleanup) and print a summary at the end"
        ),
    )
    parser.add_argument(
        "--jsonl-file",
        help=(
            "Write one JSON object per event (a test's start, phases, log lines"
            " and result, then the summary) to this file, or to standard output"
            " with -, which then has only these (see README-runner-output.md)"
        ),
    )
    parser.add_argument(
        "--timeline",
        action="store_true",
        help=(
            "Also for tests that pass, write <test directory>/timeline.jsonl"
            " (every log record of the test and its nodes, sorted by time) and"
            " keep that file. Failed tests always get one."
        ),
    )
    parser.add_argument(
        "--json-summary",
        help="Write the run's summary (counts, times, failed tests) as JSON",
    )
    parser.add_argument(
        "--junitoutput",
        "-J",
        help=(
            "File that will store JUnit formatted test results. If no absolute path is"
            " given it is treated as relative to the temporary directory."
        ),
    )
    parser.add_argument(
        "--testsuitename",
        "-n",
        default="Bitcoin ABC functional tests",
        help=(
            "Name of the test suite, as it will appear in the logs and in the JUnit"
            " report."
        ),
    )
    parser.add_argument(
        "--repeat",
        "-r",
        type=int,
        default=1,
        help=(
            "Number of times to repeat the selected tests. "
            "Useful for troubleshooting intermittent failures."
        ),
    )
    args, unknown_args = parser.parse_known_args()
    # First: with --jsonl-file=-, everything else printed goes to stderr
    jsonl = reporting.open_jsonl(args.jsonl_file)

    # args to be passed on always start with two dashes; tests are the
    # remaining unknown args
    tests = [arg for arg in unknown_args if arg[:2] != "--"]
    passon_args = [arg for arg in unknown_args if arg[:2] == "--"]
    if args.jobs > max_jobs():
        parser.error(
            f"--jobs={args.jobs} is more than the {max_jobs()} tests that can run at"
            " once with disjoint port ranges"
        )
    passon_args.append(f"--configfile={configfile}")

    # Set up logging
    logging_level = logging.INFO if args.quiet else logging.DEBUG
    logging.basicConfig(format="%(message)s", level=logging_level)
    logging.info(f"Starting {args.testsuitename}")

    # Create base test directory
    tmpdir = os.path.join(
        f"{args.tmpdirprefix}",
        f"test_runner_₿₵_🏃_{datetime.datetime.now():%Y%m%d_%H%M%S}_{random.getrandbits(16)}",
    )

    os.makedirs(tmpdir)
    phase_dir = None
    if args.phase_report:
        phase_dir = os.path.join(tmpdir, "phases")
        passon_args.append(f"--phasedir={phase_dir}")
    if args.timeline:
        passon_args.append("--timeline")

    logging.debug(f"Temporary test directory at {tmpdir}")

    if args.junitoutput and not os.path.isabs(args.junitoutput):
        args.junitoutput = os.path.join(tmpdir, args.junitoutput)

    enable_bitcoind = config["components"].getboolean("ENABLE_BITCOIND")

    if not enable_bitcoind:
        print("No functional tests to run.")
        print("Rerun ./configure with --with-daemon and then make")
        sys.exit(0)

    # Build list of tests
    all_tests, all_setup_scripts = get_all_scripts_from_disk(tests_dir, NON_TESTS)
    # Tests named with "[<variant>]": file -> the set of variants to run (None: all)
    only_variants = {}

    if tests:
        # Individual tests or setup scripts have been specified. Run specified
        # tests/setup scripts that exist in the all_tests/all_setup_scripts
        # list. Accept the name with or without .py extension, and with a
        # variant: "<file>[<variant>]" runs only that variant of the test.
        test_list = []
        for test in tests:
            if test.endswith("*"):
                continue
            file, variant, _ = parse_job_name(test)
            file = re.sub(r"\.py$", "", file) + ".py"
            if file not in (all_tests | all_setup_scripts):
                print(f"{bold('WARNING!')} Test '{file}' not found in full test list.")
                continue
            if file not in test_list:
                test_list.append(file)
            if variant is None:
                only_variants[file] = None
            elif only_variants.get(file, ()) is not None:
                only_variants.setdefault(file, set()).add(variant)

        # Allow for wildcard at the end of the name, so a single input can
        # match multiple tests
        for test in tests:
            if test.endswith("*"):
                test_list.extend([t for t in all_tests if t.startswith(test[:-1])])

        # Tests named explicitly run even if they are extended
        run_extended = True
    else:
        test_list = all_tests
        run_extended = args.extended

    # Remove the test cases that the user has explicitly asked to exclude.
    if args.exclude:
        exclude_tests = [
            re.sub(r"\.py$", "", test) + (".py" if ".py" not in test else "")
            for test in args.exclude.split(",")
        ]
        for exclude_test in exclude_tests:
            if exclude_test in test_list:
                test_list.remove(exclude_test)
            else:
                print(
                    f"{bold('WARNING!')} Test '{exclude_test}' not found in current "
                    "test list."
                )

    # Durations of earlier runs in this build directory, to start the longest
    # tests first
    durations = Timings(os.path.join(build_dir, "test", "durations.json"))

    discovered = discover_tests(tests_dir, src_dir, test_list)
    for file, variants in only_variants.items():
        known = (discovered or {}).get(file, {}).get("variants", [])
        unknown = sorted((variants or set()) - set(known))
        if unknown:
            print(
                f"{bold('ERROR!')} {file} has no variant {', '.join(unknown)}"
                f" (variants: {', '.join(known) or 'none'})"
            )
            sys.exit(1)
    test_list = args.repeat * get_tests_to_run(
        test_list, durations, discovered, only_variants, run_extended
    )

    if not test_list:
        print(
            "No valid test scripts specified. Check that your test is in one of the"
            " test lists in test_runner.py, or run test_runner.py with no arguments to"
            " run all tests"
        )
        sys.exit(0)

    if args.help:
        # Print help for test_runner.py, then print help of the first script
        # and exit.
        parser.print_help()
        subprocess.check_call(
            [sys.executable, os.path.join(tests_dir, test_list[0]), "-h"]
        )
        sys.exit(0)

    check_script_prefixes(all_tests)

    if not args.keepcache:
        shutil.rmtree(os.path.join(build_dir, "test", "cache"), ignore_errors=True)

    run_tests(
        test_list,
        build_dir,
        tests_dir,
        args.junitoutput,
        tmpdir,
        num_jobs=args.jobs,
        test_suite_name=args.testsuitename,
        enable_coverage=args.coverage,
        args=passon_args,
        combined_logs_len=args.combinedlogslen,
        durations=durations,
        failfast=args.failfast,
        phase_dir=phase_dir,
        discovered=discovered,
        test_timeout=test_timeout(args.test_timeout, passon_args),
        jsonl=jsonl,
        json_summary=args.json_summary,
    )


def run_tests(
    test_list,
    build_dir,
    tests_dir,
    junitoutput,
    tmpdir,
    num_jobs,
    test_suite_name,
    enable_coverage=False,
    args=None,
    combined_logs_len=0,
    durations=None,
    failfast=False,
    phase_dir=None,
    discovered=None,
    test_timeout=None,
    jsonl=None,
    json_summary=None,
):
    args = args or []

    # Warn if bitcoind is already running
    try:
        # pgrep exits with code zero when one or more matching processes found
        if (
            subprocess.run(
                ["pgrep", "-x", "bitcoind"], stdout=subprocess.DEVNULL
            ).returncode
            == 0
        ):
            print(
                f"{bold('WARNING!')} There is already a bitcoind process running on "
                "this system. Tests may fail unexpectedly due to resource contention!"
            )
    except OSError:
        # pgrep not supported
        pass

    # Warn if there is a cache directory
    cache_dir = os.path.join(build_dir, "test", "cache")
    if os.path.isdir(cache_dir):
        print(
            f"{bold('WARNING!')} There is a cache directory here: {cache_dir}. "
            "If tests fail unexpectedly, try deleting the cache directory."
        )

    # Test Framework Tests
    print("Running Unit Tests for Test Framework Modules")
    test_framework_tests = unittest.TestSuite()
    for module in TEST_FRAMEWORK_MODULES:
        test_framework_tests.addTest(
            unittest.TestLoader().loadTestsFromName(f"test_framework.{module}")
        )
    result = unittest.TextTestRunner(verbosity=1, failfast=True).run(
        test_framework_tests
    )
    if not result.wasSuccessful():
        logging.debug("Early exiting after failure in TestFramework unit tests")
        sys.exit(False)

    flags = [f"--cachedir={cache_dir}"] + args

    if enable_coverage:
        coverage = RPCCoverage()
        flags.append(coverage.flag)
        logging.debug(f"Initializing coverage directory at {coverage.dir}")
    else:
        coverage = None

    if len(test_list) > 1 and num_jobs > 1:
        # Populate cache
        try:
            subprocess.check_output(
                [sys.executable, os.path.join(tests_dir, "create_cache.py")]
                + flags
                + [os.path.join(f"--tmpdir={tmpdir}", "cache")]
            )
        except subprocess.CalledProcessError as e:
            sys.stdout.buffer.write(e.output)
            raise

    # Run Tests
    start_time = time.time()
    test_results = execute_test_processes(
        num_jobs,
        test_list,
        build_dir,
        tests_dir,
        tmpdir,
        flags,
        failfast,
        discovered,
        test_timeout,
        jsonl,
    )
    runtime = time.time() - start_time

    max_len_name = len(max(test_list, key=len))
    print_results(test_results, tests_dir, max_len_name, runtime, combined_logs_len)
    job_results = [job_result_of(r) for r in test_results]
    print(reporting.summary(job_results, tests_dir))
    run_summary = {
        "wall_time": runtime,
        "accumulated_time": sum(r.duration for r in job_results),
        "counts": {
            status: len([r for r in job_results if r.status == status])
            for status in sorted({r.status for r in job_results})
        },
        "failed": [r.name for r in job_results if not r.was_successful],
    }
    if jsonl is not None:
        jsonl.write("summary", **run_summary)
    if json_summary is not None:
        with open(json_summary, "w", encoding="utf8") as f:
            json.dump(dict(run_summary, schema=1), f, indent=1, sort_keys=True)

    if junitoutput is not None:
        save_results_as_junit(test_results, junitoutput, runtime, test_suite_name)

    if phase_dir is not None:
        print_phase_report(phase_dir, os.path.join(tmpdir, "phase-report.json"))

    if durations is not None:
        durations.save_timings(test_results)

    if coverage:
        coverage_passed = coverage.report_rpc_coverage()

        logging.debug("Cleaning up coverage data")
        coverage.cleanup()
    else:
        coverage_passed = True

    # Clear up the temp directory if all subdirectories are gone
    if not os.listdir(tmpdir):
        os.rmdir(tmpdir)

    all_passed = all(res.was_successful for res in test_results) and coverage_passed

    sys.exit(not all_passed)


def max_jobs():
    """How many tests can run at once with disjoint port ranges (see
    UniquePort in test_framework/util.py)."""
    return (PORT_RANGE - 1 - MAX_NODES) // MAX_NODES


def execute_test_processes(
    num_jobs,
    test_list,
    build_dir,
    tests_dir,
    tmpdir,
    flags,
    failfast=False,
    discovered=None,
    test_timeout=None,
    jsonl=None,
):
    update_queue = Queue()
    job_queue = Queue()
    failfast_event = threading.Event()
    test_results = []

    ##
    # Define some helper functions we will need for threading.
    ##

    live = reporting.LiveStatus(sys.stdout, len(test_list))
    if on_ci() or running_setup_script(test_list):
        live.enabled = False
    # Seconds between live status updates
    poll_timeout = 0.25 if live.enabled else 1
    last_shown = [0.0]

    def show_status(running_jobs, force=True):
        """Redraw the live status, at most every poll_timeout unless forced."""
        if not force and time.time() - last_shown[0] < poll_timeout:
            return
        last_shown[0] = time.time()
        failed = len([r for r in test_results if not r.was_successful])
        live.show(len(test_results), failed, list(running_jobs.values()))

    def handle_message(message, running_jobs):
        """
        handle_message handles a single message from handle_test_cases
        """
        if isinstance(message, TestCase):
            running_jobs[message.test_num] = reporting.RunningJob(
                message.test_case, time.time()
            )
            if not live.enabled:
                print(f"{bold(message.test_case)} started")
            if jsonl is not None:
                jsonl.write("start", name=message.test_case)
            show_status(running_jobs)
            return

        if isinstance(message, Progress):
            job = running_jobs.get(message.num)
            if job is not None:
                job.update(message.event)
            if jsonl is not None:
                fields = {k: v for k, v in message.event.items() if k != "event"}
                jsonl.write(message.event["event"], name=message.name, **fields)
            show_status(running_jobs, force=False)
            return

        if isinstance(message, TestResult):
            test_result = message

            running_jobs.pop(test_result.num, None)
            test_results.append(test_result)
            result = job_result_of(test_result)

            # A failed test's timeline files are written first, so that the
            # finish event can point to them.
            details = None
            if not test_result.was_successful:
                details = reporting.failure_timeline(result)
            live.clear()
            print(reporting.finish_line(result))
            if jsonl is not None:
                jsonl.write("finish", result=result.to_dict())
            if not test_result.was_successful:
                print()
                print(reporting.failure_block(result, tests_dir, details))
                print()

                # Write a symlink to the failed test directory for easy inspection
                lastfailurepath = os.path.join(build_dir, "lastfailure")
                if os.path.lexists(lastfailurepath):
                    os.remove(lastfailurepath)
                try:
                    os.symlink(
                        test_result.testdir, lastfailurepath, target_is_directory=True
                    )
                except OSError as e:
                    if os.name == "nt":
                        pass
                    raise e

                if failfast:
                    logging.debug("Early exiting after test failure")
                    failfast_event.set()
            show_status(running_jobs)
            return

        assert False, "we should not be here"

    def handle_update_messages():
        """
        handle_update_messages waits for messages to be sent from handle_test_cases via the
        update_queue.  It serializes the results so we can print nice status update messages.
        """
        running_jobs = {}

        while True:
            message = None
            try:
                message = update_queue.get(True, poll_timeout)
                if message is None:
                    break
                handle_message(message, running_jobs)
                update_queue.task_done()
            except Empty:
                show_status(running_jobs)

    def handle_test_cases(slot):
        """
        job_runner represents a single thread that is part of a worker pool.
        It waits for a test, then executes that test.
        It also reports start and result messages to handle_update_messages
        """
        while True:
            test = job_queue.get()
            if test is None:
                break
            # Signal that the test is starting to inform the poor waiting
            # programmer
            update_queue.put(test)
            test.on_progress = lambda event, test=test: update_queue.put(
                Progress(test.test_num, test.test_case, event)
            )
            result = test.run(slot)
            update_queue.put(result)
            job_queue.task_done()

    ##
    # Setup our threads, and start sending tasks
    ##

    # Start our result collection thread.
    resultCollector = threading.Thread(target=handle_update_messages)
    resultCollector.daemon = True
    resultCollector.start()

    # Start some worker threads
    for slot in range(num_jobs):
        t = threading.Thread(target=handle_test_cases, args=(slot,))
        t.daemon = True
        t.start()

    # Push all our test cases into the job queue. A test file that could not
    # be imported, or defines no test, fails without being started.
    for i, t in enumerate(test_list):
        error = (discovered or {}).get(parse_job_name(t)[0], {}).get("error")
        if error is not None:
            update_queue.put(TestCase(i, t, tests_dir, tmpdir, failfast_event, flags))
            update_queue.put(TestResult(i, t, "", "Failed", 0, "", error))
            continue
        job_queue.put(
            TestCase(
                i,
                t,
                tests_dir,
                tmpdir,
                failfast_event,
                flags,
                spec=(discovered or {}).get(parse_job_name(t)[0]),
                timeout=test_timeout,
            )
        )

    # Wait for all the jobs to be completed
    job_queue.join()

    # Wait for all the results to be compiled
    update_queue.join()

    # Flush our queues so the threads exit
    update_queue.put(None)
    for _ in range(num_jobs):
        job_queue.put(None)

    return test_results


def job_result_of(test_result):
    """The JobResult of a TestResult: the worker's, or one built from the
    output of a test run as a plain subprocess."""
    result = getattr(test_result, "job_result", None)
    if result is not None:
        return result
    status = {"Passed": PASSED, "Skipped": SKIPPED}.get(test_result.status, FAILED)
    result = JobResult(
        name=test_result.name,
        file=parse_job_name(test_result.name)[0],
        status=status,
        duration=test_result.time,
        tmpdir=test_result.testdir,
        framework_log=(
            os.path.join(test_result.testdir, "test_framework.log")
            if test_result.testdir
            else ""
        ),
        stdout_tail=reporting_tail(test_result.stdout),
        stderr_tail=reporting_tail(test_result.stderr),
        stderr_nonempty=test_result.stderr != "",
    )
    if status == FAILED:
        result.failure = {"type": "exit", "message": "the test failed", "traceback": ""}
    test_result.job_result = result
    return result


def reporting_tail(text):
    return "\n".join((text or "").splitlines()[-200:])


PHASES = ("chain_init", "network_setup", "body", "final_stop", "cleanup")


def print_phase_report(phase_dir, report_path):
    """Summarize the per-test timings written with --phasedir."""
    records = []
    if os.path.isdir(phase_dir):
        for name in sorted(os.listdir(phase_dir)):
            with open(os.path.join(phase_dir, name), encoding="utf8") as f:
                records.append(json.load(f))
    if not records:
        print("No phase timings were recorded.")
        return

    def phase(record, name):
        return sum(p["duration"] for p in record["phases"] if p["name"] == name)

    def node(record, name):
        durations = [t["duration"] for t in record["node_timings"] if t["name"] == name]
        return sum(durations), len(durations)

    totals = {name: sum(phase(r, name) for r in records) for name in PHASES}
    starts = [node(r, "node_start") for r in records]
    stops = [node(r, "node_stop") for r in records]
    start_total, start_count = sum(s for s, _ in starts), sum(n for _, n in starts)
    stop_total, stop_count = sum(s for s, _ in stops), sum(n for _, n in stops)
    grand_total = sum(totals.values())

    lines = [bold("\nPhase timings (accumulated over all tests)")]
    for name in PHASES:
        share = 100 * totals[name] / grand_total if grand_total else 0
        lines.append(f"  {name:<14} {totals[name]:>9.1f} s  {share:5.1f}%")
    lines.append(
        f"  node starts    {start_total:>9.1f} s  ({start_count} starts, "
        f"mean {start_total / max(start_count, 1) * 1000:.0f} ms)"
    )
    lines.append(
        f"  node stops     {stop_total:>9.1f} s  ({stop_count} stops, "
        f"mean {stop_total / max(stop_count, 1) * 1000:.0f} ms)"
    )
    waits = {}
    for r in records:
        for w in r.get("waits", []):
            total, count = waits.get(w["name"], (0.0, 0))
            waits[w["name"]] = (total + w["duration"], count + 1)
    for name, (total, count) in sorted(waits.items()):
        share = 100 * total / totals["body"] if totals["body"] else 0
        lines.append(
            f"  {name:<14} {total:>9.1f} s  ({count} calls, mean "
            f"{total / count * 1000:.0f} ms, {share:.1f}% of body)"
        )

    def overhead(record):
        return sum(phase(record, n) for n in PHASES if n != "body")

    def label(record):
        return " ".join(
            [record["test"]]
            + [
                a
                for a in record["argv"]
                if not a.startswith(
                    (
                        "--tmpdir",
                        "--portseed",
                        "--cachedir",
                        "--configfile",
                        "--phasedir",
                    )
                )
            ]
        )

    lines.append(bold("Top 20 tests by setup/teardown time"))
    for r in sorted(records, key=overhead, reverse=True)[:20]:
        lines.append(f"  {overhead(r):>7.1f} s  {label(r)}")
    lines.append(bold("Top 20 tests by body time"))
    for r in sorted(records, key=lambda r: phase(r, "body"), reverse=True)[:20]:
        lines.append(f"  {phase(r, 'body'):>7.1f} s  {label(r)}")
    print("\n".join(lines))

    with open(report_path, "w", encoding="utf8") as f:
        json.dump(
            {
                "totals": totals,
                "node_start": {"total": start_total, "count": start_count},
                "node_stop": {"total": stop_total, "count": stop_count},
                "waits": {k: {"total": t, "count": c} for k, (t, c) in waits.items()},
                "tests": records,
            },
            f,
        )
    print(f"Phase report written to {report_path}")


def print_results(test_results, tests_dir, max_len_name, runtime, combined_logs_len):
    results = bold(f"\n{'TEST':<{max_len_name}} | {'STATUS':<9} | DURATION\n\n")

    test_results.sort(key=TestResult.sort_key)
    all_passed = True
    time_sum = 0

    for test_result in test_results:
        all_passed = all_passed and test_result.was_successful
        time_sum += test_result.time
        test_result.padding = max_len_name
        results += str(test_result)

        testdir = test_result.testdir
        if combined_logs_len and os.path.isdir(testdir):
            # Print the final `combinedlogslen` lines of the combined logs
            print(
                bold(
                    f"Combine the logs and print the last {combined_logs_len} lines ..."
                )
            )
            print("\n============")
            print(bold(f"Combined log for {testdir}:"))
            print("============\n")
            combined_logs_args = [
                sys.executable,
                os.path.join(tests_dir, "combine_logs.py"),
                testdir,
            ]

            if BOLD[0]:
                combined_logs_args += ["--color"]
            combined_logs, _ = subprocess.Popen(
                combined_logs_args, universal_newlines=True, stdout=subprocess.PIPE
            ).communicate()
            print("\n".join(deque(combined_logs.splitlines(), combined_logs_len)))

    status = TICK + "Passed" if all_passed else CROSS + "Failed"
    if not all_passed:
        results += RED[1]
    results += bold(
        f"\n{'ALL':<{max_len_name}} | {status:<9} | "
        f"{TimeResolution.seconds(time_sum)} s (accumulated) \n"
    )
    if not all_passed:
        results += RED[0]
    results += f"Runtime: {TimeResolution.seconds(runtime)} s\n"
    print(results)


class Progress(NamedTuple):
    """A progress message from a running test (see test_framework/worker.py)."""

    num: int
    name: str
    event: Dict[str, Any]


class TestResult:
    """
    Simple data structure to store test result values and print them properly
    """

    def __init__(self, num, name, testdir, status, time, stdout, stderr):
        self.num = num
        self.name = name
        self.testdir = testdir
        self.status = status
        self.time = time
        self.padding = 0
        self.stdout = stdout
        self.stderr = stderr

    def sort_key(self):
        if self.status == "Passed":
            return 0, self.name.lower()
        elif self.status == "Failed":
            return 2, self.name.lower()
        elif self.status == "Skipped":
            return 1, self.name.lower()

    def __repr__(self):
        if self.status == "Passed":
            color = GREEN
            glyph = TICK
        elif self.status == "Failed":
            color = RED
            glyph = CROSS
        elif self.status == "Skipped":
            color = GREY
            glyph = CIRCLE

        return (
            f"{color[1]}{self.name:<{self.padding}} | {glyph}{self.status:<7} | "
            f"{TimeResolution.seconds(self.time)} s\n{color[0]}"
        )

    @property
    def was_successful(self):
        return self.status != "Failed"


def discover_tests(tests_dir, src_dir, test_list):
    """Import the selected test files in a separate process (importing can
    have side effects) and return {file: spec} from test_framework.discovery.
    A file with several test classes maps to its first class."""
    files = sorted(
        {
            parse_job_name(t)[0]
            for t in test_list
            if not t.startswith(SETUP_SCRIPTS_SUBDIR)
        }
    )
    if not files:
        return {}
    output = subprocess.run(
        [sys.executable, "-m", "test_framework.discovery", tests_dir] + files,
        cwd=tests_dir,
        env=dict(os.environ, SRCDIR=src_dir),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    discovered = {}
    for line in output.splitlines():
        spec = json.loads(line)
        discovered.setdefault(spec["file"], spec)
    return discovered


def get_all_scripts_from_disk(
    test_dir, non_tests: Set[str]
) -> Tuple[Set[str], Set[str]]:
    """
    Return all available test script from script directory (excluding NON_TESTS)
    """
    test_scripts = {t for t in os.listdir(test_dir) if t[-3:] == ".py"}
    setup_scripts = {
        os.path.join(SETUP_SCRIPTS_SUBDIR, t)
        for t in os.listdir(os.path.join(test_dir, SETUP_SCRIPTS_SUBDIR))
        if t[-3:] == ".py"
    }
    return test_scripts - non_tests, setup_scripts


def check_script_prefixes(all_scripts):
    """Check that no more than `EXPECTED_VIOLATION_COUNT` of the
    test scripts don't start with one of the allowed name prefixes."""
    EXPECTED_VIOLATION_COUNT = 13

    # LEEWAY is provided as a transition measure, so that pull-requests
    # that introduce new tests that don't conform with the naming
    # convention don't immediately cause the tests to fail.
    LEEWAY = 0

    good_prefixes_re = re.compile(
        "(abc_)?(example|feature|interface|mempool|mining|p2p|rpc|wallet|tool|chronik)_"
    )
    bad_script_names = [
        script for script in all_scripts if good_prefixes_re.match(script) is None
    ]

    if len(bad_script_names) < EXPECTED_VIOLATION_COUNT:
        print(
            f"{bold('HURRAY!')} Number of functional tests violating naming "
            "convention reduced!"
        )
        print(
            "Consider reducing EXPECTED_VIOLATION_COUNT from "
            f"{EXPECTED_VIOLATION_COUNT} to {len(bad_script_names)}"
        )
    elif len(bad_script_names) > EXPECTED_VIOLATION_COUNT:
        print(
            f"INFO: {len(bad_script_names)} tests not meeting naming conventions "
            f"(expected {EXPECTED_VIOLATION_COUNT}):"
        )
        formatted_bad_script_names = "\n  ".join(sorted(bad_script_names))
        print(f"  {formatted_bad_script_names}")
        assert len(bad_script_names) <= EXPECTED_VIOLATION_COUNT + LEEWAY, (
            f"Too many tests not following naming convention! ({len(bad_script_names)}"
            f" found, expected: <= {EXPECTED_VIOLATION_COUNT})"
        )


def get_tests_to_run(
    test_list, durations, discovered=None, only_variants=None, run_extended=False
):
    """
    Returns the test jobs to run: every variant of each test, unless
    only_variants[test] names some, and without the extended ones unless
    run_extended. The longest tests (from earlier runs' durations, else the
    extended ones) come first, to make the best use of parallel jobs.
    """
    known = {x["name"]: x["time"] for x in durations.existing_timings}

    # Run each test's variants: the first (default) one as "<file>", the
    # others as "<file>[<variant>]".
    jobs = []
    for test_name in test_list:
        spec = (discovered or {}).get(test_name, {})
        variants = spec.get("variants", [])
        extended = spec.get("extended", [])
        wanted = (only_variants or {}).get(test_name)
        for i, variant in enumerate(variants or [None]):
            if wanted is not None and variant not in wanted:
                continue
            if variant in extended and not run_extended:
                continue
            name = test_name if i == 0 else f"{test_name}[{variant}]"
            jobs.append((name, variant in extended))

    jobs.sort(key=lambda job: (-known.get(job[0], 0), not job[1], job[0]))
    return [name for name, _ in jobs]


class RPCCoverage:
    """
    Coverage reporting utilities for test_runner.

    Coverage calculation works by having each test script subprocess write
    coverage files into a particular directory. These files contain the RPC
    commands invoked during testing, as well as a complete listing of RPC
    commands per `bitcoin-cli help` (`rpc_interface.txt`).

    After all tests complete, the commands run are combined and diff'd against
    the complete list to calculate uncovered RPC commands.

    See also: test/functional/test_framework/coverage.py

    """

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="coverage")
        self.flag = f"--coveragedir={self.dir}"

    def report_rpc_coverage(self):
        """
        Print out RPC commands that were unexercised by tests.

        """
        uncovered = self._get_uncovered_rpc_commands()

        if uncovered:
            print("Uncovered RPC commands:")
            print("".join(f"  - {i}\n" for i in sorted(uncovered)))
            return False
        else:
            print("All RPC commands covered.")
            return True

    def cleanup(self):
        return shutil.rmtree(self.dir)

    def _get_uncovered_rpc_commands(self):
        """
        Return a set of currently untested RPC commands.

        """
        # This is shared from `test/functional/test_framework/coverage.py`
        reference_filename = "rpc_interface.txt"
        coverage_file_prefix = "coverage."

        coverage_ref_filename = os.path.join(self.dir, reference_filename)
        coverage_filenames = set()
        all_cmds = set()
        # Consider RPC generate covered, because it is overloaded in
        # test_framework/test_node.py and not seen by the coverage check.
        covered_cmds = set({"generate"})

        if not os.path.isfile(coverage_ref_filename):
            raise RuntimeError("No coverage reference found")

        with open(coverage_ref_filename, "r", encoding="utf8") as file:
            all_cmds.update([line.strip() for line in file.readlines()])

        for root, _, files in os.walk(self.dir):
            for filename in files:
                if filename.startswith(coverage_file_prefix):
                    coverage_filenames.add(os.path.join(root, filename))

        for filename in coverage_filenames:
            with open(filename, "r", encoding="utf8") as file:
                covered_cmds.update([line.strip() for line in file.readlines()])

        return all_cmds - covered_cmds


def save_results_as_junit(test_results, file_name, time, test_suite_name):
    """
    Save tests results to file in JUnit format

    See http://llg.cubic.org/docs/junit/ for specification of format
    """
    e_test_suite = ET.Element(
        "testsuite",
        {
            "name": f"{test_suite_name}",
            "tests": str(len(test_results)),
            # "errors":
            "failures": str(len([t for t in test_results if t.status == "Failed"])),
            "id": "0",
            "skipped": str(len([t for t in test_results if t.status == "Skipped"])),
            "time": str(TimeResolution.milliseconds(time)),
            "timestamp": datetime.datetime.now().isoformat("T"),
        },
    )

    for test_result in test_results:
        e_test_case = ET.SubElement(
            e_test_suite,
            "testcase",
            {
                "name": test_result.name,
                "classname": test_result.name,
                "time": str(TimeResolution.milliseconds(test_result.time)),
            },
        )
        result = job_result_of(test_result)
        if test_result.status == "Skipped":
            ET.SubElement(e_test_case, "skipped", {"message": result.skip_reason or ""})
        elif test_result.status == "Failed":
            failure = result.failure or {}
            e_failure = ET.SubElement(
                e_test_case,
                "failure",
                {
                    "type": failure.get("type", result.status),
                    "message": failure.get("message", ""),
                },
            )
            e_failure.text = failure.get("traceback", "")
        # no special element for passed tests
        if result.phases:
            e_properties = ET.SubElement(e_test_case, "properties")
            for phase in result.phases:
                ET.SubElement(
                    e_properties,
                    "property",
                    {
                        "name": f"phase.{phase['name']}",
                        "value": f"{phase['duration']:.3f}",
                    },
                )

        ET.SubElement(e_test_case, "system-out").text = test_result.stdout
        ET.SubElement(e_test_case, "system-err").text = test_result.stderr

    ET.ElementTree(e_test_suite).write(file_name, "UTF-8", xml_declaration=True)


class Timings:
    """
    Takes care of loading, merging and saving tests execution times.
    """

    def __init__(self, timing_file):
        self.timing_file = timing_file
        self.existing_timings = self.load_timings()

    def load_timings(self):
        if os.path.isfile(self.timing_file):
            with open(self.timing_file, encoding="utf8") as file:
                return json.load(file)
        else:
            return []

    def get_merged_timings(self, new_timings):
        """
        Return new list containing existing timings updated with new timings
        Tests that do not exists are not removed
        """

        key = "name"
        merged = {}
        for item in self.existing_timings + new_timings:
            if item[key] in merged:
                merged[item[key]].update(item)
            else:
                merged[item[key]] = item

        # Sort the result to preserve test ordering in file
        merged = list(merged.values())
        merged.sort(key=lambda t, key=key: t[key])
        return merged

    def save_timings(self, test_results):
        # we only save test that have passed - timings for failed test might be
        # wrong (timeouts or early fails), and we exclude the tests that require
        # extra privileges.
        passed_results = [
            test
            for test in test_results
            if test.status == "Passed" and test.name not in EXTRA_PRIVILEGES_TESTS
        ]
        new_timings = [
            {"name": test.name, "time": TimeResolution.seconds(test.time)}
            for test in passed_results
        ]
        merged_timings = self.get_merged_timings(new_timings)

        with open(self.timing_file, "w", encoding="utf8") as file:
            json.dump(merged_timings, file, indent=True)


class TimeResolution:
    @staticmethod
    def seconds(time_fractional_second):
        return round(time_fractional_second)

    @staticmethod
    def milliseconds(time_fractional_second):
        return round(time_fractional_second, 3)


if __name__ == "__main__":
    main()
