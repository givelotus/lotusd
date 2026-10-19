#!/usr/bin/env python3
# Copyright (c) 2017-2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Combine logs from multiple bitcoin nodes as well as the test_framework log.

This streams the combined log output to stdout. Use combine_logs.py > outputfile
to write to an outputfile.

If no argument is provided, the most recent test directory will be used."""

import argparse
import itertools
import os
import pathlib
import sys
import tempfile
from collections import defaultdict, namedtuple

# N.B.: only import test_framework.timeline, which uses only the standard
# library, so that this script remains executable without the rest of the
# framework (e.g. its build configuration).
from test_framework import timeline

# Should match same symbol in `test_framework.test_framework`.
TMPDIR_PREFIX = "bitcoin_func_test_"

# Matches on the date format at the start of the log event
TIMESTAMP_PATTERN = timeline.TIMESTAMP_PATTERN

LogEvent = namedtuple("LogEvent", ["timestamp", "source", "event"])


def main():
    """Main function. Parses args, reads the log files and renders them as text or html."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "testdir",
        nargs="?",
        default="",
        help=(
            "temporary test directory to combine logs from. Defaults to the most recent"
        ),
    )
    parser.add_argument(
        "-c",
        "--color",
        dest="color",
        action="store_true",
        help=(
            "outputs the combined log with events colored by "
            "source (requires posix terminal colors. Use less"
            " -r for viewing)"
        ),
    )
    parser.add_argument(
        "--html",
        dest="html",
        action="store_true",
        help="outputs the combined log as html. Requires jinja2. pip install jinja2",
    )
    args = parser.parse_args()

    if args.html and args.color:
        print("Only one out of --color or --html should be specified")
        sys.exit(1)

    testdir = args.testdir or find_latest_test_dir()

    if not testdir:
        print("No test directories found")
        sys.exit(1)

    if not args.testdir:
        print(f"Opening latest test directory: {testdir}", file=sys.stderr)

    colors = defaultdict(lambda: "")
    if args.color:
        colors["test"] = "\033[0;36m"  # CYAN
        colors["node0"] = "\033[0;34m"  # BLUE
        colors["node1"] = "\033[0;32m"  # GREEN
        colors["node2"] = "\033[0;31m"  # RED
        colors["node3"] = "\033[0;33m"  # YELLOW
        colors["reset"] = "\033[0m"  # Reset font color

    log_events = read_logs(testdir)

    if args.html:
        print_logs_html(log_events)
    else:
        print_logs_plain(log_events, colors)
        print_node_warnings(testdir, colors)


def read_logs(tmp_dir):
    """Reads log files.

    The framework's and the nodes' text logs, merged by timestamp (see
    test_framework/timeline.py). Events with the same timestamp keep the
    order of their log files."""
    framework_log = os.path.join(tmp_dir, "test_framework.log")
    if not os.path.isfile(framework_log):
        print(
            f"File {framework_log} could not be opened. Continuing without it.",
            file=sys.stderr,
        )
    return (to_log_event(event) for event in timeline.read_timeline(tmp_dir, False))


def to_log_event(event):
    """A timeline event as this script prints it: continuation lines are
    indented to align with the source and timestamp."""
    lines = event.raw.split("\n")
    text = "\n".join(
        [lines[0]]
        + [f"                                   {line}" for line in lines[1:]]
    )
    return LogEvent(timestamp=event.time, source=event.source, event=text.rstrip())


def print_node_warnings(tmp_dir, colors):
    """Print nodes' errors and warnings"""

    warnings = []
    for stream in ["stdout", "stderr"]:
        for i in itertools.count():
            folder = f"{tmp_dir}/node{i}/{stream}"
            if not os.path.isdir(folder):
                break
            for _, _, fns in os.walk(folder):
                for fn in fns:
                    warning = pathlib.Path(f"{folder}/{fn}").read_text().strip()
                    if warning:
                        warnings.append((f"node{i} {stream}", warning))

    print()
    for w in warnings:
        print(f"{colors[w[0].split()[0]]} {w[0]} {w[1]} {colors['reset']}")


def find_latest_test_dir():
    """Returns the latest tmpfile test directory prefix."""
    tmpdir = tempfile.gettempdir()

    def join_tmp(basename):
        return os.path.join(tmpdir, basename)

    def is_valid_test_tmpdir(basename):
        fullpath = join_tmp(basename)
        return (
            os.path.isdir(fullpath)
            and basename.startswith(TMPDIR_PREFIX)
            and os.access(fullpath, os.R_OK)
        )

    testdir_paths = [
        join_tmp(name) for name in os.listdir(tmpdir) if is_valid_test_tmpdir(name)
    ]

    return max(testdir_paths, key=os.path.getmtime) if testdir_paths else None


def get_log_events(source, logfile):
    """Generator function that returns individual log events.

    Log events may be split over multiple lines. We use the timestamp
    regex match as the marker for a new log event."""
    if not os.path.isfile(logfile):
        print(
            f"File {logfile} could not be opened. Continuing without it.",
            file=sys.stderr,
        )
        return
    for event in timeline.text_events(source, logfile):
        yield to_log_event(event)


def print_logs_plain(log_events, colors):
    """Renders the iterator of log events into text."""
    for event in log_events:
        lines = event.event.splitlines()
        print(
            f"{colors[event.source.rstrip()]} {event.source: <5} "
            f"{lines[0]} {colors['reset']}"
        )
        if len(lines) > 1:
            for line in lines[1:]:
                print(f"{colors[event.source.rstrip()]}{line}{colors['reset']}")


def print_logs_html(log_events):
    """Renders the iterator of log events into html."""
    try:
        import jinja2
    except ImportError:
        print("jinja2 not found. Try `pip install jinja2`")
        sys.exit(1)
    print(
        jinja2.Environment(loader=jinja2.FileSystemLoader("./"))
        .get_template("combined_log_template.html")
        .render(
            title="Combined Logs from testcase",
            log_events=[event._asdict() for event in log_events],
        )
    )


if __name__ == "__main__":
    main()
