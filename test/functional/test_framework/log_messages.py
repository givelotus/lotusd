# Copyright (c) 2026 The Lotus developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pure JSON log parsing and matching, shared by node helpers and their tests."""

import json
import re


def read_records(path, offset=0):
    """Read complete JSON lines; an asynchronous writer may leave a partial tail."""
    if not path.exists():
        return []
    with path.open("rb") as stream:
        stream.seek(offset)
        raw = stream.read()
    records = []
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise AssertionError(f"JSON log record is not an object: {record!r}")
        records.append(record)
    return records


def matches_fields(record, expected):
    """A nested dict is a subset of one record; booleans are not numbers."""
    for key, value in expected.items():
        if key not in record:
            return False
        actual = record[key]
        if isinstance(value, dict):
            if not isinstance(actual, dict) or not matches_fields(actual, value):
                return False
        elif isinstance(actual, bool) != isinstance(value, bool) or actual != value:
            return False
    return True


def has_message(expected, text, records):
    if isinstance(expected, dict):
        return any(matches_fields(record, expected) for record in records)
    if isinstance(text, bytes) and isinstance(expected, str):
        expected = expected.encode()
    return expected in text


def assert_no_drops(records, *, require_summary=False):
    """Check only one process lifetime, never an earlier run's appended records."""
    summaries = [r for r in records if r.get("event") == "logger_shutdown"]
    for record in records:
        count = record.get("dropped_lines")
        if record.get("event") == "logger_shutdown":
            if type(count) is not int or count < 0:
                raise AssertionError(
                    f"Invalid logger shutdown drop counter: {record!r}"
                )
            if count:
                raise AssertionError(
                    f"Logger dropped {count} debug/info lines: {record!r}"
                )
        # Also catch notices from an intentionally killed process with no summary.
        message = record.get("message", "")
        if re.search(
            r"Logging could not keep up: [1-9][0-9]* debug/info log lines were dropped",
            message,
        ):
            raise AssertionError(f"Logger dropped lines: {message}")
    if require_summary and not summaries:
        raise AssertionError(
            "Missing logger_shutdown drop counter after graceful node exit"
        )
