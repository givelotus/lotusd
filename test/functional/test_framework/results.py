#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The result of running one functional test job, as the test runner reports it.

Workers send a JobResult to the runner; reporters (console, JSON lines,
JUnit) render it. The JSON form is versioned by SCHEMA_VERSION and documented
in test/functional/README-runner-output.md.
"""

import dataclasses
import json
import unittest
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1

PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"
TIMEOUT = "timeout"
CRASHED = "crashed"
STATUSES = (PASSED, FAILED, SKIPPED, TIMEOUT, CRASHED)

# Lines of captured output kept in a result (the full output stays on disk)
TAIL_LINES = 200


def tail(text: str, lines: int = TAIL_LINES) -> str:
    return "\n".join(text.splitlines()[-lines:])


@dataclasses.dataclass
class JobResult:
    # Display name, e.g. "rpc_bind.py[ipv4]" or "wallet_basic.py"
    name: str
    file: str
    status: str
    exit_code: Optional[int] = None
    class_name: str = ""
    variant: str = ""
    settings: Dict[str, str] = dataclasses.field(default_factory=dict)
    # Seconds since the epoch, and seconds
    start_time: float = 0.0
    duration: float = 0.0
    phases: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    skip_reason: Optional[str] = None
    # {"type", "message", "traceback"}
    failure: Optional[Dict[str, str]] = None
    tmpdir: str = ""
    framework_log: str = ""
    node_logs: List[str] = dataclasses.field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    stderr_nonempty: bool = False

    def __post_init__(self):
        assert self.status in STATUSES, self.status

    @property
    def was_successful(self) -> bool:
        return self.status in (PASSED, SKIPPED)

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["schema"] = SCHEMA_VERSION
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "JobResult":
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in fields})


class TestJobResult(unittest.TestCase):
    def test_round_trip(self):
        result = JobResult(
            name="rpc_bind.py[ipv4]",
            file="rpc_bind.py",
            status=FAILED,
            exit_code=1,
            variant="ipv4",
            failure={"type": "AssertionError", "message": "x", "traceback": "tb"},
        )
        d = json.loads(result.to_json())
        self.assertEqual(d["schema"], SCHEMA_VERSION)
        self.assertEqual(JobResult.from_dict(d), result)
        self.assertFalse(result.was_successful)

    def test_status_validated(self):
        with self.assertRaises(AssertionError):
            JobResult(name="x.py", file="x.py", status="weird")
        for status in (PASSED, SKIPPED):
            self.assertTrue(JobResult(name="x", file="x", status=status).was_successful)

    def test_tail(self):
        text = "\n".join(str(i) for i in range(500))
        self.assertEqual(tail(text, 3), "497\n498\n499")
