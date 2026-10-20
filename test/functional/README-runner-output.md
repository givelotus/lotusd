# Functional test runner: structured results

`test_runner.py` keeps one result per test job (a test file, with its
arguments). The result is defined by `JobResult` in
`test_framework/results.py`; its JSON form carries `"schema": 2`. Fields may
be added in a later schema version, but existing fields keep their meaning.
Schema 2 added `timeline`.

| Field | Type | Meaning |
|---|---|---|
| `schema` | int | Version of this format (2) |
| `name` | str | Display name: the file, its variant in brackets, then any extra arguments, e.g. `wallet_basic.py`, `rpc_bind.py[ipv4]` |
| `file` | str | Test file, relative to `test/functional` |
| `class_name` | str | Test class that ran |
| `variant` | str | Variant name, empty for the default |
| `settings` | object | Reserved for settings shared by all tests; always `{}` for now |
| `status` | str | `passed`, `failed`, `skipped`, `timeout` or `crashed` |
| `exit_code` | int or null | The test's exit code (null if it never returned one) |
| `start_time` | float | Start, in seconds since the epoch |
| `duration` | float | Seconds |
| `phases` | list | `{"name", "duration"}` per phase: `chain_init`, `network_setup`, `body`, `final_stop`, `cleanup` |
| `skip_reason` | str or null | Why the test skipped |
| `failure` | object or null | `{"type", "message", "traceback"}`; `type` is the exception class, or `stderr` when a test passed but wrote to stderr |
| `tmpdir` | str | The test's directory, kept when it fails |
| `framework_log` | str | Path of its `test_framework.log` |
| `node_logs` | list | Paths of the nodes' `debug.log` |
| `timeline` | str | Path of the test's `timeline.jsonl` (see below), or empty: written for every failed test, and for passing tests with `--timeline` |
| `stdout_tail`, `stderr_tail` | str | The last 200 lines of the test's stdout and stderr |
| `stderr_nonempty` | bool | Whether the test wrote anything to stderr |

`passed` and `skipped` count as success; any other status fails the run.

## JSON lines (`--jsonl-file=FILE`)

One JSON object per line, each with `"event"` and `"schema": 1` (the
version of these events; a `finish` event's `result` has its own `schema`):

- `{"event": "start", "name": ...}` when a test starts;
- `{"event": "phase", "name": ..., "phase": ...}` as each of the test's phases
  starts (`chain_init`, `network_setup`, `body`, `final_stop`, `cleanup`);
- `{"event": "log", "name": ..., "time": ..., "level": ..., "logger": ...,
  "message": ...}` for each line the test logs at INFO or above;
- `{"event": "finish", "result": {...}}` when it finishes, with the result above;
- `{"event": "summary", ...}` once at the end, with the summary below.

Events of tests running at the same time interleave; `name` says which test
each is about. With `--jsonl-file=-` the events go to standard output, which
then carries nothing else: the usual console output goes to standard error.

## Console

On an interactive terminal (and not on CI), the bottom of the screen shows
the run's progress and one line per running test: its phase, how long it has
been running and the last line it logged. Finished tests and failure details
are printed above it. Otherwise each test prints a line when it starts and
when it finishes.

### Failure details

For a failed test the runner prints, once each:

- the traceback (or the failure message), and the test's stderr if it is not
  already the failure;
- the end of the test's **log timeline**: the framework log and every node's
  `debug.log` merged by time, up to and including the line where the
  framework logged the exception (only that line: the traceback is above),
  at most 40 lines. Without a logged exception (a timeout, a crash), the
  last 40 lines. Each line starts with its source (`test`, `node0`, ...), in
  a fixed-width column, then the time of day; node lines show the category,
  and warnings and errors their level, without the source location:

  ```
  test   12:00:01.123000 Mining 10 blocks
  node0  12:00:01.130211 [net] received: inv (37 bytes) peer=0
  node1  12:00:01.131002 WARNING [validation] ...
  test   12:00:02.004000 ERROR Unexpected exception
  ```
- the test directory, the command that reruns the test, `combined.log` and
  `timeline.jsonl`.

Where a log has structured records (a node's JSON sidecar, the framework's
`test_framework.jsonl`), a timeline line also shows a few identifying fields
compactly, e.g. `{event=p2p_message peer_id=0 txid=1f2e…}`.

`<test directory>/combined.log` is the whole timeline as plain text, written
when the test fails: the text logs (`test_framework.log` and each node's
`debug.log`) merged by time, each line prefixed by its source, continuation
lines (e.g. tracebacks) indented under their event. A node line's
`(mocktime: ...)` does not affect the order: lines are ordered by their
wall-clock timestamp, and lines with the same timestamp keep the order of
their file (the framework first, then the nodes by number). Lines before a
log's first timestamp are shown with the time they are ordered by.

`test_framework/timeline.py` builds both in constant memory:

- the timeline excerpt reads only the end of each log: the framework log
  backwards to the logged exception, and each node's log up to that time,
  found by binary search (the logs are in time order). It takes a few
  milliseconds whatever the size of the logs;
- `combined.log` is merged in large binary blocks, comparing the
  timestamps as bytes (fixed-width ISO 8601 with microseconds sorts
  correctly as bytes), without parsing lines; only blocks with lines that
  do not start with such a timestamp are parsed line by line. About 500
  MB/s of CPU time on an Apple M-series core.

For an HTML version of the text logs, run
`combine_logs.py --html <test directory> > combined.html` (needs `jinja2`).

## Structured timeline (`timeline.jsonl`)

`<test directory>/timeline.jsonl` has one JSON object per log event of the
test, from every source, sorted by `time`. It is written for every failed
test (by the runner, after the test's processes have stopped; a test run on
its own writes it at shutdown), and also for passing tests with
`--timeline` (on the runner or on the test), in which case the cleanup of
the test directory keeps that file.

Every record has:

| Key | Meaning |
|---|---|
| `time` | RFC 3339, UTC, with microseconds (the wall clock; `mocktime` is a separate field) |
| `source` | `test` for the framework, `node0`, `node1`, ... for the nodes |
| `level` | `trace`, `debug`, `info`, `warning` or `error` |
| `message` | The human-readable message; for the framework, without the traceback |

and then the record's own fields under their own names:

- A node record comes from its JSON sidecar, `debug-framework.jsonl` (see
  `doc/logging-test-framework.md`), and keeps its fields as the node wrote
  them, i.e. under their field-registry names (`category`, `thread`,
  `event`, `peer_id`, `txid`, `mocktime`, ...). The one exception: the
  node's source-location object, `source`, is renamed `source_location`,
  since `source` names the process. A node without a sidecar is read from
  `debug.log`, and its records have `category`, `thread`, `mocktime` and
  `source_location` when the line has them; their `level` is the line's,
  or `debug` for a categorized line and `info` otherwise, as bitcoind
  logs them.
- A framework record comes from `test_framework.jsonl`, which the framework
  writes next to `test_framework.log` (compact JSON, `time` first, like the
  nodes'): `category` (the logger, e.g.
  `TestFramework.node0`), `thread`, `source_location` (`file`, `line`,
  `function`), `exception` (the traceback, when one was logged), and any
  fields a test passes with `self.log.info(..., extra={"fields": {...}})`.

`test_framework/timeline.py` builds it in constant memory, merging the JSON
logs in large binary blocks without parsing records. Every record of the
nodes' sidecars and of `test_framework.jsonl` starts with the same fixed
prefix, `{"time":"<27-byte timestamp>","level":"`: the timestamps are
compared as bytes, `"source":"<source>"` is inserted after the time and the
node's `"source":{` object renamed with byte replacements (a JSON string
cannot contain an unescaped quote, so these sequences only occur as keys).
Blocks with any other line (a partial record, or another writer) are
parsed record by record, with the same result. About 300 MB/s of CPU time
on an Apple M-series core.

That prefix is what the nodes' JSON encoder writes today: the sidecar has
one write path, with timestamps and microseconds always on, and the
encoder writes `time` then `level` first. It is not a documented format
guarantee; if it changes, the merge is still correct, only slower.

`timeline.check_timeline(path)` checks that a file has the required keys
in time order. Events of one source written slightly out of time order
(the node logs asynchronously) are reordered within a block of about 4 MB.

## Summary (`--json-summary=FILE`)

`{"schema": 1, "wall_time": s, "accumulated_time": s, "counts": {status: n}, "failed": [names]}`

## JUnit (`--junitoutput=FILE`)

As before, plus:
- `<skipped message="reason">`;
- `<failure type message>traceback</failure>`;
- `<properties>` with `phase.<name>` durations when the test reported them.
