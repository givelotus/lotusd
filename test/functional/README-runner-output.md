# Functional test runner: structured results

`test_runner.py` keeps one result per test job (a test file, with its
arguments). The result is defined by `JobResult` in
`test_framework/results.py`; its JSON form carries `"schema": 1`. Fields may
be added in a later schema version, but existing fields keep their meaning.

| Field | Type | Meaning |
|---|---|---|
| `schema` | int | Version of this format (1) |
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
| `stdout_tail`, `stderr_tail` | str | The last 200 lines of the test's stdout and stderr |
| `stderr_nonempty` | bool | Whether the test wrote anything to stderr |

`passed` and `skipped` count as success; any other status fails the run.

## JSON lines (`--jsonl-file=FILE`)

One JSON object per line, each with `"event"` and `"schema": 1`:

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
- the test directory, the command that reruns the test, and `combined.log`.

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

For an HTML version of the same logs, run
`combine_logs.py --html <test directory> > combined.html` (needs `jinja2`).

## Summary (`--json-summary=FILE`)

`{"schema": 1, "wall_time": s, "accumulated_time": s, "counts": {status: n}, "failed": [names]}`

## JUnit (`--junitoutput=FILE`)

As before, plus:
- `<skipped message="reason">`;
- `<failure type message>traceback</failure>`;
- `<properties>` with `phase.<name>` durations when the test reported them.
