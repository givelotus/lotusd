# Functional test runner: structured results

`test_runner.py` keeps one result per test job (a test file, with its
arguments). The result is defined by `JobResult` in
`test_framework/results.py`; its JSON form carries `"schema": 1`. Fields may
be added in a later schema version, but existing fields keep their meaning.

| Field | Type | Meaning |
|---|---|---|
| `schema` | int | Version of this format (1) |
| `name` | str | Display name, e.g. `wallet_basic.py` or `rpc_bind.py --ipv4` |
| `file` | str | Test file, relative to `test/functional` |
| `class_name` | str | Test class that ran |
| `variant` | str | Variant name, empty for the default |
| `settings` | object | Shared settings, e.g. `{"transport": "tcp"}` |
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
