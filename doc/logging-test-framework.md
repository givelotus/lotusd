# Functional-test logs

Every `TestNode` process writes generic JSON records to
`debug-framework.jsonl` in its chain directory, alongside its normal log.
Tests exercising another primary format keep that format. An explicit
`-debuglogjsonfile` overrides the sidecar path. Paths are absolute in the
process arguments, so a test's working directory does not change their meaning.

`assert_debug_log` accepts strings or dictionaries; `wait_for_debug_log` accepts
bytes or dictionaries. Existing substring checks keep their exact text/byte
semantics. A dictionary matches a subset of **one** JSON record, recursively:

```python
with node.assert_debug_log([
    {"event": "peer_connected", "peer_id": 7},
    {"source": {"function": "UpdateTipLog"}},
]):
    trigger_action()
```

Matching fields from separate records never satisfies one dictionary. Booleans
are distinct from numeric values. Helpers snapshot both log offsets before the
action, then allow the asynchronous logger its full timeout after the action.
For a live RPC connection, each helper first calls the existing `logging` RPC
to flush older queued records before taking offsets. A stopped process needs no
RPC barrier. JSON-only nodes do not require a text log file, and a new sidecar
path selected during startup begins at offset zero. Only complete JSON lines
are parsed while the process is running; malformed
complete records fail rather than silently disappearing.

Graceful process exit asks the logger worker to drain, write an unfiltered
`logger_shutdown` record with the cumulative integer `dropped_lines` counter,
and exit before its thread-local encoder buffers are destroyed.
The internal final counter is written directly to sinks without print callbacks,
so callbacks cannot enqueue more records after the final count. The framework
checks only records appended by the current process lifetime.
Any nonzero summary or written overflow notice fails the test explicitly.
A successfully started process exiting normally must provide the summary.
This also protects tests using a custom primary log filename.

Expected initialization failures and intentional abnormal exits cannot always
write a final record. They do not require a summary, but any written drop notice
or nonzero summary still fails. An absent notice after an abrupt crash does not
prove that no logging was lost. Debug/info floods may drop in production; the
framework treats that as insufficient evidence for a passing functional test.
Warnings and errors retain their separate full-ring delivery guarantee.
