# Native V2 confirmed indexing adapter

`ChronikSync(runtime, sink, chain_id, transaction_profile, max_body_bytes)`
performs bounded `Step(error)` calls until `Ready`. `Progress` requires another
step. `Unavailable` means native authority is recovering, paused, or unknown;
`Error` means query availability must stay disabled. No result mutates consensus.

The caller serializes all runtime/index operations. Before **every runtime
mutation**, call `V2Service::invalidate_authority`. Publish the stable native
anchor with `publish_authority` only after `Step` returns `Ready`, with no runtime
mutation between observation and publication. Every step queries the current stable tip and active height mapping. Recovery journal, receipt, and propagation fences suppress
indexing. The sink's durable indexed checkpoint is mandatory, including restart.

Define `LOTUS_V2_CHRONIK_CXX` and provide generated CXX include directories and
Rust library linkage to enable `CxxChronikSink`, which directly calls the real
V2 service. The isolated test uses a recording sink and the actual native
DevelopmentRuntime, LevelDB storage, complete-connect fixtures, and wire codec.
It checks complete genesis (including burn), catchup, restart checkpoint,
ancestry-based two-block divergent suffix removal, replacement child connection,
index-error consensus isolation, authenticated transaction/output conversion,
nonzero spend ordinals with a preceding mint input, and tamper rejection.

Each step makes at most two active header queries returning at most one header
each (or one active query and one genesis header read), reads one body at most,
and changes at most one indexed block. Runtime snapshots/store internals have
their existing creation limits; this is not a bound on LevelDB internal work.
Catchup uses the active-height index directly. Divergent checkpoints are removed
one at a time until they match active ancestry. Both paths use linear step
counts and constant path memory; tests assert exact counts for initial catchup,
restart, replacement, a five-block rollback to genesis, and renewed catchup. No candidate or invalid body is indexed: only stable active
ancestry and `ReadConnectedBody` bytes enter conversion.

Build:

```
cmake -S src/lotus_v2/chronik_sync_test -B build-chronik-sync -G Ninja \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a \
  -DLOTUS_BOOST_INCLUDE=/path/to/boost/include
cmake --build build-chronik-sync --target chronik_sync_test
ctest --test-dir build-chronik-sync -R '^chronik_sync_test$' --output-on-failure
```
