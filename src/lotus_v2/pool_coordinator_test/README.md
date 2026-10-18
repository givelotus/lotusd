# Pool coordinator review target

The coordinator borrows a serialized `DevelopmentRuntime` and owns a volatile
transaction pool plus a separate, derived LevelDB transaction index. Set its
`directory` to `<nodehome>/chainstate-v2/transaction-index` and supply the exact
runtime identity, profile digest and profiles. The caller must keep the runtime
and any optional `history_env` alive and must not mutate/reenter them during a
coordinator operation.

`Tick` queries bounded active headers and commits at most the supplied number
of history block transitions. Each history connect
or undo atomically synchronizes confirmations, spent outpoints and the durable
tip. Before publishing, the pool rebuilds against the current quiescent runtime
tip and generation. Journal, receipt, propagation, paused execution, reopen and
anchor changes suppress status, admission and transaction relay until a
successful tick. Reconciliation stages validation across ticks without exposing
a partial pool; changing the runtime anchor restarts staging. Runtime generations are process-local fences, not durable
history keys; reopening always requires synchronization before publication.

Initial indexing connects genesis and advances along bounded active-header
queries. Each history transition commits durably before the next one. Reorgs
undo one inactive history tip at a time until the active common ancestor, then
advance forward. `max_path` limits transitions in each tick, independently of
chain height; a chain longer than this limit completes across multiple ticks
and survives coordinator restart between chunks. Detached wire overflow returns
explicit `Capacity` and keeps publication disabled. This target does not
implement index pruning or migration.
Status uses indexed TxID/TxHash/block/height records and exact spend mappings;
missing/spent coins alone never establish confirmation. Ordinary detached
transactions are retained in block parent order and reconciled after the new
index reaches its runtime anchor.

Build the standalone target after integrating its transaction pool dependency:

```sh
cmake -S src/lotus_v2/pool_coordinator_test -B /tmp/lotus-v2-pool-coordinator-build \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a \
  -DLOTUS_BOOST_INCLUDE=/path/to/boost/include
cmake --build /tmp/lotus-v2-pool-coordinator-build --target pool_coordinator_test
ctest --test-dir /tmp/lotus-v2-pool-coordinator-build -R '^pool_coordinator_test$' --output-on-failure
```

`LOTUS_POOL_SOURCE` can point to a separate reviewed directory containing
`transaction_pool.{h,cpp}` while the owning work is awaiting integration.
The test uses temporary development chains only. It covers budget refusal,
pending/confirmed/conflicted/unknown status, multiple pending survivors with one
validation per tick, witness mismatch, exact durable
confirmation after outputs are spent, restart fencing, replacement-chain
conflicts, pending input conflicts, bounded transaction serving, durable indexing beyond the per-tick ancestry chunk and
detached overflow, paused execution, and storage failures. An injected failure
after a real durable LevelDB sync verifies ambiguous-write poisoning and reopen
recovery, including exact restoration of predecessor transaction/spend mappings.
This is local development validation, not network or production testing.
