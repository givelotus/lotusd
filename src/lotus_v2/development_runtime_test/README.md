# Development runtime integration checks

This isolated target exercises the socket-free `DevelopmentRuntime` controller
against actual complete blocks, the V4 LevelDB store, candidate selector, bounded
body pool and recovery coordinator. It starts no node, socket or listener and
selects no launch defaults. Every home has an explicit existing development
profile, genesis and local storage/pool quotas.

`fixtures.h` copies the immutable corpus and bounded fixture helpers from
`test_reorg_recovery.cpp` at `f93ea73fd`. Original reference revisions, manifest
and generator digests remain recorded. Source branches enter storage through
complete-block validation. Replacement branches enter the volatile pool only;
framing authentication is not contextual block acceptance. The pool has exactly
three slots for the three replacement bodies and never receives source bodies.

## Coverage

- Select a strictly heavier real fork and require a fresh observation after body
  eviction/reinsertion or an indexed header revision. Header insertion during a
  bounded partial scan preserves inventory epochs and eventually completes when
  insertion stops.
- Complete two detaches and three attaches; report the terminal receipt gate and
  acknowledge it in a separate tick. Check exact reference monetary state, roots,
  touched CoinEntries/proofs, retained connected bytes and active headers.
- Reject the deterministic invalid middle replacement, restore the exact original
  source metadata/root/coins, acknowledge its receipt, then propagate causal
  invalidity in bounded separate ticks. Source restoration works after all pool
  replacements are evicted following journal preparation; its bodies come from
  retained disk data.
- Pause an operational host-step guard with the journal intact and no invalidity
  fact. Explicit retry and a fresh runtime preserve the checkpoint and raw journal
  bytes. No unsupported opcode or alternate issuance value is invented.
- Inject a reported I/O failure after a genuinely successful synchronous WAL
  write. Drop cached authority, reopen in a separate tick, observe the durable
  first-detach checkpoint and resume without duplicating that transition.
- Refuse reentry from the storage callback, preserve outputs, enforce operational
  pool/query caps, and refuse exhausted availability/context counters before
  mutation or wraparound.

Usage checks remain per component: selector rows/Gets/iterator/decoded bytes,
propagation bounds and at most one recovery call per tick. Complete VM validation,
undo, caches, storage copies and backend work retain their own existing bounds;
the test does not claim a combined global VM/read budget or measured performance.

## Build and evidence

The source packet is based on `f93ea73fd`; the frozen runtime prerequisite is
`d3e86735b` (root integration `86676b778`). Strict Debug and targeted
AddressSanitizer/UndefinedBehaviorSanitizer executions pass. Sanitizers cover the
runtime/test and disk-state boundary, targeting callback reentry and ownership
through failed writes, reopening and destruction. Bundled backend/crypto sources
retain their own build instrumentation.

```sh
cmake -S src/lotus_v2/development_runtime_test -B /tmp/lotus-v2-runtime-debug \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/lotus-v2-runtime-debug --target development_runtime_test
ctest --test-dir /tmp/lotus-v2-runtime-debug \
  -R '^development_runtime_test$' --output-on-failure
```

Use `-DCMAKE_BUILD_TYPE=Release` in another directory for the Release check, or
`-DLOTUS_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug` for the targeted sanitizer check.
The shared full-tree build registration is owned separately by integration.
