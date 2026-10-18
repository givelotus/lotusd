# V4 terminal receipt integration checks

The same test executable retains the V3 cases and repeats the real divergent
complete-block fixtures in an explicitly configured V4 home. The test-only
candidate quotas are 64 retained candidates, 64 speculative headers and eight
invalid roots. These are local fixture limits; no network profile is selected.

Terminal tests reopen after journal clearing and require a durable receipt bound
to the stable tip, root and validator profile. Completed targets, deferred clock
restorations and operational source-detach restorations carry no invalidity fact.
The deterministic missing-coin middle replacement carries the exact failed block,
parent, profile and historical parent UTXO root. That historical root is checked
against the accepted replacement parent and differs from the restored source root.

Wrong receipt IDs and stable tips cannot acknowledge a receipt. Correct
acknowledgement survives reopen and an exact retry is idempotent. Deterministic
acknowledgement establishes the causal failed root, then bounded propagation
excludes its retained child while preserving the valid replacement parent and
source. Storage's separate mechanical suite covers an older acknowledgement
against a newer pending receipt and ambiguous database writes.

The host-step guard fixture also runs in V4: inconclusive target validation leaves
the raw journal, authenticated checkpoint and progress unchanged across retry and
reopen, with no terminal receipt or invalidity fact. Both modes retain the exact
prepared-journal creation/per-call cap regression for operational source-detach
restoration.

Local corruption fixtures change the enclosed journal mode/version or the fixed
V4 evidence version/presence fields. Evidence mutations recompute the local
journal checksum so the canonical typed decoder itself rejects malformed evidence.
They also corrupt historical parent/root/profile tuples captured from an actual
deterministic validation failure. They preserve the storage checkpoint wrapper
and consensus body bytes, leave the journal pending and never reconstruct an
untrusted terminal fact. The local checksum detects corruption; it is not a MAC
or an adversarial local-database authentication boundary. These are module/storage
integration checks, not selector-ranking, socket or network synchronization tests.

## Validation evidence

The focused test packet is based on `e8914e477`. Frozen runtime prerequisites are
V4 storage `13e4a138e` (root integration `3ed3c26ed`), receipt coordinator
`3e79d498a`, and the root-owned CMake wiring for `candidate_store.cpp`.

The strict Debug standalone recovery executable passes with those exact runtime
sources. The coordinator owner independently copied the same test source and
reported Release 2/2 passing (45.23 seconds including the storage suite). Existing
V3 and typed host-guard tests run in the same executable.

```sh
cmake -S src/lotus_v2/reorg_recovery_test -B /tmp/lotus-v2-v4-recovery \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/lotus-v2-v4-recovery --target reorg_recovery_test
/tmp/lotus-v2-v4-recovery/reorg_recovery_test
```
