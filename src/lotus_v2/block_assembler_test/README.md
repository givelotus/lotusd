# Local complete-block assembler checks

This isolated target exercises the local assembler with the existing explicit
funded development profile and genesis. It starts no node or socket and changes
no production configuration. Shared immutable genesis/fork vectors and their
provenance come from `development_runtime_test/fixtures.h` at `9345b70ec`.

A public test scalar 3 controls the funding CHECKSIGVERIFY policy. The assembler
creates a 100000-atom coinbase, the normal validator accepts it, and another block
matures it. Two actual BIP340 signed transactions spend that coin and its new
output in supplied parent/child order. An independent zero-claim stored preview
quotes the entitlement and mandatory deduction; final fixed-width claim preview
must preserve exact costs and monetary recurrence. The mined wire is accepted by
the normal validator and, on a separately replayed parent, through the actual
runtime Admit/Retain/Tick/receipt-acknowledgement path.

Checks cover zero and caller-capped claims, `UINT64_MAX` request caps, reversed
dependency order, bad signatures, stale parents, canonical empty-data refusal,
resource limits, actual pending journal/receipt/propagation fences, and nonce
limits including zero attempts, 257-attempt refusal and exhaustion without wrapping
past `UINT64_MAX`. The real funded fixture's entitlement is below `UINT64_MAX`;
this does not claim a funded greater-than-u64 entitlement saturation vector.

Insufficient-entitlement testing uses the existing bare `DevelopmentGenesis`
monetary schedule. The required burn is derived from real encoded coinbase bytes,
frame prefix, effective costs and parent EMA, and exceeds even the entire parent
reserve plus tail. No one-byte synthetic transition supplies its arithmetic.

Full raw LevelDB key/value snapshots occur only in the test, with the production
store closed. They prove preview/construction and failures publish no state keys.
The preview/assembler themselves use private lookup overlays and no UTXO
enumeration API. Snapshots are not part of their reported memory or I/O bounds.
Per-transaction encoding temporaries retain existing TxProfile creation bounds;
aggregate list/wire copies use the explicit block cap. Signed transactions execute
in both aborted previews and again during normal acceptance. Nonce search checks
header/wire binding and PoW; normal validation remains the acceptance boundary.

## Build and evidence

The focused test packet is based on `9345b70ec`; runtime prerequisites are preview
core `7c8ced2fc` and assembler/store wrapper `2350e1544` (root `ba6e9b035`).
The strict standalone Debug and Release suites pass against those frozen sources
and the runtime preview facade `b968c50a8`.

```sh
cmake -S src/lotus_v2/block_assembler_test -B /tmp/lotus-v2-assembler-debug \
  -DLOTUS_SECP_LIBRARY=/path/to/libsecp256k1.a -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/lotus-v2-assembler-debug --target block_assembler_test
ctest --test-dir /tmp/lotus-v2-assembler-debug \
  -R '^block_assembler_test$' --output-on-failure
```

Use a separate directory and `-DCMAKE_BUILD_TYPE=Release` for the Release gate.
Shared full-tree registration is owned by integration.

## Runtime preview facade

The focused facade checks use the same accepted immutable fork fixtures. A Ready
preview matches direct construction without changing parent state, epochs or a
staged selection. Stale-parent and pending journal/receipt outcomes remain typed
completed operations; capacity refusal leaves output untouched. A synchronous
storage callback verifies Busy access preserves both output parameters, and a
moved-from runtime verifies the same Closed contract. The previously staged
choice still prepares on the next tick, then completes normal recovery and receipt
acknowledgement. Preview success does not claim block acceptance or time eligibility.

Final combined Debug and Release executables both printed
`local block assembler signed integration tests passed`. Borrowed production
sources and build directories are excluded from this test packet.

Final Release logs: `/private/tmp/lotus-v2-assembler-tests-release-configure.log`,
`/private/tmp/lotus-v2-assembler-tests-release-build.log`, and
`/private/tmp/lotus-v2-assembler-tests-release-test.log` (exit 0).

Frozen SHA256 values:

- Test source: `2008c51c18a445dc80aac931ca366210f3e554a183a3c856d3cd7562e72b3b84`
- Runtime header: `3eeda103c6ffde6bdd56b47cbdf6dfea8f6e665b8cebf92bfff9b4399c6b204b`
- Runtime source: `06248f3bb068534ac1521306c82b45c1e56444a1d8d1cb1b82043055d66e3052`
