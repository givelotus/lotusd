# Explicit development recovery storage

This isolated target tests the bundled ABC LevelDB recovery mechanics. Configure
with `cmake -S src/lotus_v2/reorg_storage_test -B <build> -G Ninja
-DCMAKE_BUILD_TYPE=Debug`, build, then run `ctest --test-dir <build>
--output-on-failure`. It also runs the existing disk-state suite. Address and
undefined behavior sanitizers can be enabled through the standard compiler and
linker flags.

## Storage boundary

`DiskStateOptions::recovery` explicitly creates a V3 indexed home. Its journal
and undo creation caps are persisted in `V` with the exact header profile.
Existing V1/V2 homes and changed caps are refused; no reset or migration occurs.
V1/V2 callers keep their existing ordinary storage behavior. These are local
operational limits, never block consensus limits.

`J` encodes version 1, actual tip, actual UTXO root, and a length-prefixed opaque
journal payload. The coordinator owns canonical revision, phases, pinned full
bodies, source/target plans and semantic terminal validation. Storage requires
byte-exact old payload plus expected tip/root. Journal-only writes retain the
tip. Recovery connect/disconnect enforces the proposed next tip and retains J,
writing its new actual checkpoint in the same synchronous batch as S/C/N/U and
H/A/I. Only a separate coordinator-verified terminal journal-only write removes
J. Ordinary Begin/Commit/Disconnect and header-only writes refuse pending J.
Read-only diagnostics remain available; the enclosing runtime owns serving and
mining fences while recovery is pending.

J is outside immutable U. Exact reconnects reuse U even across different journal
revisions. Undo preflight strictly parses framing/profile/row grammar and returns
before/after identities/roots plus a BLAKE3 fingerprint of
`"Lotus/v2/storage/undo" || NUL || raw_U`. This is a local storage fingerprint,
not a consensus hash domain. Preflight does not compare historical rows against
current coins/nodes or establish contextual block validity. Actual disconnect
authenticates the bounded inverse changed-path view and invokes the enclosing
metadata validator before publishing. A missing/corrupt/pin-mismatched U is an
operational failure preserving the pending checkpoint for repair.

## Allocation and durability limits

V3 calculates exact serialized undo size before allocating its encoded heads and
undo. J creation is capped before encoding. Bounded J/U reads use an iterator to
inspect the value length before copying into an application string. LevelDB may
already load an SST block or WAL/memtable before exposing that slice. Trusted
V3 creation caps bound legitimate record sizes; the caller quota does **not**
prevent engine allocation from forged/corrupt oversized blocks or records.

Embedded bodies are rewritten with each J update in this initial implementation.
Coordinator decoding, expected/next payloads, transaction capture, encoded J and
WriteBatch can hold several simultaneous bounded copies. These caps do not
constitute a hard whole-process RAM limit, and no performance gain is claimed.
There is no separate body namespace, pruning, migration, global chain selector,
network/default change or chain-wide atomicity. Each step is one durable block
checkpoint; a failed sync can recover either complete old or new checkpoint and
poisons the handle until reopen.

## Regression coverage

The fixture uses mechanically valid mined headers and opaque synthetic metadata;
contextual consensus and full block execution are covered by enclosing tests.
This suite checks exact payload CAS, expected tip/root/next tip, retained J,
ordinary-write and callback reentry fences, abort/refusal/exception preservation,
source undo fingerprints, exact creation/copy quotas, V2/V3 rejection, malformed
J/U and missing U, immutable U across rollback/reconnect, and reopen after failed
WAL Append/Sync for preparation, connect, disconnect and terminal clearing.
Recovered J, S/root, C, H, A/I and U agree at a complete checkpoint.

Native macOS arm64 review on 2026-10-15: Debug 2/2 passed in 10.58s;
AddressSanitizer + UndefinedBehaviorSanitizer 2/2 passed in 58.17s with
`ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1`. Darwin's ASan rejects
`detect_leaks=1` before running tests, so this is not leak-detector evidence.
