# Indexed development storage review

This packet adds an explicitly selected development database format through
`DiskStateOptions.header_index = hp`. The exact header profile is bound into
schema `V` version 2; absent options retain the generic version 1 format.
Existing generic homes and indexed homes opened in generic mode fail closed.
There is no automatic migration, reset, or in-place index reconstruction. To
move development data, use a separate new home and explicit validated genesis
and block replay, preserving the old home. Previously disconnected bodies do
not migrate implicitly.

## Records and atomic updates

| Key | Value |
| --- | --- |
| `H` + BlockID | version, stage, canonical 134-byte header, LE u320 cumulative work, maximum ancestor timestamp |
| `A` + height u64be | active BlockID |
| `I` | version and optional active tip, height, cumulative work and maximum ancestor timestamp |

Existing S/U head encoding remains version 1 inside the new database envelope.
No coin/tree or complete-body format changes are introduced. Bodies remain in
current/retained state metadata and immutable undo, with the existing whole-U
read allocation limitation. This packet introduces no candidate body archive,
pruning, availability promise, peer serving, or network parameters.

`PutCheckedHeader` is a capability for an enclosing validator that has already
checked contextual ASERT/MTP rules against authenticated history. It verifies
canonical identity, manifest genesis, configured version/target/PoW and parent
height, and derives cumulative work and maximum ancestor time. It does not
execute block transactions or write active A/I mappings. The untrusted-header
entry point must be the enclosing contextual admission wrapper.

`Commit(metadata, header, error)` binds exact header bytes/BlockID to metadata,
requires active-parent extension, and writes H (upgraded to Connected), A and I
in the same sync LevelDB batch as S, coins, nodes, identity and undo. The legacy
commit refuses indexed mode; the header overload also supports generic mode.
Indexed disconnect removes only the old active height and restores predecessor
I in the same state/undo batch. H survives and Connected means **ever fully
connected**, not active. Indexed genesis cannot be disconnected.

Open and indexed queries verify S/I/header/tip-height binding and fixed local
parent/work/time consistency. Requested active heights verify their header and
adjacent parent mapping. These are bounded mechanical integrity checks, not a
full index scan or a cryptographic proof of every historical aggregate. LevelDB
checksums protect record reads; a full adversarial database rewrite is not
validated as a new consensus history by these accessors.

Per-block work uses `floor(2^256/(target+1))` with a 257-bit division numerator.
A positive target bounds one block by 2^255; uint64 height bounds the sum,
including genesis, by 2^319. Fixed u320 encoding therefore represents every
such chain without wrapping. Monetary `prev_work` remains per-block work.

## Bounded queries and fork planning

Locator membership is an indexed H lookup followed by A at its height. Header
replies read successive active heights, so cost is proportional to the bounded
locator and response sizes, independently of total height. Local locators sample
exponentially spaced A heights and end at genesis. An empty locator asks for
only an explicit active stop header; nonempty unknown locators fall back to
anchored genesis and replies contain successors, inclusive of a matched stop.
All operations fence the expected active tip and preserve output on refusal.

`PlanHeaderFork` compares one requested candidate with the active tip. It plans
only strictly greater work; equal work retains the current tip. Its parent walk
and output lists are limited by caller-supplied disconnect/connect quotas.
Before each storage call it reserves a conservative maximum of actual Gets
(7 for active index, 3 for H, 11 for A), then charges actual usage. Insufficient
read budget refuses before the call. Quotas are operational, not consensus.

The maximum ancestor timestamp is `max(parent.maximum, header.time)`, allowing
eligibility of the entire candidate ancestry to be checked without a chain
walk: if maximum > now, require maximum - now <= the explicit future window.
Clock rollback can defer a candidate without invalidating it. This helper is
not a global eligibility-aware selector when the current tip itself becomes
ineligible, nor a persistent candidate queue or chain activation executor.
HeaderChecked candidates still need bodies and full state execution. A plan
proves neither body/undo availability nor recoverable whole-reorg execution.
Only each individual connect/disconnect batch is atomic; durable multi-block
reorg intent/recovery remains a separate task.

## Checks

```sh
cmake -S src/lotus_v2/chain_index_test -B build-chain-index -GNinja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-chain-index -j4
ctest --test-dir build-chain-index --output-on-failure
```

This target also runs existing generic disk-state checks. Index tests compare
work with independent Boost mathematical division for minimum/maximum/power
of two/random/canonical compact targets; exercise overflow and aliasing; build
128 active heights and a retained header fork; assert locator/reply read bounds
and per-plan actual Get budgets; test future ancestors, clock rollback, equal
work, stale tips, quota refusal, re-open, disconnected Connected status and
immutable undo reuse. Injected real LevelDB WAL Append/Sync failures check
atomic H/A/I/S/coin recovery for commit/disconnect and header-only publication.
Corrupted H work/time/stage/header, A mapping, I record and profile/mode mismatch
fail operationally without mutation.

Synthetic headers are mined at an easy caller-supplied target. Direct backend
fixtures intentionally exercise the trusted-storage capability rather than
assert contextual ASERT, body, monetary or VM acceptance. Enclosing admission
and initializer tests belong to their own validator packet. Artifacts remain
on failures; no goldens are regenerated.
