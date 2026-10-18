# Resumable development-chain recovery

`reorg_recovery.{h,cpp}` coordinates one explicitly supplied heavier target. It
uses the existing full block connector and chain-aware undo callbacks; it does
not select a global best candidate, perform networking or change consensus.

The store must have an exact indexed profile and explicitly supplied recovery
creation caps. Existing V3 homes retain Jv1 behavior. V4 candidate-enabled homes
use Jv2 evidence and terminal receipts. Store-mode/journal-version mismatches fail
closed; neither format is silently migrated. Prepare checks the bounded fork plan,
pins exact source and replacement bodies, probes/pins source undo digests, and
records a canonical plan journal. Source bodies must already be retained;
replacement bodies arrive through the caller's bounded nonmutating body source.
Framing/root checks at preparation do not establish contextual body validity.

## Durable progression

Each `StepDevelopmentSwitch` performs at most one block connect/disconnect.
Phase-only transitions and final completion also consume calls. Every active
transition publishes its next journal bytes with the state/index batch, using an
exact previous-journal/tip/root fence. Storage's outer journal envelope binds the
actual post-transition root. Immutable block undo does not contain journal bytes.

A replacement that fails full deterministic execution never publishes. The
coordinator records its ID, undoes its accepted replacement prefix, then replays
the detached source bodies through full execution. Completion requires the exact
original metadata/root tuple. An unambiguous source detach failure after partial
detach attempts a journal-only CAS into source restoration; the operational cause
and source block ID are retained separately from replacement invalidity. If that
CAS cannot establish the exact old checkpoint, recovery stays pending.

Poisoned or ambiguous writes require reopening before another decision. Resume
reads the observed journal revision and verifies current state/history/index
binding. It never guesses whether a failed synchronous write committed. Source
restoration does not repair an unrelated corrupt retained undo record; a stored
operational cause remains relevant even after the active tuple is restored.

Forward progression and final target completion check the target's authenticated
maximum ancestor timestamp against explicit caller `now`/`future_window` arguments.
Clock rollback before mutation clears the prepared attempt as Deferred. After
mutation it causes source restoration. Recovery rollback/source replay apply
existing deterministic rules without a new clock gate, so a clock rollback cannot
prevent restoring the previously valid source. No skew value or clock source is
selected here.

## Limits and storage format

The initial packet embeds pinned bodies in the capped journal instead of using a
separate body store. This intentionally repeats bounded journal serialization and
writes on every step. Body lengths and remaining aggregate quotas are checked
before copying decoded bodies or authorizing provider/retained-body calls. Source
snapshot auxiliary bytes are inspected before their additional body copy. Undo
probes receive both per-record and remaining aggregate quotas.

`fork.max_reads` bounds preparation and each call's coordinator/index prechecks.
Full block execution/undo additionally uses existing transaction/VM/block profiles
and backend overlay/creation caps; it is not claimed to consume that same index
Get budget. A single-block step bound alone is not a memory or CPU measurement.

`max_journal_bytes` is not a total process memory limit. Read/parse/encode keep
whole-journal copies, decoded pinned bodies and source metadata, old/next journals,
CAS envelopes and backend journal serialization alive at overlapping times.
The overlapping payload inventory is: current raw J; decoded old plan; a deep
next-plan copy (and one more plan copy during source-refusal fallback); immutable
and encoded serialization workspaces; expected/next CAS buffers; a transaction's
captured CAS buffers; and backend journal-read/serialization/batch buffers. Reserve
at least sixteen journal-sized payload buffers for this implementation, plus
undo decoding, current/next metadata, full block validation, backend caches and
overlays. This is a conservative payload budgeting allowance, not an allocator or
process-RSS theorem; container capacity, map nodes and engine buffers add overhead. Metadata copying is also bounded by
the home's metadata creation cap, not a smaller per-call body quota. No measured
RSS bound or zero-copy claim is made. V3 storage applies immutable U/J creation
caps and size checks before application copies; it does not claim those quotas
bound maliciously oversized LevelDB engine blocks created outside that contract.

A fixed 256-byte diagnostic area is reserved in every prepared journal, so source
failure transitions fit even when the journal exactly fills its creation cap.
Operational messages persist as bounded prefixes. Phase, revision, cursors and
failure IDs have fixed widths. The format version and padding are checked; unknown
versions, trailing bytes, inconsistent paths/cursors and profile mismatch refuse
recovery. Revision exhaustion is an operational error before mutation.

The attempt digest identifies immutable plan content; repeating identical content
can produce the same identity. It is not a fresh authorization token or a global
attempt counter. Exact journal CAS and the single-writer contract fence progress.
There is no explicit cancellation API in this packet.

In V3, terminal clearing remains the existing journal-only batch after verified
source/target completion. The caller receives diagnostics in `ReorgProgress`, but
after clearing/restart there is no durable terminal receipt or invalid-root fact.

V4 Jv2 reserves an additional fixed 184 bytes at preparation: evidence version,
presence discriminant, four binding hashes, termination cause and whole-journal
checksum. Diagnostic/evidence transitions cannot grow a prepared journal. Checksums
and exact mode/version are checked before decoding its immutable payload. Local
database/journal integrity is trusted apart from detectable corruption: the
checksum is not a MAC or a remote proof of VM rejection, and arbitrary adversarial
disk rewriting is outside this contract. Only an
opaque `DeterministicBlockFailure` from full execution can introduce evidence.
Invalid supplied bytes or Inconclusive results never establish that fact and never
advance recovery cursors.

The sole trusted journal reconstruction helper checks the failed pinned target,
its indexed parent, exact validator fingerprint and historical authenticated parent
UTXO root. The parent checkpoint's monetary bytes and root must reproduce the
parent header's state commitment, and its header must be ever connected. This root
is the pre-failure UTXO root, which can differ from the restored source's terminal
root. Missing/corrupt historical evidence fails operationally; it never downgrades
malformed evidence into an unknown outcome or creates a replacement fact.

V4 completion atomically removes J and publishes the typed durable terminal receipt
through `FinishCandidateRecovery`. CompletedTarget, RestoredSourceUnknown and
RestoredSourceDeferred carry no failure fact. RestoredSourceDeterministic requires
the verified fact. Source operational failure and clock deferral remain distinct
from deterministic replacement failure. Receipt acknowledgment/invalid-descendant
propagation belong to the candidate storage/selector owner; the coordinator does
not rank globally or acknowledge its own receipt. V4 preparation rechecks inventory
capacity at the serialized handoff before publishing J. It also fences pending
receipt/propagation work and explicitly checks causal invalidity for the target's
planned ancestors; a retained header or public selector choice grants no admission
authority. `ExcludedTarget` reports that refusal without creating a journal.

## Verification scope

The independent `test_reorg_recovery.cpp` packet uses immutable reference-generated
full wires and actual accepted source/target blocks. It checks a two-block detach
and three-block replacement, invalid-middle rollback/exact source restoration,
all-ancestor clock rollback with a lower-time target tip, restart after each step,
missing bodies and quota refusals preserving state/output/journal revision. A
controlled local undo-predecessor corruption checks source-detach refusal and
suffix restoration without classifying the target as invalid. An exact-creation-
cap regression measures the prepared journal, creates a fresh home capped to that
exact size, and verifies every later checkpoint (including diagnostic fallback)
keeps the same journal size and completes restoration.

The standalone recipe links the existing full validation components, bundled
LevelDB/CRC32C, OpenSSL and an explicitly supplied ABC secp256k1 archive. Root owns
full-tree integration; the independent test owner owns the test source/recipe.
Module checks and storage fault injection do not establish daemon integration,
whole-reorg atomicity, global selection or peer synchronization.
