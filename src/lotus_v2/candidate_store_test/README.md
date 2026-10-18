# Bounded V4 candidate inventory and terminal receipts

Build this isolated target with `cmake -S src/lotus_v2/candidate_store_test -B
<build> -G Ninja -DCMAKE_BUILD_TYPE=Debug`, then build and run `ctest --test-dir
<build> --output-on-failure`. The existing disk-state suite runs alongside the new
mechanical storage suite. The factory consumes the opaque validation evidence in
`block_transition.h`; the enclosing validator/coordinator tests cover actual
contextual failure classification.

## Explicit schema and retention

`options.candidates` creates a new V4 home and requires explicit indexed/recovery
options. Exact candidate, speculative-header and invalid-root count caps are
persisted in V with the profile and existing journal/undo caps. Older homes,
changed caps and cross-mode readers fail closed. There is no migration or reset.
V1/V2/V3 behavior remains available in its own mode.

Fixed-layout namespaces in the same LevelDB are:

- W: big-endian u320 work plus BlockID, with height/time/parent summary.
- X: parent/child adjacency. H, W, X and K publish together on admission.
- K: revision, invalidity epoch and candidate/speculative/root/excluded/child counts.
- F: deterministic causal root fact and originating receipt ID; E: inherited root.
- P/Q: one root's bounded persistent descendant queue and exclusive child cursor.
- R: canonical fixed-size terminal receipt, bound to profile, stable tip/root and
  a local hash of the exact S metadata tuple.
- T: versioned singleton last acknowledgement ID/tip/root/metadata hash for exact
  retry after ambiguous sync. A newer outstanding R takes precedence over T.

Connect removes W and updates K in the same S/C/N/U/H/A/I batch. Disconnect adds
W in that batch. Every retained nonactive nonexcluded H is ranked, including
intermediate headers and ever-connected historic side headers. Connected history
and undo are retained; this packet has no archival omission or pruning. Ordinary
active history/child-row disk growth still needs an external quota and future
pruning design. Explicit candidate capacity can refuse new admission or reorg
preparation operationally. This is an availability limit, never consensus invalidity.

Speculative H records, their ranked/child records, E records and the P/Q frontier
are bounded by configured counts and fixed layouts. F is bounded by the root
count cap. No arbitrary variable metadata is added to these records. Safe leaf
eviction is explicit: only unconnected/nonactive/nonexcluded leaves without
children, undo or a writer fence can be removed. The caller chooses eviction
policy; storage performs no whole-index victim scan. Evicted headers may be
reannounced parent-first. Invalid facts are never evicted to retry a bad branch.

## Queries and fences

Rank pages use a fixed exclusive cursor: descending numerical work, then
**descending lexicographic BlockID**. Child pages use ascending child IDs. Every
returned rank summary is checked against H and active/excluded membership. Pages
charge reads, iterator Seek/Next/Prev/key/value actions, key/value bytes and rows
before the corresponding access/copy/growth. Optional usage outputs are populated
on success and failure while ordinary result outputs remain unchanged on failure.
A partial page can resume at its last completed row. Iterator budgets are separate
from point-read budgets; neither hides an unbounded scan.

No cross-call snapshot is held. Insertions advance revision while a lower-page
cursor continues. The selector must finish/revalidate an unchanged retained pass
before claiming best work; continuous churn can yield visible Progress. A stable
checkpoint change, invalidity epoch, J, R or P immediately fences selection.
ReadCandidateView and capacity/invalidity fixed queries have conservative published
read bounds. Legacy fork/index queries retain their own creation-cap/Get accounting,
so page byte quotas are not a claim about aggregate memory for all selector work.

Prepare must recheck candidate_count + maximum disconnect count and one available
invalid-root slot at the serialized writer handoff. A returned readiness observation
is not a lease. Pending J prevents ordinary mutation; pending R/P also prevent new
recovery or unrelated writes. Read-only diagnostics remain available. During J,
View's observed checkpoint tip is intermediate and must never be treated as a new
stable source merely because the field is named stable_tip.

## Typed invalidity and durable handoff

V4 journal-only terminal deletion refuses: FinishCandidateRecovery atomically
clears J and writes R. Completed/unknown/deferred outcomes cannot contain a failure
fact. The deterministic outcome requires opaque StageCompleteBlock evidence or
its narrow trusted canonical recovery-journal codec restoration; default/unknown
proofs cannot manufacture facts. Storage independently checks failed H/parent/profile,
ever-connected parent H and exact retained historical parent UTXO root/header.
The historical parent may differ from the restored source. The enclosing codec
also validates its full StateRoot/monetary semantics and pinned target path.

Acknowledgement atomically replaces a deterministic R with F/E and P/Q, removes
its ranked root, and records T. Descendants are removed from ranking in bounded
queue steps. Selection/new admission is fenced until propagation finishes. New
children of excluded parents refuse after completion. A fact contradicting a
Connected header is operational corruption, never authority to invalidate a
previously validated source. Unknown/deferred receipts only clear the fence.
Exact acknowledgement retry is accepted after reopen; unrelated/stale identity or
an old T against a new R is refused.

## Limits and evidence scope

Local receipt/fact identities use separate BLAKE3 storage domains with a NUL
separator; they are not consensus domains. LevelDB checksums and strict record
parsing detect damage on accessed records. This is not a cryptographically
committed global header inventory or a full-index consistency scan on open.

Iterator size inspection bounds application copying for new fixed records and
query pages. Engine SST/WAL/memtable allocation can precede that inspection;
trusted creation caps bound legitimate records, not arbitrary hostile database
rewrites. Existing overlay, metadata, undo, journal and batch copies remain
additional bounded payloads and overhead. No whole-process RAM cap or performance
gain is claimed. Each recovery/propagation operation is one sync batch; there is
no multi-block atomicity, global selector implementation or network/default change.

The storage suite uses mechanically mined headers and opaque metadata, including
variable target work without claiming contextual ASERT validity. It directly
injects canonical persisted R records only for parser/propagation mechanics;
these fixtures are explicitly not VM validation proof. Separate real-block tests
must establish typed classifier and trusted journal evidence behavior.

Regression cases cover ranked/child paging and ordering, strict preauthorization
and failure usage, insertion revisions, capacities/eviction/reannouncement,
H/W/X/K active transitions, old-mode rejection, rank/counter corruption, unknown
and deferred receipts, default-proof refusal, historical parent root mismatch,
restart per descendant step, invalid-ledger saturation, and WAL Append/Sync faults
at admission/connect/disconnect/terminal/acknowledgement/propagation publication.

Native macOS arm64 Debug review on 2026-10-15: both candidate-store and existing
disk-state tests passed, 2/2 in 12.17s. The standalone target uses the root-owned
shared disk-state library registration for candidate_store.cpp and Boost headers.
