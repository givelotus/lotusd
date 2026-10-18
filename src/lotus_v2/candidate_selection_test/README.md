# Bounded socket-free candidate selector

`CandidateSelector` scans the persistent V4 candidate inventory in descending
u320 accumulated work, then descending BlockID bytes. Exact active-work ties
retain the active tip. It keeps a fixed exclusive rank cursor, at most one
pending fork and two choices, and never loads the complete header inventory.

A choice is an **unvalidated recovery attempt**, not an active tip or a conclusion
of consensus validity. `best_fetch` is the highest eligible missing-body branch
in the competitive prefix; its bounded needs are replacement bodies only.
`best_ready` is the highest eligible branch in that prefix whose target and
source-restoration bodies are available and whose preparation capacity check
succeeded. A ready prefix excludes every higher-work retained competitor under
the same view. Lower-ranked bodies need not be fetched before trying that branch.
Missing source-restoration bytes, unsupported lookup and local quota refusals
remain operational. This module writes no invalid facts or chainstate.

## API and fences

All limits, time, future window and body epoch are explicit caller arguments.
There are no network/profile defaults, sockets, listeners, service promises or
node integration. Caller serializes store, selector and body inventory access.
The body probe is pure and nonreentrant, returns no body bytes, authenticates
framing/header/commitment binding, honors its own backend read/work/byte limits,
and bounds diagnostics by the supplied per-body byte cap. Its availability and
authentication observations remain stable until the caller changes `body_epoch`.
Borrowed callbacks and store live through each call; reset before moving or
replacing the store. Moving/destroying a selector during its callback is forbidden.

Polls charge pages, actual Gets, iterator actions, page decoded bytes and scalar
body probes. Every fixed-query/fork/header call reserves its worst-case Gets
before invocation, including refused operations. Page failure usage is reported
through the storage API's independent usage pointer. Legacy fixed index/fork
queries retain the store creation caps for decoded/engine byte allocations;
`query.max_decoded_bytes` covers candidate pages, not those legacy values or
callback backend allocations. `max_resident_bytes` reserves vector payload with
conservative spare capacity for the supported standard-library vector growth;
fixed objects, allocator overhead and engine buffers have separate bounds.
Returned choices move out of selector ownership and become caller-owned payload.
Configuration overflow, absent essential limits and insufficient resident budget
refuse before any store reads. `fork.max_disconnect=0` deliberately permits only
extensions; it is not an unbounded sentinel.

Insertion revisions do not reset an unfinished pass. Finish the retained pass,
then repeat a bounded verification pass if its revision changed. Continuous
adversarial churn may yield `Progress`; a finite stable inventory terminates.
Stable tip/root/profile or invalidity changes return `Stale`. Journal, terminal
receipt and pending propagation return their distinct recovery/acknowledgement/
invalidation fences before ranking. The storage/recovery owners acknowledge
receipts and propagate typed deterministic invalidity; this selector does not
interpret diagnostic strings or produce proof objects.

Body epoch changes, backward clock movement and changed future windows reset
eligibility/availability classification. Forward time resets only when it crosses
the earliest skipped higher-work future threshold. All-ancestor maximum time is
checked with subtraction, avoiding `now + window` overflow. An already stable
active tip's temporary ineligibility is reported, without detachment or permission
to choose a lower-work replacement.

`ValidateCandidateChoice` rechecks view/body/time fences, canonical indexed header
bytes, all-ancestor eligibility and a bounded fresh fork plan. Public choices
remain mutable and are not authority. This is an eligibility/fence recheck, not
a fresh best-rank scan or an authenticated seal over the output. The controller
retains the exact returned choices and supplies one unchanged; changing both the
aggregate and its selected branch cannot authenticate a new best choice. The
recheck also excludes any target with persisted causal invalidity. Final
`PrepareDevelopmentSwitch` must independently exclude invalid targets and
repeat authoritative profile/context/source checks and reserve/pin all target,
source-restoration, undo, receipt and invalidation resources before mutation.
Capacity checking at selection time is an observation, not a lease. Allocation
failures clear selector work and return operational capacity refusal; exceptions
from body probes clear work and return operational storage failure. No failure
makes a block permanently invalid. Store I/O failures may require reopen and
authoritative J/receipt/S/H/A/I reconciliation before subsequent work.

## Standalone build

From an integrated native source tree containing the V4 storage prerequisite:

```sh
cmake -S src/lotus_v2/candidate_selection_test -B /tmp/lotus-v2-selector-build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/lotus-v2-selector-build --target candidate_selection_test
ctest --test-dir /tmp/lotus-v2-selector-build -R '^candidate_selection_test$' --output-on-failure
```

Before root integration, `-DLOTUS_CANDIDATE_STORE_SOURCE=/absolute/native/src/lotus_v2`
selects the independently owned prerequisite without copying or editing it.
Shared full-tree registration remains root owned.

Packet evidence (2026-10-15): focused Debug `candidate_selection_test` passed
1/1 in 1.20 seconds; ASan+UBSan passed 1/1 in 1.56 seconds. Both used integrated
store source `3ed3c26edd420819eaf4ff58b9ee8ec9d0f4b3a1` (storage packet
`13e4a138e`) and root's standalone storage build registration through the
explicit source override. These runs built and selected this target only; they
do not claim the inherited storage suite or full-tree integration checks.

For ASan/UBSan, configure a fresh build with both C and C++ flags
`-fsanitize=address,undefined -fno-omit-frame-pointer` and executable linker flags
`-fsanitize=address,undefined`.

Tests use actual bounded LevelDB candidate/index APIs, with explicitly synthetic
mechanical header fixtures and injected body availability. Different target bits
exercise work ranking without claiming contextual ASERT/header admission or VM
acceptance. Coverage includes work versus height/announcement order, tie order,
missing highest branch versus lower ready branch, parent-first bounded missing
prefixes/body epochs, missing source refusal, all-ancestor future time and clock
rollback/overflow, exact future thresholds, active ineligibility diagnostics,
fixed-size pages/resumed probes, insertion verification and finite-workload
progress, exact resident authorization, failed-page usage, callback reentry,
persisted journal reopen, unknown terminal receipt/acknowledgement and mutable
choice revalidation. A separately labeled canonical raw receipt fixture tests
pending-propagation fences, restart per bounded queue step and causal-exclusion
rechecking even for a forged public choice naming retained excluded H. This is
storage mechanics evidence, not a fabricated in-process validator proof or a
claim that those synthetic bytes failed consensus. Failure fixtures remain on
disk for inspection.

Deterministic invalid-replacement restoration and trusted proof publication,
atomic receipt/fact crash injection, full body authentication/pinning, actual common
validator integration and transport/download adapters remain integration gates
owned by their respective packets. This suite does not fabricate a deterministic
failure proof or claim global chain activation/network synchronization.
