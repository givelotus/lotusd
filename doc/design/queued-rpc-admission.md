# RPC admission microbatch design

Status: source-reviewed design, not implemented or enabled. Base is maintained
517 `aed364af278a26e71d34ecfa3569ea870e82ccfb`, tree
`5caf8ba1cb66ca15e50c0c761bae744a779d5798`. No build, test, profile or benchmark
was run for this document.

## What the queue can improve

A node-owned admission thread can collect already-arriving independent RPC
submissions and amortize chain/mempool lock transitions and snapshot publication.
Producers enqueue bounded requests and wait outside daemon locks. The worker
drains immediately; there is no mandatory batching delay. A quiet node processes
one request immediately, while a busy node naturally accumulates batches.

This does not make native VM execution cheap by itself. It does not turn one
atomic package verifier into independent transactions. It does not eliminate the
consistency requirements currently enforced by `cs_main`.

## Current call graph and ownership

```
sendrawtransaction / PWA RPC
  -> BroadcastTransaction(wait_callback=true)
     -> PrecomputeMempoolAdmission
        legacy: resolve copied inputs under locks, verify outside locks
        v7: return immediately (not a legacy advisory-verification target)
     -> LOCK(cs_main)
        -> check already-confirmed outputs
        -> ProcessTransaction(limits, optional advisory outcome)
           -> authoritative admission, fee/lock/conflict/deferred checks
           -> mempool insertion and validation notification
        -> AddUnbroadcastTx when relay requested
        -> register main validation-queue barrier for newly accepted tx
     -> unlock
     -> wait for main barrier, then SyncSecondaryQueues (wallet/Chronik)
     -> RelayTransaction
     -> RPC result
```

Wallet callers using `wait_callback=false` may hold wallet/chain locks. They must
continue through the direct path; sending them to a worker and waiting can
deadlock. `transaction.h` already documents this restriction for synchronous
callers. Chronik and internal callers must be inspected individually rather than
assuming every call is an unlocked public RPC.

`ProcessRawTxBatch` is a different API: it provides atomic package semantics,
one shared fee-rate limit, coordinated dependency checks and collective failure.
Independent `sendrawtransaction` requests can have different fee bounds and
must return different outcomes. Calling the atomic API once for a queue batch
would change semantics.

## Why immutable views do not remove the commit lock

Published chain/mempool snapshots let readers observe immutable data without
owning mutable daemon state. They do not atomically reserve input coins or
prevent a concurrent block, wallet send, P2P transaction, expiry sweep or reorg
from changing the state used by an admission decision. An immutable spent coin
can remain alive after another transaction has spent its outpoint.

The RPC queue has one commit owner **for queued RPCs**. Block validation, direct
wallet admission and P2P admission still exist, so it is not a global transaction
sequencer. The final commit still takes the existing authoritative locks.

Slabs also do not eliminate this distinction: they reduce allocation overhead,
while mutation ordering and object lifetime remain independent requirements.

## Phase 1: independent commits and publication coalescing

1. Add a `NodeContext`-owned `RpcAdmissionDispatcher`. Initialize it after
   chainman/mempool/peerman/validation signals exist and before RPC warmup ends.
   Use the existing process lifecycle; do not create a global singleton.
2. Route only unlocked synchronous callers (`wait_callback=true`) to it. Keep
   current legacy advisory preparation on producer threads before enqueueing.
   This retains useful parallel legacy verification. Native preparation remains
   unchanged initially.
3. Each request owns immutable `CTransactionRef`, its exact `MempoolAdmissionLimits`,
   relay intent, optional advisory result, main-callback barrier and completion
   promise. Do not retain an HTTP/session pointer or a caller's stack string.
4. Use an existing fixed-capacity Boost lock-free pointer queue for many
   producers/one consumer. Slots, pending transaction count, bytes and in-flight
   request count must all be bounded. Promise/request allocations occur before
   admission locks. A request object remains owned until the worker acknowledges
   completion, even if the HTTP connection disappears.
5. Wake the consumer on publication; drain immediately up to a bounded work
   budget. Do not sleep 10 ms to collect a batch. Determine a useful drain bound
   from measurements before selecting a production default. No new operator
   configuration is needed for an unmeasured timer.
6. Split `BroadcastTransaction` into an unchanged authoritative locked phase and
   post-lock notification/relay completion. The direct path calls both in the
   same order as today. This extraction must land with parity tests before the
   dispatcher is enabled.
7. The dispatcher takes `cs_main` and mempool ownership once for its drained
   slice, constructs one `ScopedSnapshotDefer`, and invokes the ordinary
   authoritative locked phase separately for each request in queue order.
   Never pass the slice to atomic package admission. One bad member does not
   reject earlier or later independent members. A child only sees an earlier
   parent if that parent actually committed.
8. Destroy the snapshot-defer guard and release **all** chain/mempool locks before
   any main-queue or secondary-queue wait. Relay and resolve each promise only
   after that request's existing completion requirements are met.

The batching layer must not wait for a wallet callback while it owns either
admission lock. A worker that simply calls the existing synchronous
`BroadcastTransaction` serially, including its callback waits, would remove
current RPC concurrency and is explicitly not the proposed implementation.

### Publication/callback invariant that needs a test before enabling

Today each transaction publishes its snapshot before its validation callback is
registered. A batch defer can allow queued notification processing to begin
while the batch snapshot is still old. Before enabling coalescing, establish
whether subscribers consume snapshot state during an event. If they do, stage
notifications until after publication while retaining their original sequence,
or keep per-transaction publication. Do not assume that a completion barrier
alone proves event-time state is equivalent.

The barrier must remain per request. A later request with unusually slow work
must not be silently included in an earlier request's declared completion
contract. Coalescing creates a possible additional wait inside the bounded
slice, which needs latency measurement and an explicit upper bound.

## Phase 2: native parallel preparation needs a validated read set

Do not introduce a cache of whole VM outcomes keyed only by txid. Validity also
depends on script flags, native coin data/creation height, transaction lock
context, deferred and structural records, and policy context.

A safe reusable outcome needs to own:

- Immutable transaction/witness data and the exact resolved coin bytes used.
- The tip/context identity and native script flags used for preparation.
- Every relevant outpoint and deferred/structural dependency read.
- Successful cryptographic outcomes bound to their exact signature message,
  public key and signature; full VM execution outcomes need a broader key.
- Produced native records, resource counts and error attribution.

Resolve/capture under the appropriate lifetime and consistency guards, run pure
preparation/verification through existing persistent workers outside
`cs_main`, then repeat cheap authoritative checks under the commit locks. Compare
the actual read set: unchanged tip alone is insufficient because other mempool
transactions can spend the same inputs at the same tip. A context mismatch must
fall back to ordinary authoritative verification, never trust the stale result.

Existing legacy `PrepareStaged`/`ComputeAdmissionChecks` is an example of the
capture/verify/revalidate pattern, not proof that its outcome type is sufficient
for native deferred semantics. Native atomic package collectors can eventually
share pure cryptography, but their collective failure protocol cannot become
the independent-RPC admission policy.

## Ordering, overload and lifecycle

- FIFO means linearized successful enqueue order. Concurrent callers have no
  extra cross-connection ordering guarantee today. Sequential JSON-RPC array
  execution stays sequential: its next mutating call is not enqueued until the
  previous call returns. Do not split arrays into parallel calls.
- Duplicate accepted/mempool transactions retain today's success behavior;
  already-confirmed and invalid transactions retain their error mapping.
- Per-request maximum fee and fee-hysteresis intent cannot be combined into one
  slice-wide value.
- Per-transaction mempool sequence, native produced records, unbroadcast marking
  and validation notification order remain the ordinary commit order.
- Queue overload must not drop requests or bypass policy. Prefer bounded producer
  backpressure outside daemon locks. For a request larger than the byte budget,
  retain an ordinary direct path or return an existing explicit resource error;
  choose and test the behavior before changing public responses.
- RPC disconnection does not undo a transaction already admitted. Cancellation
  may skip only requests not committed; once committed, complete normal internal
  notification/relay work even if nobody waits for the response.
- Keep the worker alive while RPC/HTTP shutdown drains handlers waiting on it.
  After producers stop, stop accepting, drain/fail queued requests deterministically,
  join the worker, then tear down peers/wallet subscribers/validation scheduler.
  A destructor must not depend on already-destroyed `NodeContext` dependencies.
- Any exception path resolves every outstanding promise or sets an exception;
  a dangling barrier capture or broken future cannot leave an RPC permanently
  waiting. Do not hold queue resources while waiting for admission locks.

## Verification gates

Phase-extraction parity and queue behavior must be tested against the direct
path, with the same signed fixtures and errors:

1. Valid parent/child ordering, invalid middle/end, missing parent, repeated
   txid, already-in-mempool and already-confirmed cases.
2. Different maximum fees and relay settings in one drained slice.
3. Two requests spending the same input: exactly the authoritative first commit
   wins, and queue insertion order has a reproducible test hook.
4. A block/reorg or another admission between preparation and commit; stale
   outcomes cannot authorize admission.
5. Native deferred/structural dependencies and expiry/context mutation, not
   only ordinary keyhash inputs.
6. Wallet sees the transaction and balances immediately after synchronous RPC
   return; native/Rust Chronik barriers retain their guarantees.
7. A subscriber reading published snapshot state during notifications, plus
   slow callbacks to catch waits performed under the mempool/chain locks.
8. Queue count/byte saturation, no lost/duplicate promises, stopped/rejected
   producers, consumer exceptions, RPC disconnect and clean shutdown with queued
   and committed-but-not-yet-notified requests.
9. Sequential mutating JSON-RPC arrays retain order; concurrent connections can
   coalesce without sharing one atomic package result.

Then perform one controlled run per case: current direct path versus dispatcher,
same binary configuration/fixtures, both quiet single-client latency and sustained
multi-client throughput, with/without loaded readers. Report enqueue delay,
drain-size distribution, `cs_main` wait/hold time, snapshot publish count/time,
worker CPU, callback time and end-to-end accepted TPS. A queue that only moves
time from one thread to another is not a demonstrated improvement.

## Delivery decision

The first useful patch is **not** an unwired queue. It is the phase extraction
plus executable parity coverage, followed by the bounded dispatcher and callback
publication coverage as one reviewable optimization. No new consensus rule is
required, but the callback/snapshot observation invariant and native read-set
design are not established by source inspection alone. This design should be
reviewed before an enabled runtime prototype; the existing 500k measurement
must continue against its pinned source without interference.


## Source prototype checkpoint (current 521)

The implementation candidate now rebases this design onto
`a60bba6facc924cdf43c34dc881805bb114fe373`, tree
`caf6bd4ce012b2383e733b45df46753b49b2a894`.

Its deliberately narrower first step batches only the `cs_main` commit ownership.
It **retains per-transaction snapshot publication**, callback registration, native
verification and per-request limits/errors. The queue consumer acknowledges commits
without waiting for validation callbacks; the original RPC producer threads retain
main/secondary callback waits and relay. It does not use `ScopedSnapshotDefer`
across independent requests. The causal callback test uses immediate delivery to
show that naive coalescing can expose an older snapshot during an event, and then
checks that dispatcher requests retain ordinary publication.

The fixed pointer queue has 256 slots, the serialized-byte admission reservation
is 32 MiB, and a drain slice has at most 32 requests. These are prototype safety
bounds, not measured tuning recommendations. No timer delay is added. A full,
stopped or oversized submission follows existing direct admission without dropping
or changing its policy result. Concurrent requests were not globally FIFO across
connections previously; successful queued requests preserve queue order, while
fallback direct work can interleave through the existing authoritative lock.

Producer/request allocations happen outside `cs_main`. A request is strongly owned
through promise completion, including exceptions. The Boost pointer queue itself is
lock-free; the sleep/wake handoff uses a short mutex to close the condition-variable
lost-wakeup race. The whole Dispatch call is not claimed lock-free. Stop closes
producer registration, completes already-registered requests and joins the worker.
HTTP/RPC handlers drain before destruction; wallet and Chronik callers never opt in.

The only public RPC opting in is `sendrawtransaction`. Ordinary RPC arrays still
execute their handlers in order. No configurable new runtime flag was added. A
profiled comparison must disclose this eligibility and distinguish queue transfer
cost from actual lock contention; an unlock sample count is not a wait-time measure.

### P2P integration boundary

P2P already owns `TxAdmissionQueue`, its fair per-peer FIFOs, `TxAdmissionSender`
strong node/peer ownership, `m_tx_admission_inflight`, pending-message deferral,
`ThreadTxAdmission` and `ProcessTxAdmissionDone` (`net_processing.cpp:3294–3460`).
Its worker sends results back to the message handler, which preserves
`PrepareTxAdmission`/`FinishTxAdmission`, peer scoring, orphan/replay handling and
network wakeups. It also has a serial `ProcessTxBatch` fallback.

This prototype does **not** send P2P work through the new RPC queue, does not wait
on RPC futures in the message handler, and does not create a second batching layer
for P2P. A unified follow-up should share an admission commit/preparation engine,
with distinct request completion adapters: RPC futures and limits versus existing
P2P sender/result records. It should retain per-peer fairness and pending-message
ordering, and arbitrate RPC work without starving peers. Returning a generic
`TransactionError` instead of the existing `MempoolAcceptResult` would lose policy,
DoS and orphan information. That integration needs its own behavior tests and is
not part of this candidate.

Build, focused execution and A/B remain pending. The source prototype is not a
validated optimization or a replacement for native off-lock verification.
