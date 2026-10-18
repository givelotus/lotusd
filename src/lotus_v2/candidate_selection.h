// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CANDIDATE_SELECTION_H
#define LOTUS_V2_CANDIDATE_SELECTION_H

#include "candidate_store.h"
#include <functional>
#include <memory>
#include <optional>

namespace lotus::v2 {

struct CandidateLimits {
    // Aggregate per-Poll rows/Gets/iterator caps; decoded bytes counts candidate
    // pages. Existing fixed index queries retain store creation byte bounds.
    CandidateQueryLimits query;
    ForkLimits fork;             // Per-branch path and Get caps.
    uint64_t max_probe_calls{};  // Per Poll; callback must honor max_probe_bytes.
    uint64_t max_probe_bytes{};  // Per body; no body bytes enter the selector.
    uint64_t max_missing_bodies{};
    uint64_t max_resident_bytes{}; // Selector-owned vector payload, not allocator overhead.
};

enum class CandidateBodyResult { Available, Missing, CapacityRefused, Unsupported, StorageError };
// Pure, nonreentrant availability lookup. Available means exact header-bound,
// framing/commitment-authenticated bytes remain available under body_epoch; it
// does not mean contextual validity or a reservation. No returned body copies.
// Callback/backend allocations and work have their own enforced byte/read caps;
// diagnostic strings must also fit max_probe_bytes. Available bodies and their
// authentication stay unchanged while body_epoch is unchanged.
using CandidateBodyProbe = std::function<CandidateBodyResult(
    const Hash &, const Header &, uint64_t max_probe_bytes, std::string &)>;

struct CandidateBodyNeed { Hash id{}; Header header; };
struct CandidateChoice {
    Hash target{};
    IndexedHeader indexed;
    ForkPlan fork;
    // Bounded prefix of missing replacement bodies. More may remain; future
    // body-epoch scans obtain the next needs. Source bodies are never included.
    std::vector<CandidateBodyNeed> missing;
};
struct CandidateChoices {
    CandidateView view;
    uint64_t body_epoch{}, sampled_now{}, future_window{};
    std::optional<uint64_t> next_eligibility_time;
    std::optional<CandidateChoice> best_fetch, best_ready;
    bool active_temporarily_ineligible{};
    bool higher_operationally_blocked{};
    // Ready names an unvalidated attempt. Prepare must repeat source/context
    // fences and reserve/pin complete target and source-restoration resources.
};
struct CandidatePollUsage {
    CandidateQueryUsage query;
    uint64_t probe_calls{};
};
enum class CandidateResult {
    Ready, NeedBodies, Deferred, RetainActive, Progress, CapacityRefused,
    Stale, RecoveryRequired, AcknowledgeRequired, InvalidationRequired,
    Unsupported, StorageError, InvalidConfiguration
};

// Caller serializes this object, the store and body inventory. Borrowed store
// identity is fixed until Reset; a moved/destroyed store requires Reset first.
// Insertion revisions do not restart an unfinished pass. Completion verifies a
// stable revision, repeating a bounded pass if it changed. Under continuous
// churn Progress is permitted; finite stable inventories eventually terminate.
class CandidateSelector {
public:
    CandidateSelector();
    ~CandidateSelector();
    CandidateSelector(CandidateSelector &&) noexcept;
    CandidateSelector &operator=(CandidateSelector &&) noexcept;
    CandidateSelector(const CandidateSelector &) = delete;
    CandidateSelector &operator=(const CandidateSelector &) = delete;
    // Choices change only on Ready/NeedBodies/Deferred/RetainActive; all are
    // complete competitive-prefix observations under the returned fences.
    // Usage is reported on every return except refused reentry, which changes
    // no outputs (they may alias the outer operation). Resources never mark invalid.
    CandidateResult Poll(const Hash &expected_stable_tip, uint64_t now,
        uint64_t future_window, uint64_t body_epoch, const CandidateLimits &,
        const CandidateBodyProbe &, const DiskStateStore &, CandidateChoices &,
        CandidatePollUsage &, DiskStateError &);
    // Reset during a callback is refused (no state change).
    bool Reset() noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Rechecks profile/root/tip/work/revision/invalidity and recovery fences, body
// epoch, clock rollback/window changes, newly eligible higher work and the
// selected branch's all-ancestor clock gate. No mutation, reservation or VM.
// This is an eligibility/fence recheck, not a new best-rank scan or a seal over
// mutable public fields. Controller retains the exact returned choices and
// passes one of those choices unchanged; Prepare independently gates invalidity.
CandidateResult ValidateCandidateChoice(const CandidateChoices &,
    const CandidateChoice &, uint64_t now, uint64_t future_window,
    uint64_t body_epoch, const CandidateLimits &, const DiskStateStore &,
    CandidatePollUsage &, DiskStateError &);

} // namespace lotus::v2
#endif
