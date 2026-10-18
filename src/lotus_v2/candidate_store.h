// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CANDIDATE_STORE_H
#define LOTUS_V2_CANDIDATE_STORE_H
#include "chain_index.h"
#include <optional>
#include <vector>
namespace lotus::v2 {
class DeterministicBlockFailure;
class DiskStateStore;
// Defined only by the trusted canonical recovery journal codec. Unknown or
// malformed persisted evidence must never be promoted to a failure fact.
struct CandidateFailureJournalAccess;
class CandidateFailureFact {
public:
    CandidateFailureFact() = default;
    bool Valid() const { return valid_; }
    const Hash &BlockId() const { return block_; }
    const Hash &ParentId() const { return parent_; }
    const Hash &ProfileDigest() const { return profile_; }
    const Hash &ParentRoot() const { return parent_root_; }
    static bool FromValidation(const DeterministicBlockFailure &, CandidateFailureFact &);
private:
    CandidateFailureFact(const Hash &block, const Hash &parent, const Hash &profile, const Hash &root)
        : block_(block), parent_(parent), profile_(profile), parent_root_(root), valid_(true) {}
    Hash block_{}, parent_{}, profile_{}, parent_root_{};
    bool valid_{};
    friend class DiskStateStore;
    friend struct CandidateFailureJournalAccess;
};
struct CandidateStoreOptions {
    uint64_t max_candidates{}, max_speculative_headers{}, max_invalid_roots{};
};
// Pages order descending numeric work, then descending lexicographic BlockID.
struct CandidateRankCursor {
    ChainWork work{};
    Hash id{};
    bool operator==(const CandidateRankCursor &) const = default;
};
struct CandidateQueryLimits {
    uint64_t max_rows{}, max_reads{}, max_iterator_steps{}, max_decoded_bytes{};
};
struct CandidateQueryUsage {
    uint64_t rows{}, reads{}, iterator_steps{}, decoded_bytes{};
};
// Conservative Get/iterator-lookup read bounds for these fixed-size queries.
// Caller reserves before invocation; LastStats reports actual database reads.
inline constexpr uint64_t CANDIDATE_VIEW_MAX_READS = 20;
inline constexpr uint64_t CANDIDATE_CAPACITY_MAX_READS = 20;
inline constexpr uint64_t CANDIDATE_INVALIDITY_MAX_READS = 12;
struct CandidateView {
    Hash identity{}, profile_digest{}, stable_tip{}, root{};
    ChainWork active_work{};
    uint64_t active_max_ancestor_time{}, revision{}, invalid_epoch{},
        candidate_count{}, speculative_count{}, invalid_root_count{};
    bool pending_journal{}, pending_receipt{}, pending_propagation{};
};
struct CandidateRow { Hash id{}; IndexedHeader indexed; };
struct CandidatePage {
    CandidateView view;
    std::vector<CandidateRow> rows;
    std::optional<CandidateRankCursor> next;
    bool complete{};
    CandidateQueryUsage used;
};
struct CandidateChildrenPage {
    std::vector<Hash> children;
    std::optional<Hash> next;
    bool complete{};
    CandidateQueryUsage used;
};
enum class CandidateTerminalOutcome : uint8_t {
    CompletedTarget = 0, RestoredSourceUnknown = 1,
    RestoredSourceDeferred = 2, RestoredSourceDeterministic = 3
};
struct CandidateTerminalClaim {
    Hash attempt{}, source{}, target{};
    uint64_t revision{};
    CandidateTerminalOutcome outcome{CandidateTerminalOutcome::RestoredSourceUnknown};
    std::optional<CandidateFailureFact> failure;
};
struct CandidateTerminalReceipt {
    Hash id{}, identity{}, profile_digest{}, attempt{}, source{}, target{},
        stable_tip{}, stable_root{}, metadata_digest{};
    uint64_t revision{};
    CandidateTerminalOutcome outcome{CandidateTerminalOutcome::RestoredSourceUnknown};
    std::optional<CandidateFailureFact> failure;
};
struct CandidateInvalidationProgress {
    std::optional<Hash> root;
    uint64_t pending_nodes{}, excluded{};
    bool complete{};
    CandidateQueryUsage used;
};
} // namespace lotus::v2
#endif
