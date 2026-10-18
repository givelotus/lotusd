// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DEVELOPMENT_RUNTIME_H
#define LOTUS_V2_DEVELOPMENT_RUNTIME_H
#include "block_assembler.h"
#include "candidate_body_pool.h"
#include "candidate_selection.h"
#include "development_chain.h"
#include "header_admission.h"
#include "reorg_recovery.h"
namespace lotus::v2 {
enum class RuntimeBlockStatus { Accepted, Rejected, Finalized, Invalid, Stale };
struct RuntimeBlockUpdate {
    Hash block{};
    RuntimeBlockStatus status{};
    Hash expected_tip{};
    uint64_t expected_generation{};
};
struct RuntimeBlockObservation {
    bool known{}, valid{}, active{}, parked{}, finalized{}, conflicting_finalized{}, forks_active{}, has_data{};
};
struct DevelopmentRuntimeConfig {
    std::string directory;
    std::vector<uint8_t> genesis_wire;
    ReorgProfiles profiles;
    MonetaryState initial_money;
    DiskStateOptions
        storage; // Explicit V4 candidates + recovery caps required.
    CandidateBodyLimits bodies;
    uint64_t initial_body_epoch{}, initial_context_generation{};
};
struct DevelopmentTickLimits {
    CandidateLimits selection;
    ReorgLimits recovery;
    CandidateQueryLimits propagation;
};
enum class DevelopmentRuntimeResult {
    Progress,
    Prepared,
    Recovering,
    CompleteTarget,
    RestoredSource,
    Acknowledged,
    Invalidated,
    NeedBodies,
    Deferred,
    RetainActive,
    Reopened,
    Inconclusive,
    CapacityRefused,
    ReopenRequired,
    StorageError,
    InvalidConfiguration,
    Busy,
    Closed,
    ExcludedTarget,
    MissingHeader,
    MissingBody,
    MalformedBody
};
struct DevelopmentRuntimeSnapshot {
    uint64_t body_epoch{}, context_generation{};
    bool reopen_required{}, execution_paused{};
    // Last authoritative observation; absent whenever its authority is unknown.
    std::optional<CandidateView> chain;
};
// Pure in-memory authority comparison for verified body slices. Pending,
// paused or unavailable snapshots never authorize a cached response.
bool SameDevelopmentBodyAuthority(const DevelopmentRuntimeSnapshot &,
                                  const DevelopmentRuntimeSnapshot &);
struct DevelopmentBodyChunk {
    uint64_t total_bytes{};
    std::vector<uint8_t> bytes;
    DevelopmentRuntimeSnapshot snapshot;
};
// Per-call work diagnostics only; these counters never affect validation.
struct DevelopmentBodyChunkUsage {
    uint64_t view_calls{}, body_load_attempts{}, cache_hits{}, copied_bytes{};
};
struct DevelopmentTickUsage {
    // Callback/probe copies only, saturating on overflow; coordinator-internal
    // pinned source/journal/VM allocations retain their own creation caps.
    uint64_t view_calls{}, body_probe_calls{}, disk_probe_calls{},
        copied_body_bytes{};
    CandidatePollUsage selection;
    CandidateQueryUsage propagation;
    uint64_t recovery_calls{};
    bool reopened{};
    // Full block validation/undo retain their profile/creation/overlay bounds;
    // they are not charged to selection.query.max_reads. View calls reserve
    // CANDIDATE_VIEW_MAX_READS each, plus storage creation-capped decode/copy.
    // Runtime keeps one bounded choice observation; returning choices adds one
    // more copy besides selector-owned memory. Caller owns returned snapshots.
};
struct DevelopmentTick {
    DevelopmentRuntimeResult result{DevelopmentRuntimeResult::Progress};
    DevelopmentRuntimeSnapshot snapshot;
    DevelopmentTickUsage usage;
    std::optional<CandidateChoices>
        choices; // Bounded selector observation only.
    std::optional<ReorgProgress> recovery;
    bool context_changed{};
    std::string diagnostic;
};
// Single owner, socket-free V4 state machine. Explicit
// directory/genesis/profile; no launch defaults, profile adoption, peer
// requests or mutable store escape. Each Tick performs one recovery step,
// receipt ack, propagation step, selector Poll or validated Prepare. Reopen
// consumes a tick. Inconclusive execution pauses with J intact until
// RetryPausedExecution or a new runtime is opened. Move transfers the stable
// heap-owned store/selector together. Do not move or destroy an owner during an
// operation/callback. Mutating reentry refuses Busy.
class DevelopmentRuntime {
public:
    static bool Open(DevelopmentRuntimeConfig,
                     std::unique_ptr<DevelopmentRuntime> &out,
                     std::string &error);
    ~DevelopmentRuntime();
    DevelopmentRuntime(DevelopmentRuntime &&) noexcept;
    DevelopmentRuntime &operator=(DevelopmentRuntime &&) noexcept;
    DevelopmentRuntime(const DevelopmentRuntime &) = delete;
    DevelopmentRuntime &operator=(const DevelopmentRuntime &) = delete;
    DevelopmentTick Tick(uint64_t now, uint64_t future_window,
                         const DevelopmentTickLimits &);
    DevelopmentRuntimeResult AdmitHeader(const Header &, HeaderAdmission &out,
                                         std::string &error);
    // Body binding is obtained from the indexed header, never caller
    // assertions.
    DevelopmentRuntimeResult RetainBody(const Hash &,
                                        const std::vector<uint8_t> &,
                                        CandidateBodyStatus &out,
                                        std::string &error);
    DevelopmentRuntimeResult EvictBody(const Hash &, CandidateBodyStatus &out,
                                       std::string &error);
    // Deterministic abort-only preview, not wall-clock eligibility or acceptance.
    // Access refusal preserves status/out. Once dispatched, status is valid even
    // on capacity/storage refusal; Progress means completed call, not Ready.
    // Successful preview leaves selection and availability epochs unchanged.
    DevelopmentRuntimeResult BuildTemplate(const LocalBlockRequest &,
                                            const LocalBlockLimits &,
                                            LocalBlockBuildResult &status,
                                            LocalBlockTemplate &out,
                                            std::string &error);
    bool RetryPausedExecution() noexcept;
    DevelopmentRuntimeSnapshot Snapshot() const;
    // Typed boundary for the Avalanche adapter; caller maps each status by name.
    // Every update must carry the same current tip/generation. Negative votes
    // park blocks and never produce deterministic-invalid ledger entries.
    bool ObserveAvalancheBlock(const Hash &, RuntimeBlockObservation &, std::string &);
    bool ApplyAvalancheUpdates(const std::vector<RuntimeBlockUpdate> &, std::string &);
    // Bounded persisted candidate inventory, including parked forks. Requires
    // explicit Avalanche policy and stable recovery authority. Refusal leaves
    // out unchanged; Resource limits do not revoke storage authority. Callers
    // fence pagination using page.view and Snapshot() availability epochs.
    DevelopmentRuntimeResult ReadAvalancheCandidates(
        const std::optional<CandidateRankCursor> &, const CandidateQueryLimits &,
        CandidatePage &out, std::string &error);
    // Read-only facade for a later bounded peer router. Outputs preserve the
    // underlying modules' success contracts. No borrowed store/pool handles.
    DevelopmentRuntimeResult ReadHeader(const Hash &,
                                        std::optional<IndexedHeader> &out,
                                        std::string &error);
    DevelopmentRuntimeResult
    ReadInvalidity(const Hash &, std::optional<Hash> &out, std::string &error);
    // Serving previously connected bytes without advertising pool-only bodies.
    DevelopmentRuntimeResult ReadConnectedBody(const Hash &, uint64_t max_bytes,
                                               std::vector<uint8_t> &out,
                                               std::string &error);
    // One-entry cache of authenticated, previously connected disk bytes.
    // Every call observes current authority; at most 65536 bytes are returned.
    // InvalidConfiguration here means invalid length/offset, including offset
    // past the end. Offset at the end succeeds with an empty slice. Every
    // failure preserves out; current max_body_bytes applies to cache hits too.
    DevelopmentRuntimeResult ReadConnectedBodyChunk(
        const Hash &, uint64_t max_body_bytes, uint64_t offset, uint64_t length,
        DevelopmentBodyChunk &out, std::string &error,
        DevelopmentBodyChunkUsage *usage = nullptr);
    DevelopmentRuntimeResult ReadBody(const Hash &, uint64_t max_bytes,
                                      std::vector<uint8_t> &out,
                                      std::string &error);
    ChainIndexResult BuildLocator(const Hash &expected_tip, size_t max_ids,
                                  std::vector<Hash> &out,
                                  DiskStateError &error);
    ChainIndexResult ReadHeaders(const Hash &expected_tip,
                                 std::span<const Hash> locator,
                                 const Hash &stop, size_t max_locator,
                                 size_t max_headers, std::vector<Header> &out,
                                 DiskStateError &error);
    DevelopmentRuntimeResult
    ReadCoin(const Outpoint &, std::optional<Coin> &out, std::string &error);
    DevelopmentRuntimeResult ProveCoin(const Outpoint &, CoinProof &out,
                                       std::string &error);
    // max_bytes bounds the sum of returned header/money/auxiliary payload.
    // The initial storage snapshot is separately creation-capped; this is not
    // a per-call bound on LevelDB or metadata snapshot allocations.
    DevelopmentRuntimeResult ReadMetadata(uint64_t max_bytes,
                                          DiskStateMetadata &out, Hash &root,
                                          std::string &error);
    DevelopmentRuntimeResult ReadBlockLocation(
        const Hash &, std::optional<DiskBlockLocation> &out, std::string &error);
    DevelopmentRuntimeResult ReadUndoLocation(
        const Hash &, std::optional<DiskUndoLocation> &out, std::string &error);
    DevelopmentRuntimeResult ReadBlockSlice(
        const Hash &, uint64_t offset, uint64_t length,
        std::vector<uint8_t> &out, uint64_t *total_bytes, std::string &error);
    DevelopmentRuntimeResult ReadUndoSlice(
        const Hash &, uint64_t offset, uint64_t length,
        std::vector<uint8_t> &out, uint64_t *total_bytes, std::string &error);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    explicit DevelopmentRuntime(std::unique_ptr<Impl>);
};
} // namespace lotus::v2
#endif
