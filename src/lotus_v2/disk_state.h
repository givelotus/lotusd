// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DISK_STATE_H
#define LOTUS_V2_DISK_STATE_H

#include "sparse_state.h"
#include "chain_index.h"
#include "candidate_store.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace leveldb { class Env; }
namespace lotus::v2 {

// Storage failures are operational; callers must never translate them into a
// consensus-invalid block. Mutation errors are separate from storage errors.
enum class DiskStateErrorCode {
    None, Database, Resource, Corruption, ProfileMismatch, Closed,
    Duplicate, Missing, InvalidCoin, UndoMismatch, TransactionAborted
};
struct DiskStateError {
    DiskStateErrorCode code{DiskStateErrorCode::None};
    std::string message;
};
// Raw engine diagnostics for storage tests; never a consensus input.
struct DiskStateSyncStatus {
    bool writable_map{}, safe_nosync{}, nometasync{}, utterly_nosync{};
    uint64_t sync_bytes{}, unsynced_bytes{};
    uint32_t sync_period_16dot16{};
};
struct DiskFileLocation {
    uint32_t file_num{};
    uint32_t data_pos{};
    uint32_t length{};
    bool operator==(const DiskFileLocation &) const = default;
};
using DiskBlockLocation = DiskFileLocation;
using DiskUndoLocation = DiskFileLocation;
// Explicit journal-aware indexed-home creation limits, not consensus caps.
// Embedded pinned bodies live inside the bounded coordinator journal payload.
struct DiskRecoveryOptions {
    size_t max_journal_bytes{};
    size_t max_undo_bytes{};
};
struct DiskRecoveryUpdate {
    std::optional<std::vector<uint8_t>> expected_journal, next_journal;
    Hash expected_tip{}, expected_root{}, next_tip{};
    std::optional<Hash> expected_undo_digest;
};
struct DiskRecoveryUndoInfo {
    uint64_t bytes{};
    Hash digest{}, before_tip{}, after_tip{}, before_root{}, after_root{};
};
struct DiskStateOptions {
    Hash identity{};
    Hash profile_digest{};
    // Expiry-authenticated development formats V5 (generic), V6 (indexed),
    // V7 (recovery), V8 (candidates). All require fresh homes; pre-expiry
    // formats V1-V4 are rejected without implicit migration/reset.
    std::optional<HeaderChainProfile> header_index;
    // Recovery requires header_index and a fresh V7 directory.
    std::optional<DiskRecoveryOptions> recovery;
    // V8 inventory/receipt home requires recovery and a new directory.
    std::optional<CandidateStoreOptions> candidates;
    // Explicit fresh-home Avalanche policy. Auto-unparking is disabled.
    bool avalanche{};
    // Open only an initialized home; never create schema or initial metadata.
    // This still takes LevelDB's exclusive lock and may maintain engine files.
    bool existing_only{false};
    uint64_t max_avalanche_reads{100000};
    size_t cache_bytes{8 << 20};
    size_t write_buffer_bytes{4 << 20}; // LevelDB's minimum is 64 KiB.
    // Limits retained overlay key/value payload, not total RAM. Map overhead,
    // LevelDB buffers and temporary batch/undo encoding add memory overhead.
    size_t max_pending_bytes{64 << 20}; // Operational limit, not consensus.
    size_t max_metadata_bytes{16 << 20};
    // Optional borrowed Env for embedding/testing; must outlive store/transactions.
    leveldb::Env *env{nullptr};
};
// Enclosing validator owns framing and semantic checks of these opaque bytes.
// All metadata and the authenticated UTXO root commit in the same sync batch.
struct DiskStateMetadata {
    Hash tip{};
    std::vector<uint8_t> header;
    std::vector<uint8_t> monetary;
    std::vector<uint8_t> auxiliary;
    bool operator==(const DiskStateMetadata &) const = default;
};
// Raw retained metadata plus its historical UTXO commitment. This neither
// classifies active-chain membership nor revalidates block/VM semantics.
struct RetainedDiskState {
    DiskStateMetadata metadata;
    Hash root{};
};
// The enclosing validator checks opaque predecessor metadata against this
// restored authenticated root before publication. Callback reads on the store
// still see the current state; validate the supplied arguments. Begin and
// Disconnect are blocked during the callback. Refusal/exception is operational.
using DiskStateMetadataValidator = std::function<bool(const DiskStateMetadata &,
                                                     const Hash &, DiskStateError &)>;
struct DiskStateStats {
    uint64_t database_reads{};
    uint64_t dirty_nodes{};
    uint64_t dirty_coins{};
    uint64_t batch_puts{};
    uint64_t batch_deletes{};
    uint64_t batch_bytes{};
    uint64_t pending_bytes{};
};
struct DiskBlockPolicy {
    bool known{}, parked{}, finalized{}, conflicting_finalized{};
    std::optional<Hash> park_root;
};
struct DiskParkUpdate { Hash block{}; bool parked{}; };
class DiskStateTransaction;
// Bundled ABC LevelDB, hidden behind this backend seam. No complete UTXO set is
// held in memory or scanned on open, connect, proof, or disconnect. Callers must
// serialize operations on one store and its transactions. A transaction keeps
// its store alive; only one may be active. Read the staged view through it.
class DiskStateStore {
public:
    DiskStateStore();
    ~DiskStateStore();
    DiskStateStore(DiskStateStore &&) noexcept;
    DiskStateStore &operator=(DiskStateStore &&) noexcept;
    DiskStateStore(const DiskStateStore &) = delete;
    DiskStateStore &operator=(const DiskStateStore &) = delete;
    static bool Open(const std::string &directory, const DiskStateOptions &options,
                     const DiskStateMetadata &initial, DiskStateStore &out,
                     DiskStateError &error);
    bool IsOpen() const;
    bool CandidatesEnabled() const;
    bool MatchesProfile(const Hash &identity, const Hash &digest) const;
    Hash Root() const;
    DiskStateMetadata Metadata() const;
    // Current S or immutable U.after lookup; true + nullopt means no directly
    // addressable record. On false out is unchanged. Reads/checksums the full
    // LevelDB value before parsing; caller quotas do not bound Get allocation.
    // No historical C/N lookup, height index, pruning or availability promise.
    bool ReadRetainedState(const Hash &, std::optional<RetainedDiskState> &out,
                           DiskStateError &) const;
    bool ReadBlockLocation(const Hash &, std::optional<DiskBlockLocation> &out,
                           DiskStateError &) const;
    bool ReadUndoLocation(const Hash &, std::optional<DiskUndoLocation> &out,
                          DiskStateError &) const;
    bool ReadBlockSlice(const Hash &, uint64_t offset, uint64_t length,
                        std::vector<uint8_t> &out, uint64_t *total_bytes,
                        DiskStateError &) const;
    bool ReadUndoSlice(const Hash &, uint64_t offset, uint64_t length,
                       std::vector<uint8_t> &out, uint64_t *total_bytes,
                       DiskStateError &) const;
    bool ReadCoin(const Outpoint &, std::optional<Coin> &, DiskStateError &) const;
    bool Prove(const Outpoint &, CoinProof &, DiskStateError &) const;
    // Enclosing validator has already checked contextual header rules. This
    // mechanically binds identity/PoW/parent/height and derives work/time itself.
    // HeaderChecked never writes active-height mappings or Connected status.
    bool PutCheckedHeader(const Header &, DiskStateError &);
    bool ReadIndexedHeader(const Hash &, std::optional<IndexedHeader> &, DiskStateError &) const;
    bool ReadActiveId(uint64_t height, std::optional<Hash> &, DiskStateError &) const;
    bool ReadActiveIndex(std::optional<ActiveChainIndex> &, DiskStateError &) const;
    bool Begin(DiskStateTransaction &, DiskStateError &);
    bool CommitFinalizedOverlay(const class MempoolOverlayLayer &overlay,
                                const std::vector<Coin> &coinbase_coins,
                                const DiskStateMetadata &next,
                                DiskStateError &error);
    bool CommitFinalizedOverlay(const class MempoolOverlayLayer &overlay,
                                const std::vector<Coin> &coinbase_coins,
                                const DiskStateMetadata &next,
                                const Header &fully_connected,
                                DiskStateError &error);
    // Coordinator owns canonical phase/revision/plan grammar in opaque bytes.
    // Payload CAS plus expected tip/root fences updates. Stored J independently
    // binds the actual checkpoint. Only WriteRecoveryJournal may remove J after
    // coordinator-verified completion; state-changing recovery steps retain J.
    bool ReadRecoveryJournal(size_t max_bytes, std::optional<std::vector<uint8_t>> &out,
                             DiskStateError &) const;
    bool WriteRecoveryJournal(const DiskRecoveryUpdate &, DiskStateError &);
    bool BeginRecovery(const DiskRecoveryUpdate &, DiskStateTransaction &, DiskStateError &);
    bool DisconnectRecovery(const Hash &expected_tip, const DiskStateMetadataValidator &,
                            const DiskRecoveryUpdate &, DiskStateError &);
    // Size-probes value before copying to an application string. Engine SST
    // block allocation is bounded by trusted creation caps, not this quota;
    // forged/corrupt oversized engine records are outside that allocation claim.
    bool ProbeRecoveryUndo(const Hash &, size_t max_bytes,
                           std::optional<DiskRecoveryUndoInfo> &out, DiskStateError &) const;
    bool Disconnect(const Hash &expected_tip, DiskStateError &);
    bool Disconnect(const Hash &expected_tip, const DiskStateMetadataValidator &validate,
                    DiskStateError &);
    // Candidate pages are exclusive descending-work scans with fixed cursors.
    // Insertions may advance revision while a pass continues. The selector must
    // finish/revalidate a stable pass before claiming the best candidate.
    bool ReadCandidateView(CandidateView &, DiskStateError &) const;
    bool ReadCandidatePage(const std::optional<CandidateRankCursor> &after,
                           const CandidateQueryLimits &, CandidatePage &, DiskStateError &,
                           CandidateQueryUsage *usage = nullptr) const;
    bool ReadCandidateChildren(const Hash &parent, const std::optional<Hash> &after,
                               const CandidateQueryLimits &, CandidateChildrenPage &, DiskStateError &,
                               CandidateQueryUsage *usage = nullptr) const;
    bool ReadCandidateInvalidity(const Hash &, std::optional<Hash> &causal_root, DiskStateError &) const;
    // Must recheck at serialized preparation handoff; observation is no lease.
    bool CheckCandidateRecoveryCapacity(uint64_t max_disconnects, DiskStateError &) const;
    bool EvictCandidateLeaf(const Hash &, DiskStateError &);
    // J-clear and typed terminal receipt publish together. Unknown outcomes can
    // never establish permanent invalidity. Ack fences exact receipt/stable tip,
    // publishes causal fact/propagation cursor if proven, and removes receipt.
    bool FinishCandidateRecovery(const DiskRecoveryUpdate &, const CandidateTerminalClaim &, DiskStateError &);
    bool ReadCandidateReceipt(std::optional<CandidateTerminalReceipt> &, DiskStateError &) const;
    bool AcknowledgeCandidateReceipt(const Hash &expected_receipt_id,
                                    const Hash &expected_stable_tip, DiskStateError &);
    bool StepCandidateInvalidation(const CandidateQueryLimits &, CandidateInvalidationProgress &, DiskStateError &,
                                   CandidateQueryUsage *usage = nullptr);
    bool AvalancheEnabled() const;
    // Bounded ancestry lookup; parking is policy, never consensus invalidity.
    bool ReadBlockPolicy(const Hash &, uint64_t max_reads, DiskBlockPolicy &,
                         DiskStateError &) const;
    // One sync batch, no J/R/P or active transaction. Volatile finality publishes
    // only after successful sync and resets when the store is reopened.
    bool ApplyBlockPolicy(const Hash &expected_tip, uint64_t expected_revision,
                          const std::vector<DiskParkUpdate> &,
                          const std::optional<Hash> &finalize, DiskStateError &);
    bool ExportCoins(std::vector<Coin> &out, DiskStateError &error) const;
    bool ImportFastSyncPivot(const DiskStateMetadata &pivot_metadata,
                             const Header &pivot_header,
                             const std::vector<Coin> &verified_coins,
                             DiskStateError &error);
    bool PeelBlockStateReverse(const Hash &expected_tip_h,
                               const DiskStateMetadata &parent_metadata,
                               const Header &parent_header,
                               const std::vector<Outpoint> &net_created_to_erase,
                               const std::vector<Coin> &prior_spent_to_insert,
                               DiskStateError &error,
                               const std::vector<Coin> &expired_swept_to_insert = {});
    // MonadDB-style asynchronous NVMe/MDBX page pre-faulting: sorts target
    // coin and SMT prefix keys in B+Tree order and issues non-blocking
    // madvise(POSIX_MADV_WILLNEED) + cursor warm-up on the memory-mapped store.
    bool PrefetchOutpointsAsync(std::span<const Outpoint> outpoints,
                                DiskStateError &error) const;
    // Kaspa-style Finality Horizon & Spent-Undo Pruning:
    // Safely deletes ancient block undo records (h <= finalized_tip_height - keep_recent_blocks)
    // from dbi_undo_locs while preserving 100% of the live UTXO state tree,
    // headers, and the recent keep_recent_blocks reverse-peel window.
    bool PruneFinalizedUndoHorizon(uint64_t finalized_tip_height,
                                   uint64_t keep_recent_blocks,
                                   DiskStateError &error,
                                   uint64_t *pruned_count_out = nullptr);
    uint64_t PrunedUndoHorizonHeight() const;
    DiskStateStats LastStats() const;
private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
    bool DisconnectImpl(const Hash &, const DiskStateMetadataValidator &,
                        const DiskRecoveryUpdate *, DiskStateError &);
    friend class DiskStateTransaction;
    friend bool RawDiskStateSyncStatus(const DiskStateStore &, DiskStateSyncStatus &,
                                      DiskStateError &);
    friend bool RawDiskStateAccess(const std::string &, const std::optional<std::string> &,
                                   std::optional<std::string> *,
                                   const std::vector<std::pair<std::string, std::optional<std::string>>> &,
                                   std::string *);
    friend bool RawDiskStateSnapshot(const std::string &, std::map<std::string, std::string> &,
                                     std::string *);
};
class DiskStateTransaction {
public:
    DiskStateTransaction();
    ~DiskStateTransaction();
    DiskStateTransaction(DiskStateTransaction &&) noexcept;
    DiskStateTransaction &operator=(DiskStateTransaction &&) noexcept;
    DiskStateTransaction(const DiskStateTransaction &) = delete;
    DiskStateTransaction &operator=(const DiskStateTransaction &) = delete;
    bool ReadCoin(const Outpoint &, std::optional<Coin> &, DiskStateError &) const;
    bool Prove(const Outpoint &, CoinProof &, DiskStateError &) const;
    bool Insert(const Coin &, DiskStateError &);
    bool Erase(const Outpoint &, DiskStateError &);
    Hash Root() const;
    DiskStateStats Stats() const;
    // One sync WriteBatch: changed coins/nodes, head, identity/profile and
    // immutable undo keyed by next.tip. A failed write poisons the store until
    // reopen because a failed sync can have an ambiguous durability outcome.
    bool Commit(const DiskStateMetadata &next, DiskStateError &);
    // Required in indexed mode; upgrades H and writes A/I atomically with S and
    // coins/nodes/undo. In generic mode binds the header then uses legacy commit.
    bool Commit(const DiskStateMetadata &next, const Header &fully_connected,
                DiskStateError &);
    void Abort();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool CommitImpl(const DiskStateMetadata &, const Header *, DiskStateError &);
    friend class DiskStateStore;
};
bool RawDiskStateAccess(const std::string &directory,
                        const std::optional<std::string> &read_key,
                        std::optional<std::string> *read_out,
                        const std::vector<std::pair<std::string, std::optional<std::string>>> &writes,
                        std::string *error = nullptr);
bool RawDiskStateSnapshot(const std::string &directory,
                          std::map<std::string, std::string> &out,
                          std::string *error = nullptr);
bool RawDiskStateSyncStatus(const DiskStateStore &, DiskStateSyncStatus &,
                           DiskStateError &);
} // namespace lotus::v2
#endif
