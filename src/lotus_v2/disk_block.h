// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_DISK_BLOCK_H
#define LOTUS_V2_DISK_BLOCK_H
#include "block_transition.h"
#include "disk_state.h"
namespace lotus::v2 {
// Local storage-format fingerprint of all validator parameters. Excludes only
// per-block candidate height/MTP, which are checked against authenticated history.
// This is not the network manifest digest or a new consensus hash domain.
Hash BlockValidationProfileDigest(const HeaderChainProfile &,
    const OrdinaryCandidateProfile &, const MonetaryProfile &, const BlockCostProfile &);
// Versioned local metadata containing the newest-first header window and exact
// block bytes. Empty bytes are permitted only for an explicitly trusted initial
// state supplied by the enclosing genesis initializer; this does not validate it.
std::vector<uint8_t> EncodeDiskChainContext(const std::vector<Header> &history,
                                          const std::vector<uint8_t> &block);
// Authenticates history against meta.tip and checks stored block header/length.
// Does not revalidate the body transaction root or VM; body bytes remain local
// previously validated data and must not be advertised as freshly revalidated.
bool ReadDiskChainContext(const DiskStateMetadata &, const HeaderChainProfile &,
                          std::vector<Header> &history, std::vector<uint8_t> &block,
                          std::string &error);
// Derives height and median time from persisted authenticated header context.
// Every connector clears the optional failure output before any early return.
// Invalid alone concerns supplied bytes; only a valid failure token certifies a
// deterministic failure bound to the exact body, parent and validator profile.
// Inconclusive is a local execution limitation, never permanent invalidity.
CandidateCheckResult ConnectStoredDiskBlock(
    const std::vector<uint8_t> &wire, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure = nullptr);
// Always-aborted local construction preview. Authenticates the same stored
// parent/profile/history as the normal connector, derives height/MTP, and opens
// a fresh private overlay. Never commits or issues deterministic-failure proof.
// Resource refusal is CapacityRefused; pending writer is Inconclusive; database
// or authenticated metadata corruption is StorageError. Failure preserves out.
BlockPreviewResult PreviewStoredBlockTemplate(
    const std::vector<Transaction> &, uint64_t candidate_time,
    const BlockPreviewLimits &, const HeaderChainProfile &,
    OrdinaryCandidateProfile, const MonetaryProfile &, const BlockCostProfile &,
    DiskStateStore &, BlockPreview &out, std::string &error);
// Executes identical deterministic validation while the storage transaction
// publishes the supplied recovery progress in the same accepted-block batch.
// The coordinator owns all-ancestor clock eligibility and plan validation.
CandidateCheckResult ConnectStoredRecoveryBlock(
    const std::vector<uint8_t> &wire, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    const DiskRecoveryUpdate &recovery, DiskStateStore &store,
    StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure = nullptr);
// Node admission adds external-clock eligibility without changing deterministic
// consensus. Deferred bodies must be reconsidered as time advances; callers own
// bounded retry queues and best-chain selection. No time-window default exists.
enum class DiskBlockAdmission { Accepted, Invalid, Deferred, StorageError, Inconclusive };
DiskBlockAdmission ConnectEligibleDiskBlock(
    const std::vector<uint8_t> &wire, uint64_t now, uint64_t future_window,
    const HeaderChainProfile &hp, OrdinaryCandidateProfile op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure = nullptr);
// Caller serializes access to the store. History is authenticated chain ancestry
// ending at its stored tip; clock eligibility and best-chain selection are
// enclosing-node responsibilities. Success means one durable database batch.
// On StorageError after a failed sync, reopen before determining which tip won.
CandidateCheckResult ConnectDiskBlock(
    const std::vector<uint8_t> &wire, const std::vector<Header> &history,
    const HeaderChainProfile &hp, const OrdinaryCandidateProfile &op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure = nullptr);
} // namespace lotus::v2
#endif
