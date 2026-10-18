// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_BLOCK_TRANSITION_H
#define LOTUS_V2_BLOCK_TRANSITION_H
#include "block.h"
namespace lotus::v2 {
// A private, abortable storage transaction pinned to the authenticated parent.
// Mutations never publish the live tip. Caller atomically commits accepted
// metadata with these writes afterward. All failed attempts call Abort().
class BlockStateTransaction {
public:
    virtual ~BlockStateTransaction() = default;
    virtual CoinReadResult Read(const Outpoint &, Coin &, std::string &) = 0;
    virtual bool Insert(const Coin &, std::string &) = 0;
    virtual bool Erase(const Outpoint &, std::string &) = 0;
    virtual Hash Root() const = 0;
    virtual void Abort() noexcept = 0;
};
struct StagedBlockTransition {
    Header header;
    Hash block_id{};
    Hash utxo_root{};
    Hash state_root{};
    MonetaryTransition monetary;
    // Authenticated effective costs used by this accepted transition.
    MonetaryInteger account_cost{}, enforce_cost{};
    VmCostUnits invocation_cost{};
};
struct BlockPreviewLimits {
    uint64_t max_transactions{}, max_block_bytes{};
};
enum class BlockPreviewResult {
    Ready,
    InvalidTransactions,
    CapacityRefused,
    Inconclusive,
    StorageError
};
struct BlockPreview {
    Header header;
    Hash parent_id{}, parent_utxo_root{}, profile_digest{}, utxo_root{},
        state_root{};
    MonetaryTransition monetary;
    MonetaryInteger account_cost{}, enforce_cost{};
    VmCostUnits invocation_cost{};
    uint64_t coinbase_bytes{}, frame_prefix_bytes{};
};
// Constructs an unsealed template from a complete, ordered transaction list.
// Ready is not block acceptance. Always aborts the supplied private overlay,
// including on Ready; leaves out unchanged on failure. No invalidity proof.
// max_block_bytes caps complete canonical wire before its encode/decode copies;
// temporary per-transaction encoding is separately bounded by TxProfile.
// Borrowed input transactions/backend overlays and allocator overhead are
// extra.
BlockPreviewResult PreviewBlockTemplate(
    const std::vector<Transaction> &complete_txs, uint64_t candidate_time,
    const BlockPreviewLimits &, const OrdinaryParentContext &,
    const std::vector<Header> &history, const HeaderChainProfile &,
    const OrdinaryCandidateProfile &, const MonetaryProfile &,
    const BlockCostProfile &, BlockStateTransaction &, BlockPreview &,
    std::string &error);

// Storage fingerprint, moved unchanged from disk_block.cpp. No backend linkage.
Hash BlockValidationProfileDigest(const HeaderChainProfile &,
                                  const OrdinaryCandidateProfile &,
                                  const MonetaryProfile &,
                                  const BlockCostProfile &);

// Only StageCompleteBlock can issue this proof, after authenticating the parent
// state and matching the complete body's commitments. An Invalid enum without
// this proof is insufficient to persist a header-invalid fact.
class DeterministicBlockFailure {
public:
    bool Valid() const { return valid_; }
    const Hash &BlockId() const { return block_; }
    const Hash &ParentId() const { return parent_; }
    const Hash &ProfileDigest() const { return profile_; }
    const Hash &ParentRoot() const { return root_; }

private:
    bool valid_ = false;
    Hash block_{}, parent_{}, profile_{}, root_{};
    friend CandidateCheckResult StageCompleteBlock(
        const std::vector<uint8_t> &, const OrdinaryParentContext &,
        const std::vector<Header> &, const HeaderChainProfile &,
        const OrdinaryCandidateProfile &, const MonetaryProfile &,
        const BlockCostProfile &, BlockStateTransaction &,
        StagedBlockTransition &, std::string &, DeterministicBlockFailure *);
};

// No full UTXO enumeration/copy. Memory is bounded by the decoded block and
// transaction/block deltas, plus the backend's operational cache/overlay limits.
// Accepted means validated and staged, not durably published or ConnectTip.
CandidateCheckResult StageCompleteBlock(
    const std::vector<uint8_t> &wire, const OrdinaryParentContext &parent,
    const std::vector<Header> &history,
    const HeaderChainProfile &header_profile,
    const OrdinaryCandidateProfile &ordinary_profile,
    const MonetaryProfile &monetary_profile,
    const BlockCostProfile &cost_profile, BlockStateTransaction &state,
    StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure = nullptr);
} // namespace lotus::v2
#endif
