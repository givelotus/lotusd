// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_MEMPOOL_OVERLAY_H
#define LOTUS_V2_MEMPOOL_OVERLAY_H

#include "commitment.h"
#include "header.h"
#include "monetary.h"
#include "output.h"
#include "set_reconciliation.h"
#include "sparse_state.h"
#include "tagged_hash.h"
#include "tx_merklix.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

namespace lotus::v2 {

/**
 * Persistent Sparse Merkle Tree node for UTXO state commitments.
 * Shared across historical block snapshots and mempool overlay layers.
 */
struct SmtNode {
    Hash digest{};
    size_t count{0};
    uint64_t total_value{0};
    Hash key{};
    std::shared_ptr<const Coin> coin;
    std::array<std::shared_ptr<const SmtNode>, 2> child;

    bool IsLeaf() const noexcept { return coin != nullptr; }
    Hash ChildHash(unsigned bit) const {
        return child[bit] ? child[bit]->digest : EmptyUtxoRoot();
    }
    void Refresh(unsigned depth);
};

bool SmtKeyBit(const Hash &key, unsigned depth) noexcept;
void SmtInsert(std::shared_ptr<const SmtNode> &root, const Coin &coin);
void SmtErase(std::shared_ptr<const SmtNode> &root, const Outpoint &outpoint);
/**
 * 16-shard MonadDB-style parallel Sparse Merkle Tree batch update.
 * Pre-computes OutpointKey and UtxoLeaf digests in parallel, partitions
 * mutations across the 16 independent subtrees at depth 4 (`key[0] & 0x0F`),
 * updates all 16 subtrees in parallel with zero lock contention, and zips the
 * 16 depth-4 roots through depths 3 -> 2 -> 1 -> 0.
 * Guaranteed 100% bit-identical to serial SmtErase + SmtInsert.
 */
void SmtBatchUpdateParallel(
    std::shared_ptr<const SmtNode> &root,
    std::span<const Outpoint> erased,
    std::span<const Coin> inserted);
std::shared_ptr<const Coin> SmtFind(const std::shared_ptr<const SmtNode> &root,
                                    const Outpoint &outpoint);
Hash SmtRoot(const std::shared_ptr<const SmtNode> &root);

/**
 * Contiguous arena node for the radix-256 Transaction Commitment Subtree A
 * (non-coinbase transactions keyed by 256-bit TxID, LSB-first bit routing).
 */
struct TxOverlayNode {
    Hash digest{};
    uint32_t count{0};
    uint32_t left{0};
    uint32_t right{0};
    Hash key{};
    Hash tx_hash{};
    bool is_leaf{false};
    bool digest_dirty{false};
};

/**
 * Persistent path-copying arena for Subtree A (non-coinbase transactions).
 * Produces digests bit-for-bit identical to consensus TransactionRoot Subtree A.
 *
 * Legacy reference only: production overlay layers use txmerklix::Tree
 * (slab-backed, path-compressed, reference-counted, reclaiming). This
 * append-only arena never reclaims superseded path copies until Reset and is
 * retained for equivalence tests and A/B microbenchmarks.
 */
class TxOverlayArena {
public:
    static constexpr uint32_t kNullIdx = 0;

    TxOverlayArena();

    void Reset();
    void Reserve(size_t capacity);

    uint32_t InsertTxLeaf(uint32_t root_idx, const Hash &tx_id,
                          const Hash &tx_hash);
    uint32_t EraseTxLeaf(uint32_t root_idx, const Hash &tx_id);

    /**
     * 16-shard parallel batch insertion into the contiguous TxOverlayArena.
     * Partitions transactions by `tx_id[0] & 0x0F` (depth-4 routing prefix),
     * builds per-shard arena subtrees in parallel, splices them into the
     * contiguous `nodes_` vector, and zips depths 3 -> 2 -> 1 -> 0.
     * Produces a SubtreeARoot 100% bit-identical to serial InsertTxLeaf.
     */
    uint32_t InsertBatchParallel(
        uint32_t root_idx,
        std::span<const std::pair<Hash, Hash>> txs);

    Hash SubtreeARoot(uint32_t root_idx) const;
    uint32_t Count(uint32_t root_idx) const noexcept;
    size_t ArenaNodeCount() const noexcept { return nodes_.size(); }

private:
    mutable std::vector<TxOverlayNode> nodes_;

    uint32_t AllocNode(const TxOverlayNode &node);
    uint32_t MakeLeaf(const Hash &tx_id, const Hash &tx_hash,
                      const Hash &leaf_hash);
    uint32_t JoinLeaves(uint32_t existing_idx, uint32_t added_idx,
                        unsigned depth);
    uint32_t InsertAt(uint32_t node_idx, const Hash &tx_id,
                      const Hash &tx_hash, const Hash &leaf_hash,
                      unsigned depth);
    uint32_t EraseAt(uint32_t node_idx, const Hash &tx_id, unsigned depth);
    Hash ChildHash(uint32_t idx) const;
    void RefreshNode(uint32_t idx, unsigned depth) const;
    void EnsureDigest(uint32_t idx, unsigned depth) const;
};

/**
 * Contiguous arena node for UTXO Sparse Merkle Tree overlays.
 * Supports lazy O(1) structural sharing from a base SmtNode snapshot.
 */
struct UtxoOverlayNode {
    Hash digest{};
    uint32_t count{0};
    std::array<uint32_t, 2> child{{0, 0}};
    std::array<std::shared_ptr<const SmtNode>, 2> base_child{{nullptr, nullptr}};
    std::shared_ptr<const SmtNode> base_self{nullptr};
    Hash key{};
    std::shared_ptr<const Coin> coin;
    bool is_leaf{false};
    bool digest_dirty{false};
};

/**
 * Contiguous arena-backed UTXO SMT overlay supporting O(1) initialization from
 * a parent block's SmtNode root and path-copying InsertCoin / EraseOutpoint.
 *
 * [Optimization — Rolls into Patch 020]:
 * Eliminates duplicate per-coin SmtInsert/SmtErase tree walks and BLAKE3 hashes
 * during InsertCoin/EraseOutpoint. Instead, all mutations operate solely on the
 * contiguous `nodes_` arena and `GetSmtRoot()` lazily exports `current_smt_root_`
 * from `nodes_[root_idx_]` on demand with zero BLAKE3 re-hashing.
 */
class UtxoOverlayArena {
public:
    static constexpr uint32_t kNullIdx = 0;

    UtxoOverlayArena();
    explicit UtxoOverlayArena(std::shared_ptr<const SmtNode> base_root);

    void Reset(std::shared_ptr<const SmtNode> base_root = nullptr);
    void Reserve(size_t capacity);

    void InsertCoin(const Coin &coin);
    void EraseOutpoint(const Outpoint &outpoint);

    /**
     * 16-shard MonadDB-style parallel batch update on the contiguous UTXO
     * overlay arena. Guaranteed 100% bit-identical to serial EraseOutpoint +
     * InsertCoin.
     */
    void BatchUpdateParallel(
        std::span<const Outpoint> erased,
        std::span<const Coin> inserted);

    Hash RootDigest() const;
    Hash RootDigestWithExtraCoins(std::span<const Coin> extra_coins) const;
    uint32_t RootIdx() const noexcept { return root_idx_; }
    const std::shared_ptr<const SmtNode> &GetSmtRoot() const;
    bool IsSmtRootReady() const noexcept { return !smt_root_dirty_; }
    const std::shared_ptr<const SmtNode> &GetBaseSmtRoot() const noexcept {
        return base_smt_root_;
    }
    size_t ArenaNodeCount() const noexcept { return nodes_.size(); }

private:
    mutable std::vector<UtxoOverlayNode> nodes_;
    uint32_t root_idx_{kNullIdx};
    std::shared_ptr<const SmtNode> base_smt_root_;
    mutable std::shared_ptr<const SmtNode> current_smt_root_;
    mutable bool smt_root_dirty_{false};

    uint32_t AllocNode(const UtxoOverlayNode &node);
    uint32_t ImportSmtNode(const std::shared_ptr<const SmtNode> &smt_node);
    std::shared_ptr<const SmtNode> ExportSmtNode(uint32_t node_idx) const;
    uint32_t MakeLeaf(const Coin &coin, const Hash &key, const Hash &leaf_hash);
    uint32_t JoinLeaves(uint32_t existing_idx, uint32_t added_idx,
                        unsigned depth);
    uint32_t EnsureChildLoaded(uint32_t node_idx, unsigned bit);
    uint32_t InsertAt(uint32_t node_idx, const Coin &coin, const Hash &key,
                      const Hash &leaf_hash, unsigned depth);
    uint32_t EraseAt(uint32_t node_idx, const Outpoint &outpoint,
                     const Hash &key, unsigned depth);
    Hash ChildHash(const UtxoOverlayNode &node, unsigned bit) const;
    uint32_t ChildCount(const UtxoOverlayNode &node, unsigned bit) const;
    void RefreshNode(uint32_t idx, unsigned depth) const;
    void EnsureDigest(uint32_t idx, unsigned depth) const;
};

Hash EmptyTxRoot();

/**
 * O(1) hash functor for Outpoint in unordered_map tables.
 */
struct OutpointHasher {
    size_t operator()(const Outpoint &op) const noexcept {
        uint64_t h = 0;
        std::memcpy(&h, op.tx_id.data(), sizeof(h));
        return static_cast<size_t>(
            h ^ (static_cast<uint64_t>(op.index) * 0x9e3779b97f4a7c15ULL));
    }
};

/**
 * Comparator matching Bitcoin/Lotus CTOR TxId ordering (uint256::Compare,
 * comparing bytes from index 31 down to 0).
 */
struct CtorTxIdCompare {
    bool operator()(const Hash &a, const Hash &b) const noexcept {
        for (size_t i = 0; i < 32; ++i) {
            const uint8_t ba = a[31 - i];
            const uint8_t bb = b[31 - i];
            if (ba != bb) {
                return ba < bb;
            }
        }
        return false;
    }
};

struct OverlayTxEntry {
    Hash tx_id{};
    Hash tx_hash{};
    uint64_t linear_cost{0};
    uint64_t effective_cost{0};
    int64_t fee_sats{0};
    int64_t sigchecks{0};
    //! Conservative retained-body charge used by pinned reconciliation views.
    uint32_t payload_bytes{0};
    std::vector<Outpoint> spent_outpoints;
    std::vector<Coin> created_coins;
    std::shared_ptr<const void> tx_ref;
};

/**
 * A single overlay layer in the progressive Merklix Overlay Stack:
 *   Layer 0 (Confirmed Chain Tip) -> Layer 1..k (Frozen Epoch Batches) -> Speculative Tip.
 *
 * Maintains:
 *   - Subtree A (non-coinbase TxRoot Merklix) via txmerklix::Tree: lazy
 *     digests, O(1) structural pins for advertised/hashed snapshots, and an
 *     incrementally maintained bottom-k MinHash of the same membership
 *   - UTXO State Root SMT via UtxoOverlayArena (with intra-overlay spend elision)
 *   - Additive non-coinbase effective block cost for O(1) MonetaryState transition
 *   - CTOR-sorted active transaction map for O(1) block template emission
 */
class MempoolOverlayLayer {
public:
    MempoolOverlayLayer();
    MempoolOverlayLayer(const Hash &parent_block_id,
                        std::shared_ptr<const SmtNode> base_utxo_root,
                        const MonetaryState &base_mon_state,
                        uint64_t height,
                        uint64_t parent_mtp,
                        uint64_t layer_id = 0);

    void Reset(const Hash &parent_block_id,
               std::shared_ptr<const SmtNode> base_utxo_root,
               const MonetaryState &base_mon_state,
               uint64_t height,
               uint64_t parent_mtp,
               uint64_t layer_id = 0);

    bool AddTransaction(const Hash &tx_id,
                        const Hash &tx_hash,
                        uint64_t linear_cost,
                        const std::vector<Outpoint> &spent_outpoints,
                        const std::vector<Coin> &created_coins,
                        int64_t fee_sats = 0,
                        int64_t sigchecks = 0,
                        std::shared_ptr<const void> tx_ref = nullptr,
                        uint32_t payload_bytes = 0);

    /**
     * Coalesced batch transaction insertion into the overlay. Transaction
     * tree inserts are sequential path-copy/in-place updates without hashing;
     * the UTXO arena is rebuilt lazily as before.
     */
    size_t AddTransactionBatch(std::span<OverlayTxEntry> entries);

    /**
     * Re-anchoring support: adopt an existing transaction tree whose
     * membership exactly equals the entries subsequently re-added with
     * AddTransactionBatch(entries, tree_already_contains = true).
     */
    void AdoptTxTree(txmerklix::Tree tree) { tx_tree_ = std::move(tree); }
    size_t AddTransactionBatch(std::span<OverlayTxEntry> entries,
                               bool tree_already_contains);

    bool RemoveTransaction(const Hash &tx_id);

    bool Contains(const Hash &tx_id) const;

    /** Lazily completes only dirty digests; caller holds the writer lock. */
    Hash GetSubtreeARoot() const { return tx_tree_.RootDigest(); }
    /** O(1) immutable view of the current Subtree A membership + MinHash. */
    std::shared_ptr<const txmerklix::Snapshot> PinTxTree() const {
        return tx_tree_.Pin();
    }
    Hash GetUtxoRootDigest() const {
        EnsureUtxoArenaUpdated();
        return utxo_arena_.RootDigest();
    }
    const std::shared_ptr<const SmtNode> &GetUtxoRoot() const {
        EnsureUtxoArenaUpdated();
        return utxo_arena_.GetSmtRoot();
    }
    bool IsOverlayWarm() const noexcept {
        return !utxo_arena_dirty_ && utxo_arena_.IsSmtRootReady();
    }
    const std::shared_ptr<const SmtNode> &GetBaseUtxoRoot() const noexcept {
        return utxo_arena_.GetBaseSmtRoot();
    }
    const MonetaryState &GetBaseMonetaryState() const noexcept {
        return base_mon_state_;
    }
    uint64_t GetSumNonCbEffectiveCost() const noexcept {
        return sum_non_cb_effective_cost_;
    }
    int64_t GetTotalFeesSats() const noexcept { return total_fees_sats_; }
    int64_t GetTotalSigChecks() const noexcept { return total_sigchecks_; }
    uint64_t GetTotalBytes() const noexcept { return total_bytes_; }
    bool HasDoubleSpends() const noexcept { return conflict_count_ > 0; }
    size_t GetTxCount() const noexcept { return active_txs_.size(); }
    const Hash &GetParentBlockId() const noexcept { return parent_block_id_; }
    uint64_t GetHeight() const noexcept { return height_; }
    uint64_t GetParentMtp() const noexcept { return parent_mtp_; }
    uint64_t GetLayerId() const noexcept { return layer_id_; }

    void SetCommitStateRootInHeader(bool commit) noexcept {
        commit_state_root_in_header_ = commit;
    }
    bool GetCommitStateRootInHeader() const noexcept {
        return commit_state_root_in_header_;
    }

    bool IsSpent(const Outpoint &op) const noexcept {
        auto it = spent_outpoints_.find(op);
        return it != spent_outpoints_.end() && it->second > 0;
    }

    bool FindCreatedCoin(const Outpoint &op, Coin *out = nullptr) const {
        if (IsSpent(op)) {
            return false;
        }
        auto it = created_coins_.find(op);
        if (it == created_coins_.end()) {
            return false;
        }
        if (out != nullptr) {
            *out = it->second;
        }
        return true;
    }

    const Hash &GetNullMerkleRoot() const {
        EnsurePositionalMerkleUpdated();
        return null_merkle_root_;
    }

    const std::vector<Hash> &GetCoinbaseMerkleBranch() const {
        EnsurePositionalMerkleUpdated();
        return coinbase_merkle_branch_;
    }

    Hash ComputePositionalMerkleRoot(const Hash &coinbase_txid) const;

    const BucketSyndrome &GetSyndrome() const noexcept { return syndrome_; }
    std::pair<uint64_t, uint64_t> GetSipHashKey() const noexcept {
        return {siphash_k0_, siphash_k1_};
    }

    const std::map<Hash, OverlayTxEntry, CtorTxIdCompare> &
    GetOrderedTxs() const noexcept {
        return active_txs_;
    }

    /**
     * Export net base-chain erased outpoints and surviving created coins
     * (with intra-overlay ephemeral outputs elided) for atomic MDBX commit.
     */
    std::vector<Outpoint> GetNetErasedOutpoints() const;
    std::vector<Coin> GetNetInsertedCoins() const;

    const txmerklix::Tree &GetTxTree() const noexcept { return tx_tree_; }
    const UtxoOverlayArena &GetUtxoArena() const {
        EnsureUtxoArenaUpdated();
        return utxo_arena_;
    }

private:
    void EnsureUtxoArenaUpdated() const;
    void EnsurePositionalMerkleUpdated() const;

    uint64_t layer_id_{0};
    Hash parent_block_id_{};
    uint64_t height_{1};
    uint64_t parent_mtp_{0};
    MonetaryState base_mon_state_{};
    bool commit_state_root_in_header_{false};

    txmerklix::Tree tx_tree_;
    mutable UtxoOverlayArena utxo_arena_;
    mutable bool utxo_arena_dirty_{false};
    uint64_t sum_non_cb_effective_cost_{0};
    int64_t total_fees_sats_{0};
    int64_t total_sigchecks_{0};
    uint64_t total_bytes_{0};
    size_t conflict_count_{0};
    uint64_t siphash_k0_{0};
    uint64_t siphash_k1_{0};
    BucketSyndrome syndrome_{};

    mutable bool positional_merkle_dirty_{true};
    mutable Hash null_merkle_root_{};
    mutable std::vector<Hash> coinbase_merkle_branch_;

    std::map<Hash, OverlayTxEntry, CtorTxIdCompare> active_txs_;
    std::unordered_map<Outpoint, Coin, OutpointHasher> created_coins_;
    std::unordered_map<Outpoint, uint32_t, OutpointHasher> spent_outpoints_;
};

/**
 * Manages the progressive stack of frozen pre-consensus epoch overlay layers
 * and the mutable speculative mempool tip overlay.
 */
class MerklixOverlayManager {
public:
    MerklixOverlayManager();

    void ResetToTip(const Hash &tip_block_id,
                    std::shared_ptr<const SmtNode> base_utxo_root,
                    const MonetaryState &base_mon_state,
                    uint64_t next_height,
                    uint64_t parent_mtp);

    void Clear();

    bool IsAnchoredAt(const Hash &tip_block_id,
                      uint64_t next_height,
                      uint64_t parent_mtp) const noexcept;

    /**
     * Re-anchors existing speculative transactions onto a new tip snapshot
     * (e.g. after a block connects or when height/MTP changes).
     */
    void ReanchorExistingTxs(const Hash &tip_block_id,
                             std::shared_ptr<const SmtNode> base_utxo_root,
                             const MonetaryState &base_mon_state,
                             uint64_t next_height,
                             uint64_t parent_mtp);

    bool AddTransaction(const Hash &tx_id,
                        const Hash &tx_hash,
                        uint64_t linear_cost,
                        const std::vector<Outpoint> &spent_outpoints,
                        const std::vector<Coin> &created_coins,
                        int64_t fee_sats = 0,
                        int64_t sigchecks = 0,
                        std::shared_ptr<const void> tx_ref = nullptr);

    size_t AddTransactionBatch(std::span<OverlayTxEntry> entries);

    bool RemoveTransaction(const Hash &tx_id);

    bool LookupCoinInStack(const Outpoint &op, Coin *out,
                           bool &spent_in_stack) const;

    /**
     * Freezes the current speculative state as an immutable epoch overlay
     * snapshot and increments the epoch counter.
     */
    const MempoolOverlayLayer &FreezeEpochBatch();

    const MempoolOverlayLayer &GetSpeculativeOverlay() const noexcept {
        return speculative_layer_;
    }
    MempoolOverlayLayer &GetSpeculativeOverlay() noexcept {
        return speculative_layer_;
    }
    const std::vector<MempoolOverlayLayer> &GetFrozenEpochs() const noexcept {
        return frozen_epochs_;
    }

private:
    uint64_t next_epoch_id_{1};
    MempoolOverlayLayer speculative_layer_;
    std::vector<MempoolOverlayLayer> frozen_epochs_;
};

const MonetaryProfile &GetDefaultV2MonetaryProfile() noexcept;
MonetaryState GetInitialV2MonetaryState();

} // namespace lotus::v2

#endif // LOTUS_V2_MEMPOOL_OVERLAY_H
