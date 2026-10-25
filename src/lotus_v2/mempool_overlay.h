// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_MEMPOOL_OVERLAY_H
#define LOTUS_V2_MEMPOOL_OVERLAY_H

#include "commitment.h"
#include "header.h"
#include "monetary.h"
#include "output.h"
#include "sparse_state.h"
#include "tx_merklix.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lotus::v2 {

/**
 * Persistent Sparse Merkle Tree node for UTXO state commitments.
 * Shared across historical block snapshots and mempool overlay layers.
 */
struct SmtNode {
    Hash digest{};
    uint32_t count{0};
    uint32_t min_expiration_height{UINT32_MAX};
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
const Coin *SmtFindBorrowed(const SmtNode *root,
                            const Outpoint &outpoint) noexcept;
Hash SmtRoot(const std::shared_ptr<const SmtNode> &root);
std::vector<Coin> SmtCollectExpired(
    const std::shared_ptr<const SmtNode> &root, uint64_t block_height,
    size_t max_sweeps = MAX_EXPIRY_SWEEPS_PER_BLOCK);
ExpirySweepResult SmtSweepExpired(
    std::shared_ptr<const SmtNode> &root, uint64_t block_height,
    uint64_t total_block_fees_atoms = 0,
    size_t max_sweeps = MAX_EXPIRY_SWEEPS_PER_BLOCK);

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
    bool SpendsOutpoint(const Outpoint &outpoint) const;
    std::vector<Hash>
    FindTransactionsSpending(std::span<const Outpoint> outpoints) const;

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
    size_t GetTxCount() const noexcept { return active_txs_.size(); }
    const Hash &GetParentBlockId() const noexcept { return parent_block_id_; }
    uint64_t GetHeight() const noexcept { return height_; }
    uint64_t GetParentMtp() const noexcept { return parent_mtp_; }
    uint64_t GetLayerId() const noexcept { return layer_id_; }
    void SetLayerId(uint64_t layer_id) noexcept { layer_id_ = layer_id; }

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

    uint64_t layer_id_{0};
    Hash parent_block_id_{};
    uint64_t height_{1};
    uint64_t parent_mtp_{0};
    MonetaryState base_mon_state_{};

    txmerklix::Tree tx_tree_;
    mutable UtxoOverlayArena utxo_arena_;
    mutable bool utxo_arena_dirty_{false};
    uint64_t sum_non_cb_effective_cost_{0};

    std::map<Hash, OverlayTxEntry, CtorTxIdCompare> active_txs_;
    std::unordered_map<Outpoint, Coin, OutpointHasher> created_coins_;
    std::unordered_map<Outpoint, uint32_t, OutpointHasher> spent_outpoints_;
};

/**
 * Outcome of attempting to union a transaction into the active pre-consensus
 * epoch in MerklixOverlayManager.
 */
enum class EpochUnionOutcome : uint8_t {
    ADMITTED = 0,
    ALREADY_PRESENT = 1,
    QUARANTINED_CONFLICT = 2,
    DEFERRED_LATE_DRIP = 3,
    REJECTED_EPOCH_LOCKED = 4,
};

/**
 * Relationship between a peer's advertised (parent_base_root, active_sketch_root)
 * and our local (parent_base_root, active_sketch_root) during numberless
 * parent_base_root-anchored self-clocking layer reconciliation.
 */
enum class LayerSyncRelation : uint8_t {
    //! peer.parent_base_root == local.parent_base_root -> normal union & snowball
    SAME_PARENT_BASE = 0,
    //! peer.parent_base_root == local.active_sketch_root -> peer already
    //! crystallized our candidate root R_1 and promoted to R_1! Counts as a
    //! matching confirmation on R_1 without mixing peer's new layer into R_1.
    PEER_AHEAD_CONFIRMS_LOCAL = 1,
    //! peer.active_sketch_root == local.parent_base_root -> local already
    //! crystallized peer's candidate root; ignore peer's lagging layer.
    LOCAL_AHEAD_OF_PEER = 2,
    //! Disjoint parent_base_root requiring base catch-up.
    DIVERGENT_BASE = 3,
};

/**
 * Deterministic result of resolving Option B quarantined transactions for
 * Epoch E+1 using the finalized BatchId(E) of Epoch E.
 */
struct QuarantineResolutionResult {
    std::vector<OverlayTxEntry> promoted_winners;
    std::vector<OverlayTxEntry> rejected_losers;
};

/**
 * Ungrindable tie-break score for Option B post-quarantine resolution:
 *   score(T) = TaggedHash(HashDomain::PreconsensusBatch, BatchId(E) || tx_id).
 *
 * Security / Ungrindability:
 *   1. When conflicting transactions (T_1, T_2) are broadcast during Epoch E,
 *      BatchId(E) does not yet exist because it commits to the finalized
 *      SubtreeARoot(E) and UtxoRoot(E) of all non-conflicting transactions in
 *      Epoch E. Neither sender can predict or grind score(T_i) in advance.
 *   2. Once Epoch E finalizes and reveals BatchId(E), the quarantined set Q_E
 *      is already closed. If an attacker attempts to broadcast a newly ground
 *      T_3 spending the same UTXO during Epoch E+1, T_3 arrives in open Epoch
 *      E+1 where the promoted winner T_win already resides, which simply
 *      triggers Option B quarantine for Epoch E+1 and defers resolution to
 *      Epoch E+2 under the not-yet-existing BatchId(E+1).
 */
Hash ComputePreconsensusTiebreakScore(const Hash &finalized_batch_id,
                                      const Hash &tx_id);

/**
 * Manages the progressive stack of frozen pre-consensus epoch overlay layers
 * and the mutable speculative mempool tip overlay, including:
 *   - Option B same-epoch conflict quarantine (order-independent transitive
 *     conflict removal into `quarantined_txs_`)
 *   - Two-phase anti-drip union gate (`r <= R_cut` unrestricted union vs
 *     `r > R_cut` sample-quorum gate routing late singletons to Epoch E+1)
 *   - Deterministic `BatchId(E)` post-quarantine resolution into Epoch E+1
 */
class MerklixOverlayManager {
public:
    static constexpr uint32_t DEFAULT_MAX_UNRESTRICTED_UNION_ROUNDS = 3;

    MerklixOverlayManager();
    MerklixOverlayManager(const MerklixOverlayManager &other);
    MerklixOverlayManager &operator=(const MerklixOverlayManager &other);
    MerklixOverlayManager(MerklixOverlayManager &&other) noexcept;
    MerklixOverlayManager &operator=(MerklixOverlayManager &&other) noexcept;

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

    /**
     * Union a transaction into the active pre-consensus epoch with:
     *   1. Snowballed epoch immutability check (`epoch_snowballed_locked_`)
     *   2. Two-phase anti-drip union gate (`union_round_ > max_unrestricted_union_rounds_`
     *      requires `peer_sample_support * 2 >= peer_sample_size`, else defers
     *      to `deferred_next_epoch_txs_` for Epoch E+1)
     *   3. Option B order-independent same-epoch conflict quarantine
     */
    EpochUnionOutcome UnionEpochTransaction(
        const OverlayTxEntry &entry,
        uint32_t peer_sample_support = 1,
        uint32_t peer_sample_size = 1);

    EpochUnionOutcome UnionEpochTransaction(
        const Hash &tx_id,
        const Hash &tx_hash,
        uint64_t linear_cost,
        const std::vector<Outpoint> &spent_outpoints,
        const std::vector<Coin> &created_coins,
        int64_t fee_sats = 0,
        int64_t sigchecks = 0,
        std::shared_ptr<const void> tx_ref = nullptr,
        uint32_t peer_sample_support = 1,
        uint32_t peer_sample_size = 1);

    /**
     * Advance the Snowstorm reconciliation round counter for the active
     * epoch. Once `union_round_ > max_unrestricted_union_rounds_`, Phase 2
     * anti-drip filtering activates.
     */
    uint32_t AdvanceUnionRound() noexcept { return ++union_round_; }
    void SetUnionRound(uint32_t round) noexcept { union_round_ = round; }
    uint32_t GetUnionRound() const noexcept { return union_round_; }

    void SetMaxUnrestrictedUnionRounds(uint32_t max_rounds) noexcept {
        max_unrestricted_union_rounds_ = std::max(1U, max_rounds);
    }
    uint32_t GetMaxUnrestrictedUnionRounds() const noexcept {
        return max_unrestricted_union_rounds_;
    }

    /**
     * Symmetric Phase 2 minority-support demotion with hysteresis
     * (m = min_consecutive_minority_rounds), transitive in-epoch descendant
     * closure, and per-epoch deferral latch.
     *
     * When `union_round_ > max_unrestricted_union_rounds_` and the active epoch
     * is not yet snowballed-locked, inspects every transaction T in the active
     * epoch delta (present in `speculative_layer_` but not in
     * `frozen_epochs_.back()`):
     *   - If `support(T) * 2 < peer_sample_size`, increments T's minority
     *     streak; otherwise resets T's streak to 0.
     *   - Once T's streak reaches `min_consecutive_minority_rounds`, demotes T
     *     and all of its transitive in-epoch descendants from
     *     `speculative_layer_` into `deferred_next_epoch_txs_` and latches
     *     their txids in `deferred_txids_for_epoch_` so they cannot oscillate
     *     back into Epoch E.
     *
     * Returns the number of transactions demoted from the active epoch.
     */
    size_t ApplyPhase2PeerSampleSupport(
        const std::map<Hash, uint32_t, CtorTxIdCompare> &tx_support_counts,
        uint32_t peer_sample_size,
        uint32_t min_consecutive_minority_rounds = 2);

    const std::set<Hash, CtorTxIdCompare> &
    GetDeferredTxIdsForEpoch() const noexcept {
        return deferred_txids_for_epoch_;
    }

    /**
     * Lock or unlock the active epoch once Snowstorm reaches beta_snow
     * consecutive matching sample rounds. When locked, conflicting double-spends
     * cannot displace transactions in the snowballed epoch.
     */
    void SetEpochSnowballedLocked(bool locked) noexcept {
        epoch_snowballed_locked_ = locked;
    }
    bool IsEpochSnowballedLocked() const noexcept {
        return epoch_snowballed_locked_;
    }

    /**
     * Deterministically resolve all Option B quarantined transactions from
     * Epoch E using `finalized_batch_id = BatchId(E)`, promoting the winning
     * non-conflicting transactions (and any Phase 2 late-drip deferred
     * transactions) into the speculative overlay for Epoch E+1 and returning
     * both the promoted winners and rejected losers.
     */
    QuarantineResolutionResult
    ResolveQuarantinedTxsWithBatchId(const Hash &finalized_batch_id);

    const std::unordered_set<Outpoint, OutpointHasher> &
    GetConflictedOutpoints() const noexcept {
        return conflicted_outpoints_;
    }
    const std::map<Hash, OverlayTxEntry, CtorTxIdCompare> &
    GetQuarantinedTxs() const noexcept {
        return quarantined_txs_;
    }
    const std::vector<OverlayTxEntry> &
    GetDeferredNextEpochTxs() const noexcept {
        return deferred_next_epoch_txs_;
    }

    size_t GetQuarantinedTxCount() const noexcept {
        return quarantined_tx_count_.load(std::memory_order_relaxed);
    }
    uint64_t GetTotalQuarantinedEvents() const noexcept {
        return total_quarantined_events_.load(std::memory_order_relaxed);
    }
    uint64_t GetLateDripDeferredCount() const noexcept {
        return late_drip_deferred_count_.load(std::memory_order_relaxed);
    }

    /**
     * Numberless parent_base_root-anchored self-clocking layer pipeline:
     *   - GetParentBaseRoot(): SubtreeARoot of the last crystallized/snowballed
     *     layer (`frozen_epochs_.back()`), or `EmptyTxRoot()` right after a
     *     block connects / on kick-off.
     *   - GetActiveSketchRoot(): SubtreeARoot of the currently snowballing
     *     `ActiveSketchLayer` (`speculative_layer_`).
     *   - ClassifyPeerLayerSketch(): resolves boundary races when one peer
     *     crystallizes `R_1` one tick ahead of another and advertises
     *     `peer.parent_base_root == R_1`.
     *   - StageIncomingTransaction() / PromoteIncomingToActiveSketchLayer():
     *     stages unsnowballed incoming transactions in `IncomingMempool` while
     *     `ActiveSketchLayer` is converging, then promotes them into the next
     *     `ActiveSketchLayer` anchored on `parent_base_root = R_1` as soon as
     *     `ActiveSketchLayer` reaches `snowballed` (`FreezeEpochBatch()`).
     */
    Hash GetParentBaseRoot() const;
    Hash GetActiveSketchRoot() const;
    size_t GetActiveLayerDeltaTxCount() const noexcept;

    LayerSyncRelation
    ClassifyPeerLayerSketch(const Hash &peer_parent_base_root,
                            const Hash &peer_active_sketch_root) const;

    bool StageIncomingTransaction(const OverlayTxEntry &entry);
    bool StageIncomingTransaction(
        const Hash &tx_id,
        const Hash &tx_hash,
        uint64_t linear_cost,
        const std::vector<Outpoint> &spent_outpoints,
        const std::vector<Coin> &created_coins,
        int64_t fee_sats = 0,
        int64_t sigchecks = 0,
        std::shared_ptr<const void> tx_ref = nullptr);

    size_t PromoteIncomingToActiveSketchLayer();

    const std::vector<OverlayTxEntry> &
    GetIncomingMempoolTxs() const noexcept {
        return incoming_mempool_txs_;
    }
    size_t GetIncomingMempoolTxCount() const noexcept {
        return incoming_mempool_txs_.size();
    }

    uint64_t GetLastLayerConvergenceMs() const noexcept {
        return last_layer_convergence_ms_.load(std::memory_order_relaxed);
    }
    void SetLastLayerConvergenceMs(uint64_t ms) noexcept {
        last_layer_convergence_ms_.store(ms, std::memory_order_relaxed);
    }

    /**
     * Freezes the current speculative state as an immutable epoch overlay
     * snapshot and increments the epoch counter. Also folds ActiveSketchLayer
     * into CrystallizedBase (`parent_base_root = SubtreeARoot(CrystallizedBase)`),
     * records `last_layer_convergence_ms_`, and promotes any staged
     * `incoming_mempool_txs_` into the new ActiveSketchLayer.
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
    std::vector<MempoolOverlayLayer> &GetFrozenEpochsMutable() noexcept {
        return frozen_epochs_;
    }

private:
    uint64_t next_epoch_id_{1};
    MempoolOverlayLayer speculative_layer_;
    std::vector<MempoolOverlayLayer> frozen_epochs_;

    uint32_t union_round_{0};
    uint32_t max_unrestricted_union_rounds_{
        DEFAULT_MAX_UNRESTRICTED_UNION_ROUNDS};
    bool epoch_snowballed_locked_{false};

    std::unordered_set<Outpoint, OutpointHasher> conflicted_outpoints_;
    std::map<Hash, OverlayTxEntry, CtorTxIdCompare> quarantined_txs_;
    std::vector<OverlayTxEntry> deferred_next_epoch_txs_;
    std::set<Hash, CtorTxIdCompare> deferred_txids_for_epoch_;
    std::map<Hash, uint32_t, CtorTxIdCompare> phase2_low_support_streak_;
    std::vector<OverlayTxEntry> incoming_mempool_txs_;

    uint64_t active_layer_start_ns_{0};
    std::atomic<uint64_t> last_layer_convergence_ms_{0};

    std::atomic<size_t> quarantined_tx_count_{0};
    std::atomic<uint64_t> total_quarantined_events_{0};
    std::atomic<uint64_t> late_drip_deferred_count_{0};
};

const MonetaryProfile &GetDefaultV2MonetaryProfile() noexcept;
MonetaryState GetInitialV2MonetaryState();

} // namespace lotus::v2

#endif // LOTUS_V2_MEMPOOL_OVERLAY_H
