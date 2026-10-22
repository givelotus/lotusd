// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_SNAPSHOT_H
#define BITCOIN_NODE_SNAPSHOT_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <feerate.h>
#include <flatfile.h>
#include <lotus_v2/header.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <radix.h>
#include <support/allocators/chunked_slab.h>
#include <uint256.h>
#include <uint256radixkey.h>
#include <util/hasher.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class ChainstateManager;
class CTxMemPool;

namespace node {

/**
 * Snapshot of a single mempool entry for lock-free getmempoolentry,
 * getrawmempool(verbose=true), getrawtransaction, and gettxout.
 */
struct MempoolEntrySnapshot {
    TxId txid{};
    CTransactionRef tx;
    Amount fee{Amount::zero()};
    Amount modified_fee{Amount::zero()};
    size_t tx_size{0};
    int64_t time{0};
    int height{0};
    int64_t sigchecks{0};
    uint64_t entry_id{0};
    CFeeRate modified_feerate{};
    std::vector<std::string> depends;
    std::vector<std::string> spentby;
    bool unbroadcast{false};
};

/**
 * Snapshot of a single active-chain block header and disk location for
 * lock-free getblockhash, getblockheader, and getrawtransaction.
 */
struct BlockHeaderSnapshot {
    BlockHash hash{};
    CBlockHeader header{};
    int height{0};
    uint64_t size{0};
    int64_t time{0};
    int64_t mediantime{0};
    double difficulty{0.0};
    uint256 chainwork{};
    unsigned int nTx{0};
    FlatFilePos data_pos{};
    bool has_data{false};
};

/**
 * Immutable active-chain header index shared across mempool snapshots in O(1)
 * and updated when the active chain tip changes.
 */
struct ActiveChainSnapshot {
    std::vector<BlockHeaderSnapshot> by_height;
    std::unordered_map<BlockHash, int, SaltedBlockHashHasher> height_by_hash;

    const BlockHeaderSnapshot *FindByHeight(int height) const noexcept {
        if (height < 0 ||
            static_cast<size_t>(height) >= by_height.size()) {
            return nullptr;
        }
        return &by_height[static_cast<size_t>(height)];
    }

    const BlockHeaderSnapshot *FindByHash(const BlockHash &hash) const noexcept {
        const auto it = height_by_hash.find(hash);
        if (it == height_by_hash.end()) {
            return nullptr;
        }
        return FindByHeight(it->second);
    }
};

// Use 1024-slot chunks rather than the transaction allocator's larger default.
// Slab refills may still allocate, and chunks are retained for process
// lifetime; steady-state snapshot churn reuses slots, including cross-thread
// RCU frees.
template <typename T>
using SnapshotAllocator = GlobalConcurrentSlabAllocator<T, 1024>;

/** An immutable value. Updating an entry creates a new value; readers never
 * retain mutable CTxMemPoolEntry objects. The existing ABC radix tree supplies
 * copy-on-write paths and RCU lifetime management. */
struct ImmutableMempoolEntry final {
    const MempoolEntrySnapshot entry;
    static void *operator new(std::size_t size) {
        assert(size == sizeof(ImmutableMempoolEntry));
        return SnapshotAllocator<ImmutableMempoolEntry>{}.allocate(1);
    }
    static void operator delete(void *ptr) noexcept {
        SnapshotAllocator<ImmutableMempoolEntry>{}.deallocate(
            static_cast<ImmutableMempoolEntry *>(ptr), 1);
    }

    explicit ImmutableMempoolEntry(MempoolEntrySnapshot value)
        : entry(std::move(value)) {}
    IMPLEMENT_RCU_REFCOUNT(uint32_t);
};
struct SnapshotEntryAdapter {
    Uint256RadixKey getId(const ImmutableMempoolEntry &value) const {
        return value.entry.txid;
    }
};
using MempoolSnapshotTree =
    RadixTree<ImmutableMempoolEntry, SnapshotEntryAdapter,
              SnapshotAllocator<std::byte>>;

/**
 * Pre-assembled block template snapshot for O(1) getblocktemplate and
 * submitsealedheader.
 */
struct MiningTemplateSnapshot {
    uint64_t template_id{0};
    BlockHash prev_block_hash{};
    int next_height{0};
    uint32_t nHeaderVersion{lotus::v2::kHeaderVersion};
    uint32_t nBits{0};
    int64_t min_time{0};
    int64_t parent_mtp{0};
    Amount total_fees{Amount::zero()};
    Amount block_reward{Amount::zero()};
    uint64_t non_cb_serialized_size{0};
    uint64_t max_generated_block_size{0};
    int64_t total_sigchecks{0};
    std::vector<CTransactionRef> non_coinbase_txs;
    std::vector<Amount> tx_fees;
    std::vector<int64_t> tx_sigchecks;
    mutable std::vector<std::string> tx_hex;
    std::shared_ptr<std::mutex> tx_hex_mutex{
        std::allocate_shared<std::mutex>(SnapshotAllocator<std::mutex>{})};
    std::shared_ptr<const lotus::v2::SmtNode> tip_utxo_root;
    lotus::v2::MonetaryState tip_mon_state{};
    bool has_tip_utxo_snapshot{false};
    mutable lotus::v2::Hash subtree_a_root{};
    mutable V2TemplateBaseState v2_base_state{};
    mutable bool roots_ready{false};
    std::shared_ptr<std::mutex> validation_mutex{
        std::allocate_shared<std::mutex>(SnapshotAllocator<std::mutex>{})};
    mutable bool validated{false};
    bool template_valid{false};
    const CTxMemPool *mempool_ptr{nullptr};
    unsigned int transactions_updated{0};

    const std::vector<std::string> &EnsureTxHex() const;
    void EnsureRoots() const;
};

/**
 * Immutable RCU snapshot of chain tip, mempool summary, and pre-assembled
 * mining template state. Published on tip and mempool updates and read
 * lock-free by RPC handlers without acquiring cs_main or mempool.cs.
 */
struct ChainAndMempoolSnapshot {
    const ChainstateManager *chainman_ptr{nullptr};
    const CTxMemPool *mempool_ptr{nullptr};

    // Chain tip state
    bool chain_valid{false};
    int height{-1};
    int headers_height{-1};
    BlockHash best_block_hash{};
    BlockHash finalized_block_hash{};
    double difficulty{0.0};
    int64_t time{0};
    int64_t mediantime{0};
    double verification_progress{0.0};
    bool initial_block_download{false};
    uint256 chainwork{};
    uint64_t size_on_disk{0};
    bool pruned{false};
    bool has_prune_height{false};
    int prune_height{0};
    bool automatic_pruning{false};
    uint64_t prune_target_size{0};
    bool fast_sync_active{false};
    int earliest_verified_height{0};
    std::string chain_type_string;
    uint32_t nBits{0};
    uint32_t next_nBits{0};
    Amount next_subsidy{Amount::zero()};
    std::optional<Consensus::Params> consensus_params;
    // Rules captured with the published tip, never inferred from mutable state.
    std::optional<uint32_t> next_script_flags;
    std::array<int64_t, 18> prev_header_received_time{};
    std::shared_ptr<const ActiveChainSnapshot> active_chain;
    bool has_utxo_snapshot{false};
    std::shared_ptr<const lotus::v2::SmtNode> tip_utxo_root;
    lotus::v2::MonetaryState tip_mon_state{};

    // Mempool state
    bool mempool_valid{false};
    bool mempool_loaded{false};
    size_t mempool_size{0};
    size_t mempool_bytes{0};
    size_t finalized_txs_size{0};
    size_t finalized_txs_bytes{0};
    int64_t finalized_txs_sigchecks{0};
    size_t mempool_usage{0};
    Amount total_fee{Amount::zero()};
    size_t max_mempool{0};
    CFeeRate mempool_min_fee{};
    CFeeRate min_relay_tx_fee{};
    double rolling_minimum_fee_rate{0.0};
    int64_t last_rolling_fee_update{0};
    bool block_since_last_rolling_fee_bump{false};
    size_t unbroadcast_count{0};
    unsigned int transactions_updated{0};
    uint64_t mempool_sequence{0};
    uint64_t mempool_reset_seq{0};
    bool mempool_has_fee_deltas{false};
    std::shared_ptr<const MempoolSnapshotTree> entry_tree;
    uint64_t last_mempool_entry_id{0};
    mutable std::vector<TxId> mempool_txids;
    mutable std::vector<MempoolEntrySnapshot> mempool_entries;
    mutable std::vector<COutPoint> mempool_spent_outpoints;
    mutable bool mempool_vectors_ready{false};
    std::shared_ptr<std::mutex> mempool_vectors_mutex{
        std::allocate_shared<std::mutex>(SnapshotAllocator<std::mutex>{})};

    // Pre-assembled mining template
    mutable MiningTemplateSnapshot mining_template{};
    mutable bool mining_template_ready{true};

    void EnsureMempoolVectors() const;
    void EnsureMiningTemplate() const;

    const MempoolEntrySnapshot *FindMempoolEntry(const TxId &txid) const {
        EnsureMempoolVectors();
        const auto it = std::lower_bound(
            mempool_entries.begin(), mempool_entries.end(), txid,
            [](const MempoolEntrySnapshot &entry, const TxId &id) {
                return entry.txid < id;
            });
        if (it != mempool_entries.end() && it->txid == txid) {
            return &(*it);
        }
        return nullptr;
    }

    bool IsSpentInMempool(const COutPoint &outpoint) const {
        EnsureMempoolVectors();
        return std::binary_search(mempool_spent_outpoints.begin(),
                                  mempool_spent_outpoints.end(), outpoint);
    }
};

/**
 * Lock-free RCU publisher for ChainAndMempoolSnapshot.
 * Readers call Load() which performs an atomic acquire load on the ring index
 * and copies a std::shared_ptr<const ChainAndMempoolSnapshot> without taking
 * any mutex or spinlock.
 */
class SnapshotPublisher {
private:
    static constexpr size_t kRingSize = 1024;
    static constexpr size_t kTemplateHistorySize = 32;

    mutable std::mutex m_publish_mutex;
    std::array<std::shared_ptr<const ChainAndMempoolSnapshot>, kRingSize>
        m_ring;
    std::atomic<uint64_t> m_seq{0};
    std::atomic<uint64_t> m_next_template_id{1};

    std::array<MiningTemplateSnapshot, kTemplateHistorySize> m_template_history;
    size_t m_template_history_pos{0};

public:
    SnapshotPublisher();

    /**
     * Lock-free reader path: returns the latest immutable snapshot.
     * Never blocks and never acquires cs_main, mempool.cs, or m_publish_mutex.
     */
    std::shared_ptr<const ChainAndMempoolSnapshot> Load() const noexcept {
        const uint64_t seq = m_seq.load(std::memory_order_acquire);
        return std::atomic_load_explicit(&m_ring[seq % kRingSize],
                                         std::memory_order_acquire);
    }

    /** Publish a new immutable snapshot. Serializes writers only. */
    void Publish(std::shared_ptr<const ChainAndMempoolSnapshot> next);

    /** Allocate the next monotonically increasing template ID. */
    uint64_t AllocateTemplateId() noexcept {
        return m_next_template_id.fetch_add(1, std::memory_order_relaxed);
    }

    /** Record a mining template in the template history ring. */
    void RecordMiningTemplate(const MiningTemplateSnapshot &tmpl);

    /** Look up a recently published mining template by template_id (or 0 for latest). */
    std::optional<MiningTemplateSnapshot>
    FindMiningTemplate(uint64_t template_id = 0,
                       const BlockHash &prev_block_hash = BlockHash()) const;
};

/** Return the process-wide SnapshotPublisher shared by NodeContext and validation/mempool hooks. */
std::shared_ptr<SnapshotPublisher> GetGlobalSnapshotPublisherPtr();
SnapshotPublisher &GetGlobalSnapshotPublisher();

/**
 * Publish an updated chain + template snapshot when the active tip changes.
 * Must be called with ::cs_main held.
 */
void PublishChainTipSnapshot(ChainstateManager &chainman,
                             const CTxMemPool *mempool);

/**
 * Publish an updated mempool + template snapshot when the mempool changes.
 * Must be called with mempool.cs held.
 */
void PublishMempoolSnapshot(const CTxMemPool &mempool);

/**
 * [Patch 034 optimization] Publish a lightweight RCU snapshot update when only
 * a transaction's unbroadcast state changes, avoiding a full template rebuild.
 * Must be called with mempool.cs held.
 */
void PublishMempoolUnbroadcastSnapshot(const CTxMemPool &mempool,
                                       const TxId &txid,
                                       bool unbroadcast);

} // namespace node

#endif // BITCOIN_NODE_SNAPSHOT_H
