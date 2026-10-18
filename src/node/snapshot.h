// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_SNAPSHOT_H
#define BITCOIN_NODE_SNAPSHOT_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <feerate.h>
#include <lotus_v2/tagged_hash.h>
#include <flatfile.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <radix.h>
#include <uint256radixkey.h>
#include <uint256.h>
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
 * Snapshot of a single mempool entry for getmempoolentry,
 * getrawmempool(verbose=true), getrawtransaction, and gettxout.
 */
struct MempoolEntrySnapshot {
    TxId txid{};
    CTransactionRef tx;
    Amount fee{Amount::zero()};
    Amount modified_fee{Amount::zero()};
    size_t tx_size{0};
    int64_t time{0};
    int64_t sigchecks{0};
    uint64_t entry_id{0};
    CFeeRate modified_feerate{};
    int height{0};
    std::vector<std::string> depends;
    std::vector<std::string> spentby;
    bool unbroadcast{false};
};

/**
 * Snapshot of a single active-chain block header and disk location for
 * getblockhash, getblockheader, and getrawtransaction without chain locks.
 */
struct BlockHeaderSnapshot {
    BlockHash hash{};
    CBlockHeader header{};
    int height{0};
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

/** An immutable value. Updating an entry creates a new value; readers never
 * retain mutable CTxMemPoolEntry objects. The existing ABC radix tree supplies
 * copy-on-write paths and RCU lifetime management. */
struct ImmutableMempoolEntry {
    const MempoolEntrySnapshot entry;
    explicit ImmutableMempoolEntry(MempoolEntrySnapshot value)
        : entry(std::move(value)) {}
    IMPLEMENT_RCU_REFCOUNT(uint32_t);
};
struct SnapshotEntryAdapter {
    Uint256RadixKey getId(const ImmutableMempoolEntry &value) const {
        return value.entry.txid;
    }
};
using MempoolSnapshotTree = RadixTree<ImmutableMempoolEntry, SnapshotEntryAdapter>;

struct MiningTemplateSnapshot {
    MiningTemplateSnapshot() = default;
    MiningTemplateSnapshot(const MiningTemplateSnapshot &other);
    MiningTemplateSnapshot &operator=(const MiningTemplateSnapshot &other);
    uint64_t template_id{0};
    BlockHash prev_block_hash{};
    int next_height{0};
    uint32_t nHeaderVersion{2};
    uint32_t nBits{0};
    int64_t min_time{0};
    int64_t parent_mtp{0};
    Amount total_fees{Amount::zero()};
    Amount block_reward{Amount::zero()};
    uint64_t non_cb_serialized_size{0};
    std::vector<CTransactionRef> non_coinbase_txs;
    std::vector<Amount> tx_fees;
    std::vector<int64_t> tx_sigchecks;
    mutable std::vector<std::string> tx_hex;
    std::shared_ptr<std::mutex> tx_hex_mutex{std::make_shared<std::mutex>()};
    mutable lotus::v2::Hash subtree_a_root{};
    mutable std::vector<lotus::v2::Hash> coinbase_merkle_branch;
    mutable bool roots_ready{false};
    mutable bool merkle_cache_safe{false};
    bool template_valid{false};

    /**
     * Lazily populate tx_hex on demand (only needed when a caller invokes
     * legacy full-hex getblocktemplate rather than mode="compact_template").
     */
    const std::vector<std::string> &EnsureTxHex() const;

    /**
     * Lazily compute subtree_a_root and coinbase_merkle_branch on demand so
     * snapshot publication does not hash transactions while holding mempool.cs.
     */
    void EnsureTemplateRoots() const;
};

/** One lazy result shared only by generations with identical mining inputs.
 * Initialization is serialized; callers receive a const completed template. */
struct MiningTemplateCache {
    std::mutex mutex;
    std::mutex validation_mutex;
    bool validated{false};
    MiningTemplateSnapshot value;
    bool ready{false};
};

/** Published chain and mempool state. Lazy vectors derive exclusively from
 * the pinned immutable entry tree, never from the live mempool. */
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
    int miner_fund_ratio{0};
    bool miner_fund_active{false};
    bool ctor_active{false};
    int32_t next_block_version{0};
    bool staking_rewards_active{false};
    std::optional<Consensus::Params> consensus_params;
    std::array<int64_t, 18> prev_header_received_time{};
    std::shared_ptr<const ActiveChainSnapshot> active_chain;

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
    std::shared_ptr<const MempoolSnapshotTree> entry_tree;
    mutable std::vector<TxId> mempool_txids;
    mutable std::vector<MempoolEntrySnapshot> mempool_entries;
    mutable std::vector<COutPoint> mempool_spent_outpoints;
    mutable bool mempool_vectors_ready{false};
    std::shared_ptr<std::mutex> mempool_vectors_mutex{
        std::make_shared<std::mutex>()};

    std::shared_ptr<MiningTemplateCache> mining{std::make_shared<MiningTemplateCache>()};
    bool overlay_all_fit_candidate{false};
    uint64_t overlay_bytes{0};
    int64_t overlay_sigchecks{0};
    const MiningTemplateSnapshot &GetMiningTemplate() const;
    void EnsureMiningTemplate() const { (void)GetMiningTemplate(); }
    void EnsureMempoolVectors() const;

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

using ChainTipSnapshot = ChainAndMempoolSnapshot;

/** Atomic publication keeps RPC readers independent of chain/mempool locks.
 * Standard atomic shared_ptr operations may internally synchronize; this API
 * does not promise wait freedom or a platform-independent lock-free primitive.
 * Only readers retain older snapshots, avoiding a ring of 1024 chain indexes. */
class SnapshotPublisher {
    std::shared_ptr<const ChainAndMempoolSnapshot> m_current;
    std::atomic<uint64_t> m_publications{0};
    static constexpr size_t kTemplateHistorySize = 32;
    mutable std::mutex m_publish_mutex;
    std::atomic<uint64_t> m_next_template_id{1};
    std::array<MiningTemplateSnapshot, kTemplateHistorySize> m_template_history;
    size_t m_template_history_pos{0};
public:
    SnapshotPublisher();
    uint64_t AllocateTemplateId() noexcept {
        return m_next_template_id.fetch_add(1, std::memory_order_relaxed);
    }
    void RecordMiningTemplate(const MiningTemplateSnapshot &tmpl);
    std::optional<MiningTemplateSnapshot> FindMiningTemplate(
        uint64_t template_id = 0, const BlockHash &prev_block_hash = BlockHash()) const;
    std::shared_ptr<const ChainAndMempoolSnapshot> Load() const noexcept {
        return std::atomic_load_explicit(&m_current, std::memory_order_acquire);
    }
    void Publish(std::shared_ptr<const ChainAndMempoolSnapshot> next);
    uint64_t PublicationCount() const noexcept { return m_publications.load(); }
};

/** Keep readers on the last coherent generation while chain activation or
 * unwinding temporarily clears/rebuilds the mempool. Construct and destroy
 * under cs_main and the pool lock; the outer scope publishes their final state. */
class ScopedChainSnapshotDefer {
public:
    ScopedChainSnapshotDefer(ChainstateManager &chainman, const CTxMemPool *mempool);
    ~ScopedChainSnapshotDefer();
    ScopedChainSnapshotDefer(const ScopedChainSnapshotDefer &) = delete;
    ScopedChainSnapshotDefer &operator=(const ScopedChainSnapshotDefer &) = delete;
};

/** Return the process-wide SnapshotPublisher shared by NodeContext and validation/mempool hooks. */
std::shared_ptr<SnapshotPublisher> GetGlobalSnapshotPublisherPtr();
SnapshotPublisher &GetGlobalSnapshotPublisher();

inline std::shared_ptr<const ChainTipSnapshot> GetChainTipSnapshot() noexcept {
    return GetGlobalSnapshotPublisher().Load();
}

/**
 * Publish an updated chain snapshot when the active tip changes.
 * Must be called with ::cs_main held.
 */
void PublishChainTipSnapshot(ChainstateManager &chainman,
                             const CTxMemPool *mempool);

inline void UpdateChainTipSnapshot(ChainstateManager &chainman,
                                   const CTxMemPool *mempool) {
    PublishChainTipSnapshot(chainman, mempool);
}

/** Refresh best-header/IBD metadata after header-only admission or header
 * invalidation/reconsideration, sharing the existing active-chain index. */
void PublishBestHeaderSnapshot(ChainstateManager &chainman);

/**
 * Publish an updated mempool snapshot when the mempool changes.
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
