// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/snapshot.h>

#include <node/metrics.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/activation.h>
#include <minerfund.h>
#include <node/blockfitter.h>
#include <policy/block/stakingrewards.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/fee_hysteresis.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <streams.h>
#include <timedata.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <validation.h>
#include <versionbits.h>

#include <algorithm>
#include <cstring>
#include <queue>
#include <set>
#include <unordered_map>

namespace node {
namespace {

struct ChainPublicationScope {
    unsigned depth{0};
    ChainstateManager *chainman{nullptr};
    const CTxMemPool *mempool{nullptr};
    bool dirty{false};
};
thread_local ChainPublicationScope g_chain_publication;

double ComputeDifficultyFromBits(uint32_t nBits) {
    int nShift = (nBits >> 24) & 0xff;
    double dDiff = double(0x0000ffff) / double(nBits & 0x00ffffff);
    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

std::string SerializeTxToHex(const CTransaction &tx) {
    DataStream ssTx{};
    ssTx << tx;
    return HexStr(ssTx);
}

std::vector<lotus::v2::Hash>
ComputeCoinbaseMerkleBranch(const std::vector<CTransactionRef> &non_cb_txs) {
    std::vector<lotus::v2::Hash> branch;
    if (non_cb_txs.empty()) {
        return branch;
    }
    std::vector<lotus::v2::Hash> level;
    level.reserve(non_cb_txs.size() + 1);
    level.push_back(lotus::v2::Hash{}); // Slot 0: coinbase placeholder
    for (const auto &tx : non_cb_txs) {
        lotus::v2::Hash txid_bytes{};
        const TxId &txid = tx->GetId();
        std::memcpy(txid_bytes.data(), txid.begin(), 32);
        level.push_back(txid_bytes);
    }
    while (level.size() > 1) {
        branch.push_back(level[1]);
        if (level.size() & 1U) {
            level.push_back(level.back());
        }
        const size_t pairs = level.size() / 2;
        SHA256D64(level[0].data(), level[0].data(), pairs);
        level.resize(pairs);
    }
    return branch;
}

std::optional<int> ComputePruneHeight(const BlockManager &blockman,
                                      const CChain &chain)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);
    const CBlockIndex *first_block{chain[1]};
    const CBlockIndex *chain_tip{chain.Tip()};
    if (!first_block || !chain_tip) {
        return std::nullopt;
    }
    if (!(chain_tip->nStatus.hasData() && chain_tip->nStatus.hasUndo())) {
        return chain_tip->nHeight;
    }
    const CBlockIndex *first_unpruned{
        blockman.GetFirstBlock(*chain_tip, [](const BlockStatus &status) {
            return status.hasData() && status.hasUndo();
        })};
    if (!first_unpruned || first_unpruned == first_block ||
        !first_unpruned->pprev) {
        return std::nullopt;
    }
    return first_unpruned->pprev->nHeight;
}

BlockHeaderSnapshot MakeBlockHeaderSnapshot(const CBlockIndex &blockindex)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
    AssertLockHeld(::cs_main);
    BlockHeaderSnapshot hdr{};
    hdr.hash = blockindex.GetBlockHash();
    hdr.header = blockindex.GetBlockHeader();
    hdr.height = blockindex.nHeight;
    hdr.time = blockindex.GetBlockTime();
    hdr.mediantime = blockindex.GetMedianTimePast();
    hdr.difficulty = ComputeDifficultyFromBits(blockindex.nBits);
    hdr.chainwork = ArithToUint256(blockindex.nChainWork);
    hdr.nTx = blockindex.nTx;
    hdr.data_pos = blockindex.GetBlockPos();
    hdr.has_data = blockindex.nStatus.hasData();
    return hdr;
}

void PopulateMempoolScalarsLocked(ChainAndMempoolSnapshot &snap,
                                  const CTxMemPool &mempool)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    snap.mempool_ptr = &mempool;
    snap.mempool_valid = true;
    snap.mempool_loaded = mempool.GetLoadTried();
    snap.mempool_size = mempool.size();
    snap.mempool_bytes = mempool.GetTotalTxSize();
    snap.finalized_txs_size = mempool.GetFinalizedTxCount();
    snap.finalized_txs_bytes = mempool.GetTotalFinalizedTxSize();
    snap.finalized_txs_sigchecks = mempool.GetTotalFinalizedTxSigchecks();
    snap.mempool_usage = mempool.DynamicMemoryUsage();
    snap.total_fee = mempool.GetTotalFee();
    snap.max_mempool = mempool.m_opts.max_size_bytes;
    snap.min_relay_tx_fee = mempool.m_opts.min_relay_feerate;
    const CFeeRate current_min_fee = mempool.GetMinFee();
    snap.mempool_min_fee =
        std::max(current_min_fee, mempool.m_opts.min_relay_feerate);
    snap.rolling_minimum_fee_rate = mempool.GetRollingMinimumFeeRate();
    snap.last_rolling_fee_update = mempool.GetLastRollingFeeUpdate();
    snap.block_since_last_rolling_fee_bump =
        mempool.GetBlockSinceLastRollingFeeBump();
    snap.unbroadcast_count = mempool.GetUnbroadcastTxCount();
    snap.transactions_updated = mempool.GetTransactionsUpdated();
    snap.mempool_sequence = mempool.GetSequence();

    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    if (mempool.fee_policy_worker) {
        mempool.fee_policy_worker->RecordBacklog(snap.mempool_bytes, now_ms);
    } else {
        // Standalone/test pools without a node-owned worker retain synchronous
        // policy semantics.
        lotus::v2::GetGlobalFeeHysteresisController().RecordMempoolBacklog(
            snap.mempool_bytes, now_ms);
    }
}

MempoolEntrySnapshot MakeMempoolEntrySnapshot(const CTxMemPoolEntry &e,
                                              const CTxMemPool &mempool)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    MempoolEntrySnapshot entry_snap{};
    entry_snap.txid = e.GetTx().GetId();
    entry_snap.tx = e.GetSharedTx();
    entry_snap.fee = e.GetFee();
    entry_snap.modified_fee = e.GetModifiedFee();
    entry_snap.tx_size = e.GetTxSize();
    entry_snap.time = count_seconds(e.GetTime());
    entry_snap.sigchecks = e.GetSigChecks();
    entry_snap.entry_id = e.GetEntryId();
    entry_snap.modified_feerate = e.GetModifiedFeeRate();
    entry_snap.height = static_cast<int>(e.GetHeight());

    const auto &parents = e.GetMemPoolParentsConst();
    if (!parents.empty()) {
        std::set<std::string> set_depends;
        for (const auto &parent : parents) {
            set_depends.insert(parent.get()->GetTx().GetId().ToString());
        }
        entry_snap.depends.assign(set_depends.begin(), set_depends.end());
    }

    const auto &children = e.GetMemPoolChildrenConst();
    entry_snap.spentby.reserve(children.size());
    for (const auto &child : children) {
        entry_snap.spentby.push_back(
            child.get()->GetTx().GetId().ToString());
    }
    entry_snap.unbroadcast = mempool.IsUnbroadcastTx(entry_snap.txid);
    return entry_snap;
}

void CaptureMempoolEntriesLocked(ChainAndMempoolSnapshot &snap,
                                 const CTxMemPool &mempool,
                                 const ChainAndMempoolSnapshot *prev)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    const bool full = mempool.SnapshotNeedsReset() || !prev ||
                      prev->mempool_ptr != &mempool || !prev->entry_tree;
    if (!full && mempool.SnapshotChangedEntries().empty()) {
        snap.entry_tree = prev->entry_tree;
        return;
    }
    // The published tree is immutable: its sole mutable builder is moved
    // into the snapshot below. Pinning prev keeps it alive while the new
    // builder shares its root, so no global writer grace period is needed.
    auto tree =
        full ? std::allocate_shared<MempoolSnapshotTree>(
                   SnapshotAllocator<MempoolSnapshotTree>{})
             : std::allocate_shared<MempoolSnapshotTree>(
                   SnapshotAllocator<MempoolSnapshotTree>{}, *prev->entry_tree,
                   MempoolSnapshotTree::ImmutableSnapshotTag{});
    auto capture = [&](const CTxMemPoolEntry &entry) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
        tree->insert(RCUPtr<ImmutableMempoolEntry>::make(
            MakeMempoolEntrySnapshot(entry, mempool)));
    };
    if (full) {
        for (const auto &entry : mempool.mapTx) capture(*entry);
    } else {
        for (const TxId &id : mempool.SnapshotChangedEntries()) {
            tree->remove(Uint256RadixKey(id));
            const auto it = mempool.mapTx.find(id);
            if (it != mempool.mapTx.end()) capture(**it);
        }
    }
    snap.entry_tree = std::move(tree);
    mempool.ClearSnapshotChanges();
}

std::shared_ptr<ChainAndMempoolSnapshot>
CloneChainStateOnly(const ChainAndMempoolSnapshot *prev) {
    auto next = std::allocate_shared<ChainAndMempoolSnapshot>(
        SnapshotAllocator<ChainAndMempoolSnapshot>{});
    if (!prev) {
        return next;
    }
    next->chainman_ptr = prev->chainman_ptr;
    next->mempool_ptr = prev->mempool_ptr;
    next->chain_valid = prev->chain_valid;
    next->height = prev->height;
    next->headers_height = prev->headers_height;
    next->best_block_hash = prev->best_block_hash;
    next->finalized_block_hash = prev->finalized_block_hash;
    next->difficulty = prev->difficulty;
    next->time = prev->time;
    next->mediantime = prev->mediantime;
    next->verification_progress = prev->verification_progress;
    next->initial_block_download = prev->initial_block_download;
    next->chainwork = prev->chainwork;
    next->size_on_disk = prev->size_on_disk;
    next->pruned = prev->pruned;
    next->has_prune_height = prev->has_prune_height;
    next->prune_height = prev->prune_height;
    next->automatic_pruning = prev->automatic_pruning;
    next->prune_target_size = prev->prune_target_size;
    next->fast_sync_active = prev->fast_sync_active;
    next->earliest_verified_height = prev->earliest_verified_height;
    next->chain_type_string = prev->chain_type_string;
    next->nBits = prev->nBits;
    next->next_nBits = prev->next_nBits;
    next->next_subsidy = prev->next_subsidy;
    next->miner_fund_ratio = prev->miner_fund_ratio;
    next->miner_fund_active = prev->miner_fund_active;
    next->ctor_active = prev->ctor_active;
    next->next_block_version = prev->next_block_version;
    next->staking_rewards_active = prev->staking_rewards_active;
    next->consensus_params = prev->consensus_params;
    next->prev_header_received_time = prev->prev_header_received_time;
    next->active_chain = prev->active_chain;
    return next;
}

void InitMiningTemplate(ChainAndMempoolSnapshot &snap,
                        const ChainAndMempoolSnapshot *prev,
                        const CTxMemPool *pool) NO_THREAD_SAFETY_ANALYSIS {
    if (!snap.chain_valid || !snap.consensus_params) return;
    if (prev && prev->chainman_ptr == snap.chainman_ptr &&
        prev->mempool_ptr == snap.mempool_ptr &&
        prev->best_block_hash == snap.best_block_hash &&
        prev->next_nBits == snap.next_nBits &&
        prev->transactions_updated == snap.transactions_updated &&
        prev->mempool_size == snap.mempool_size &&
        prev->mining->value.template_valid) {
        snap.mining = prev->mining;
        return;
    }
    auto &t = snap.mining->value;
    t.template_id = GetGlobalSnapshotPublisher().AllocateTemplateId();
    t.prev_block_hash = snap.best_block_hash;
    t.next_height = snap.height + 1;
    t.nHeaderVersion = snap.next_block_version;
    t.nBits = snap.next_nBits;
    t.parent_mtp = snap.mediantime;
    t.min_time = snap.mediantime + 1;
    t.block_reward = snap.next_subsidy;
    t.template_valid = true;
    if (pool) {
        AssertLockHeld(pool->cs);
        // This hint is optional: mining can select from the immutable entry
        // tree. Publishing a generation must not materialize pending overlay
        // work merely to obtain the fast-path hint. In particular, reading the
        // live overlay later cannot certify an older snapshot's membership.
        if (pool->HasPendingOverlayChanges()) return;
        lotus::v2::Hash tip{};
        std::memcpy(tip.data(), snap.best_block_hash.begin(), 32);
        const auto &overlay = pool->GetMerklixOverlay().GetSpeculativeOverlay();
        snap.overlay_all_fit_candidate =
            pool->GetMerklixOverlay().IsAnchoredAt(tip, t.next_height, t.parent_mtp) &&
            !overlay.HasDoubleSpends() && overlay.GetTxCount() == snap.mempool_size;
        snap.overlay_bytes = overlay.GetTotalBytes();
        snap.overlay_sigchecks = overlay.GetTotalSigChecks();
    }
}

} // namespace

void ChainAndMempoolSnapshot::EnsureMempoolVectors() const {
    std::lock_guard<std::mutex> lock(*mempool_vectors_mutex);
    if (mempool_vectors_ready) return;
    if (entry_tree) {
        entry_tree->forEachLeaf([&](const auto &value) {
            const auto &entry = value->entry;
            mempool_txids.push_back(entry.txid);
            mempool_entries.push_back(entry);
            for (const auto &input : entry.tx->vin)
                mempool_spent_outpoints.push_back(input.prevout);
            return true;
        });
    }
    std::sort(mempool_txids.begin(), mempool_txids.end());
    std::sort(mempool_entries.begin(), mempool_entries.end(),
              [](const auto &a, const auto &b) { return a.txid < b.txid; });
    std::sort(mempool_spent_outpoints.begin(), mempool_spent_outpoints.end());
    mempool_vectors_ready = true;
}

ScopedChainSnapshotDefer::ScopedChainSnapshotDefer(
    ChainstateManager &chainman, const CTxMemPool *mempool) {
    AssertLockHeld(::cs_main);
    if (mempool) AssertLockHeld(mempool->cs);
    auto &scope = g_chain_publication;
    if (scope.depth++ == 0) {
        scope.chainman = &chainman;
        scope.mempool = mempool;
        scope.dirty = false;
    } else {
        assert(scope.chainman == &chainman && scope.mempool == mempool);
    }
}

ScopedChainSnapshotDefer::~ScopedChainSnapshotDefer() {
    AssertLockHeld(::cs_main);
    auto &scope = g_chain_publication;
    assert(scope.depth > 0);
    if (--scope.depth != 0) return;
    const auto completed = scope;
    scope = {};
    if (completed.dirty) {
        PublishChainTipSnapshot(*completed.chainman, completed.mempool);
    }
}

MiningTemplateSnapshot::MiningTemplateSnapshot(const MiningTemplateSnapshot &other) {
    *this = other;
}
MiningTemplateSnapshot &MiningTemplateSnapshot::operator=(const MiningTemplateSnapshot &other) {
    if (this == &other) return *this;
    std::scoped_lock lock(*tx_hex_mutex, *other.tx_hex_mutex);
    template_id = other.template_id;
    prev_block_hash = other.prev_block_hash;
    next_height = other.next_height;
    nHeaderVersion = other.nHeaderVersion;
    nBits = other.nBits;
    min_time = other.min_time;
    parent_mtp = other.parent_mtp;
    total_fees = other.total_fees;
    block_reward = other.block_reward;
    non_cb_serialized_size = other.non_cb_serialized_size;
    non_coinbase_txs = other.non_coinbase_txs;
    tx_fees = other.tx_fees;
    tx_sigchecks = other.tx_sigchecks;
    tx_hex = other.tx_hex;
    subtree_a_root = other.subtree_a_root;
    coinbase_merkle_branch = other.coinbase_merkle_branch;
    roots_ready = other.roots_ready;
    merkle_cache_safe = other.merkle_cache_safe;
    template_valid = other.template_valid;
    return *this;
}

const std::vector<std::string> &MiningTemplateSnapshot::EnsureTxHex() const {
    if (!tx_hex_mutex) {
        return tx_hex;
    }
    std::lock_guard<std::mutex> lock(*tx_hex_mutex);
    if (tx_hex.size() == non_coinbase_txs.size()) {
        return tx_hex;
    }
    tx_hex.clear();
    tx_hex.reserve(non_coinbase_txs.size());
    for (const auto &tx : non_coinbase_txs) {
        tx_hex.push_back(SerializeTxToHex(*tx));
    }
    return tx_hex;
}

void MiningTemplateSnapshot::EnsureTemplateRoots() const {
    if (!tx_hex_mutex) {
        return;
    }
    std::lock_guard<std::mutex> lock(*tx_hex_mutex);
    if (roots_ready) {
        return;
    }
    if (non_coinbase_txs.empty()) {
        merkle_cache_safe = true;
        subtree_a_root = lotus::v2::EmptyTxRoot();
        coinbase_merkle_branch.clear();
        roots_ready = true;
        return;
    }
    std::set<TxId> unique_ids;
    merkle_cache_safe = true;
    for (const auto &tx : non_coinbase_txs) {
        if (tx->IsCoinBase() || !unique_ids.insert(tx->GetId()).second) merkle_cache_safe = false;
    }
    lotus::v2::TxOverlayArena tx_arena;
    uint32_t tx_root_idx = lotus::v2::TxOverlayArena::kNullIdx;
    for (const auto &tx : non_coinbase_txs) {
        lotus::v2::Hash tx_id{};
        lotus::v2::Hash tx_hash{};
        std::memcpy(tx_id.data(), tx->GetId().begin(), 32);
        std::memcpy(tx_hash.data(), tx->GetHash().begin(), 32);
        tx_root_idx = tx_arena.InsertTxLeaf(tx_root_idx, tx_id, tx_hash);
    }
    subtree_a_root = tx_arena.SubtreeARoot(tx_root_idx);
    coinbase_merkle_branch = ComputeCoinbaseMerkleBranch(non_coinbase_txs);
    roots_ready = true;
}

const MiningTemplateSnapshot &ChainAndMempoolSnapshot::GetMiningTemplate() const {
    std::lock_guard<std::mutex> lock(mining->mutex);
    if (mining->ready || !mining->value.template_valid) return mining->value;
    EnsureMempoolVectors();
    auto &t = mining->value;
    BlockFitter fitter(GetConfig());
    std::vector<const MempoolEntrySnapshot *> selected;
    selected.reserve(mempool_entries.size());
    bool all_fit = ctor_active && overlay_all_fit_candidate && fitter.testTxFits(overlay_bytes, overlay_sigchecks);
    // The overlay certifies ordering/resource bookkeeping, never script or
    // UTXO validity. Check contextual eligibility even for unchecked fixtures.
    for (const auto &entry : mempool_entries) {
        TxValidationState state;
        if (fitter.isBelowBlockMinFeeRate(entry.modified_feerate) ||
            !ContextualCheckTransaction(*consensus_params, *entry.tx, state,
                                       t.next_height, t.parent_mtp)) {
            all_fit = false;
            break;
        }
    }
    if (all_fit) {
        for (const auto &entry : mempool_entries) selected.push_back(&entry);
    } else {
        struct DepNode {
            const MempoolEntrySnapshot *entry;
            size_t missing{0};
            std::vector<size_t> children;
        };
        std::vector<DepNode> nodes;
        std::unordered_map<std::string, size_t> locations;
        for (const auto &entry : mempool_entries) {
            locations.emplace(entry.txid.ToString(), nodes.size());
            nodes.push_back({&entry, entry.depends.size(), {}});
        }
        for (size_t child = 0; child < nodes.size(); ++child) {
            for (const auto &parent : nodes[child].entry->depends) {
                const auto pos = locations.find(parent);
                if (pos != locations.end()) nodes[pos->second].children.push_back(child);
            }
        }
        auto lower = [&nodes](size_t a, size_t b) {
            const auto &x = *nodes[a].entry, &y = *nodes[b].entry;
            if (x.modified_feerate != y.modified_feerate) return x.modified_feerate < y.modified_feerate;
            if (x.entry_id != y.entry_id) return x.entry_id > y.entry_id;
            return y.txid < x.txid;
        };
        std::priority_queue<size_t, std::vector<size_t>, decltype(lower)> ready(lower);
        for (size_t i = 0; i < nodes.size(); ++i) if (!nodes[i].missing) ready.push(i);
        while (!ready.empty()) {
            const size_t i = ready.top(); ready.pop();
            const auto &entry = *nodes[i].entry;
            if (fitter.isBelowBlockMinFeeRate(entry.modified_feerate)) break;
            if (!fitter.testTxFits(entry.tx_size, entry.sigchecks)) continue;
            TxValidationState state;
            if (!ContextualCheckTransaction(*consensus_params, *entry.tx, state,
                                           t.next_height, t.parent_mtp)) continue;
            fitter.addTx(entry.tx_size, entry.sigchecks, entry.fee);
            selected.push_back(&entry);
            for (size_t child : nodes[i].children) if (--nodes[child].missing == 0) ready.push(child);
        }
        if (ctor_active) std::sort(selected.begin(), selected.end(), [](auto a, auto b) { return a->txid < b->txid; });
    }
    for (const auto *entry : selected) {
        t.non_coinbase_txs.push_back(entry->tx);
        t.tx_fees.push_back(entry->fee);
        t.tx_sigchecks.push_back(entry->sigchecks);
        t.total_fees += entry->fee;
        t.non_cb_serialized_size += entry->tx_size;
    }
    t.block_reward = next_subsidy + t.total_fees;
    mining->ready = true;
    GetGlobalSnapshotPublisher().RecordMiningTemplate(t);
    return t;
}

void SnapshotPublisher::RecordMiningTemplate(
    const MiningTemplateSnapshot &tmpl) {
    if (!tmpl.template_valid || tmpl.template_id == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(m_publish_mutex);
    m_template_history[m_template_history_pos % kTemplateHistorySize] = tmpl;
    ++m_template_history_pos;
}

std::optional<MiningTemplateSnapshot>
SnapshotPublisher::FindMiningTemplate(uint64_t template_id,
                                      const BlockHash &prev_block_hash) const {
    auto current = Load();
    if (current && current->GetMiningTemplate().template_valid) {
        if (template_id != 0 &&
            current->GetMiningTemplate().template_id == template_id &&
            (prev_block_hash.IsNull() ||
             current->GetMiningTemplate().prev_block_hash == prev_block_hash)) {
            current->EnsureMiningTemplate();
            current->GetMiningTemplate().EnsureTemplateRoots();
            return current->GetMiningTemplate();
        }
        if (template_id == 0 &&
            (prev_block_hash.IsNull() ||
             current->GetMiningTemplate().prev_block_hash == prev_block_hash)) {
            current->EnsureMiningTemplate();
            current->GetMiningTemplate().EnsureTemplateRoots();
            return current->GetMiningTemplate();
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_publish_mutex);
        for (size_t offset = 1; offset <= m_template_history_pos &&
                                offset <= kTemplateHistorySize;
             ++offset) {
            const auto &entry =
                m_template_history[(m_template_history_pos - offset) %
                                   kTemplateHistorySize];
            if (template_id != 0 && entry.template_id == template_id &&
                (prev_block_hash.IsNull() ||
                 entry.prev_block_hash == prev_block_hash)) {
                entry.EnsureTemplateRoots();
                return entry;
            }
            if (template_id == 0 &&
                (prev_block_hash.IsNull() ||
                 entry.prev_block_hash == prev_block_hash)) {
                entry.EnsureTemplateRoots();
                return entry;
            }
        }
    }
    if (template_id == 0 && current && current->GetMiningTemplate().template_valid) {
        current->EnsureMiningTemplate();
        current->GetMiningTemplate().EnsureTemplateRoots();
        return current->GetMiningTemplate();
    }
    return std::nullopt;
}

SnapshotPublisher::SnapshotPublisher()
    : m_current(std::allocate_shared<const ChainAndMempoolSnapshot>(SnapshotAllocator<ChainAndMempoolSnapshot>{})) {}

void SnapshotPublisher::Publish(std::shared_ptr<const ChainAndMempoolSnapshot> next) {
    if (!next) return;
    std::atomic_store_explicit(&m_current, std::move(next), std::memory_order_release);
    m_publications.fetch_add(1);
}

std::shared_ptr<SnapshotPublisher> GetGlobalSnapshotPublisherPtr() {
    static auto g_publisher = std::make_shared<SnapshotPublisher>();
    return g_publisher;
}

SnapshotPublisher &GetGlobalSnapshotPublisher() {
    return *GetGlobalSnapshotPublisherPtr();
}

void PublishChainTipSnapshot(ChainstateManager &chainman,
                             const CTxMemPool *mempool)
    NO_THREAD_SAFETY_ANALYSIS {
    AssertLockHeld(::cs_main);
    if (g_chain_publication.depth && g_chain_publication.chainman == &chainman) {
        assert(g_chain_publication.mempool == mempool);
        g_chain_publication.dirty = true;
        return;
    }
    const auto publish_start{SnapshotPublishStart()};
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    auto next = CloneChainStateOnly(prev.get());

    Chainstate &active_chainstate = chainman.ActiveChainstate();
    const CBlockIndex *tip = active_chainstate.m_chain.Tip();
    if (!tip) {
        return;
    }

    const CChainParams &chainparams = chainman.GetParams();
    next->chainman_ptr = &chainman;
    next->chain_valid = true;
    next->height = tip->nHeight;
    next->headers_height =
        chainman.m_best_header ? chainman.m_best_header->nHeight : -1;
    next->best_block_hash = tip->GetBlockHash();
    const CBlockIndex *avalanche_finalized_tip =
        chainman.GetAvalancheFinalizedTip();
    next->finalized_block_hash =
        avalanche_finalized_tip ? avalanche_finalized_tip->GetBlockHash()
                                : chainparams.GenesisBlock().GetHash();
    next->difficulty = ComputeDifficultyFromBits(tip->nBits);
    next->time = tip->GetBlockTime();
    next->mediantime = tip->GetMedianTimePast();
    next->verification_progress =
        GuessVerificationProgress(chainparams.TxData(), tip);
    next->initial_block_download = chainman.IsInitialBlockDownload();
    next->chainwork = ArithToUint256(tip->nChainWork);
    next->size_on_disk = chainman.m_blockman.CalculateCurrentUsage();
    next->pruned = chainman.m_blockman.IsPruneMode();
    if (next->pruned) {
        const auto prune_height =
            ComputePruneHeight(chainman.m_blockman, active_chainstate.m_chain);
        next->has_prune_height = true;
        next->prune_height = prune_height ? prune_height.value() + 1 : 0;
        next->automatic_pruning =
            chainman.m_blockman.GetPruneTarget() !=
            BlockManager::PRUNE_TARGET_MANUAL;
        if (next->automatic_pruning) {
            next->prune_target_size = chainman.m_blockman.GetPruneTarget();
        }
    } else {
        next->has_prune_height = false;
        next->prune_height = 0;
        next->automatic_pruning = false;
        next->prune_target_size = 0;
    }
    next->fast_sync_active = active_chainstate.IsFastSyncActive();
    next->earliest_verified_height =
        active_chainstate.GetEarliestVerifiedHeight();
    next->chain_type_string = chainparams.GetChainTypeString();
    next->nBits = tip->nBits;
    next->consensus_params = chainparams.GetConsensus();

    CBlockHeader dummyHeader;
    dummyHeader.hashPrevBlock = tip->GetBlockHash();
    const int64_t now_time =
        TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    dummyHeader.SetBlockTime(
        static_cast<uint64_t>(std::max<int64_t>(tip->GetMedianTimePast() + 1, now_time)));
    next->next_nBits = GetNextWorkRequired(tip, &dummyHeader, chainparams);
    next->next_subsidy =
        GetBlockSubsidy(tip->nHeight + 1, *next->consensus_params);

    next->miner_fund_active = IsAxionEnabled(*next->consensus_params, tip);
    next->ctor_active = IsMagneticAnomalyEnabled(*next->consensus_params, tip);
    next->next_block_version = ComputeBlockVersion(tip, *next->consensus_params);
    if (chainparams.MineBlocksOnDemand()) {
        next->next_block_version = gArgs.GetIntArg("-blockversion", next->next_block_version);
    }
    next->miner_fund_ratio = int(GetMinerFundAmount(*next->consensus_params, 100 * SATOSHI, tip) / SATOSHI);
    next->staking_rewards_active = IsStakingRewardsActivated(*next->consensus_params, tip);

    next->prev_header_received_time.fill(0);
    const CBlockIndex *prev_idx = tip;
    for (size_t i = 1; i < 18 && prev_idx != nullptr; ++i) {
        next->prev_header_received_time[i] =
            prev_idx->GetHeaderReceivedTime();
        prev_idx = prev_idx->pprev;
    }

    std::shared_ptr<ActiveChainSnapshot> active_chain_snap;
    const int tip_height = tip->nHeight;
    if (tip_height >= 1 && tip->pprev && prev && prev->active_chain &&
        prev->chainman_ptr == &chainman && !next->pruned &&
        prev->active_chain->by_height.size() ==
            static_cast<size_t>(tip_height) &&
        prev->active_chain->by_height.back().hash ==
            tip->pprev->GetBlockHash()) {
        active_chain_snap = std::allocate_shared<ActiveChainSnapshot>(
            SnapshotAllocator<ActiveChainSnapshot>{}, *prev->active_chain);
        BlockHeaderSnapshot tip_hdr = MakeBlockHeaderSnapshot(*tip);
        active_chain_snap->height_by_hash.emplace(tip_hdr.hash, tip_height);
        active_chain_snap->by_height.push_back(std::move(tip_hdr));
    } else {
        active_chain_snap = std::allocate_shared<ActiveChainSnapshot>(
            SnapshotAllocator<ActiveChainSnapshot>{});
        if (tip_height >= 0) {
            active_chain_snap->by_height.reserve(
                static_cast<size_t>(tip_height) + 1);
            active_chain_snap->height_by_hash.reserve(
                static_cast<size_t>(tip_height) + 1);
            for (int h = 0; h <= tip_height; ++h) {
                const CBlockIndex *pindex = active_chainstate.m_chain[h];
                BlockHeaderSnapshot hdr = MakeBlockHeaderSnapshot(*pindex);
                active_chain_snap->height_by_hash.emplace(hdr.hash, h);
                active_chain_snap->by_height.push_back(std::move(hdr));
            }
        }
    }
    next->active_chain = std::move(active_chain_snap);

    if (mempool) {
        LOCK(mempool->cs);
        mempool->ClearSnapshotDirty();
        mempool->SyncMerklixOverlayToTip(
            tip->GetBlockHash(), uint64_t(tip->nHeight + 1),
            uint64_t(tip->GetMedianTimePast()));
        PopulateMempoolScalarsLocked(*next, *mempool);
        CaptureMempoolEntriesLocked(*next, *mempool, prev.get());
        InitMiningTemplate(*next, prev.get(), mempool);
    }

    if (!mempool) InitMiningTemplate(*next, prev.get(), nullptr);
    publisher.Publish(std::move(next));
    RecordSnapshotPublication(SnapshotKind::CHAIN_TIP, publish_start);
}

void PublishBestHeaderSnapshot(ChainstateManager &chainman)
    NO_THREAD_SAFETY_ANALYSIS {
    AssertLockHeld(::cs_main);
    if (g_chain_publication.depth && g_chain_publication.chainman == &chainman) {
        g_chain_publication.dirty = true;
        return;
    }
    auto &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    if (!prev || !prev->chain_valid || prev->chainman_ptr != &chainman) return;
    // Serialize with mempool writers so a header refresh cannot overwrite a
    // newer mempool generation. Readers still acquire neither writer lock.
    auto &chainstate = chainman.ActiveChainstate();
    LOCK(chainstate.MempoolMutex());
    prev = publisher.Load();
    if (!prev || !prev->chain_valid || prev->chainman_ptr != &chainman) return;
    const int height = chainman.m_best_header ? chainman.m_best_header->nHeight : -1;
    const bool ibd = chainman.IsInitialBlockDownload();
    if (prev->headers_height == height && prev->initial_block_download == ibd) return;
    const auto publish_start{SnapshotPublishStart()};
    auto next = CloneChainStateOnly(prev.get());
    next->headers_height = height;
    next->initial_block_download = ibd;
    if (const auto *mempool = chainstate.GetMempool()) {
        PopulateMempoolScalarsLocked(*next, *mempool);
        CaptureMempoolEntriesLocked(*next, *mempool, prev.get());
        InitMiningTemplate(*next, prev.get(), mempool);
    }
    publisher.Publish(std::move(next));
    RecordSnapshotPublication(SnapshotKind::BEST_HEADER, publish_start);
}

void PublishMempoolSnapshot(const CTxMemPool &mempool)
    NO_THREAD_SAFETY_ANALYSIS {
    AssertLockHeld(mempool.cs);
    if (g_chain_publication.depth && g_chain_publication.mempool == &mempool) {
        g_chain_publication.dirty = true;
        return;
    }
    if (mempool.DeferSnapshotIfActive()) {
        return;
    }
    const auto publish_start{SnapshotPublishStart()};
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    auto next = mempool.HasSnapshotState() && prev && prev->mempool_ptr == &mempool
                    ? CloneChainStateOnly(prev.get())
                    : std::allocate_shared<ChainAndMempoolSnapshot>(SnapshotAllocator<ChainAndMempoolSnapshot>{});

    PopulateMempoolScalarsLocked(*next, mempool);
    next->mempool_vectors_ready = false;
    CaptureMempoolEntriesLocked(*next, mempool, prev.get());
    InitMiningTemplate(*next, prev.get(), &mempool);

    publisher.Publish(std::move(next));
    RecordSnapshotPublication(SnapshotKind::MEMPOOL, publish_start);
}

void PublishMempoolUnbroadcastSnapshot(const CTxMemPool &mempool,
                                       const TxId &txid, bool unbroadcast)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    mempool.MarkSnapshotEntryChanged(txid);
    PublishMempoolSnapshot(mempool);
}

} // namespace node
