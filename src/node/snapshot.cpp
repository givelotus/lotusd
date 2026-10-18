// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/snapshot.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <lotus_v2/mempool_overlay.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <streams.h>
#include <timedata.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <validation.h>

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
    auto tree = full ? std::make_shared<MempoolSnapshotTree>()
                     : std::make_shared<MempoolSnapshotTree>(*prev->entry_tree);
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
    auto next = std::make_shared<ChainAndMempoolSnapshot>();
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
    next->consensus_params = prev->consensus_params;
    next->prev_header_received_time = prev->prev_header_received_time;
    next->active_chain = prev->active_chain;
    return next;
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

SnapshotPublisher::SnapshotPublisher()
    : m_current(std::make_shared<const ChainAndMempoolSnapshot>()) {}

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
    next->fast_sync_active = false;
    next->earliest_verified_height = 0;
    next->chain_type_string = chainparams.GetChainTypeString();
    next->nBits = tip->nBits;
    next->consensus_params = chainparams.GetConsensus();

    CBlockHeader dummyHeader;
    dummyHeader.hashPrevBlock = tip->GetBlockHash();
    const int64_t now_time =
        TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    dummyHeader.nTime =
        static_cast<uint32_t>(std::max<int64_t>(tip->GetMedianTimePast() + 1, now_time));
    next->next_nBits = GetNextWorkRequired(tip, &dummyHeader, chainparams);
    next->next_subsidy =
        GetBlockSubsidy(tip->nHeight + 1, *next->consensus_params);

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
        active_chain_snap =
            std::make_shared<ActiveChainSnapshot>(*prev->active_chain);
        BlockHeaderSnapshot tip_hdr = MakeBlockHeaderSnapshot(*tip);
        active_chain_snap->height_by_hash.emplace(tip_hdr.hash, tip_height);
        active_chain_snap->by_height.push_back(std::move(tip_hdr));
    } else {
        active_chain_snap = std::make_shared<ActiveChainSnapshot>();
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
    }

    publisher.Publish(std::move(next));
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
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    auto next = mempool.HasSnapshotState() && prev && prev->mempool_ptr == &mempool
                    ? CloneChainStateOnly(prev.get())
                    : std::make_shared<ChainAndMempoolSnapshot>();

    PopulateMempoolScalarsLocked(*next, mempool);
    next->mempool_vectors_ready = false;
    CaptureMempoolEntriesLocked(*next, mempool, prev.get());

    publisher.Publish(std::move(next));
}

void PublishMempoolUnbroadcastSnapshot(const CTxMemPool &mempool,
                                       const TxId &txid, bool unbroadcast)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    mempool.MarkSnapshotEntryChanged(txid);
    PublishMempoolSnapshot(mempool);
}

} // namespace node
