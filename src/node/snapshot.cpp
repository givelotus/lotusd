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
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/fee_hysteresis.h>
#include <node/blockfitter.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <rpc/async_waiter.h>
#include <streams.h>
#include <timedata.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cstring>
#include <queue>
#include <unordered_map>

namespace node {
namespace {

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
    hdr.size = blockindex.nSize;
    hdr.time = blockindex.GetBlockTime();
    hdr.mediantime = blockindex.GetMedianTimePast();
    hdr.difficulty = ComputeDifficultyFromBits(blockindex.nBits);
    hdr.chainwork = ArithToUint256(blockindex.nChainWork);
    hdr.nTx = blockindex.nTx;
    hdr.data_pos = blockindex.GetBlockPos();
    hdr.has_data = blockindex.nStatus.hasData();
    return hdr;
}

std::shared_ptr<ChainAndMempoolSnapshot>
CloneChainStateOnly(const ChainAndMempoolSnapshot *prev) {
    auto next = std::allocate_shared<ChainAndMempoolSnapshot>(
        SnapshotAllocator<ChainAndMempoolSnapshot>{});
    if (!prev) {
        return next;
    }
    next->chainman_ptr = prev->chainman_ptr;
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
    next->has_utxo_snapshot = prev->has_utxo_snapshot;
    next->tip_utxo_root = prev->tip_utxo_root;
    next->tip_mon_state = prev->tip_mon_state;
    return next;
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
    // Sorted, as the depends list, so the order does not depend on
    // admission order.
    std::sort(entry_snap.spentby.begin(), entry_snap.spentby.end());
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
    snap.mempool_reset_seq = mempool.GetSnapshotResetSequence();
    snap.mempool_has_fee_deltas = !mempool.mapDeltas.empty();

    const auto &id_idx = mempool.mapTx.get<entry_id>();
    snap.last_mempool_entry_id =
        id_idx.empty() ? 0 : (*std::prev(id_idx.end()))->GetEntryId();

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

// Entries copied from the previous snapshot keep their old unbroadcast flag;
// the unbroadcast set changes without adding or removing an entry.
static void RefreshUnbroadcast(std::vector<MempoolEntrySnapshot> &entries,
                               const CTxMemPool &mempool)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    for (MempoolEntrySnapshot &entry : entries) {
        entry.unbroadcast = mempool.IsUnbroadcastTx(entry.txid);
    }
}

void PopulateMempoolVectorsLocked(ChainAndMempoolSnapshot &snap,
                                  const CTxMemPool &mempool,
                                  const ChainAndMempoolSnapshot *prev)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    const auto &id_idx = mempool.mapTx.get<entry_id>();
    const bool can_reuse_prev =
        prev && prev->mempool_valid && prev->mempool_ptr == &mempool &&
        prev->mempool_vectors_ready;
    if (can_reuse_prev && prev->mempool_reset_seq == snap.mempool_reset_seq &&
        mempool.mapDeltas.empty() && prev->last_mempool_entry_id != 0 &&
        id_idx.size() >= prev->mempool_entries.size() &&
        !prev->mempool_entries.empty()) {
        const size_t delta_count = id_idx.size() - prev->mempool_entries.size();
        const auto new_begin = std::prev(id_idx.end(), delta_count);
        if (new_begin != id_idx.begin() &&
            (*std::prev(new_begin))->GetEntryId() ==
                prev->last_mempool_entry_id) {
            const uint64_t prev_max_entry_id = prev->last_mempool_entry_id;
            if (delta_count == 0) {
                snap.mempool_txids = prev->mempool_txids;
                snap.mempool_entries = prev->mempool_entries;
                snap.mempool_spent_outpoints = prev->mempool_spent_outpoints;
                RefreshUnbroadcast(snap.mempool_entries, mempool);
                snap.mempool_vectors_ready = true;
                return;
            }

            snap.mempool_txids = prev->mempool_txids;
            snap.mempool_txids.reserve(id_idx.size());

            std::vector<COutPoint> delta_spent;
            delta_spent.reserve(delta_count * 2);
            std::vector<MempoolEntrySnapshot> delta_entries;
            delta_entries.reserve(delta_count);
            std::vector<std::pair<TxId, std::string>> parent_spentby_updates;

            for (auto it = new_begin; it != id_idx.end(); ++it) {
                const CTxMemPoolEntry &e = **it;
                const CTransaction &tx = e.GetTx();
                const TxId &txid = tx.GetId();
                snap.mempool_txids.push_back(txid);

                for (const CTxIn &txin : tx.vin) {
                    if (!txin.prevout.IsNull()) {
                        delta_spent.push_back(txin.prevout);
                    }
                }
                for (const auto &parent : e.GetMemPoolParentsConst()) {
                    if (parent.get()->GetEntryId() <= prev_max_entry_id) {
                        parent_spentby_updates.emplace_back(
                            parent.get()->GetTx().GetId(), txid.ToString());
                    }
                }
                delta_entries.push_back(MakeMempoolEntrySnapshot(e, mempool));
            }

            std::sort(delta_spent.begin(), delta_spent.end());
            snap.mempool_spent_outpoints.clear();
            snap.mempool_spent_outpoints.reserve(
                prev->mempool_spent_outpoints.size() + delta_spent.size());
            std::merge(prev->mempool_spent_outpoints.begin(),
                       prev->mempool_spent_outpoints.end(),
                       delta_spent.begin(), delta_spent.end(),
                       std::back_inserter(snap.mempool_spent_outpoints));

            auto entry_cmp = [](const MempoolEntrySnapshot &a,
                                const MempoolEntrySnapshot &b) {
                return a.txid < b.txid;
            };
            std::sort(delta_entries.begin(), delta_entries.end(), entry_cmp);
            snap.mempool_entries.clear();
            snap.mempool_entries.reserve(prev->mempool_entries.size() +
                                         delta_entries.size());
            std::merge(prev->mempool_entries.begin(),
                       prev->mempool_entries.end(), delta_entries.begin(),
                       delta_entries.end(),
                       std::back_inserter(snap.mempool_entries), entry_cmp);

            for (auto &[parent_txid, child_txid_str] : parent_spentby_updates) {
                auto pit = std::lower_bound(
                    snap.mempool_entries.begin(), snap.mempool_entries.end(),
                    parent_txid,
                    [](const MempoolEntrySnapshot &entry, const TxId &id) {
                        return entry.txid < id;
                    });
                if (pit != snap.mempool_entries.end() &&
                    pit->txid == parent_txid) {
                    pit->spentby.insert(
                        std::upper_bound(pit->spentby.begin(),
                                         pit->spentby.end(), child_txid_str),
                        child_txid_str);
                }
            }
            RefreshUnbroadcast(snap.mempool_entries, mempool);
            snap.mempool_vectors_ready = true;
            return;
        }
    }

    snap.mempool_txids.clear();
    mempool.getAllTxIds(snap.mempool_txids);

    snap.mempool_entries.clear();
    snap.mempool_entries.reserve(mempool.mapTx.size());
    snap.mempool_spent_outpoints.clear();
    snap.mempool_spent_outpoints.reserve(mempool.mapNextTx.size());
    for (const CTxMemPoolEntryRef &e : id_idx) {
        const CTransaction &tx = e->GetTx();
        const TxId &txid = tx.GetId();
        for (const CTxIn &txin : tx.vin) {
            if (!txin.prevout.IsNull()) {
                snap.mempool_spent_outpoints.push_back(txin.prevout);
            }
        }

        const auto &parents = e->GetMemPoolParentsConst();
        const auto &children = e->GetMemPoolChildrenConst();
        if (can_reuse_prev && prev->mempool_vectors_ready) {
            const auto it = std::lower_bound(
                prev->mempool_entries.begin(), prev->mempool_entries.end(), txid,
                [](const MempoolEntrySnapshot &entry, const TxId &id) {
                    return entry.txid < id;
                });
            const MempoolEntrySnapshot *prev_entry =
                (it != prev->mempool_entries.end() && it->txid == txid)
                    ? &(*it)
                    : nullptr;
            if (prev_entry && prev_entry->tx.get() == &tx &&
                prev_entry->modified_fee == e->GetModifiedFee() &&
                prev_entry->depends.size() == parents.size() &&
                prev_entry->spentby.size() == children.size()) {
                MempoolEntrySnapshot entry_snap = *prev_entry;
                entry_snap.unbroadcast = mempool.IsUnbroadcastTx(txid);
                snap.mempool_entries.push_back(std::move(entry_snap));
                continue;
            }
        }

        snap.mempool_entries.push_back(MakeMempoolEntrySnapshot(*e, mempool));
    }
    std::sort(snap.mempool_entries.begin(), snap.mempool_entries.end(),
              [](const MempoolEntrySnapshot &a,
                 const MempoolEntrySnapshot &b) { return a.txid < b.txid; });
    std::sort(snap.mempool_spent_outpoints.begin(),
              snap.mempool_spent_outpoints.end());
    snap.mempool_vectors_ready = true;
}

void PopulateMempoolFieldsLocked(ChainAndMempoolSnapshot &snap,
                                 const CTxMemPool &mempool,
                                 const ChainAndMempoolSnapshot *prev)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs) {
    PopulateMempoolScalarsLocked(snap, mempool);
    PopulateMempoolVectorsLocked(snap, mempool, prev);
}

void PopulateMiningTemplate(ChainAndMempoolSnapshot &snap,
                            const CTxMemPool *mempool_locked,
                            const ChainAndMempoolSnapshot *prev,
                            SnapshotPublisher &publisher)
     NO_THREAD_SAFETY_ANALYSIS {
    if (!snap.chain_valid || snap.height < 0 || !snap.consensus_params) {
        return;
    }

    MiningTemplateSnapshot tmpl{};
    tmpl.template_id = snap.mining_template.template_id != 0
                           ? snap.mining_template.template_id
                           : publisher.AllocateTemplateId();
    tmpl.prev_block_hash = snap.best_block_hash;
    tmpl.next_height = snap.height + 1;
    tmpl.nHeaderVersion = lotus::v2::kHeaderVersion;
    if (snap.consensus_params->fPowAllowMinDifficultyBlocks) {
        tmpl.nHeaderVersion =
            gArgs.GetIntArg("-blockversion", tmpl.nHeaderVersion);
    }
    tmpl.nBits = snap.next_nBits;
    tmpl.parent_mtp = snap.mediantime;
    tmpl.min_time = snap.mediantime + 1;
    tmpl.total_fees = Amount::zero();
    tmpl.non_cb_serialized_size = 0;
    tmpl.total_sigchecks = 0;
    tmpl.tip_utxo_root = snap.tip_utxo_root;
    tmpl.tip_mon_state = snap.tip_mon_state;
    tmpl.has_tip_utxo_snapshot = snap.has_utxo_snapshot;
    tmpl.roots_ready = false;
    tmpl.transactions_updated = snap.transactions_updated;

    std::vector<const MempoolEntrySnapshot *> id_idx;
    if (snap.entry_tree) {
        snap.entry_tree->forEachLeaf([&](const auto &value) {
            id_idx.push_back(&value->entry);
            return true;
        });
        std::sort(id_idx.begin(), id_idx.end(), [](const auto *a, const auto *b) {
            return a->entry_id < b->entry_id;
        });
    }
    BlockFitter blockFitter(GetConfig());
    tmpl.max_generated_block_size = blockFitter.getMaxGeneratedBlockSize();

    if (!id_idx.empty()) {
        struct SelectedEntry {
            CTransactionRef tx;
            Amount fee;
            int64_t sigchecks;
        };

        const bool can_reuse_prev_check =
            prev && prev->mining_template.template_valid &&
            prev->mining_template_ready &&
            prev->mining_template.prev_block_hash == tmpl.prev_block_hash &&
            prev->mining_template.next_height == tmpl.next_height &&
            prev->mining_template.parent_mtp == tmpl.parent_mtp &&
            prev->mining_template.max_generated_block_size ==
                tmpl.max_generated_block_size;

        // Fast O(delta) append path when only new transactions were added since
        // `prev` and all previous mempool transactions fit in `prev->mining_template`.
        bool used_delta_selection = false;
        if (can_reuse_prev_check && prev->mempool_valid &&
            prev->mempool_vectors_ready &&
            prev->mempool_ptr == snap.mempool_ptr &&
            prev->mempool_reset_seq == snap.mempool_reset_seq &&
            !snap.mempool_has_fee_deltas &&
            prev->last_mempool_entry_id != 0 &&
            !prev->mempool_entries.empty() &&
            prev->mining_template.non_coinbase_txs.size() ==
                prev->mempool_entries.size() &&
            id_idx.size() >= prev->mempool_entries.size()) {
            const size_t delta_count =
                id_idx.size() - prev->mempool_entries.size();
            const auto new_begin = std::prev(id_idx.end(), delta_count);
            if (new_begin != id_idx.begin() &&
                (*std::prev(new_begin))->entry_id ==
                    prev->last_mempool_entry_id) {
                blockFitter.nBlockSize +=
                    prev->mining_template.non_cb_serialized_size;
                blockFitter.nBlockTx +=
                    prev->mining_template.non_coinbase_txs.size();
                blockFitter.nBlockSigChecks +=
                    uint64_t(prev->mining_template.total_sigchecks);
                blockFitter.nFees += prev->mining_template.total_fees;

                std::vector<SelectedEntry> delta_selected;
                delta_selected.reserve(delta_count);
                bool all_delta_eligible = true;
                for (auto it = new_begin; it != id_idx.end(); ++it) {
                    const MempoolEntrySnapshot &e = **it;
                    const uint64_t tx_size = e.tx_size;
                    const int64_t tx_sigchecks = e.sigchecks;
                    const Amount fee = e.fee;
                    if (blockFitter.isBelowBlockMinFeeRate(
                            e.modified_feerate) ||
                        !blockFitter.testTxFits(tx_size, tx_sigchecks)) {
                        all_delta_eligible = false;
                        break;
                    }
                    TxValidationState tx_state;
                    if (!ContextualCheckTransaction(
                            *snap.consensus_params, *e.tx, tx_state,
                            tmpl.next_height, tmpl.parent_mtp)) {
                        all_delta_eligible = false;
                        break;
                    }
                    blockFitter.addTx(tx_size, tx_sigchecks, fee);
                    delta_selected.push_back(
                        {e.tx, fee, tx_sigchecks});
                }

                if (all_delta_eligible) {
                    std::sort(delta_selected.begin(), delta_selected.end(),
                              [](const SelectedEntry &a,
                                 const SelectedEntry &b) {
                                  return a.tx->GetId() < b.tx->GetId();
                              });

                    const auto &prev_tmpl = prev->mining_template;
                    const size_t total_count =
                        prev_tmpl.non_coinbase_txs.size() +
                        delta_selected.size();
                    tmpl.non_coinbase_txs.reserve(total_count);
                    tmpl.tx_fees.reserve(total_count);
                    tmpl.tx_sigchecks.reserve(total_count);
                    tmpl.tx_hex.reserve(total_count);
                    tmpl.total_fees = blockFitter.nFees;
                    tmpl.non_cb_serialized_size =
                        blockFitter.nBlockSize -
                        BlockFitter::COINBASE_RESERVED_SIZE;
                    tmpl.total_sigchecks =
                        int64_t(blockFitter.nBlockSigChecks -
                                BlockFitter::COINBASE_RESERVED_SIGCHECKS);

                    const bool prev_has_hex =
                        prev_tmpl.tx_hex.size() ==
                        prev_tmpl.non_coinbase_txs.size();
                    size_t i = 0;
                    size_t j = 0;
                    while (i < prev_tmpl.non_coinbase_txs.size() &&
                           j < delta_selected.size()) {
                        if (prev_tmpl.non_coinbase_txs[i]->GetId() <
                            delta_selected[j].tx->GetId()) {
                            tmpl.non_coinbase_txs.push_back(
                                prev_tmpl.non_coinbase_txs[i]);
                            tmpl.tx_fees.push_back(prev_tmpl.tx_fees[i]);
                            tmpl.tx_sigchecks.push_back(
                                prev_tmpl.tx_sigchecks[i]);
                            tmpl.tx_hex.push_back(
                                prev_has_hex ? prev_tmpl.tx_hex[i]
                                             : std::string());
                            ++i;
                        } else {
                            tmpl.non_coinbase_txs.push_back(
                                std::move(delta_selected[j].tx));
                            tmpl.tx_fees.push_back(delta_selected[j].fee);
                            tmpl.tx_sigchecks.push_back(
                                delta_selected[j].sigchecks);
                            tmpl.tx_hex.emplace_back();
                            ++j;
                        }
                    }
                    while (i < prev_tmpl.non_coinbase_txs.size()) {
                        tmpl.non_coinbase_txs.push_back(
                            prev_tmpl.non_coinbase_txs[i]);
                        tmpl.tx_fees.push_back(prev_tmpl.tx_fees[i]);
                        tmpl.tx_sigchecks.push_back(prev_tmpl.tx_sigchecks[i]);
                        tmpl.tx_hex.push_back(
                            prev_has_hex ? prev_tmpl.tx_hex[i] : std::string());
                        ++i;
                    }
                    while (j < delta_selected.size()) {
                        tmpl.non_coinbase_txs.push_back(
                            std::move(delta_selected[j].tx));
                        tmpl.tx_fees.push_back(delta_selected[j].fee);
                        tmpl.tx_sigchecks.push_back(
                            delta_selected[j].sigchecks);
                        tmpl.tx_hex.emplace_back();
                        ++j;
                    }
                    if (delta_selected.empty() && prev_tmpl.roots_ready) {
                        tmpl.subtree_a_root = prev_tmpl.subtree_a_root;
                        tmpl.v2_base_state = prev_tmpl.v2_base_state;
                        tmpl.roots_ready = true;
                    }
                    used_delta_selection = true;
                } else {
                    blockFitter.resetBlock();
                }
            }
        }

        if (!used_delta_selection) {
            std::vector<SelectedEntry> selected;
            selected.reserve(id_idx.size());

            bool used_all_eligible_selection = false;
            if (!snap.mempool_has_fee_deltas) {
                bool all_eligible = true;
                for (const auto &entry : id_idx) {
                    const uint64_t tx_size = entry->tx_size;
                    const int64_t tx_sigchecks = entry->sigchecks;
                    const Amount fee = entry->fee;
                    if (blockFitter.isBelowBlockMinFeeRate(
                            entry->modified_feerate) ||
                        !blockFitter.testTxFits(tx_size, tx_sigchecks)) {
                        all_eligible = false;
                        break;
                    }
                    TxValidationState tx_state;
                    if (!ContextualCheckTransaction(
                            *snap.consensus_params, *entry->tx, tx_state,
                            tmpl.next_height, tmpl.parent_mtp)) {
                        all_eligible = false;
                        break;
                    }
                    blockFitter.addTx(tx_size, tx_sigchecks, fee);
                    tmpl.total_fees += fee;
                    tmpl.total_sigchecks += tx_sigchecks;
                    selected.push_back(
                        {entry->tx, fee, tx_sigchecks});
                }
                if (all_eligible) {
                    std::sort(selected.begin(), selected.end(),
                              [](const SelectedEntry &a,
                                 const SelectedEntry &b) {
                                  return a.tx->GetId() < b.tx->GetId();
                              });
                    used_all_eligible_selection = true;
                    tmpl.mempool_ptr = mempool_locked;
                } else {
                    blockFitter.resetBlock();
                    tmpl.total_fees = Amount::zero();
                    tmpl.total_sigchecks = 0;
                    selected.clear();
                }
            }

            if (!used_all_eligible_selection) {
                struct DepNode {
                    const MempoolEntrySnapshot *entry;
                    size_t missing_parents;
                    std::vector<size_t> children;
                };
                std::vector<DepNode> nodes;
                nodes.reserve(id_idx.size());
                std::unordered_map<TxId, size_t, SaltedTxIdHasher> locations;
                locations.reserve(id_idx.size());
                for (const auto &entry : id_idx) {
                    locations.emplace(entry->tx->GetId(), nodes.size());
                    nodes.push_back(
                        {entry, entry->depends.size(), {}});
                }
                for (size_t child = 0; child < nodes.size(); ++child) {
                    for (const auto &parent :
                         nodes[child].entry->depends) {
                        const auto pos =
                            locations.find(TxId(uint256S(parent)));
                        if (pos != locations.end()) {
                            nodes[pos->second].children.push_back(child);
                        }
                    }
                }
                auto lowerPriority = [&nodes](size_t a, size_t b) {
                    const auto &lhs = *nodes[b].entry;
                    const auto &rhs = *nodes[a].entry;
                    if (lhs.modified_feerate != rhs.modified_feerate)
                        return lhs.modified_feerate > rhs.modified_feerate;
                    if (lhs.entry_id != rhs.entry_id) return lhs.entry_id < rhs.entry_id;
                    return lhs.txid < rhs.txid;
                };
                std::priority_queue<size_t, std::vector<size_t>,
                                    decltype(lowerPriority)>
                    ready(lowerPriority);
                for (size_t i = 0; i < nodes.size(); ++i) {
                    if (nodes[i].missing_parents == 0) {
                        ready.push(i);
                    }
                }

                while (!ready.empty()) {
                    const size_t idx = ready.top();
                    ready.pop();
                    const auto &entry = nodes[idx].entry;
                    if (blockFitter.isBelowBlockMinFeeRate(
                            entry->modified_feerate)) {
                        break;
                    }
                    const uint64_t tx_size = entry->tx_size;
                    const int64_t tx_sigchecks = entry->sigchecks;
                    if (!blockFitter.testTxFits(tx_size, tx_sigchecks)) {
                        continue;
                    }
                    TxValidationState tx_state;
                    if (!ContextualCheckTransaction(*snap.consensus_params,
                                                    *entry->tx, tx_state,
                                                    tmpl.next_height,
                                                    tmpl.parent_mtp)) {
                        continue;
                    }
                    blockFitter.addTx(tx_size, tx_sigchecks, entry->fee);
                    tmpl.total_fees += entry->fee;
                    tmpl.total_sigchecks += tx_sigchecks;
                    selected.push_back(
                        {entry->tx, entry->fee, tx_sigchecks});
                    for (const size_t child : nodes[idx].children) {
                        if (nodes[child].missing_parents > 0 &&
                            --nodes[child].missing_parents == 0) {
                            ready.push(child);
                        }
                    }
                }

                std::sort(selected.begin(), selected.end(),
                          [](const SelectedEntry &a, const SelectedEntry &b) {
                              return a.tx->GetId() < b.tx->GetId();
                          });
            }

            tmpl.non_coinbase_txs.reserve(selected.size());
            tmpl.tx_fees.reserve(selected.size());
            tmpl.tx_sigchecks.reserve(selected.size());
            tmpl.tx_hex.reserve(selected.size());

            // [Patch 036 optimization] Carry forward any already-built tx_hex from
            // the previous snapshot and defer hex-encoding of new transactions
            // until EnsureTxHex() is called by getblocktemplate.
            const bool can_reuse_prev_hex =
                prev && prev->mining_template.template_valid &&
                prev->mining_template_ready &&
                prev->mining_template.non_coinbase_txs.size() ==
                    prev->mining_template.tx_hex.size();
            size_t prev_idx = 0;
            for (auto &item : selected) {
                tmpl.non_cb_serialized_size += item.tx->GetTotalSize();
                if (can_reuse_prev_hex) {
                    const auto &prev_txs =
                        prev->mining_template.non_coinbase_txs;
                    const TxId &target_id = item.tx->GetId();
                    while (prev_idx < prev_txs.size() &&
                           prev_txs[prev_idx]->GetId() < target_id) {
                        ++prev_idx;
                    }
                    if (prev_idx < prev_txs.size() &&
                        prev_txs[prev_idx].get() == item.tx.get() &&
                        !prev->mining_template.tx_hex[prev_idx].empty()) {
                        tmpl.tx_hex.push_back(
                            prev->mining_template.tx_hex[prev_idx]);
                    } else {
                        tmpl.tx_hex.emplace_back();
                    }
                } else {
                    tmpl.tx_hex.emplace_back();
                }
                tmpl.non_coinbase_txs.push_back(std::move(item.tx));
                tmpl.tx_fees.push_back(item.fee);
                tmpl.tx_sigchecks.push_back(item.sigchecks);
            }
        }
    }

    tmpl.block_reward = tmpl.total_fees + snap.next_subsidy;

    if (tmpl.non_coinbase_txs.empty() &&
        (tmpl.has_tip_utxo_snapshot || tmpl.next_height <= 1)) {
        tmpl.subtree_a_root = lotus::v2::EmptyTxRoot();
        tmpl.v2_base_state = V2TemplateBaseState{};
        tmpl.v2_base_state.utxo_root = tmpl.tip_utxo_root;
        tmpl.v2_base_state.mon_state = tmpl.tip_mon_state;
        tmpl.v2_base_state.height = uint64_t(tmpl.next_height);
        tmpl.v2_base_state.parent_mtp = uint64_t(tmpl.parent_mtp);
        tmpl.roots_ready = true;
    }

    tmpl.template_valid = true;

    snap.mining_template = std::move(tmpl);
    snap.mining_template_ready = true;
}

void InitLazyMiningTemplateStub(ChainAndMempoolSnapshot &snap,
                                const CTxMemPool &mempool_locked,
                                const ChainAndMempoolSnapshot *prev,
                                SnapshotPublisher &publisher)
    NO_THREAD_SAFETY_ANALYSIS {
    if (!snap.chain_valid || snap.height < 0 || !snap.consensus_params) {
        return;
    }
    if (prev && prev->mining_template.template_valid &&
        prev->mining_template_ready &&
        prev->mining_template.prev_block_hash == snap.best_block_hash &&
        prev->mining_template.next_height == snap.height + 1 &&
        prev->mining_template.nBits == snap.next_nBits &&
        prev->mining_template.parent_mtp == snap.mediantime &&
        prev->mempool_ptr == &mempool_locked &&
        prev->transactions_updated == snap.transactions_updated &&
        prev->mempool_size == snap.mempool_size &&
        prev->mining_template.non_coinbase_txs.size() == snap.mempool_size) {
        snap.mining_template = prev->mining_template;
        snap.mining_template_ready = true;
        return;
    }
    if (mempool_locked.mapTx.empty()) {
        PopulateMiningTemplate(snap, &mempool_locked, prev, publisher);
        return;
    }
    MiningTemplateSnapshot tmpl{};
    tmpl.template_id = publisher.AllocateTemplateId();
    tmpl.prev_block_hash = snap.best_block_hash;
    tmpl.next_height = snap.height + 1;
    tmpl.nHeaderVersion = lotus::v2::kHeaderVersion;
    if (snap.consensus_params->fPowAllowMinDifficultyBlocks) {
        tmpl.nHeaderVersion =
            gArgs.GetIntArg("-blockversion", tmpl.nHeaderVersion);
    }
    tmpl.nBits = snap.next_nBits;
    tmpl.parent_mtp = snap.mediantime;
    tmpl.min_time = snap.mediantime + 1;
    tmpl.total_fees = Amount::zero();
    tmpl.block_reward = snap.next_subsidy;
    tmpl.non_cb_serialized_size = 0;
    tmpl.total_sigchecks = 0;
    tmpl.tip_utxo_root = snap.tip_utxo_root;
    tmpl.tip_mon_state = snap.tip_mon_state;
    tmpl.has_tip_utxo_snapshot = snap.has_utxo_snapshot;
    tmpl.roots_ready = false;
    tmpl.template_valid = true;
    snap.mining_template = std::move(tmpl);
    snap.mining_template_ready = false;
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
                if (input.nFlags != 3) mempool_spent_outpoints.push_back(input.prevout);
            return true;
        });
    }
    std::sort(mempool_txids.begin(), mempool_txids.end());
    std::sort(mempool_entries.begin(), mempool_entries.end(),
              [](const auto &a, const auto &b) { return a.txid < b.txid; });
    std::sort(mempool_spent_outpoints.begin(), mempool_spent_outpoints.end());
    mempool_vectors_ready = true;
}

void ChainAndMempoolSnapshot::EnsureMiningTemplate() const
    NO_THREAD_SAFETY_ANALYSIS {
    if (!mempool_vectors_mutex) {
        return;
    }
    std::lock_guard<std::mutex> lock(*mempool_vectors_mutex);
    if (mining_template_ready || !mempool_ptr) {
        return;
    }
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    PopulateMiningTemplate(const_cast<ChainAndMempoolSnapshot &>(*this),
                           nullptr, nullptr, publisher);
    publisher.RecordMiningTemplate(mining_template);
}

const std::vector<std::string> &MiningTemplateSnapshot::EnsureTxHex() const {
    if (!tx_hex_mutex) {
        return tx_hex;
    }
    std::lock_guard<std::mutex> lock(*tx_hex_mutex);
    if (tx_hex.size() < non_coinbase_txs.size()) {
        tx_hex.resize(non_coinbase_txs.size());
    }
    for (size_t i = 0; i < non_coinbase_txs.size(); ++i) {
        if (tx_hex[i].empty() && non_coinbase_txs[i]) {
            tx_hex[i] = SerializeTxToHex(*non_coinbase_txs[i]);
        }
    }
    return tx_hex;
}

void MiningTemplateSnapshot::EnsureRoots() const {
    if (!tx_hex_mutex) {
        return;
    }
    std::lock_guard<std::mutex> lock(*tx_hex_mutex);
    if (roots_ready) {
        return;
    }
    if (non_coinbase_txs.empty()) {
        subtree_a_root = lotus::v2::EmptyTxRoot();
        if (has_tip_utxo_snapshot || next_height <= 1) {
            v2_base_state = V2TemplateBaseState{};
            v2_base_state.utxo_root = tip_utxo_root;
            v2_base_state.mon_state = tip_mon_state;
            v2_base_state.height = uint64_t(next_height);
            v2_base_state.parent_mtp = uint64_t(parent_mtp);
        } else {
            v2_base_state = BuildV2TemplateBaseState(
                non_coinbase_txs, prev_block_hash, uint64_t(next_height),
                uint64_t(parent_mtp));
        }
        roots_ready = true;
        return;
    }

    if (has_tip_utxo_snapshot &&
        (tip_utxo_root != nullptr || next_height <= 1)) {
        if (mempool_ptr != nullptr) {
            TRY_LOCK(mempool_ptr->cs, lock_mp);
            if (lock_mp && mempool_ptr->GetTransactionsUpdated() == transactions_updated &&
                mempool_ptr->size() == non_coinbase_txs.size()) {
                mempool_ptr->SyncMerklixOverlayToTip(
                    prev_block_hash, uint64_t(next_height),
                    uint64_t(parent_mtp));
                const auto &overlay =
                    mempool_ptr->GetMerklixOverlay().GetSpeculativeOverlay();
                if (overlay.GetTxCount() == non_coinbase_txs.size()) {
                    subtree_a_root = overlay.GetSubtreeARoot();
                    (void)overlay.GetUtxoRootDigest();
                    v2_base_state = V2TemplateBaseState{};
                    v2_base_state.utxo_arena =
                        std::make_shared<const lotus::v2::UtxoOverlayArena>(
                            overlay.GetUtxoArena());
                    v2_base_state.mon_state = overlay.GetBaseMonetaryState();
                    v2_base_state.non_cb_tx_count = overlay.GetTxCount();
                    v2_base_state.sum_non_cb_effective_cost =
                        overlay.GetSumNonCbEffectiveCost();
                    v2_base_state.height = uint64_t(next_height);
                    v2_base_state.parent_mtp = uint64_t(parent_mtp);
                    roots_ready = true;
                    return;
                }
            }
        }
        lotus::v2::Hash parent_id{};
        std::memcpy(parent_id.data(), prev_block_hash.begin(), 32);
        lotus::v2::MempoolOverlayLayer overlay(
            parent_id, tip_utxo_root, tip_mon_state, uint64_t(next_height),
            uint64_t(parent_mtp));
        std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> batch;
        batch.reserve(non_coinbase_txs.size());
        for (size_t i = 0; i < non_coinbase_txs.size(); ++i) {
            const int64_t fee_sats =
                i < tx_fees.size() ? tx_fees[i] / SATOSHI : 0;
            const int64_t sigchecks =
                i < tx_sigchecks.size() ? tx_sigchecks[i] : 0;
            batch.emplace_back(non_coinbase_txs[i], fee_sats, sigchecks);
        }
        AddTransactionsToOverlayBatch(overlay, batch);
        subtree_a_root = overlay.GetSubtreeARoot();
        (void)overlay.GetUtxoRootDigest();
        v2_base_state = V2TemplateBaseState{};
        v2_base_state.utxo_arena =
            std::make_shared<const lotus::v2::UtxoOverlayArena>(
                overlay.GetUtxoArena());
        v2_base_state.mon_state = overlay.GetBaseMonetaryState();
        v2_base_state.non_cb_tx_count = overlay.GetTxCount();
        v2_base_state.sum_non_cb_effective_cost =
            overlay.GetSumNonCbEffectiveCost();
        v2_base_state.height = uint64_t(next_height);
        v2_base_state.parent_mtp = uint64_t(parent_mtp);
        roots_ready = true;
        return;
    }

    std::vector<lotus::v2::TxIdentityPair> id_pairs;
    id_pairs.reserve(non_coinbase_txs.size());
    for (const auto &ptx : non_coinbase_txs) {
        lotus::v2::TxIdentityPair pair{};
        std::memcpy(pair.tx_hash.data(), ptx->GetHash().begin(), 32);
        std::memcpy(pair.tx_id.data(), ptx->GetId().begin(), 32);
        id_pairs.push_back(pair);
    }
    subtree_a_root = lotus::v2::TransactionSubtreeARoot(id_pairs);
    v2_base_state = BuildV2TemplateBaseState(
        non_coinbase_txs, prev_block_hash, uint64_t(next_height),
        uint64_t(parent_mtp));
    roots_ready = true;
}

SnapshotPublisher::SnapshotPublisher() {
    auto empty = std::allocate_shared<const ChainAndMempoolSnapshot>(
        SnapshotAllocator<ChainAndMempoolSnapshot>{});
    std::atomic_store_explicit(&m_ring[0], std::move(empty),
                               std::memory_order_release);
}

void SnapshotPublisher::Publish(
    std::shared_ptr<const ChainAndMempoolSnapshot> next) {
    if (!next) {
        return;
    }
    std::lock_guard<std::mutex> lock(m_publish_mutex);
    if (next->mining_template.template_valid && next->mining_template_ready &&
        next->mining_template.template_id > 0) {
        m_template_history[m_template_history_pos % kTemplateHistorySize] =
            next->mining_template;
        ++m_template_history_pos;
    }
    const uint64_t next_seq = m_seq.load(std::memory_order_relaxed) + 1;
    std::atomic_store_explicit(&m_ring[next_seq % kRingSize], std::move(next),
                               std::memory_order_release);
    m_seq.store(next_seq, std::memory_order_release);
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
    if (current && current->mining_template.template_valid) {
        if (template_id != 0 &&
            current->mining_template.template_id == template_id &&
            (prev_block_hash.IsNull() ||
             current->mining_template.prev_block_hash == prev_block_hash)) {
            current->EnsureMiningTemplate();
            current->mining_template.EnsureRoots();
            return current->mining_template;
        }
        if (template_id == 0 &&
            (prev_block_hash.IsNull() ||
             current->mining_template.prev_block_hash == prev_block_hash)) {
            current->EnsureMiningTemplate();
            current->mining_template.EnsureRoots();
            return current->mining_template;
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
            if (template_id != 0 && entry.template_id == template_id) {
                entry.EnsureRoots();
                return entry;
            }
            if (template_id == 0 &&
                (prev_block_hash.IsNull() ||
                 entry.prev_block_hash == prev_block_hash)) {
                entry.EnsureRoots();
                return entry;
            }
        }
    }
    if (template_id == 0 && current && current->mining_template.template_valid) {
        current->EnsureMiningTemplate();
        current->mining_template.EnsureRoots();
        return current->mining_template;
    }
    return std::nullopt;
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
    dummyHeader.SetBlockTime(tip->GetBlockTime());
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

    if (tip->nHeight == 0) {
        next->tip_utxo_root.reset();
        next->tip_mon_state = lotus::v2::GetInitialV2MonetaryState();
        next->has_utxo_snapshot = true;
    } else {
        next->tip_mon_state = lotus::v2::GetInitialV2MonetaryState();
        next->has_utxo_snapshot = GetV2BlockStateSnapshot(
            tip->GetBlockHash(), next->tip_utxo_root, next->tip_mon_state);
    }

    if (mempool) {
        LOCK(mempool->cs);
        mempool->ClearSnapshotDirty();
        mempool->SyncMerklixOverlayToTip(
            tip->GetBlockHash(), uint64_t(tip->nHeight + 1),
            uint64_t(tip->GetMedianTimePast()));
        CaptureMempoolEntriesLocked(*next, *mempool, prev.get());
        PopulateMempoolFieldsLocked(*next, *mempool, prev.get());
        PopulateMiningTemplate(*next, mempool, prev.get(), publisher);
    } else {
        PopulateMiningTemplate(*next, nullptr, prev.get(), publisher);
    }

    publisher.Publish(std::move(next));
    RecordSnapshotPublication(SnapshotKind::CHAIN_TIP, publish_start);
}

void PublishMempoolSnapshot(const CTxMemPool &mempool)
    NO_THREAD_SAFETY_ANALYSIS {
    AssertLockHeld(mempool.cs);
    if (mempool.DeferSnapshotIfActive()) {
        return;
    }
    const auto publish_start{SnapshotPublishStart()};
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    auto next = CloneChainStateOnly(prev.get());

    CaptureMempoolEntriesLocked(*next, mempool, prev.get());
    if (mempool.mapTx.size() <= 64) {
        PopulateMempoolFieldsLocked(*next, mempool, prev.get());
        PopulateMiningTemplate(*next, &mempool, prev.get(), publisher);
    } else {
        PopulateMempoolScalarsLocked(*next, mempool);
        next->mempool_vectors_ready = false;
        InitLazyMiningTemplateStub(*next, mempool, prev.get(), publisher);
    }

    publisher.Publish(std::move(next));
    RecordSnapshotPublication(SnapshotKind::MEMPOOL, publish_start);
}

void PublishMempoolUnbroadcastSnapshot(const CTxMemPool &mempool,
                                       const TxId &txid,
                                       bool unbroadcast)
    NO_THREAD_SAFETY_ANALYSIS {
    AssertLockHeld(mempool.cs);
    mempool.MarkSnapshotEntryChanged(txid);
    if (mempool.DeferSnapshotIfActive()) {
        return;
    }
    SnapshotPublisher &publisher = GetGlobalSnapshotPublisher();
    auto prev = publisher.Load();
    if (!prev || !prev->mempool_valid || prev->mempool_ptr != &mempool) {
        PublishMempoolSnapshot(mempool);
        return;
    }
    PublishMempoolSnapshot(mempool);
}

} // namespace node

