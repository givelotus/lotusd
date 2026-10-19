// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/index_tx.h>

#include <chronik/native/error.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/txs.h>

#include <algorithm>
#include <map>

namespace chronik::native::index {

std::vector<IndexTx> PrepareIndexedTxs(const KvStore &store,
                                       const ReadTxn &txn, TxNum first_tx_num,
                                       std::span<const Tx *const> txs) {
    TxNumCache cache;
    return PrepareIndexedTxsCached(store, txn, first_tx_num, txs, cache,
                                   PrepareUpdateMode::Read);
}

std::vector<IndexTx> PrepareIndexedTxs(const KvStore &store,
                                       const ReadTxn &txn, TxNum first_tx_num,
                                       const std::vector<Tx> &txs) {
    std::vector<const Tx *> ptrs;
    ptrs.reserve(txs.size());
    for (const Tx &tx : txs) {
        ptrs.push_back(&tx);
    }
    return PrepareIndexedTxs(store, txn, first_tx_num, ptrs);
}

std::vector<IndexTx> PrepareIndexedTxsCached(const KvStore &store,
                                             const ReadTxn &txn,
                                             TxNum first_tx_num,
                                             std::span<const Tx *const> txs,
                                             TxNumCache &cache,
                                             PrepareUpdateMode update_mode) {
    std::unordered_map<TxId, TxNum, Hash32Hasher> tx_nums_by_txid;
    tx_nums_by_txid.reserve(txs.size());
    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        tx_nums_by_txid.insert_or_assign(txs[tx_idx]->txid,
                                         first_tx_num + tx_idx);
    }
    // BTreeSet in Rust: sorted, deduplicated
    std::map<TxId, size_t> db_txid_idx;
    for (const Tx *tx : txs) {
        for (const TxInput &tx_input : tx->inputs) {
            const TxId &prev_txid = tx_input.prev_out.txid;
            if (tx_nums_by_txid.count(prev_txid)) {
                continue;
            }
            if (const std::optional<TxNum> tx_num = cache.Get(prev_txid)) {
                tx_nums_by_txid.emplace(prev_txid, *tx_num);
                continue;
            }
            db_txid_idx.emplace(prev_txid, 0);
        }
    }
    std::vector<TxId> db_txids;
    db_txids.reserve(db_txid_idx.size());
    for (auto &[txid, idx] : db_txid_idx) {
        idx = db_txids.size();
        db_txids.push_back(txid);
    }
    const TxReader tx_reader(store, txn);
    const std::vector<std::optional<TxNum>> db_tx_nums =
        tx_reader.TxNumsByTxids(db_txids);

    std::vector<IndexTx> index_txs;
    index_txs.reserve(txs.size());
    for (size_t tx_idx = 0; tx_idx < txs.size(); ++tx_idx) {
        const Tx *tx = txs[tx_idx];
        IndexTx index_tx;
        index_tx.tx = tx;
        index_tx.tx_num = first_tx_num + tx_idx;
        index_tx.is_coinbase = tx_idx == 0;
        if (!index_tx.is_coinbase) {
            index_tx.input_nums.reserve(tx->inputs.size());
            for (const TxInput &input : tx->inputs) {
                auto it = tx_nums_by_txid.find(input.prev_out.txid);
                if (it != tx_nums_by_txid.end()) {
                    index_tx.input_nums.push_back(it->second);
                    continue;
                }
                auto db_it = db_txid_idx.find(input.prev_out.txid);
                if (db_it == db_txid_idx.end() ||
                    !db_tx_nums[db_it->second]) {
                    throw ChronikError("Unknown input spent: " +
                                       DebugOutPoint(input.prev_out));
                }
                index_tx.input_nums.push_back(*db_tx_nums[db_it->second]);
            }
        }
        index_txs.push_back(std::move(index_tx));
    }
    switch (update_mode) {
        case PrepareUpdateMode::Add:
            cache.AddToCache(index_txs);
            break;
        case PrepareUpdateMode::Delete:
            cache.Clear();
            break;
        case PrepareUpdateMode::Read:
            break;
    }
    return index_txs;
}

TxNumCache::TxNumCache(TxNumCacheSettings settings)
    : m_num_buckets(settings.num_buckets),
      m_bucket_size(settings.bucket_size) {
    for (size_t i = 0; i < m_num_buckets; ++i) {
        Bucket bucket;
        bucket.reserve(m_bucket_size);
        m_buckets.push_back(std::move(bucket));
    }
}

void TxNumCache::AddToCache(std::span<const IndexTx> index_txs) {
    if (m_num_buckets == 0) {
        return;
    }
    for (const IndexTx &tx : index_txs) {
        // Bucket at the front is full, get a new empty one
        if (m_buckets.front().size() >= m_bucket_size) {
            // Drop off the last bucket, empty it and move it to the front
            Bucket new_bucket = std::move(m_buckets.back());
            m_buckets.pop_back();
            new_bucket.clear();
            m_buckets.push_front(std::move(new_bucket));
        }
        m_buckets.front().insert_or_assign(tx.tx->txid, tx.tx_num);
    }
}

void TxNumCache::Clear() {
    for (Bucket &bucket : m_buckets) {
        bucket.clear();
    }
}

std::optional<TxNum> TxNumCache::Get(const TxId &txid) const {
    for (const Bucket &bucket : m_buckets) {
        auto it = bucket.find(txid);
        if (it != bucket.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

} // namespace chronik::native::index
