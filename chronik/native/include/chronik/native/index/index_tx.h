// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_INDEX_TX_H
#define CHRONIK_NATIVE_INDEX_INDEX_TX_H

#include <chronik/native/index/data.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <cstddef>
#include <deque>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

/** Port of chronik-db index_tx.rs: [`IndexTx`] and [`PrepareIndexedTxs`]. */
namespace chronik::native::index {

/**
 * Tx in a block to be added to the index, with prepared data to guide
 * indexing.
 */
struct IndexTx {
    /** Tx from the node to be indexed. */
    const Tx *tx = nullptr;
    /** [`TxNum`] of this tx. */
    TxNum tx_num{};
    /** Whether this tx is a coinbase tx. */
    bool is_coinbase{};
    /**
     * [`TxNum`]s of the inputs of the tx. Either references tx from the DB or
     * other txs within the new block. Empty for coinbase txs.
     */
    std::vector<TxNum> input_nums;

    bool operator==(const IndexTx &other) const {
        return tx == other.tx && tx_num == other.tx_num &&
               is_coinbase == other.is_coinbase &&
               input_nums == other.input_nums;
    }
};

/** Params for tuning the TxNumCache. */
struct TxNumCacheSettings {
    /** How many buckets are on the belt */
    size_t num_buckets = 0;
    /** How many txs are cached in each bucket */
    size_t bucket_size = 0;
};

/**
 * Cache for tx nums to speed up PrepareIndexedTxsCached.
 *
 * It works by having an internal "conveyor belt" of buckets, and each block
 * puts all their TxId -> TxNum tuples into the bucket at the front of the
 * belt, one-by-one. If this bucket is full, the bucket at the end of the belt
 * is "dropped off", emptied and moved to the front, moving all other buckets
 * one step back. Then the new empty bucket will be filled, until it is full,
 * etc.
 *
 * When querying the cache, buckets are looked into one-by-one in the order on
 * the belt.
 *
 * On a reorg, all buckets are simply cleared, as the goal is to speed up
 * initial sync.
 */
class TxNumCache {
public:
    using Bucket = std::unordered_map<TxId, TxNum, Hash32Hasher>;

    TxNumCache() = default;
    /** Will allocate all the needed memory up-front. */
    explicit TxNumCache(TxNumCacheSettings settings);

    void AddToCache(std::span<const IndexTx> index_txs);
    void Clear();
    std::optional<TxNum> Get(const TxId &txid) const;

    /** The buckets, front of the belt first (for tests). */
    const std::deque<Bucket> &Buckets() const { return m_buckets; }

private:
    size_t m_num_buckets = 0;
    size_t m_bucket_size = 0;
    std::deque<Bucket> m_buckets;
};

/**
 * Update mode of [`PrepareIndexedTxsCached`], to ensure the cache is updated
 * correctly.
 */
enum class PrepareUpdateMode {
    /** Txs are being added to the DB, will add them to the cache */
    Add,
    /** Txs are being removed from the DB, will clear the cache */
    Delete,
    /** Txs are only read from the DB, won't update the cache */
    Read,
};

/**
 * Prepare txs of a block which is about to be added/removed from the DB with
 * some additional data, either coming from the DB (through `txn`) or from
 * within the block. Uses the provided [`TxNumCache`], and puts the new TxNums
 * into it.
 *
 * Throws "Unknown input spent: <OutPoint Debug>" if an input references a
 * txid which can neither be found in the DB nor within the new block.
 */
std::vector<IndexTx> PrepareIndexedTxsCached(const KvStore &store,
                                             const ReadTxn &txn,
                                             TxNum first_tx_num,
                                             std::span<const Tx *const> txs,
                                             TxNumCache &cache,
                                             PrepareUpdateMode update_mode);

/** Like [`PrepareIndexedTxsCached`], but with the cache disabled. */
std::vector<IndexTx> PrepareIndexedTxs(const KvStore &store,
                                       const ReadTxn &txn, TxNum first_tx_num,
                                       std::span<const Tx *const> txs);

/** Convenience overload for a vector of txs (tests). */
std::vector<IndexTx> PrepareIndexedTxs(const KvStore &store,
                                       const ReadTxn &txn, TxNum first_tx_num,
                                       const std::vector<Tx> &txs);

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_INDEX_TX_H
