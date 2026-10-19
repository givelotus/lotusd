// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_BLOCK_STATS_H
#define CHRONIK_NATIVE_INDEX_BLOCK_STATS_H

#include <chronik/native/index/blocks.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>

#include <cstdint>
#include <optional>
#include <span>

/** Port of chronik-db io/block_stats.rs: the `blk_stats` table. */
namespace chronik::native::index {

/** Statistics about a block, like num txs, block size, etc. */
struct BlockStats {
    /** Block size of this block in bytes (including headers etc.) */
    uint64_t block_size{};
    /** Number of txs in this block */
    uint64_t num_txs{};
    /** Total number of tx inputs in block (including coinbase) */
    uint64_t num_inputs{};
    /** Total number of tx output in block (including coinbase) */
    uint64_t num_outputs{};
    /** Total number of satoshis spent by tx inputs */
    int64_t sum_input_sats{};
    /** Block reward for this block */
    int64_t sum_coinbase_output_sats{};
    /** Total number of satoshis in non-coinbase tx outputs */
    int64_t sum_normal_output_sats{};
    /** Total number of satoshis burned using OP_RETURN */
    int64_t sum_burned_sats{};

    bool operator==(const BlockStats &) const = default;
};

inline constexpr std::string_view kBlockStatsTypeName =
    "chronik_db::io::block_stats::BlockStats";

Bytes SerializeBlockStats(const BlockStats &stats);
BlockStats DeserializeBlockStats(ByteView bytes);

/** Write [`BlockStats`] to the DB. */
class BlockStatsWriter {
public:
    explicit BlockStatsWriter(const KvStore &store);

    /**
     * Measure the [`BlockStats`] of the block with the given the block txs
     * and add them to the txn.
     */
    void Insert(WriteTxn &txn, BlockHeight block_height, uint64_t block_size,
                std::span<const IndexTx> txs) const;
    /** Delete the block stats for the block with the given height. */
    void Delete(WriteTxn &txn, BlockHeight block_height) const;

private:
    TableId m_cf;
};

/** Read [`BlockStats`] from the DB. */
class BlockStatsReader {
public:
    BlockStatsReader(const KvStore &store, const ReadTxn &txn);

    /** The [`BlockStats`], or nullopt if the block doesn't exist. */
    std::optional<BlockStats> ByHeight(BlockHeight block_height) const;

private:
    const ReadTxn &m_txn;
    TableId m_cf;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_BLOCK_STATS_H
