// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_TXS_H
#define CHRONIK_NATIVE_INDEX_TXS_H

#include <chronik/native/index/blocks.h>
#include <chronik/native/index/data.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <array>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

/**
 * Port of chronik-db io/txs.rs: txs keyed by a serial TxNum (BE8) in `tx`,
 * `blk_by_first_tx` / `first_tx_by_blk`, and the reverse index
 * `lookup_tx_by_hash` (64-bit seahash cheap hash).
 *
 * We only store the `txid`, `data_pos`, `undo_pos` and `time_first_seen`;
 * `undo_pos == 0` marks a coinbase tx.
 */
namespace chronik::native::index {

/** Entry of a tx in the DB. */
struct TxEntry {
    /** TxId of the tx. */
    TxId txid;
    /** Position of the tx data in the tx's block's block file. */
    uint32_t data_pos{};
    /** Position of the tx undo data in the tx's block's undo file. */
    uint32_t undo_pos{};
    /** When this tx has first been seen in the mempool. */
    int64_t time_first_seen{};
    /** Whether this is a coinbase tx. */
    bool is_coinbase{};
    /** Creating transaction grammar. */
    bool is_legacy{};

    bool operator==(const TxEntry &) const = default;
};

/** Tx from the DB with height (Rust `io::BlockTx`). */
struct BlockTx {
    /** Tx data. */
    TxEntry entry;
    /** Height of block of the tx. */
    BlockHeight block_height{};

    bool operator==(const BlockTx &) const = default;
};

/** Txs of a block, bundled in one struct so we can add it easily to the DB. */
struct BlockTxs {
    /** Tx data. */
    std::vector<TxEntry> txs;
    /** Height of the block of the txs. */
    BlockHeight block_height{};
};

/** Stats about cache hits, num requests etc. */
struct TxsStats {
    /** Total number of txs updated. */
    size_t n_total = 0;
    /** Time [s] for insert/delete. */
    double t_total = 0;
    /** Time [s] for indexing txs. */
    double t_index = 0;
};

/** In-memory data for the tx history. */
struct TxsMemData {
    TxsStats stats;
};

/** Serialized form of a tx in `tx` (Rust `SerTx`). */
struct SerTx {
    std::array<uint8_t, 32> txid{};
    uint32_t data_pos{};
    /** == 0 <==> is_coinbase == true */
    uint32_t undo_pos{};
    int64_t time_first_seen{};
    bool is_legacy{};

    bool operator==(const SerTx &) const = default;
};

inline constexpr std::string_view kSerTxTypeName = "chronik_db::io::txs::SerTx";

Bytes SerializeSerTx(const SerTx &tx);
SerTx DeserializeSerTx(ByteView bytes);
SerTx ToSerTx(const TxEntry &entry);
TxEntry FromSerTx(const SerTx &ser);

/** big-endian, so txs are sorted ascendingly */
std::array<uint8_t, 8> TxNumToBytes(TxNum tx_num);
TxNum BytesToTxNum(ByteView bytes);

/** Write [`BlockTxs`] to the DB. */
class TxWriter {
public:
    explicit TxWriter(const KvStore &store);

    /** Insert and index the txs into the DB. Returns the first tx_num. */
    TxNum Insert(WriteTxn &txn, const BlockTxs &block_txs,
                 TxsMemData &mem_data) const;
    /** Delete and unindex the txs from the DB. Returns the first tx_num. */
    TxNum Delete(WriteTxn &txn, const BlockTxs &block_txs,
                 TxsMemData &mem_data) const;

private:
    TableId m_tx, m_blk_by_first_tx, m_first_tx_by_blk, m_lookup;
};

/** Read [`BlockTx`]s from the DB. */
class TxReader {
public:
    TxReader(const KvStore &store, const ReadTxn &txn);

    /** Read a tx by txid, or None if not in the DB. */
    std::optional<BlockTx> TxByTxid(const TxId &txid) const;
    /** Read a [`BlockTx`] and its [`TxNum`] by [`TxId`]. */
    std::optional<std::pair<TxNum, BlockTx>>
    TxAndNumByTxid(const TxId &txid) const;
    /** Read just the [`TxNum`] of the tx by [`TxId`]. */
    std::optional<TxNum> TxNumByTxid(const TxId &txid) const;
    /** Batch-read just the [`TxNum`]s of the txs by [`TxId`]s. */
    std::vector<std::optional<TxNum>>
    TxNumsByTxids(const std::vector<TxId> &txids) const;
    /** Read the [`BlockTx`] by [`TxNum`]. */
    std::optional<BlockTx> TxByTxNum(TxNum tx_num) const;
    /** Read just the [`TxId`] of the tx by [`TxNum`]. */
    std::optional<TxId> TxidByTxNum(TxNum tx_num) const;
    /** Batched [`TxReader::TxidByTxNum`]. */
    std::vector<std::optional<TxId>>
    TxidsByTxNums(const std::vector<TxNum> &tx_nums) const;
    /** Read the first [`TxNum`] of a [`BlockHeight`]. */
    std::optional<TxNum> FirstTxNumByBlock(BlockHeight block_height) const;
    /**
     * Return the range [start, end) of [`TxNum`]s of the block, or nullopt if
     * the block doesn't exist.
     */
    std::optional<std::pair<TxNum, TxNum>>
    BlockTxNumRange(BlockHeight block_height) const;
    /** Read the last [`TxNum`] of the DB. */
    std::optional<TxNum> LastTxNum() const;
    /** Read the block height the tx_num has. Throws if not found. */
    BlockHeight BlockHeightByTxNum(TxNum tx_num) const;

private:
    std::optional<SerTx> GetTx(TxNum tx_num) const;

    const ReadTxn &m_txn;
    TableId m_tx, m_blk_by_first_tx, m_first_tx_by_blk, m_lookup;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_TXS_H
