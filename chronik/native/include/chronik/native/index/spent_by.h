// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_SPENT_BY_H
#define CHRONIK_NATIVE_INDEX_SPENT_BY_H

#include <chronik/native/index/data.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>

#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

/**
 * Port of chronik-db io/spent_by.rs: which outputs of a tx have been spent by
 * which tx (and input).
 *
 * For each tx that has any output spent, there is a list of entries, sorted
 * by out_idx, at key postcard(tx_num) (a varint, more compact than TxWriter's
 * big-endian keys; no ordering is relied upon). Entries are concatenated
 * postcard SpentByEntry values.
 */
namespace chronik::native::index {

/**
 * Indicates an output has been spent by an input in a tx.
 * This is an entry in the list of spent outputs of a tx.
 */
struct SpentByEntry {
    /** Which output has been spent. */
    uint32_t out_idx{};
    /** Which tx spent the output. */
    TxNum tx_num{};
    /** Which input of the spending tx spent the output. */
    uint32_t input_idx{};

    auto operator<=>(const SpentByEntry &) const = default;
};

inline constexpr std::string_view kSpentByEntryTypeName =
    "chronik_db::io::spent_by::SpentByEntry";

/** Rust Debug of a SpentByEntry. */
std::string DebugSpentByEntry(const SpentByEntry &entry);
Bytes SerializeSpentByEntries(std::span<const SpentByEntry> entries);
std::vector<SpentByEntry> DeserializeSpentByEntries(ByteView bytes);

/** Stats about cache hits, num requests etc. */
struct SpentByStats {
    /** Total number of txs updated. */
    size_t n_total = 0;
    /** Time [s] for insert/delete. */
    double t_total = 0;
    /** Time [s] for fetching txs. */
    double t_fetch = 0;
};

/** In-memory data for spent-by data. */
struct SpentByMemData {
    SpentByStats stats;
};

/**
 * Write to the DB which outputs of a tx have been spent by which tx (and
 * input).
 */
class SpentByWriter {
public:
    explicit SpentByWriter(const KvStore &store);

    /**
     * Add spent-by entries to txs spent in the txs (Rust: merge_cf, one
     * operand per spent tx).
     */
    void Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                SpentByMemData &mem_data) const;
    /** Remove spent-by entries from txs spent in the txs. */
    void Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                SpentByMemData &mem_data) const;

private:
    TableId m_cf;
};

/**
 * Read from the DB which outputs of a tx have been spent by which tx (and
 * input).
 */
class SpentByReader {
public:
    SpentByReader(const KvStore &store, const ReadTxn &txn);

    /** Query the spent-by entries by [`TxNum`]. */
    std::optional<std::vector<SpentByEntry>> ByTxNum(TxNum tx_num) const;

private:
    const ReadTxn &m_txn;
    TableId m_cf;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_SPENT_BY_H
