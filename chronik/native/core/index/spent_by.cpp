// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/spent_by.h>

#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/index/merge.h>
#include <chronik/native/schema.h>

#include <algorithm>
#include <chrono>
#include <unordered_map>

namespace chronik::native::index {

namespace {

double SecondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                         start)
        .count();
}

Bytes SerTxNum(TxNum tx_num) {
    Bytes out;
    postcard::Writer(out).U64(tx_num);
    return out;
}

TxNum DeserTxNum(ByteView bytes) {
    return postcard::DbDeserialize(
        bytes, "u64", [](postcard::Reader &r) { return r.U64(); });
}

/** Binary search by out_idx: (found, index) like Rust binary_search_by_key. */
std::pair<bool, size_t> SearchOutIdx(const std::vector<SpentByEntry> &entries,
                                     uint32_t out_idx) {
    auto it = std::lower_bound(entries.begin(), entries.end(), out_idx,
                               [](const SpentByEntry &entry, uint32_t idx) {
                                   return entry.out_idx < idx;
                               });
    const size_t pos = size_t(it - entries.begin());
    return {it != entries.end() && it->out_idx == out_idx, pos};
}

} // namespace

std::string DebugSpentByEntry(const SpentByEntry &entry) {
    return "SpentByEntry { out_idx: " + std::to_string(entry.out_idx) +
           ", tx_num: " + std::to_string(entry.tx_num) +
           ", input_idx: " + std::to_string(entry.input_idx) + " }";
}

Bytes SerializeSpentByEntries(std::span<const SpentByEntry> entries) {
    Bytes out;
    postcard::Writer w(out);
    for (const SpentByEntry &entry : entries) {
        w.U32(entry.out_idx);
        w.U64(entry.tx_num);
        w.U32(entry.input_idx);
    }
    return out;
}

std::vector<SpentByEntry> DeserializeSpentByEntries(ByteView bytes) {
    return postcard::DbDeserializeVec(
        bytes, kSpentByEntryTypeName, [](postcard::Reader &r) {
            SpentByEntry entry;
            entry.out_idx = r.U32();
            entry.tx_num = r.U64();
            entry.input_idx = r.U32();
            return entry;
        });
}

SpentByWriter::SpentByWriter(const KvStore &store)
    : m_cf(store.Table(schema::kSpentBy)) {}

void SpentByWriter::Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                           SpentByMemData &mem_data) const {
    SpentByStats &stats = mem_data.stats;
    const auto t_start = std::chrono::steady_clock::now();
    stats.n_total += txs.size();
    std::unordered_map<TxNum, std::vector<SpentByEntry>> spent_by_map;
    for (const IndexTx &tx : txs) {
        if (tx.is_coinbase) {
            // a coinbase doesn't spend anything
            continue;
        }
        const size_t n = std::min(tx.tx->inputs.size(), tx.input_nums.size());
        for (size_t input_idx = 0; input_idx < n; ++input_idx) {
            const SpentByEntry spent_by{
                tx.tx->inputs[input_idx].prev_out.out_idx,
                tx.tx_num,
                uint32_t(input_idx),
            };
            spent_by_map[tx.input_nums[input_idx]].push_back(spent_by);
        }
    }
    for (const auto &[tx_num, entries] : spent_by_map) {
        const Bytes operand = SerializeSpentByEntries(entries);
        merge::CatchMergeErrors(
            txn, m_cf, SerTxNum(tx_num), std::span<const Bytes>(&operand, 1),
            // init_merge_spent_by
            [](ByteView, std::optional<ByteView> existing, size_t) {
                return existing ? DeserializeSpentByEntries(*existing)
                                : std::vector<SpentByEntry>{};
            },
            // apply_merge_spent_by
            [](ByteView key, std::vector<SpentByEntry> &entries,
               ByteView operand) {
                const std::vector<SpentByEntry> extra_entries =
                    DeserializeSpentByEntries(operand);
                entries.reserve(entries.size() + extra_entries.size());
                for (const SpentByEntry &spent_by : extra_entries) {
                    const auto [found, idx] =
                        SearchOutIdx(entries, spent_by.out_idx);
                    if (found) {
                        const TxNum input_tx_num = DeserTxNum(key);
                        // Output already spent by another tx -> corrupted DB?
                        throw ChronikError(
                            "Inconsistent DB: Duplicate spend by entry for "
                            "tx_num = " +
                            std::to_string(input_tx_num) + ": " +
                            DebugSpentByEntry(entries[idx]) +
                            " already exists, but tried to add " +
                            DebugSpentByEntry(spent_by));
                    }
                    // No entry found -> insert it
                    entries.insert(entries.begin() + idx, spent_by);
                }
            },
            // ser_merge_spent_by
            [](ByteView, std::vector<SpentByEntry> &&entries) {
                return SerializeSpentByEntries(entries);
            });
    }
    stats.t_total += SecondsSince(t_start);
}

void SpentByWriter::Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                           SpentByMemData &mem_data) const {
    SpentByStats &stats = mem_data.stats;
    const auto t_start = std::chrono::steady_clock::now();
    stats.n_total += txs.size();
    std::unordered_map<TxNum, std::vector<SpentByEntry>> spent_by_map;
    for (const IndexTx &tx : txs) {
        if (tx.is_coinbase) {
            // a coinbase doesn't spend anything
            continue;
        }
        const size_t n = std::min(tx.tx->inputs.size(), tx.input_nums.size());
        for (size_t input_idx = 0; input_idx < n; ++input_idx) {
            const TxNum input_tx_num = tx.input_nums[input_idx];
            const SpentByEntry spent_by{
                tx.tx->inputs[input_idx].prev_out.out_idx,
                tx.tx_num,
                uint32_t(input_idx),
            };
            const auto t_fetch = std::chrono::steady_clock::now();
            auto it = spent_by_map.find(input_tx_num);
            if (it == spent_by_map.end()) {
                std::vector<SpentByEntry> db_entries;
                if (const std::optional<ByteView> data =
                        txn.Get(m_cf, SerTxNum(input_tx_num))) {
                    db_entries = DeserializeSpentByEntries(*data);
                }
                it = spent_by_map.emplace(input_tx_num, std::move(db_entries))
                         .first;
            }
            stats.t_fetch += SecondsSince(t_fetch);
            std::vector<SpentByEntry> &spent_by_entries = it->second;
            const auto [found, idx] =
                SearchOutIdx(spent_by_entries, spent_by.out_idx);
            if (!found) {
                // Spent-by entry not found, but should be there.
                throw ChronikError(
                    "Inconsistent DB: Missing spend by entry for tx_num = " +
                    std::to_string(input_tx_num) + ": Expected " +
                    DebugSpentByEntry(spent_by) +
                    " to be present, but none found");
            }
            // Found the spent-by entry -> remove it.
            if (spent_by_entries[idx] != spent_by) {
                // Existing entry doesn't match what's in the DB.
                throw ChronikError(
                    "Inconsistent DB: Mismatched spend by entry for tx_num = " +
                    std::to_string(input_tx_num) + ": Expected " +
                    DebugSpentByEntry(spent_by) + " to be present, but got " +
                    DebugSpentByEntry(spent_by_entries[idx]));
            }
            spent_by_entries.erase(spent_by_entries.begin() + idx);
        }
    }
    for (const auto &[tx_num, entries] : spent_by_map) {
        const Bytes ser_num = SerTxNum(tx_num);
        if (entries.empty()) {
            txn.Del(m_cf, ser_num);
        } else {
            txn.Put(m_cf, ser_num, SerializeSpentByEntries(entries));
        }
    }
    stats.t_total += SecondsSince(t_start);
}

SpentByReader::SpentByReader(const KvStore &store, const ReadTxn &txn)
    : m_txn(txn), m_cf(store.Table(schema::kSpentBy)) {}

std::optional<std::vector<SpentByEntry>>
SpentByReader::ByTxNum(TxNum tx_num) const {
    const std::optional<ByteView> data = m_txn.Get(m_cf, SerTxNum(tx_num));
    if (!data) {
        return std::nullopt;
    }
    return DeserializeSpentByEntries(*data);
}

} // namespace chronik::native::index
