// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_SPENT_BY_H
#define CHRONIK_NATIVE_MEM_SPENT_BY_H

#include <chronik/native/error.h>
#include <chronik/native/mem/mempool_tx.h>
#include <chronik/native/types.h>

#include <map>
#include <string>
#include <unordered_map>

/** Port of chronik-db mem/spent_by.rs. */
namespace chronik::native::mem {

/** Rust bitcoinsuite `SpentBy`: which input of which tx spent an output. */
struct SpentBy {
    /** TxId of the tx with the input. */
    TxId txid;
    /** Index in the inputs of the tx. */
    uint32_t input_idx = 0;

    bool operator==(const SpentBy &) const = default;
};

/** Rust Debug: "SpentBy { txid: TxId(<hex>), input_idx: 0 }". */
std::string DebugSpentBy(const SpentBy &spent_by);

/** Rust `MempoolSpentByError`, with its exact texts. */
class MempoolSpentByError : public ChronikError {
public:
    using ChronikError::ChronikError;
};

/** Which tx outputs have been spent by tx in the mempool. */
class MempoolSpentBy {
public:
    using Entries = std::map<uint32_t, SpentBy>;

    /**
     * Mark all the outputs spent by this tx. Fails if a spent output already
     * has been marked as spent (outputs marked before the failing input stay
     * marked, like Rust).
     */
    void Insert(const MempoolTx &tx);

    /**
     * Un-mark all the outputs spent by this tx as spent. Only to be used
     * when the tx has been added to the mempool before.
     */
    void Remove(const MempoolTx &tx);

    /** The outputs of the given tx spent by mempool txs, or nullptr. */
    const Entries *OutputsSpent(const TxId &txid) const;

    const std::unordered_map<TxId, Entries, Hash32Hasher> &All() const {
        return m_spent_by;
    }

private:
    std::unordered_map<TxId, Entries, Hash32Hasher> m_spent_by;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_SPENT_BY_H
