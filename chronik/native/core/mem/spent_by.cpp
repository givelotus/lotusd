// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/mem/spent_by.h>

#include <chronik/native/index/debug_fmt.h>

namespace chronik::native::mem {

std::string DebugSpentBy(const SpentBy &spent_by) {
    return "SpentBy { txid: " + index::DebugTxId(spent_by.txid) +
           ", input_idx: " + std::to_string(spent_by.input_idx) + " }";
}

void MempoolSpentBy::Insert(const MempoolTx &tx) {
    const std::vector<TxInput> &inputs = tx.tx->inputs;
    for (size_t input_idx = 0; input_idx < inputs.size(); ++input_idx) {
        const OutPoint &prev_out = inputs[input_idx].prev_out;
        Entries &entries = m_spent_by[prev_out.txid];
        const SpentBy new_entry{tx.tx->txid, uint32_t(input_idx)};
        const auto [it, inserted] =
            entries.emplace(prev_out.out_idx, new_entry);
        if (!inserted) {
            throw MempoolSpentByError(
                "Inconsistent mempool: Duplicate spend by entry for " +
                index::DebugOutPoint(prev_out) + ": " +
                DebugSpentBy(it->second) +
                " already exists, but tried to add " +
                DebugSpentBy(new_entry));
        }
    }
}

void MempoolSpentBy::Remove(const MempoolTx &tx) {
    const std::vector<TxInput> &inputs = tx.tx->inputs;
    for (size_t input_idx = 0; input_idx < inputs.size(); ++input_idx) {
        const OutPoint spent_outpoint = inputs[input_idx].prev_out;
        // Like Rust's entry().or_default(), this creates an (empty) entry
        // even if the removal fails.
        Entries &entries = m_spent_by[spent_outpoint.txid];
        const SpentBy removed_entry{tx.tx->txid, uint32_t(input_idx)};
        const auto it = entries.find(spent_outpoint.out_idx);
        if (it == entries.end()) {
            throw MempoolSpentByError(
                "Inconsistent mempool: Missing spend by entry for " +
                index::DebugOutPoint(spent_outpoint) + ": Expected " +
                DebugSpentBy(removed_entry) +
                " to be present, but none found");
        }
        if (it->second != removed_entry) {
            throw MempoolSpentByError(
                "Inconsistent mempool: Mismatched spent-by entry for " +
                index::DebugOutPoint(spent_outpoint) + ": Expected " +
                DebugSpentBy(removed_entry) + " to be present, but got " +
                DebugSpentBy(it->second));
        }
        entries.erase(it);
        if (entries.empty()) {
            m_spent_by.erase(spent_outpoint.txid);
        }
    }
}

const MempoolSpentBy::Entries *
MempoolSpentBy::OutputsSpent(const TxId &txid) const {
    const auto it = m_spent_by.find(txid);
    return it == m_spent_by.end() ? nullptr : &it->second;
}

} // namespace chronik::native::mem
