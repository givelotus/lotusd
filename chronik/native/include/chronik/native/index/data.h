// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_DATA_H
#define CHRONIK_NATIVE_INDEX_DATA_H

#include <compare>
#include <cstdint>
#include <string>

/** Port of chronik-db data.rs: data structs for the DB. */
namespace chronik::native::index {

/**
 * Number that uniquely identifies a tx in the blockchain, in block order
 * (txs.rs TxNum).
 */
using TxNum = uint64_t;

/** Outpoint in the DB, but with [`TxNum`] instead of `TxId` for the txid. */
struct DbOutpoint {
    /** [`TxNum`] of tx of the outpoint. */
    TxNum tx_num{};
    /** Output of the tx referenced by the outpoint. */
    uint32_t out_idx{};

    auto operator<=>(const DbOutpoint &) const = default;
};

/** Rust Debug: "DbOutpoint { tx_num: 1, out_idx: 2 }". */
inline std::string DebugDbOutpoint(const DbOutpoint &outpoint) {
    return "DbOutpoint { tx_num: " + std::to_string(outpoint.tx_num) +
           ", out_idx: " + std::to_string(outpoint.out_idx) + " }";
}

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_DATA_H
