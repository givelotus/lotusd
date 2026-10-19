// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_DEBUG_FMT_H
#define CHRONIK_NATIVE_INDEX_DEBUG_FMT_H

#include <chronik/native/codec/hex.h>
#include <chronik/native/types.h>

#include <string>

/**
 * Rust `{:?}` (Debug) renderings used inside the index error messages, so the
 * texts match the Rust Chronik byte-for-byte.
 */
namespace chronik::native::index {

/** Debug of a Vec<u8>, e.g. "[0, 0, 255]". */
inline std::string DebugByteVec(ByteView bytes) {
    std::string out = "[";
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
            out += ", ";
        }
        out += std::to_string(bytes[i]);
    }
    out += "]";
    return out;
}

/** Debug of a bitcoinsuite TxId: "TxId(<display hex>)". */
inline std::string DebugTxId(const TxId &txid) {
    return "TxId(" + HashToHex(txid) + ")";
}

/** Debug of a bitcoinsuite OutPoint. */
inline std::string DebugOutPoint(const OutPoint &outpoint) {
    return "OutPoint { txid: " + DebugTxId(outpoint.txid) +
           ", out_idx: " + std::to_string(outpoint.out_idx) + " }";
}

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_DEBUG_FMT_H
