// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TX_LEGACY_TX_H
#define CHRONIK_NATIVE_TX_LEGACY_TX_H

#include <chronik/native/types.h>

#include <optional>
#include <string>

namespace chronik::native {

/**
 * Port of bitcoinsuite-core's BitcoinSer for TxMut: the legacy Bitcoin
 * transaction wire format (version, inputs, outputs, locktime), as used by
 * ABC/eCash, BCHN and Doged. Hosts with this format use it to decode
 * broadcast/validate requests with exactly the Rust Chronik error texts.
 */
struct LegacyTxDecodeResult {
    /** DataError Display text, e.g. "Invalid length, expected 4 bytes but
     * got 0 bytes"; nullopt on success. */
    std::optional<std::string> error;
    /** Decoded tx; txid is NOT set (hosts compute it), coins unresolved. */
    Tx tx;
    /** Bytes consumed. Like Rust, trailing bytes are not an error. */
    size_t consumed{};
};

LegacyTxDecodeResult DecodeLegacyTx(ByteView raw);

/** Serialize the tx fields (ignores txid, raw, wire_size). */
Bytes SerializeLegacyTx(const Tx &tx);

void WriteCompactSize(Bytes &out, uint64_t size);
size_t CompactSizeLen(uint64_t size);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_TX_LEGACY_TX_H
