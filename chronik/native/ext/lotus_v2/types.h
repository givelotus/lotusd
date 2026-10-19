// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_TYPES_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_TYPES_H

#include <chronik/native/types.h>

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Lossless public Lotus V2 indexing records, separate from legacy
 * transactions: port of bitcoinsuite-core/src/lotus_v2.rs (V2 tier).
 *
 * Wire order is the native byte order: hashes are never reversed. The output
 * codec follows src/lotus_v2/output.{h,cpp}. No transaction codec, identity
 * computation, contextual validation or ownership inference is implied.
 */
namespace chronik::native::lotus_v2 {

/** A 32-byte commitment in V2 wire order (no display-endian conversion). */
using Hash32 = native::Hash32;

/** V2 transaction identifier; distinct from the full-serialization hash. */
struct TxId {
    Hash32 hash;
    auto operator<=>(const TxId &) const = default;
};

/** V2 full transaction hash (accepted witness variant identity). */
struct TxHash {
    Hash32 hash;
    auto operator<=>(const TxHash &) const = default;
};

/** An output reference uses TxID, never TxHash. */
struct OutPoint {
    TxId txid;
    uint32_t out_idx = 0;
    auto operator<=>(const OutPoint &) const = default;
};

/** Hard native framing bound, independent of stricter deployment profiles. */
inline constexpr size_t MAX_OUTPUT_BYTES = 812;
/** Maximum branches and paths in the native output grammar. */
inline constexpr size_t MAX_OUTPUT_BRANCHES = 16;

/** A stable native output framing/structural error category (OutputError). */
struct OutputError {
    std::string_view category;
    bool operator==(const OutputError &) const = default;
    /** "invalid Lotus V2 output: <category>" (Rust Display). */
    std::string Message() const;
};

/**
 * Native public output fields. Branch positions are vector indices (0..16),
 * not hidden leaf positions. Root matches establish neither ownership nor
 * spendability; burns also carry public roots.
 */
struct Output {
    /** Bit 0: token; bit 1: burn. All other bits must be zero. */
    uint8_t flags = 0;
    /** Unsigned native/token quantity, including the full u64 range. */
    uint64_t value = 0;
    /** Nonzero exactly when the token flag is set; otherwise all zero. */
    Hash32 token_id;
    /** Complete ordered, distinct public authorization roots. */
    std::vector<Hash32> branches;
    /** Lexicographically ordered paths of strictly increasing indices. */
    std::vector<std::vector<uint8_t>> paths;

    bool operator==(const Output &) const = default;

    bool HasToken() const { return (flags & 1) != 0; }
    /** Whether this is a burn commitment (excluded from UTXOs). */
    bool IsBurn() const { return (flags & 2) != 0; }

    /** Check native output structure only (no coin or script validation). */
    std::optional<OutputError> Validate() const;
    /** Encode a canonical native output frame after structural checks. */
    std::optional<Bytes> Encode(OutputError *error = nullptr) const;
    /**
     * Decode exactly one native frame, rejecting trailing bytes and
     * allocating only after count bounds and available bytes are checked.
     */
    static std::optional<Output> Decode(ByteView bytes,
                                        OutputError *error = nullptr);
};

/**
 * A revealed branch witness. Siblings prove unordered membership, not a
 * hidden leaf position, tree size or uniqueness.
 */
struct BranchWitness {
    Bytes script;
    std::vector<Hash32> siblings;
    std::vector<Bytes> arguments;
    bool operator==(const BranchWitness &) const = default;
};

/** Native transaction input, retaining framing distinctions losslessly. */
struct Input {
    OutPoint prev_out;
    uint32_t sequence = 0;
    /** Native discriminator: 1 spend, 2 coinbase, 3 mint. */
    uint8_t flags = 0;
    /** Selected public output path (meaningful only for spends). */
    uint8_t path_index = 0;
    std::vector<BranchWitness> witnesses;
    /** Presence is distinct from a present empty coinbase payload. */
    std::optional<Bytes> coinbase_data;
    bool operator==(const Input &) const = default;
};

/** Native transaction fields; callers must perform profile/context checks. */
struct Transaction {
    uint64_t lock = 0;
    std::vector<Input> inputs;
    std::vector<Output> outputs;
    bool operator==(const Transaction &) const = default;
};

/** Authoritative confirmed transaction location, bound to a block. */
struct TxLocation {
    /** Native block ID in wire order. */
    Hash32 block_id;
    uint64_t height = 0;
    uint32_t tx_index = 0;
    /** Merkleized transaction ID. */
    TxId txid;
    /** Full transaction hash of the accepted variant. */
    TxHash txhash;
    bool operator==(const TxLocation &) const = default;
};

/** A recorded consumption of an indexed output. */
struct SpendLocation {
    TxLocation transaction;
    uint32_t input_index = 0;
    bool operator==(const SpendLocation &) const = default;
};

/**
 * Complete confirmed output record; no pending state is inferred. Burns
 * belong in creation history, never the UTXO set.
 */
struct OutputRecord {
    OutPoint outpoint;
    Output output;
    TxLocation creation;
    std::optional<SpendLocation> spend;
    bool operator==(const OutputRecord &) const = default;
};

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_TYPES_H
