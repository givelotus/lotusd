// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_MODEL_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_MODEL_H

#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <ext/lotus_v2/types.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Plain records of the Lotus V2 confirmed index (the `v2_index` env), ports
 * of chronik-db/src/v2_branch.rs, v2_explorer.rs and v2_asset.rs, with their
 * postcard encodings. Every encoding is byte-identical to Rust, since the
 * env is shared with (and dump-diffed against) the Rust Chronik.
 */
namespace chronik::native::lotus_v2 {

using Bytes32 = std::array<uint8_t, 32>;

/** Schema cannot share a legacy Chronik database directory. */
inline constexpr uint32_t SCHEMA_VERSION = 3;
/**
 * Shortest V2 transaction: the native codec rejects anything shorter (a
 * 16-byte header and at least one input).
 */
inline constexpr size_t MIN_TX_WIRE_BYTES = 58;
/** Shortest V2 transaction header (version, lock, input/output counts). */
inline constexpr size_t MIN_TX_HEADER_WIRE_BYTES = 16;
/** Shortest V2 input (a coinbase input without data). */
inline constexpr size_t MIN_INPUT_WIRE_BYTES = 42;
/** Shortest V2 spend input (no witnesses). */
inline constexpr size_t MIN_SPEND_WIRE_BYTES = 43;
/** Shortest V2 output. */
inline constexpr size_t MIN_OUTPUT_WIRE_BYTES = 43;
/** Shortest V2 branch witness. */
inline constexpr size_t MIN_WITNESS_WIRE_BYTES = 3;
/**
 * Staging reserved per wire byte of a block. Every per-element reservation
 * of a connect (branch.h, explorer.h), charged to the shortest wire encoding
 * of its element, stays within it (staging_covers_shortest_encodings test).
 */
inline constexpr size_t STAGING_PER_WIRE_BYTE = 1024;
/** Staging reserved once per block (framing, checkpoint, header facts). */
inline constexpr size_t STAGING_PER_BLOCK = 64 * 1024;

/**
 * v2_branch::Error. what() is the Rust Display text:
 *   Db       "V2 database: mdbx storage error: <detail>"
 *   Invalid  "invalid V2 index transition: <detail>"
 *   Corrupt  "corrupt V2 index encoding"
 */
class V2Error : public ChronikError {
public:
    enum class Kind { Db, Invalid, Corrupt };

    static V2Error Db(const std::string &detail) {
        return V2Error(Kind::Db, detail,
                       "V2 database: mdbx storage error: " + detail);
    }
    static V2Error Invalid(std::string_view detail) {
        return V2Error(Kind::Invalid, std::string(detail),
                       "invalid V2 index transition: " + std::string(detail));
    }
    static V2Error Corrupt() {
        return V2Error(Kind::Corrupt, "", "corrupt V2 index encoding");
    }

    Kind kind() const { return m_kind; }
    /** MdbxError text (Db) or the static reason (Invalid); empty if Corrupt. */
    const std::string &detail() const { return m_detail; }
    bool IsInvalid(std::string_view detail) const {
        return m_kind == Kind::Invalid && m_detail == detail;
    }

private:
    V2Error(Kind kind, std::string detail, const std::string &msg)
        : ChronikError(msg), m_kind(kind), m_detail(std::move(detail)) {}

    Kind m_kind;
    std::string m_detail;
};

[[noreturn]] inline void ThrowInvalid(std::string_view detail) {
    throw V2Error::Invalid(detail);
}
[[noreturn]] inline void ThrowCorrupt() { throw V2Error::Corrupt(); }

/**
 * Size bounds of the index (v2_branch::Bounds), derived from the consensus
 * block-size limit (the largest valid block's wire bytes). A block within
 * that limit always fits them: its transaction count, its created and
 * consumed outputs and the staging reserved for it are all bounded by its
 * wire bytes. The memory of one connect is linear in the block's size.
 */
class Bounds {
public:
    /** Largest supported block-size limit (hosts pass it in 32 bits). */
    static constexpr uint64_t MAX_BLOCK_BYTES = UINT32_MAX;

    /** Bounds for blocks of at most `max_block_bytes` wire bytes. */
    explicit Bounds(uint64_t max_block_bytes) {
        if (max_block_bytes == 0 || max_block_bytes > MAX_BLOCK_BYTES) {
            ThrowInvalid("block size limit");
        }
        m_block_bytes = size_t(max_block_bytes);
    }
    /** Consensus block-size limit in wire bytes. */
    size_t BlockBytes() const { return m_block_bytes; }
    /** Most transactions a block within the limit can hold. */
    size_t Transactions() const { return m_block_bytes / MIN_TX_WIRE_BYTES; }
    /** Most created plus consumed outputs such a block can hold. */
    size_t Changes() const { return m_block_bytes / MIN_INPUT_WIRE_BYTES; }
    /**
     * Bound on the staging reserved for one block within the limit, and on
     * its receipt, undo and write batch.
     */
    size_t BatchBytes() const {
        return m_block_bytes * STAGING_PER_WIRE_BYTE + STAGING_PER_BLOCK;
    }
    bool operator==(const Bounds &) const = default;

private:
    size_t m_block_bytes;
};

/** Immutable deployment binding; all bytes are native V2 wire order. */
struct Binding {
    Bytes32 chain_id{};
    Bytes32 genesis{};
    Bytes32 profile{};
    bool operator==(const Binding &) const = default;
};

/** Confirmed checkpoint, including the explicitly indexed genesis. */
struct Anchor {
    Bytes32 block_id{};
    uint64_t height = 0;
    bool operator==(const Anchor &) const = default;
};

/** Payload or native framed-table byte interval in the exact transaction. */
struct WireRange {
    uint64_t offset = 0;
    uint64_t length = 0;
    bool operator==(const WireRange &) const = default;
    /** Throws Invalid("explorer wire range") on overflow or out of frame. */
    void Validate(uint64_t wire_size) const;
};

/** One native public witness, represented without large inline vectors. */
struct WitnessFact {
    WireRange script;
    WireRange siblings_table;
    uint32_t siblings_count = 0;
    WireRange arguments_table;
    uint32_t arguments_count = 0;
    bool operator==(const WitnessFact &) const = default;
};

/** Immutable creation fact resolved by the single DB owner before a spend. */
struct ResolvedCreation {
    OutPoint outpoint;
    Output output;
    TxLocation creation;
    bool operator==(const ResolvedCreation &) const = default;
};

struct InputMeta;

/** Complete native input facts; selectors retain their raw meaning by flags. */
struct InputFact {
    Bytes32 prev_txid{};
    uint32_t prev_index = 0;
    uint32_t sequence = 0;
    uint8_t flags = 0;
    uint8_t path_index = 0;
    bool has_coinbase_data = false;
    WireRange coinbase_data;
    std::vector<WitnessFact> witnesses;
    std::optional<ResolvedCreation> resolved_creation;
    bool operator==(const InputFact &) const = default;
    /** Bounded persisted descriptor. */
    InputMeta Metadata() const;
};

/** Required native transaction frame, never reconstructed from records. */
struct ExplorerTxFacts {
    Bytes wire;
    uint64_t lock = 0;
    std::vector<InputFact> inputs;
    bool operator==(const ExplorerTxFacts &) const = default;
};

/** Native header length. */
inline constexpr size_t HEADER_BYTES = 134;
using HeaderWire = std::array<uint8_t, HEADER_BYTES>;

/** Exact authenticated native header (genesis keeps a zero predecessor). */
struct ExplorerBlockFacts {
    HeaderWire header_wire{};
    bool operator==(const ExplorerBlockFacts &) const = default;
};

/**
 * Fixed transaction metadata with a compact (file_num, data_pos, wire_size)
 * pointer into the append-only flat segment file (v2_tx_NNNNN.dat).
 */
struct TxMeta {
    TxLocation location;
    uint64_t lock = 0;
    uint32_t input_count = 0;
    uint32_t output_count = 0;
    uint32_t file_num = 0;
    uint64_t data_pos = 0;
    uint64_t wire_size = 0;
    uint64_t wire_checksum = 0;
    bool operator==(const TxMeta &) const = default;
};

/** Fixed block metadata joined to canonical height. */
struct BlockMeta {
    Anchor anchor;
    HeaderWire header_wire{};
    uint32_t tx_count = 0;
    bool operator==(const BlockMeta &) const = default;
};

/** Input descriptor with a count instead of an unbounded witness vector. */
struct InputMeta {
    Bytes32 prev_txid{};
    uint32_t prev_index = 0;
    uint32_t sequence = 0;
    uint8_t flags = 0;
    uint8_t path_index = 0;
    bool has_coinbase_data = false;
    WireRange coinbase_data;
    uint32_t witness_count = 0;
    std::optional<ResolvedCreation> resolved_creation;
    bool operator==(const InputMeta &) const = default;
};

/** Confirmed native spend input, preserving its original input ordinal. */
struct SpentInput {
    OutPoint outpoint;
    uint32_t input_index = 0;
    bool operator==(const SpentInput &) const = default;
};

/** A transaction from the authoritative committed block, in block order. */
struct ConfirmedTx {
    TxLocation location;
    std::vector<Output> outputs;
    std::vector<SpentInput> spends;
    ExplorerTxFacts explorer;
    bool operator==(const ConfirmedTx &) const = default;
};

/** Confirmed-only transition. */
struct CommittedBlock {
    Anchor anchor;
    Anchor parent;
    std::vector<ConfirmedTx> transactions;
    ExplorerBlockFacts explorer;
    bool operator==(const CommittedBlock &) const = default;
};

using U128 = unsigned __int128;

/** Aggregate effects for one token in one canonical transaction. */
struct AssetEvent {
    Hash32 token_id;
    TxLocation location;
    U128 spent_units = 0;
    U128 output_units = 0;
    U128 explicit_burn_units = 0;
    U128 minted_units = 0;
    U128 implicit_burn_units = 0;
    bool has_mint_input = false;
    bool operator==(const AssetEvent &) const = default;
};

/** Covered-history occurrence counts. */
struct AssetSummary {
    Hash32 token_id;
    TxLocation first_seen;
    uint64_t event_count = 0;
    uint64_t output_count = 0;
    bool operator==(const AssetSummary &) const = default;
};

/**
 * Storage-read budget, shared by initial existence joins and page reads.
 * Every charge happens before the corresponding get/iterator advancement.
 */
class AssetReadBudget {
public:
    explicit AssetReadBudget(size_t limit) : m_limit(limit) {}
    size_t Reads() const { return m_reads; }
    size_t Remaining() const { return m_limit - m_reads; }
    /** Throws Invalid("asset read budget") when exhausted. */
    void Charge() {
        if (m_reads == m_limit) {
            ThrowInvalid("asset read budget");
        }
        ++m_reads;
    }

private:
    size_t m_limit;
    size_t m_reads = 0;
};

/**
 * Postcard (serde) codecs, field order as the Rust derives. Write() of an
 * invalid Output throws Corrupt (its serde adapter fails); Read() throws
 * postcard::Error on malformed input and Corrupt on an invalid Output frame.
 */
namespace codec {
using postcard::Reader;
using postcard::Writer;

inline void Write(Writer &w, const Bytes32 &v) { w.Raw(v); }
inline void Write(Writer &w, const Hash32 &v) { w.Raw(v.b); }
void Write(Writer &w, const Output &v);
void Write(Writer &w, const OutPoint &v);
/** native_serde::location == v2_branch::Loc: (block, height, idx, txid, hash) */
void Write(Writer &w, const TxLocation &v);
void Write(Writer &w, const Binding &v);
void Write(Writer &w, const Anchor &v);
void Write(Writer &w, const WireRange &v);
void Write(Writer &w, const WitnessFact &v);
void Write(Writer &w, const ResolvedCreation &v);
void Write(Writer &w, const InputFact &v);
void Write(Writer &w, const ExplorerTxFacts &v);
void Write(Writer &w, const ExplorerBlockFacts &v);
void Write(Writer &w, const TxMeta &v);
void Write(Writer &w, const BlockMeta &v);
void Write(Writer &w, const InputMeta &v);
void Write(Writer &w, const AssetEvent &v);
void Write(Writer &w, const AssetSummary &v);

void Read(Reader &r, Bytes32 &v);
void Read(Reader &r, Hash32 &v);
void Read(Reader &r, Output &v);
void Read(Reader &r, OutPoint &v);
void Read(Reader &r, TxLocation &v);
void Read(Reader &r, Binding &v);
void Read(Reader &r, Anchor &v);
void Read(Reader &r, WireRange &v);
void Read(Reader &r, WitnessFact &v);
void Read(Reader &r, ResolvedCreation &v);
void Read(Reader &r, InputFact &v);
void Read(Reader &r, ExplorerTxFacts &v);
void Read(Reader &r, ExplorerBlockFacts &v);
void Read(Reader &r, TxMeta &v);
void Read(Reader &r, BlockMeta &v);
void Read(Reader &r, InputMeta &v);
void Read(Reader &r, AssetEvent &v);
void Read(Reader &r, AssetSummary &v);

template <typename T> void Write(Writer &w, const std::vector<T> &v) {
    w.SeqLen(v.size());
    for (const T &item : v) {
        Write(w, item);
    }
}
template <typename T> void Read(Reader &r, std::vector<T> &v) {
    const uint64_t n = r.SeqLen();
    v.clear();
    for (uint64_t i = 0; i < n; ++i) {
        T item{};
        Read(r, item);
        v.push_back(std::move(item));
    }
}
template <typename T> void Write(Writer &w, const std::optional<T> &v) {
    w.OptionTag(v.has_value());
    if (v) {
        Write(w, *v);
    }
}
template <typename T> void Read(Reader &r, std::optional<T> &v) {
    v.reset();
    if (r.OptionTag()) {
        T item{};
        Read(r, item);
        v = std::move(item);
    }
}

/** postcard::to_allocvec */
template <typename T> Bytes Encode(const T &v) {
    Bytes out;
    Writer w(out);
    Write(w, v);
    return out;
}
/** postcard::from_bytes (trailing bytes ignored); failure is Corrupt. */
template <typename T> T Decode(ByteView bytes) {
    T v{};
    try {
        Reader r(bytes);
        Read(r, v);
    } catch (const postcard::Error &) {
        ThrowCorrupt();
    }
    return v;
}
} // namespace codec

/** Hash32 from a 32-byte array (and back). */
inline Hash32 H(const Bytes32 &b) { return Hash32{b}; }

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_MODEL_H
