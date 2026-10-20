// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TYPES_H
#define CHRONIK_NATIVE_TYPES_H

#include <array>
#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

/**
 * Neutral data model shared by the native Chronik core and its host adapters.
 *
 * The core never sees node types (CTransaction, CBlockIndex, Coin, ...). Host
 * adapters convert their validation events into these structs, computing every
 * chain-specific value (txids, header bytes, block-tx offsets) themselves.
 */
namespace chronik::native {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

/**
 * 32-byte hash in the node's INTERNAL (little-endian) byte order, exactly as
 * the Rust Chronik stores them (TxId::to_bytes / BlockHash::to_bytes).
 */
struct Hash32 {
    std::array<uint8_t, 32> b{};
    auto operator<=>(const Hash32 &) const = default;
    bool IsNull() const { return *this == Hash32{}; }
    /** Bytes in reversed (big-endian, display) order. */
    std::array<uint8_t, 32> Reversed() const {
        std::array<uint8_t, 32> r;
        for (size_t i = 0; i < 32; ++i) {
            r[i] = b[31 - i];
        }
        return r;
    }
    static Hash32 FromBytes(ByteView v) {
        Hash32 h;
        for (size_t i = 0; i < 32 && i < v.size(); ++i) {
            h.b[i] = v[i];
        }
        return h;
    }
    static Hash32 FromReversed(ByteView v) {
        Hash32 h;
        for (size_t i = 0; i < 32 && i < v.size(); ++i) {
            h.b[31 - i] = v[i];
        }
        return h;
    }
};
using TxId = Hash32;
using BlockHash = Hash32;

struct Hash32Hasher {
    size_t operator()(const Hash32 &h) const {
        size_t v;
        static_assert(sizeof(v) <= 32);
        __builtin_memcpy(&v, h.b.data(), sizeof(v));
        return v;
    }
};

struct OutPoint {
    TxId txid;
    uint32_t out_idx{};
    auto operator<=>(const OutPoint &) const = default;
};

struct OutPointHasher {
    size_t operator()(const OutPoint &o) const {
        return Hash32Hasher{}(o.txid) ^ (size_t(o.out_idx) * 0x9e3779b97f4a7c15ULL);
    }
};

struct TxOutput {
    int64_t sats{};
    /**
     * Host-defined "indexed script" bytes. ABC: scriptPubKey. BCHN:
     * CashTokens wrapped script (token prefix || scriptPubKey). Lotus V2: the
     * synthetic native-output frame produced by the V2 adapter. The core never
     * interprets these bytes beyond script classification/compression.
     */
    Bytes script;
    /**
     * Lotus V2: the 32-byte state root of a HAS_STATE output
     * (TxOutput.state_root in the protobuf API), empty for every other
     * output. Host-provided for a transaction's own outputs; the core only
     * forwards it.
     */
    Bytes state_root;
    bool operator==(const TxOutput &) const = default;
};

struct Coin {
    TxOutput output;
    int32_t height{};
    bool is_coinbase{};
    bool is_legacy{};
    bool operator==(const Coin &) const = default;
};

struct TxInput {
    OutPoint prev_out;
    /** scriptSig, or host-defined (V2: coinbase data / witness[0].script). */
    Bytes script;
    uint32_t sequence{};
    /** Spent coin; Coin{} for coinbase (as Rust), nullopt if unresolved (decoded txs). */
    std::optional<Coin> coin;
    bool operator==(const TxInput &) const = default;
};

struct Tx {
    /** Host-computed (ABC: GetId; Core: stripped GetHash; Lotus: merkleized) */
    TxId txid;
    /** Signed: Doged needs negative versions; ABC casts back to uint32. */
    int32_t version{};
    std::vector<TxInput> inputs;
    std::vector<TxOutput> outputs;
    uint32_t locktime{};
    /**
     * Full wire serialization. Hosts fill it whenever they have it at hand;
     * if empty, Host::LoadRawTx is authoritative. wire_size is ALWAYS set.
     */
    Bytes raw;
    uint32_t wire_size{};
    bool is_coinbase() const {
        return inputs.size() == 1 && inputs[0].prev_out.txid.IsNull();
    }
};
using TxRef = std::shared_ptr<const Tx>;

/** undo_pos == 0 <=> coinbase */
struct BlockTx {
    TxRef tx;
    uint32_t data_pos{};
    uint32_t undo_pos{};
};

struct BlockInfo {
    BlockHash hash, prev_hash;
    int32_t height{};
    uint32_t n_bits{};
    int64_t timestamp{};
    uint32_t file_num{}, data_pos{}, undo_pos{};
    /** Serialized block size (Core: with witness). */
    uint64_t size{};
};

struct Block {
    BlockInfo info;
    /** vtx order; txs[0] is the coinbase; inputs carry spent coins (undo). */
    std::vector<BlockTx> txs;
};

enum class MempoolRemovalReason : uint8_t {
    Expiry,
    SizeLimit,
    Reorg,
    Block,
    Conflict,
    Replaced,
    Other,
};

struct HostCapabilities {
    /** Block/Tx Finalized+Invalidated events, preconsensus query. */
    bool avalanche = false;
    /** Allows -chroniktokenindex (core SLP/ALP module). */
    bool slp_alp_tokens = false;
    /** -chronikallowpause permitted (never on mainnet). */
    bool allow_pause_on_this_chain = false;
    /** Tx::raw carries witness serialization. */
    bool witness = false;
    /** "main","test","regtest",... for defaults and log. */
    std::string network;
    /** -chronikbind default port. */
    uint16_t default_http_port = 0;
    std::string client_name;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_TYPES_H
