// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_FFI_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_FFI_H

#include <array>
#include <cstdint>
#include <vector>

/**
 * Native V2 service input/output structs: plain C++ mirrors of the
 * chronik-lib/src/v2_ffi.rs CXX bridge structs (namespace chronik_v2). The
 * host adapter fills NativeBlock from its node block; identities are native
 * wire order. No node headers are involved.
 */
namespace chronik::native::lotus_v2::ffi {

using Bytes32 = std::array<uint8_t, 32>;

struct Binding {
    Bytes32 chain_id{};
    Bytes32 genesis{};
    Bytes32 profile{};
};

struct Anchor {
    Bytes32 block_id{};
    uint64_t height = 0;
    bool operator==(const Anchor &) const = default;
};

struct ServiceLimits {
    uint32_t block_bytes = 0;
    uint32_t transactions = 0;
    uint32_t changes = 0;
    uint32_t roots = 0;
    uint32_t clauses = 0;
    uint32_t page_size = 0;
    uint32_t posting_reads = 0;
    uint32_t work = 0;
    uint32_t response_bytes = 0;
};

/** A consumed coin and its native input ordinal. */
struct Input {
    Bytes32 txid{};
    uint32_t out_idx = 0;
    uint32_t input_index = 0;
};

struct NativeOutput {
    std::vector<uint8_t> wire;
};

/** Byte range in the exact transaction frame. */
struct WireRange {
    uint64_t offset = 0;
    uint64_t length = 0;
};

/** Authenticated witness section locations. */
struct NativeWitness {
    WireRange script;
    WireRange siblings_table;
    uint32_t siblings_count = 0;
    WireRange arguments_table;
    uint32_t arguments_count = 0;
};

/** Complete input descriptor, including non-spend selectors. */
struct NativeFullInput {
    Bytes32 prev_txid{};
    uint32_t prev_index = 0;
    uint32_t sequence = 0;
    uint8_t flags = 0;
    uint8_t path_index = 0;
    bool has_coinbase_data = false;
    WireRange coinbase_data;
    std::vector<NativeWitness> witnesses;
};

struct NativeTx {
    Bytes32 txid{};
    Bytes32 txhash{};
    uint32_t index = 0;
    std::vector<Input> inputs;
    std::vector<NativeOutput> outputs;
    std::vector<uint8_t> wire;
    uint64_t lock = 0;
    std::vector<NativeFullInput> full_inputs;
};

struct NativeBlock {
    Anchor anchor;
    Anchor parent;
    std::vector<NativeTx> transactions;
    std::array<uint8_t, 134> header_wire{};
};

struct Status {
    bool initialized = false;
    Anchor indexed;
    Anchor node;
    bool ready = false;
};

struct Root {
    Bytes32 bytes{};
};

struct Position {
    uint8_t position = 0;
    std::vector<Root> roots;
};

struct Continuation {
    bool present = false;
    uint8_t version = 0;
    Bytes32 chain_id{};
    Bytes32 profile{};
    Anchor anchor;
    Bytes32 filter_digest{};
    bool has_last = false;
    Bytes32 last_txid{};
    uint32_t last_out_idx = 0;
};

struct BranchRequest {
    std::vector<Root> any_branch;
    std::vector<Position> positions;
    bool utxos = false;
    bool include_burn = false;
    Continuation cursor;
};

struct Location {
    Anchor anchor;
    uint32_t tx_index = 0;
    Bytes32 txid{};
    Bytes32 txhash{};
};

struct OutputMatch {
    Bytes32 txid{};
    uint32_t out_idx = 0;
    std::vector<uint8_t> wire;
    Location creation;
    bool spent = false;
    Location spend;
    uint32_t input_index = 0;
    std::vector<uint8_t> matching_positions;
};

struct BranchPage {
    Anchor anchor;
    Bytes32 chain_id{};
    Bytes32 profile{};
    std::vector<OutputMatch> matches;
    Continuation cursor;
    uint64_t posting_reads = 0;
    uint64_t work = 0;
    uint64_t encoded_bytes = 0;
};

} // namespace chronik::native::lotus_v2::ffi

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_SERVICE_FFI_H
