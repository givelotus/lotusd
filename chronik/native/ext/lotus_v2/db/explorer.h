// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_DB_EXPLORER_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_DB_EXPLORER_H

#include <ext/lotus_v2/db/model.h>

#include <cstdint>
#include <utility>
#include <vector>

/**
 * Complete native explorer facts (port of chronik-db/src/v2_explorer.rs):
 * the explorer_* subdatabases and the flat segment (file_num, data_pos,
 * wire_size) pointers. Only the V2 DB owner commits these entries, together
 * with its receipt, checkpoint and undo. The ReadSnapshot readers are
 * declared in branch.h.
 */
namespace chronik::native::lotus_v2 {

/** Maximum wire slice size per HTTP wire request (32 KiB). */
inline constexpr size_t WIRE_CHUNK_BYTES = 32768;
/** Maximum serialized individual explorer metadata record. */
inline constexpr size_t MAX_EXPLORER_RECORD_BYTES = 16 * 1024;
/** Explorer staging reserved once per block. */
inline constexpr size_t RESERVE_EXPLORER_BLOCK = 4096;
/** Explorer staging reserved per wire byte (entries, flat-file staging). */
inline constexpr size_t RESERVE_EXPLORER_PER_WIRE_BYTE = 6;
/** Explorer staging reserved per transaction. */
inline constexpr size_t RESERVE_EXPLORER_TX = 4096;
/** Explorer staging reserved per input. */
inline constexpr size_t RESERVE_EXPLORER_INPUT = 8192;
/** Explorer staging reserved per branch witness. */
inline constexpr size_t RESERVE_EXPLORER_WITNESS = 2048;
/** Explorer staging reserved per started wire chunk. */
inline constexpr size_t RESERVE_EXPLORER_CHUNK = 1024;

/** Bounded record encoder: Invalid("explorer record bound") if too large. */
template <typename T> Bytes EncodeRecord(const T &value) {
    Bytes bytes = codec::Encode(value);
    if (bytes.size() > MAX_EXPLORER_RECORD_BYTES) {
        ThrowInvalid("explorer record bound");
    }
    return bytes;
}
/** Stored record decoder; rejects excessive records before decoding. */
template <typename T> T DecodeRecord(ByteView bytes) {
    if (bytes.size() > MAX_EXPLORER_RECORD_BYTES) {
        ThrowCorrupt();
    }
    return codec::Decode<T>(bytes);
}

Bytes HeightKey(uint64_t height);
Bytes BlockKey(const Hash32 &id);
Bytes BlockTxKey(const Hash32 &id, uint32_t index);
Bytes TxKey(const TxId &id);
Bytes TxHashKey(const TxHash &id);
Bytes InputKey(const TxId &id, uint32_t index);
Bytes WitnessKey(const TxId &id, uint32_t input, uint32_t index);

/**
 * Conservative reservation before any planner allocation. The block's owner
 * checks it against the index bounds.
 */
size_t PreflightExplorerBlock(const CommittedBlock &block);
/** Validate a bounded stored input descriptor (shape only); else Corrupt. */
void ValidateInputMeta(const InputMeta &input, uint64_t wire_size);
/** Check witness ranges without allocating; else Corrupt. */
void ValidateWitnessFact(const WitnessFact &witness, uint64_t wire_size);

struct FlatWrite {
    uint32_t file_num = 0;
    uint64_t data_pos = 0;
    Bytes wire;
};
struct ExplorerPlan {
    /** Sorted, unique (key, value) entries. */
    std::vector<std::pair<Bytes, Bytes>> entries;
    /** One per transaction, in block order. */
    std::vector<FlatWrite> flat_writes;
    /** Flat position after the block. */
    std::pair<uint32_t, uint64_t> next_flat_pos;
};
/** Deterministic exact entries and flat writes from (file, pos). */
ExplorerPlan PlanExplorerBlockAt(const CommittedBlock &block,
                                 uint32_t start_file_num,
                                 uint64_t start_data_pos);
/** Entries starting at flat position (0, 0). */
std::vector<std::pair<Bytes, Bytes>>
PlanExplorerBlock(const CommittedBlock &block);

} // namespace chronik::native::lotus_v2

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_DB_EXPLORER_H
