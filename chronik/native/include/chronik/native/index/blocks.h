// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_BLOCKS_H
#define CHRONIK_NATIVE_INDEX_BLOCKS_H

#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

/**
 * Port of chronik-db io/blocks.rs: the `blk` table (height BE4 -> postcard
 * SerBlock) and its `lookup_blk_by_hash` reverse index.
 *
 * Writers write into a WriteTxn (the Rust WriteBatch). Readers read through
 * any ReadTxn, including a WriteTxn (which observes its own writes).
 */
namespace chronik::native::index {

/**
 * Height of a block in the chain. Genesis block has height 0.
 * -1 indicates "not part of the chain".
 */
using BlockHeight = int32_t;

/** Block data to/from the database. */
struct DbBlock {
    /** Hash of the block. */
    BlockHash hash;
    /** Hash of the previous block of the block. */
    BlockHash prev_hash;
    /** Height of the block in the chain. */
    BlockHeight height{};
    /** `nBits` field of the block; encodes the target compactly. */
    uint32_t n_bits{};
    /** Timestamp field of the block. */
    int64_t timestamp{};
    /** Number of the node's blk?????.dat flat file where the block is stored. */
    uint32_t file_num{};
    /**
     * Location in the flat file where the first byte of the block is stored,
     * starting at the header.
     */
    uint32_t data_pos{};

    bool operator==(const DbBlock &) const = default;
};

/** Serialized form of a block in `blk` (Rust `SerBlock`). */
struct SerBlock {
    std::array<uint8_t, 32> hash{};
    uint32_t n_bits{};
    int64_t timestamp{};
    uint32_t file_num{};
    uint32_t data_pos{};

    bool operator==(const SerBlock &) const = default;
};

inline constexpr std::string_view kSerBlockTypeName =
    "chronik_db::io::blocks::SerBlock";

Bytes SerializeSerBlock(const SerBlock &block);
SerBlock DeserializeSerBlock(ByteView bytes);

/**
 * Serialize block height for using it as keys in the DB.
 * Big-endian, so blocks are sorted ascendingly.
 */
std::array<uint8_t, 4> BhToBytes(BlockHeight height);
/** Deserialize block height from bytes. */
BlockHeight BytesToBh(ByteView bytes);

/** Writes block data to the database. */
class BlockWriter {
public:
    /** Throws if the tables don't exist. */
    explicit BlockWriter(const KvStore &store);

    /** Add a new block to the database. */
    void Insert(WriteTxn &txn, const DbBlock &block) const;
    /** Remove a block by height from the database. */
    void Delete(WriteTxn &txn, const DbBlock &block) const;

private:
    TableId m_blk;
    TableId m_lookup;
};

/** Reads block data ([`DbBlock`]) from the database. */
class BlockReader {
public:
    BlockReader(const KvStore &store, const ReadTxn &txn);

    /**
     * The height of the most-work fully-validated chain. The genesis block has
     * height 0
     */
    BlockHeight Height() const;
    /**
     * Tip of the chain: the most recently added block.
     * nullopt if chain is empty (not even the genesis block).
     */
    std::optional<DbBlock> Tip() const;
    /** [`DbBlock`] by height. The genesis block has height 0. */
    std::optional<DbBlock> ByHeight(BlockHeight height) const;
    /**
     * Block hashes for a contiguous height range, starting at `start_height`.
     * Returns at most `count` hashes, truncated at the first gap.
     */
    std::vector<std::array<uint8_t, 32>>
    HashesByRange(BlockHeight start_height, size_t count) const;
    /** [`DbBlock`] by hash. */
    std::optional<DbBlock> ByHash(const BlockHash &hash) const;

private:
    std::array<uint8_t, 32> GetPrevHash(BlockHeight height) const;
    std::optional<SerBlock> GetBlock(BlockHeight height) const;
    DbBlock MakeDbBlock(BlockHeight height, const SerBlock &ser) const;

    const ReadTxn &m_txn;
    TableId m_blk;
    TableId m_lookup;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_BLOCKS_H
