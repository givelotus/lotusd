// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/blocks.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/codec/seahash.h>
#include <chronik/native/error.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/reverse_lookup.h>
#include <chronik/native/schema.h>

namespace chronik::native::index {

namespace {

/** LookupColumn for blocks (Rust `BlockColumn`). */
struct BlockColumn {
    using SerialNum = BlockHeight;
    using Data = SerBlock;
    static constexpr std::string_view kCfData = schema::kBlk;
    static constexpr std::string_view kCfIndex = schema::kLookupBlkByHash;
    static constexpr std::string_view kSerialTypeName = "i32";
    static constexpr std::string_view kSerialVecTypeName =
        "alloc::vec::Vec<i32>";

    const ReadTxn &txn;
    TableId blk;
    TableId lookup;

    static Bytes CheapHash(const Key32 &key) {
        // use the lowest 32 bits of seashash as hash
        const auto be = ToBe<uint32_t>(uint32_t(SeaHash(AsView(key))));
        return Bytes(be.begin(), be.end());
    }
    static const Key32 &DataKey(const SerBlock &data) { return data.hash; }
    static void SerSerial(postcard::Writer &w, BlockHeight height) {
        w.I32(height);
    }
    static BlockHeight DeserSerial(postcard::Reader &r) { return r.I32(); }
    TableId IndexTable() const { return lookup; }

    std::optional<SerBlock> GetData(BlockHeight height) const {
        const std::optional<ByteView> bytes = txn.Get(blk, BhToBytes(height));
        if (!bytes) {
            return std::nullopt;
        }
        return DeserializeSerBlock(*bytes);
    }
    std::vector<std::optional<SerBlock>>
    GetDataMulti(const std::vector<BlockHeight> &heights) const {
        std::vector<std::optional<SerBlock>> out;
        out.reserve(heights.size());
        for (const BlockHeight height : heights) {
            out.push_back(GetData(height));
        }
        return out;
    }
};

using LookupByHash = ReverseLookup<BlockColumn>;

/** BlockColumn for writes; the reads of delete_pairs go through `txn`. */
BlockColumn WriteColumn(const WriteTxn &txn, TableId blk, TableId lookup) {
    return BlockColumn{txn, blk, lookup};
}

} // namespace

Bytes SerializeSerBlock(const SerBlock &block) {
    Bytes out;
    postcard::Writer w(out);
    w.Raw(block.hash);
    w.U32(block.n_bits);
    w.I64(block.timestamp);
    w.U32(block.file_num);
    w.U32(block.data_pos);
    return out;
}

SerBlock DeserializeSerBlock(ByteView bytes) {
    return postcard::DbDeserialize(
        bytes, kSerBlockTypeName, [](postcard::Reader &r) {
            SerBlock block;
            block.hash = r.Array<32>();
            block.n_bits = r.U32();
            block.timestamp = r.I64();
            block.file_num = r.U32();
            block.data_pos = r.U32();
            return block;
        });
}

std::array<uint8_t, 4> BhToBytes(BlockHeight height) {
    return ToBe<int32_t>(height);
}

BlockHeight BytesToBh(ByteView bytes) {
    if (bytes.size() != 4) {
        throw ChronikError("Inconsistent DB: Invalid height bytes: " +
                           DebugByteVec(bytes));
    }
    return FromBe<int32_t>(bytes);
}

BlockWriter::BlockWriter(const KvStore &store)
    : m_blk(store.Table(schema::kBlk)),
      m_lookup(store.Table(schema::kLookupBlkByHash)) {}

void BlockWriter::Insert(WriteTxn &txn, const DbBlock &block) const {
    // Serialize the block data
    const Bytes data = SerializeSerBlock(SerBlock{
        block.hash.b,
        block.n_bits,
        block.timestamp,
        block.file_num,
        block.data_pos,
    });
    txn.Put(m_blk, BhToBytes(block.height), data);
    LookupByHash::InsertPairs(WriteColumn(txn, m_blk, m_lookup), txn,
                              {{block.height, block.hash.b}});
}

void BlockWriter::Delete(WriteTxn &txn, const DbBlock &block) const {
    txn.Del(m_blk, BhToBytes(block.height));
    LookupByHash::DeletePairs(WriteColumn(txn, m_blk, m_lookup), txn,
                              {{block.height, block.hash.b}});
}

BlockReader::BlockReader(const KvStore &store, const ReadTxn &txn)
    : m_txn(txn), m_blk(store.Table(schema::kBlk)),
      m_lookup(store.Table(schema::kLookupBlkByHash)) {}

std::optional<SerBlock> BlockReader::GetBlock(BlockHeight height) const {
    return BlockColumn{m_txn, m_blk, m_lookup}.GetData(height);
}

DbBlock BlockReader::MakeDbBlock(BlockHeight height,
                                 const SerBlock &ser) const {
    DbBlock block;
    block.hash.b = ser.hash;
    block.prev_hash.b = GetPrevHash(height);
    block.height = height;
    block.n_bits = ser.n_bits;
    block.timestamp = ser.timestamp;
    block.file_num = ser.file_num;
    block.data_pos = ser.data_pos;
    return block;
}

BlockHeight BlockReader::Height() const {
    const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_blk);
    if (!cursor->SeekLast()) {
        return -1;
    }
    return BytesToBh(cursor->Key());
}

std::optional<DbBlock> BlockReader::Tip() const {
    BlockHeight height;
    SerBlock block_data;
    {
        const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_blk);
        if (!cursor->SeekLast()) {
            return std::nullopt;
        }
        height = BytesToBh(cursor->Key());
        block_data = DeserializeSerBlock(cursor->Value());
    }
    return MakeDbBlock(height, block_data);
}

std::optional<DbBlock> BlockReader::ByHeight(BlockHeight height) const {
    const std::optional<SerBlock> block_data = GetBlock(height);
    if (!block_data) {
        return std::nullopt;
    }
    return MakeDbBlock(height, *block_data);
}

std::vector<std::array<uint8_t, 32>>
BlockReader::HashesByRange(BlockHeight start_height, size_t count) const {
    std::vector<std::array<uint8_t, 32>> hashes;
    if (count == 0 || start_height < 0) {
        return hashes;
    }
    hashes.reserve(count);
    BlockHeight expected = start_height;
    const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_blk);
    for (bool ok = cursor->SeekGe(BhToBytes(start_height)); ok;
         ok = cursor->Next()) {
        const BlockHeight height = BytesToBh(cursor->Key());
        if (height != expected) {
            break;
        }
        hashes.push_back(DeserializeSerBlock(cursor->Value()).hash);
        if (hashes.size() >= count) {
            break;
        }
        ++expected;
    }
    return hashes;
}

std::optional<DbBlock> BlockReader::ByHash(const BlockHash &hash) const {
    const std::optional<std::pair<BlockHeight, SerBlock>> found =
        LookupByHash::Get(BlockColumn{m_txn, m_blk, m_lookup}, m_txn, hash.b);
    if (!found) {
        return std::nullopt;
    }
    return MakeDbBlock(found->first, found->second);
}

std::array<uint8_t, 32> BlockReader::GetPrevHash(BlockHeight height) const {
    if (height == 0) {
        return {};
    }
    const std::optional<ByteView> prev_block_data =
        m_txn.Get(m_blk, BhToBytes(height - 1));
    if (!prev_block_data) {
        throw ChronikError("Inconsistent DB: Orphan block at height " +
                           std::to_string(height));
    }
    return DeserializeSerBlock(*prev_block_data).hash;
}

} // namespace chronik::native::index
