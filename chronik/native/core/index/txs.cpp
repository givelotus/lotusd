// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/txs.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/codec/seahash.h>
#include <chronik/native/error.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/reverse_lookup.h>
#include <chronik/native/schema.h>

#include <chrono>

namespace chronik::native::index {

namespace {

double SecondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                         start)
        .count();
}

/** LookupColumn for txs (Rust `TxColumn`). */
struct TxColumn {
    using SerialNum = TxNum;
    using Data = SerTx;
    static constexpr std::string_view kCfData = schema::kTx;
    static constexpr std::string_view kCfIndex = schema::kLookupTxByHash;
    static constexpr std::string_view kSerialTypeName = "u64";
    static constexpr std::string_view kSerialVecTypeName =
        "alloc::vec::Vec<u64>";

    const ReadTxn &txn;
    TableId tx;
    TableId lookup;

    static Bytes CheapHash(const Key32 &key) {
        const auto be = ToBe<uint64_t>(SeaHash(AsView(key)));
        return Bytes(be.begin(), be.end());
    }
    static const Key32 &DataKey(const SerTx &data) { return data.txid; }
    static void SerSerial(postcard::Writer &w, TxNum tx_num) { w.U64(tx_num); }
    static TxNum DeserSerial(postcard::Reader &r) { return r.U64(); }
    TableId IndexTable() const { return lookup; }

    std::optional<SerTx> GetData(TxNum tx_num) const {
        const std::optional<ByteView> bytes = txn.Get(tx, TxNumToBytes(tx_num));
        if (!bytes) {
            return std::nullopt;
        }
        return DeserializeSerTx(*bytes);
    }
    std::vector<std::optional<SerTx>>
    GetDataMulti(const std::vector<TxNum> &tx_nums) const {
        std::vector<std::optional<SerTx>> out;
        out.reserve(tx_nums.size());
        for (const TxNum tx_num : tx_nums) {
            out.push_back(GetData(tx_num));
        }
        return out;
    }
};

using LookupByHash = ReverseLookup<TxColumn>;

} // namespace

Bytes SerializeSerTx(const SerTx &tx) {
    Bytes out;
    postcard::Writer w(out);
    w.Raw(tx.txid);
    w.U32(tx.data_pos);
    w.U32(tx.undo_pos);
    w.I64(tx.time_first_seen);
    w.Bool(tx.is_legacy);
    return out;
}

SerTx DeserializeSerTx(ByteView bytes) {
    return postcard::DbDeserialize(bytes, kSerTxTypeName,
                                   [](postcard::Reader &r) {
                                       SerTx tx;
                                       tx.txid = r.Array<32>();
                                       tx.data_pos = r.U32();
                                       tx.undo_pos = r.U32();
                                       tx.time_first_seen = r.I64();
                                       tx.is_legacy = r.Bool();
                                       return tx;
                                   });
}

SerTx ToSerTx(const TxEntry &entry) {
    return SerTx{entry.txid.b, entry.data_pos, entry.undo_pos,
                 entry.time_first_seen, entry.is_legacy};
}

TxEntry FromSerTx(const SerTx &ser) {
    TxEntry entry;
    entry.txid.b = ser.txid;
    entry.data_pos = ser.data_pos;
    entry.undo_pos = ser.undo_pos;
    entry.time_first_seen = ser.time_first_seen;
    entry.is_coinbase = entry.undo_pos == 0;
    entry.is_legacy = ser.is_legacy;
    return entry;
}

std::array<uint8_t, 8> TxNumToBytes(TxNum tx_num) {
    return ToBe<uint64_t>(tx_num);
}

TxNum BytesToTxNum(ByteView bytes) {
    if (bytes.size() != 8) {
        throw ChronikError("Inconsistent DB: Invalid tx_num bytes: " +
                           DebugByteVec(bytes));
    }
    return FromBe<uint64_t>(bytes);
}

TxWriter::TxWriter(const KvStore &store)
    : m_tx(store.Table(schema::kTx)),
      m_blk_by_first_tx(store.Table(schema::kBlkByFirstTx)),
      m_first_tx_by_blk(store.Table(schema::kFirstTxByBlk)),
      m_lookup(store.Table(schema::kLookupTxByHash)) {}

TxNum TxWriter::Insert(WriteTxn &txn, const BlockTxs &block_txs,
                       TxsMemData &mem_data) const {
    TxsStats &stats = mem_data.stats;
    const auto t_start = std::chrono::steady_clock::now();
    stats.n_total += block_txs.txs.size();
    TxNum first_new_tx = 0;
    {
        const std::unique_ptr<Cursor> cursor = txn.OpenCursor(m_tx);
        if (cursor->SeekLast()) {
            first_new_tx = BytesToTxNum(cursor->Key()) + 1;
        }
    }
    txn.Put(m_blk_by_first_tx, TxNumToBytes(first_new_tx),
            BhToBytes(block_txs.block_height));
    txn.Put(m_first_tx_by_blk, BhToBytes(block_txs.block_height),
            TxNumToBytes(first_new_tx));
    std::vector<std::pair<TxNum, Key32>> index_pairs;
    index_pairs.reserve(block_txs.txs.size());
    TxNum next_tx_num = first_new_tx;
    for (const TxEntry &tx : block_txs.txs) {
        txn.Put(m_tx, TxNumToBytes(next_tx_num),
                SerializeSerTx(ToSerTx(tx)));
        index_pairs.emplace_back(next_tx_num, tx.txid.b);
        ++next_tx_num;
    }
    const auto t_index = std::chrono::steady_clock::now();
    LookupByHash::InsertPairs(TxColumn{txn, m_tx, m_lookup}, txn, index_pairs);
    stats.t_index += SecondsSince(t_index);
    stats.t_total += SecondsSince(t_start);
    return first_new_tx;
}

TxNum TxWriter::Delete(WriteTxn &txn, const BlockTxs &block_txs,
                       TxsMemData &mem_data) const {
    TxsStats &stats = mem_data.stats;
    const auto t_start = std::chrono::steady_clock::now();
    stats.n_total += block_txs.txs.size();
    const std::optional<ByteView> first_tx_num_bytes =
        txn.Get(m_first_tx_by_blk, BhToBytes(block_txs.block_height));
    if (!first_tx_num_bytes) {
        throw ChronikError("Inconsistent DB: Txs for block " +
                           std::to_string(block_txs.block_height) +
                           " not found");
    }
    const TxNum first_tx_num = BytesToTxNum(*first_tx_num_bytes);
    TxNum next_tx_num = first_tx_num;
    std::vector<std::pair<TxNum, Key32>> index_pairs;
    index_pairs.reserve(block_txs.txs.size());
    for (const TxEntry &tx : block_txs.txs) {
        txn.Del(m_tx, TxNumToBytes(next_tx_num));
        index_pairs.emplace_back(next_tx_num, tx.txid.b);
        ++next_tx_num;
    }
    txn.Del(m_blk_by_first_tx, TxNumToBytes(first_tx_num));
    txn.Del(m_first_tx_by_blk, BhToBytes(block_txs.block_height));
    const auto t_index = std::chrono::steady_clock::now();
    LookupByHash::DeletePairs(TxColumn{txn, m_tx, m_lookup}, txn, index_pairs);
    stats.t_index += SecondsSince(t_index);
    stats.t_total += SecondsSince(t_start);
    return first_tx_num;
}

TxReader::TxReader(const KvStore &store, const ReadTxn &txn)
    : m_txn(txn), m_tx(store.Table(schema::kTx)),
      m_blk_by_first_tx(store.Table(schema::kBlkByFirstTx)),
      m_first_tx_by_blk(store.Table(schema::kFirstTxByBlk)),
      m_lookup(store.Table(schema::kLookupTxByHash)) {}

std::optional<SerTx> TxReader::GetTx(TxNum tx_num) const {
    return TxColumn{m_txn, m_tx, m_lookup}.GetData(tx_num);
}

std::optional<BlockTx> TxReader::TxByTxid(const TxId &txid) const {
    std::optional<std::pair<TxNum, BlockTx>> found = TxAndNumByTxid(txid);
    if (!found) {
        return std::nullopt;
    }
    return std::move(found->second);
}

std::optional<std::pair<TxNum, BlockTx>>
TxReader::TxAndNumByTxid(const TxId &txid) const {
    const std::optional<std::pair<TxNum, SerTx>> found =
        LookupByHash::Get(TxColumn{m_txn, m_tx, m_lookup}, m_txn, txid.b);
    if (!found) {
        return std::nullopt;
    }
    const BlockHeight block_height = BlockHeightByTxNum(found->first);
    return std::make_pair(found->first,
                          BlockTx{FromSerTx(found->second), block_height});
}

std::optional<TxNum> TxReader::TxNumByTxid(const TxId &txid) const {
    const std::optional<std::pair<TxNum, SerTx>> found =
        LookupByHash::Get(TxColumn{m_txn, m_tx, m_lookup}, m_txn, txid.b);
    if (!found) {
        return std::nullopt;
    }
    return found->first;
}

std::vector<std::optional<TxNum>>
TxReader::TxNumsByTxids(const std::vector<TxId> &txids) const {
    std::vector<Key32> keys;
    keys.reserve(txids.size());
    for (const TxId &txid : txids) {
        keys.push_back(txid.b);
    }
    const auto data =
        LookupByHash::GetMulti(TxColumn{m_txn, m_tx, m_lookup}, m_txn, keys);
    std::vector<std::optional<TxNum>> out;
    out.reserve(data.size());
    for (const auto &entry : data) {
        out.push_back(entry ? std::optional<TxNum>(entry->first)
                            : std::nullopt);
    }
    return out;
}

std::optional<BlockTx> TxReader::TxByTxNum(TxNum tx_num) const {
    const std::optional<SerTx> ser_tx = GetTx(tx_num);
    if (!ser_tx) {
        return std::nullopt;
    }
    const BlockHeight block_height = BlockHeightByTxNum(tx_num);
    return BlockTx{FromSerTx(*ser_tx), block_height};
}

std::optional<TxId> TxReader::TxidByTxNum(TxNum tx_num) const {
    const std::optional<SerTx> ser_tx = GetTx(tx_num);
    if (!ser_tx) {
        return std::nullopt;
    }
    TxId txid;
    txid.b = ser_tx->txid;
    return txid;
}

std::vector<std::optional<TxId>>
TxReader::TxidsByTxNums(const std::vector<TxNum> &tx_nums) const {
    std::vector<std::optional<TxId>> out;
    out.reserve(tx_nums.size());
    for (const TxNum tx_num : tx_nums) {
        out.push_back(TxidByTxNum(tx_num));
    }
    return out;
}

std::optional<TxNum>
TxReader::FirstTxNumByBlock(BlockHeight block_height) const {
    const std::optional<ByteView> bytes =
        m_txn.Get(m_first_tx_by_blk, BhToBytes(block_height));
    if (!bytes) {
        return std::nullopt;
    }
    return BytesToTxNum(*bytes);
}

std::optional<std::pair<TxNum, TxNum>>
TxReader::BlockTxNumRange(BlockHeight block_height) const {
    const std::optional<TxNum> tx_num_start = FirstTxNumByBlock(block_height);
    if (!tx_num_start) {
        return std::nullopt;
    }
    TxNum tx_num_end;
    if (const std::optional<TxNum> next = FirstTxNumByBlock(block_height + 1)) {
        tx_num_end = *next;
    } else if (const std::optional<TxNum> last = LastTxNum()) {
        tx_num_end = *last + 1;
    } else {
        throw ChronikError("Inconsistent DB: Txs for block " +
                           std::to_string(block_height) + " not found");
    }
    return std::make_pair(*tx_num_start, tx_num_end);
}

std::optional<TxNum> TxReader::LastTxNum() const {
    const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_tx);
    if (!cursor->SeekLast()) {
        return std::nullopt;
    }
    return BytesToTxNum(cursor->Key());
}

BlockHeight TxReader::BlockHeightByTxNum(TxNum tx_num) const {
    const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_blk_by_first_tx);
    if (!cursor->SeekLe(TxNumToBytes(tx_num))) {
        throw ChronikError("Inconsistent DB: Block for tx " +
                           std::to_string(tx_num) + " not found");
    }
    return BytesToBh(cursor->Value());
}

} // namespace chronik::native::index
