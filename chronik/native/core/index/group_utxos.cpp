// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/group_utxos.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>

#include <chrono>
#include <map>
#include <variant>

namespace chronik::native::index {

namespace {

double SecondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                         start)
        .count();
}

std::string_view EntryTypeName(UtxoDataKind kind) {
    return kind == UtxoDataKind::Value
               ? "chronik_db::io::group_utxos::UtxoEntry<i64>"
               : "chronik_db::io::group_utxos::UtxoEntry<(i64, "
                 "bytes::bytes::Bytes)>";
}

std::string_view DataTypeName(UtxoDataKind kind) {
    return kind == UtxoDataKind::Value ? "i64" : "(i64, bytes::bytes::Bytes)";
}

using Prefix12 = std::array<uint8_t, 12>;

/**
 * Dup ops of one Insert/Delete call, keyed like the Rust WriteBatch's
 * `dup_ops: BTreeMap<key, BTreeMap<[u8; 12], DupOp>>`.
 */
class DupBatch {
public:
    struct Put {
        Bytes value;
    };
    struct Delete {};

    void PutDup(Bytes key, Bytes value) {
        Prefix12 prefix;
        std::copy(value.begin(), value.begin() + 12, prefix.begin());
        m_ops[std::move(key)][prefix] = Put{std::move(value)};
    }

    void DeleteDupPrefix(Bytes key, const Prefix12 &prefix) {
        auto &key_map = m_ops[std::move(key)];
        auto it = key_map.find(prefix);
        if (it != key_map.end()) {
            if (std::holds_alternative<Put>(it->second)) {
                // Created and spent within the same batch: cancel the
                // pending Put without touching the table.
                key_map.erase(it);
            }
            return;
        }
        key_map.emplace(prefix, Delete{});
    }

    void Apply(WriteTxn &txn, TableId cf) const {
        for (const auto &[key, key_map] : m_ops) {
            for (const auto &[prefix, op] : key_map) {
                if (const Put *put = std::get_if<Put>(&op)) {
                    txn.PutDup(cf, key, put->value);
                } else {
                    txn.DelDupByPrefix(cf, key, prefix);
                }
            }
        }
    }

private:
    std::map<Bytes, std::map<Prefix12, std::variant<Put, Delete>>> m_ops;
};

UtxoEntry FromOutput(UtxoDataKind kind, const DbOutpoint &outpoint,
                     const TxOutput &output) {
    UtxoEntry entry;
    entry.outpoint = outpoint;
    entry.sats = output.sats;
    if (kind == UtxoDataKind::Output) {
        entry.script = output.script;
    }
    return entry;
}

} // namespace

std::array<uint8_t, 12> EncodeOutpointPrefix(const DbOutpoint &outpoint) {
    std::array<uint8_t, 12> prefix;
    const auto tx_num = ToBe<uint64_t>(outpoint.tx_num);
    const auto out_idx = ToBe<uint32_t>(outpoint.out_idx);
    std::copy(tx_num.begin(), tx_num.end(), prefix.begin());
    std::copy(out_idx.begin(), out_idx.end(), prefix.begin() + 8);
    return prefix;
}

Bytes EncodeUtxoDup(UtxoDataKind kind, const UtxoEntry &entry) {
    Bytes buf;
    buf.reserve(UtxoFixedDupSize(kind).value_or(48));
    PutBe<uint64_t>(buf, entry.outpoint.tx_num);
    PutBe<uint32_t>(buf, entry.outpoint.out_idx);
    PutLe<int64_t>(buf, entry.sats);
    if (kind == UtxoDataKind::Output) {
        Append(buf, entry.script);
    }
    return buf;
}

UtxoEntry DecodeUtxoDup(UtxoDataKind kind, ByteView bytes) {
    if (bytes.size() < 12) {
        postcard::ThrowDeserializeError(EntryTypeName(kind),
                                        postcard::kUnexpectedEnd, bytes);
    }
    UtxoEntry entry;
    entry.outpoint.tx_num = FromBe<uint64_t>(bytes.subspan(0, 8));
    entry.outpoint.out_idx = FromBe<uint32_t>(bytes.subspan(8, 4));
    const ByteView data = bytes.subspan(12);
    const bool ok = kind == UtxoDataKind::Value ? data.size() == 8
                                                : data.size() >= 8;
    if (!ok) {
        postcard::ThrowDeserializeError(DataTypeName(kind),
                                        postcard::kUnexpectedEnd, bytes);
    }
    entry.sats = FromLe<int64_t>(data.subspan(0, 8));
    if (kind == UtxoDataKind::Output) {
        entry.script.assign(data.begin() + 8, data.end());
    }
    return entry;
}

GroupUtxoConf RequireUtxoConf(const GroupDef &group) {
    std::optional<GroupUtxoConf> conf = group.UtxoConf();
    if (!conf) {
        throw ChronikError(std::string(group.Name()) +
                           " should not be used to group UTXOs");
    }
    return *conf;
}

GroupUtxoWriter::GroupUtxoWriter(const KvStore &store, const GroupDef &group)
    : m_group(group), m_kind(group.UtxoData()),
      m_cf(store.Table(RequireUtxoConf(group).cf_name)) {}

UtxoEntry GroupUtxoWriter::OutputUtxo(const IndexTx &index_tx,
                                      size_t idx) const {
    return FromOutput(m_kind, DbOutpoint{index_tx.tx_num, uint32_t(idx)},
                      index_tx.tx->outputs.at(idx));
}

UtxoEntry GroupUtxoWriter::InputUtxo(const IndexTx &index_tx,
                                     size_t idx) const {
    const TxInput &input = index_tx.tx->inputs.at(idx);
    const DbOutpoint outpoint{index_tx.input_nums.at(idx),
                              input.prev_out.out_idx};
    if (!input.coin) {
        // UtxoData::default()
        UtxoEntry entry;
        entry.outpoint = outpoint;
        return entry;
    }
    return FromOutput(m_kind, outpoint, input.coin->output);
}

void GroupUtxoWriter::Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                             const GroupAux *aux,
                             GroupUtxoMemData &mem_data) const {
    GroupUtxoStats &stats = mem_data.stats;
    stats.n_total += txs.size();
    const auto t_start = std::chrono::steady_clock::now();
    DupBatch batch;
    std::vector<MemberItem> items;
    for (const IndexTx &index_tx : txs) {
        const GroupQuery query{index_tx.is_coinbase, index_tx.tx};
        items.clear();
        m_group.OutputMembers(query, aux, items);
        for (const MemberItem &item : items) {
            const UtxoEntry new_entry = OutputUtxo(index_tx, item.idx);
            batch.PutDup(m_group.SerMember(item.member),
                         EncodeUtxoDup(m_kind, new_entry));
        }
    }
    for (const IndexTx &index_tx : txs) {
        if (index_tx.is_coinbase) {
            continue;
        }
        const GroupQuery query{index_tx.is_coinbase, index_tx.tx};
        items.clear();
        m_group.InputMembers(query, aux, items);
        for (const MemberItem &item : items) {
            const DbOutpoint delete_outpoint =
                InputUtxo(index_tx, item.idx).outpoint;
            batch.DeleteDupPrefix(m_group.SerMember(item.member),
                                  EncodeOutpointPrefix(delete_outpoint));
        }
    }
    batch.Apply(txn, m_cf);
    stats.t_total += SecondsSince(t_start);
}

void GroupUtxoWriter::Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                             const GroupAux *aux,
                             GroupUtxoMemData &mem_data) const {
    GroupUtxoStats &stats = mem_data.stats;
    stats.n_total += txs.size();
    const auto t_start = std::chrono::steady_clock::now();
    DupBatch batch;
    std::vector<MemberItem> items;
    for (const IndexTx &index_tx : txs) {
        if (index_tx.is_coinbase) {
            continue;
        }
        const GroupQuery query{index_tx.is_coinbase, index_tx.tx};
        items.clear();
        m_group.InputMembers(query, aux, items);
        for (const MemberItem &item : items) {
            const UtxoEntry new_entry = InputUtxo(index_tx, item.idx);
            batch.PutDup(m_group.SerMember(item.member),
                         EncodeUtxoDup(m_kind, new_entry));
        }
    }
    for (const IndexTx &index_tx : txs) {
        const GroupQuery query{index_tx.is_coinbase, index_tx.tx};
        items.clear();
        m_group.OutputMembers(query, aux, items);
        for (const MemberItem &item : items) {
            const DbOutpoint delete_outpoint =
                OutputUtxo(index_tx, item.idx).outpoint;
            batch.DeleteDupPrefix(m_group.SerMember(item.member),
                                  EncodeOutpointPrefix(delete_outpoint));
        }
    }
    batch.Apply(txn, m_cf);
    stats.t_total += SecondsSince(t_start);
}

void GroupUtxoWriter::Wipe(WriteTxn &txn) const {
    txn.Clear(m_cf);
}

GroupUtxoReader::GroupUtxoReader(const KvStore &store, const ReadTxn &txn,
                                 const GroupDef &group)
    : m_txn(txn), m_kind(group.UtxoData()),
      m_cf(store.Table(RequireUtxoConf(group).cf_name)) {}

std::optional<std::vector<UtxoEntry>>
GroupUtxoReader::Utxos(ByteView member) const {
    const std::unique_ptr<DupCursor> dups = m_txn.OpenDupCursor(m_cf);
    if (!dups->Seek(member)) {
        return std::nullopt;
    }
    std::vector<UtxoEntry> utxos;
    utxos.reserve(dups->CountRemaining());
    do {
        utxos.push_back(DecodeUtxoDup(m_kind, dups->Value()));
    } while (dups->Next());
    return utxos;
}

void GroupUtxoReader::VisitPrefix(
    ByteView member_prefix, ByteView member_start,
    const std::function<bool(ByteView, std::vector<UtxoEntry> &&)> &visit)
    const {
    const std::unique_ptr<Cursor> cursor = m_txn.OpenCursor(m_cf);
    const std::unique_ptr<DupCursor> dups = m_txn.OpenDupCursor(m_cf);
    bool ok = member_start.empty() ? cursor->SeekFirst()
                                   : cursor->SeekGe(member_start);
    while (ok) {
        const Bytes key(cursor->Key().begin(), cursor->Key().end());
        if (!StartsWith(key, member_prefix)) {
            return;
        }
        std::vector<UtxoEntry> utxos;
        for (bool has = dups->Seek(key); has; has = dups->Next()) {
            utxos.push_back(DecodeUtxoDup(m_kind, dups->Value()));
        }
        if (!visit(key, std::move(utxos))) {
            return;
        }
        // Step to the next distinct key (a backend's cursor may step
        // through each dup).
        do {
            ok = cursor->Next();
        } while (ok && Equal(cursor->Key(), key));
    }
}

} // namespace chronik::native::index
