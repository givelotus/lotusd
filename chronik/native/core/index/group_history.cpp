// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/index/group_history.h>

#include <chronik/native/codec/bytes.h>
#include <chronik/native/codec/hex.h>
#include <chronik/native/codec/postcard.h>
#include <chronik/native/error.h>
#include <chronik/native/index/debug_fmt.h>
#include <chronik/native/index/merge.h>

#include <chrono>
#include <cstdio>
#include <map>

namespace chronik::native::index {

namespace {

constexpr uint8_t CONCAT = 'C';
constexpr uint8_t TRIM = 'T';

double SecondsSince(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                         start)
        .count();
}

/** db_serialize_vec::<TxNum> */
Bytes SerTxNums(std::span<const TxNum> tx_nums) {
    Bytes out;
    postcard::Writer w(out);
    for (const TxNum tx_num : tx_nums) {
        w.U64(tx_num);
    }
    return out;
}

std::string UnknownOperandPrefix(ByteView operand) {
    char prefix[3];
    std::snprintf(prefix, sizeof(prefix), "%02x", operand[0]);
    return "Bad usage of merge: Unknown prefix " + std::string(prefix) +
           ", expected C or T: " + HexEncode(operand);
}

/** Merge pages with the CONCAT/TRIM operands (Rust *_concat_trim). */
void MergeConcatTrim(WriteTxn &txn, TableId cf, ByteView key,
                     const Bytes &operand) {
    merge::CatchMergeErrors(
        txn, cf, key, std::span<const Bytes>(&operand, 1),
        // init_concat_trim
        [](ByteView, std::optional<ByteView> existing, size_t) {
            return existing ? Bytes(existing->begin(), existing->end())
                            : Bytes{};
        },
        // apply_concat_trim
        [](ByteView, Bytes &bytes, ByteView op) {
            if (op[0] == CONCAT) {
                bytes.insert(bytes.end(), op.begin() + 1, op.end());
            } else if (op[0] == TRIM) {
                const NumTxs trim_len = FromBe<NumTxs>(op.subspan(1, 4));
                if (trim_len > bytes.size()) {
                    // Rust: Vec::drain panics on an out-of-range trim
                    throw ChronikError("Inconsistent DB: Tried trimming " +
                                       std::to_string(trim_len) +
                                       " bytes from a page of " +
                                       std::to_string(bytes.size()) +
                                       " bytes");
                }
                bytes.resize(bytes.size() - trim_len);
            } else {
                throw ChronikError(UnknownOperandPrefix(op));
            }
        },
        // ser_concat_trim
        [](ByteView, Bytes &&bytes) { return std::move(bytes); });
}

std::optional<TableId> MemberHashTable(const KvStore &store,
                                       const GroupHistoryConf &conf) {
    if (!conf.cf_member_hash_name) {
        return std::nullopt;
    }
    return store.Table(*conf.cf_member_hash_name);
}

} // namespace

NumTxs BytesToNumTxs(ByteView bytes) {
    if (bytes.size() != sizeof(NumTxs)) {
        throw ChronikError("Inconsistent DB: Bad num_txs size: " +
                           DebugByteVec(bytes));
    }
    return FromBe<NumTxs>(bytes);
}

Bytes KeyForMemberPage(ByteView member_ser, PageNum page_num) {
    Bytes key(member_ser.begin(), member_ser.end());
    PutBe<PageNum>(key, page_num);
    return key;
}

GroupHistoryConf RequireHistoryConf(const GroupDef &group) {
    std::optional<GroupHistoryConf> conf = group.TxHistoryConf();
    if (!conf) {
        throw ChronikError(std::string(group.Name()) +
                           " should not be used to group history");
    }
    return *conf;
}

GroupHistoryWriter::GroupHistoryWriter(const KvStore &store,
                                       const GroupDef &group)
    : m_group(group), m_conf(RequireHistoryConf(group)),
      m_cf_page(store.Table(m_conf.cf_page_name)),
      m_cf_num_txs(store.Table(m_conf.cf_num_txs_name)),
      m_cf_member_hash(MemberHashTable(store, m_conf)) {}

void GroupHistoryWriter::Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                                const GroupAux *aux,
                                GroupHistoryMemData &mem_data) const {
    const auto t_start = std::chrono::steady_clock::now();
    Fetched fetched = FetchMembersNumTxs(txn, txs, aux, mem_data);
    for (size_t i = 0; i < fetched.grouped_txs.size(); ++i) {
        const Bytes &member = fetched.grouped_txs[i].first;
        std::vector<TxNum> &new_tx_nums = fetched.grouped_txs[i].second;
        const Bytes &member_ser = fetched.ser_members[i];
        NumTxs num_txs = fetched.members_num_txs[i];
        // The member hash index can only be enabled for ScriptGroup. For
        // other groups cf_member_hash will be None.
        if (m_cf_member_hash) {
            // The is_member_hash_index_enabled flag is controlled by an init
            // flag so users can enable or disable this index.
            if (num_txs == 0 && mem_data.is_member_hash_index_enabled) {
                txn.Put(*m_cf_member_hash, m_group.SerHashMember(member),
                        member_ser);
            }
        }
        PageNum page_num = num_txs / m_conf.page_size;
        NumTxs last_page_num_txs = num_txs % m_conf.page_size;
        size_t drained = 0;
        while (true) {
            const size_t space_left = m_conf.page_size - last_page_num_txs;
            const size_t num_new_txs =
                std::min(space_left, new_tx_nums.size() - drained);
            const Bytes merge_tx_nums = SerTxNums(
                std::span<const TxNum>(new_tx_nums).subspan(drained,
                                                            num_new_txs));
            drained += num_new_txs;
            Bytes operand{CONCAT};
            Append(operand, merge_tx_nums);
            MergeConcatTrim(txn, m_cf_page,
                            KeyForMemberPage(member_ser, page_num), operand);
            num_txs += NumTxs(num_new_txs);
            if (drained == new_tx_nums.size()) {
                txn.Put(m_cf_num_txs, member_ser, ToBe<NumTxs>(num_txs));
                break;
            }
            last_page_num_txs = 0;
            ++page_num;
        }
    }
    mem_data.stats.t_total += SecondsSince(t_start);
}

void GroupHistoryWriter::Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                                const GroupAux *aux,
                                GroupHistoryMemData &mem_data) const {
    const auto t_start = std::chrono::steady_clock::now();
    Fetched fetched = FetchMembersNumTxs(txn, txs, aux, mem_data);
    for (size_t i = 0; i < fetched.grouped_txs.size(); ++i) {
        const Bytes &member = fetched.grouped_txs[i].first;
        std::vector<TxNum> &removed_tx_nums = fetched.grouped_txs[i].second;
        const Bytes &member_ser = fetched.ser_members[i];
        NumTxs num_txs = fetched.members_num_txs[i];
        size_t num_remaining_removes = removed_tx_nums.size();
        PageNum page_num = num_txs / m_conf.page_size;
        NumTxs last_page_num_txs = num_txs % m_conf.page_size;
        while (true) {
            const size_t num_page_removes =
                std::min(size_t(last_page_num_txs), num_remaining_removes);
            const Bytes key = KeyForMemberPage(member_ser, page_num);
            if (num_page_removes == last_page_num_txs) {
                txn.Del(m_cf_page, key);
            } else {
                // Like Rust, only this branch drains removed_tx_nums; the
                // trim length is the size of the drained serialized txs.
                const size_t start = removed_tx_nums.size() - num_page_removes;
                const Bytes merge_removed_txs = SerTxNums(
                    std::span<const TxNum>(removed_tx_nums).subspan(start));
                removed_tx_nums.resize(start);
                const NumTxs num_trimmed_bytes =
                    NumTxs(merge_removed_txs.size());
                Bytes operand{TRIM};
                PutBe<NumTxs>(operand, num_trimmed_bytes);
                MergeConcatTrim(txn, m_cf_page, key, operand);
            }
            num_txs -= NumTxs(num_page_removes);
            num_remaining_removes -= num_page_removes;
            if (num_remaining_removes == 0) {
                if (num_txs > 0) {
                    txn.Put(m_cf_num_txs, member_ser, ToBe<NumTxs>(num_txs));
                } else {
                    txn.Del(m_cf_num_txs, member_ser);
                    if (m_cf_member_hash &&
                        mem_data.is_member_hash_index_enabled) {
                        txn.Del(*m_cf_member_hash,
                                m_group.SerHashMember(member));
                    }
                }
                break;
            }
            if (page_num > 0) {
                --page_num;
                last_page_num_txs = m_conf.page_size;
            }
        }
    }
    mem_data.stats.t_total += SecondsSince(t_start);
}

void GroupHistoryWriter::Wipe(WriteTxn &txn) const {
    txn.Clear(m_cf_page);
    txn.Clear(m_cf_num_txs);
}

void GroupHistoryWriter::WipeMemberHash(WriteTxn &txn) const {
    if (!m_cf_member_hash) {
        // Rust: unwrap() on None
        throw ChronikError(std::string(m_group.Name()) +
                           " has no member hash column family");
    }
    txn.Clear(*m_cf_member_hash);
}

GroupHistoryWriter::Fetched
GroupHistoryWriter::FetchMembersNumTxs(const ReadTxn &txn,
                                       std::span<const IndexTx> txs,
                                       const GroupAux *aux,
                                       GroupHistoryMemData &mem_data) const {
    GroupHistoryStats &stats = mem_data.stats;
    Fetched fetched;
    const auto t_group = std::chrono::steady_clock::now();
    fetched.grouped_txs = GroupTxs(txs, aux);
    stats.t_group += SecondsSince(t_group);

    const auto t_ser_members = std::chrono::steady_clock::now();
    fetched.ser_members.reserve(fetched.grouped_txs.size());
    for (const auto &[member, tx_nums] : fetched.grouped_txs) {
        fetched.ser_members.push_back(m_group.SerMember(member));
    }
    stats.t_ser_members += SecondsSince(t_ser_members);

    stats.n_total += fetched.grouped_txs.size();

    const auto t_fetch = std::chrono::steady_clock::now();
    fetched.members_num_txs.reserve(fetched.ser_members.size());
    for (const Bytes &member_ser : fetched.ser_members) {
        const std::optional<ByteView> db_num_txs =
            txn.Get(m_cf_num_txs, member_ser);
        fetched.members_num_txs.push_back(db_num_txs ? BytesToNumTxs(*db_num_txs)
                                                     : 0);
    }
    stats.t_fetch += SecondsSince(t_fetch);
    return fetched;
}

std::vector<std::pair<Bytes, std::vector<TxNum>>>
GroupHistoryWriter::GroupTxs(std::span<const IndexTx> txs,
                             const GroupAux *aux) const {
    std::map<Bytes, std::vector<TxNum>> group_tx_nums;
    for (const IndexTx &index_tx : txs) {
        const GroupQuery query{index_tx.is_coinbase, index_tx.tx};
        for (Bytes &member : TxMembersForGroup(m_group, query, aux)) {
            std::vector<TxNum> &tx_nums = group_tx_nums[std::move(member)];
            if (!tx_nums.empty() && tx_nums.back() == index_tx.tx_num) {
                continue;
            }
            tx_nums.push_back(index_tx.tx_num);
        }
    }
    return {std::make_move_iterator(group_tx_nums.begin()),
            std::make_move_iterator(group_tx_nums.end())};
}

void GroupHistoryWriter::ReindexMemberHash(
    KvStore &store, const std::function<Bytes(ByteView)> &decompress_script,
    const std::function<bool()> &shutdown_requested,
    const std::function<void(const std::string &, bool)> &log) const {
    if (!m_cf_member_hash) {
        return;
    }
    log("Writing Chronik scripthash index.\n", false);
    const auto t_start = std::chrono::steady_clock::now();
    std::unique_ptr<WriteTxn> txn = store.BeginWrite();
    const uint64_t estimated_num_keys = txn->EstimateEntries(m_cf_num_txs);
    std::unique_ptr<Cursor> cursor = txn->OpenCursor(m_cf_num_txs);
    size_t db_idx = 0;
    bool ok = cursor->SeekFirst();
    while (ok) {
        if (db_idx % 10000 == 0 && shutdown_requested()) {
            log("Cancelled script hash reindexing before it completed.\n",
                false);
            // Like Rust, the pending (uncommitted) entries are dropped
            return;
        }
        const Bytes compressed_script(cursor->Key().begin(),
                                      cursor->Key().end());
        const Bytes script = decompress_script(compressed_script);
        txn->Put(*m_cf_member_hash, m_group.SerHashMember(script),
                 compressed_script);

        if (db_idx % 1000000 == 0) {
            log("Upgraded " + std::to_string(db_idx) + " of " +
                    std::to_string(estimated_num_keys) + " (estimated)\n",
                true);
            cursor.reset();
            txn->Commit();
            txn = store.BeginWrite();
            cursor = txn->OpenCursor(m_cf_num_txs);
            // Resume after the last processed key
            ok = cursor->SeekGe(compressed_script);
            if (ok && Equal(cursor->Key(), compressed_script)) {
                ok = cursor->Next();
            }
        } else {
            ok = cursor->Next();
        }
        ++db_idx;
    }
    cursor.reset();
    txn->Commit();
    const double duration = SecondsSince(t_start);
    log("Upgrade for scripthash index complete in " +
            std::to_string(duration) + " seconds\n",
        false);
}

GroupHistoryReader::GroupHistoryReader(const KvStore &store,
                                       const ReadTxn &txn,
                                       const GroupDef &group)
    : m_txn(txn), m_conf(RequireHistoryConf(group)),
      m_cf_page(store.Table(m_conf.cf_page_name)),
      m_cf_num_txs(store.Table(m_conf.cf_num_txs_name)),
      m_cf_member_hash(MemberHashTable(store, m_conf)) {}

std::optional<std::vector<TxNum>>
GroupHistoryReader::PageTxs(ByteView member_ser, PageNum page_num) const {
    const std::optional<ByteView> value =
        m_txn.Get(m_cf_page, KeyForMemberPage(member_ser, page_num));
    if (!value) {
        return std::nullopt;
    }
    return postcard::DbDeserializeVec(
        *value, "u64", [](postcard::Reader &r) { return r.U64(); });
}

std::pair<size_t, size_t>
GroupHistoryReader::MemberNumPagesAndTxs(ByteView member_ser) const {
    const std::optional<ByteView> bytes = m_txn.Get(m_cf_num_txs, member_ser);
    if (!bytes) {
        return {0, 0};
    }
    const NumTxs num_txs = BytesToNumTxs(*bytes);
    const NumTxs num_pages =
        num_txs / m_conf.page_size + (num_txs % m_conf.page_size != 0);
    return {num_pages, num_txs};
}

std::optional<Bytes> GroupHistoryReader::MemberSerByMemberHash(
    const std::array<uint8_t, 32> &member_hash) const {
    if (!m_cf_member_hash) {
        throw ChronikError(
            "Tried to access member hash db via non-script group");
    }
    const std::optional<ByteView> value =
        m_txn.Get(*m_cf_member_hash, member_hash);
    if (!value) {
        return std::nullopt;
    }
    return Bytes(value->begin(), value->end());
}

} // namespace chronik::native::index
