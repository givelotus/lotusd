// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_INDEX_GROUP_HISTORY_H
#define CHRONIK_NATIVE_INDEX_GROUP_HISTORY_H

#include <chronik/native/extension.h>
#include <chronik/native/index/data.h>
#include <chronik/native/index/index_tx.h>
#include <chronik/native/store.h>
#include <chronik/native/types.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

/**
 * Port of chronik-db io/group_history.rs.
 *
 * Txs of a group member are stored paginated: each page is stored at the key
 * `<serialized member> || <4-byte BE page num>` as concatenated postcard
 * TxNums, and the member's total number of txs at `<serialized member>` in the
 * num_txs table (u32 BE). Txs are ordered strictly ascendingly, within and
 * between pages.
 *
 * Pages are extended/trimmed with the Rust CONCAT ('C') / TRIM ('T') merge
 * operands, applied here as read-modify-writes with the same bytes and error
 * handling (index/merge.h).
 */
namespace chronik::native::index {

/** Represent page numbers with 32-bit unsigned integers. */
using PageNum = uint32_t;
/** Represent num txs with 32-bit unsigned integers. */
using NumTxs = uint32_t;

/** Settings for group history. */
struct GroupHistorySettings {
    /** Whether to index scripts by scripthash */
    bool is_member_hash_index_enabled = false;
};

/** Stats about cache hits, num requests etc. */
struct GroupHistoryStats {
    /** Total number of members updated. */
    size_t n_total = 0;
    /** Time [s] for insert/delete. */
    double t_total = 0;
    /** Time [s] for grouping txs. */
    double t_group = 0;
    /** Time [s] for serializing members. */
    double t_ser_members = 0;
    /** Time [s] for fetching existing tx data. */
    double t_fetch = 0;
};

/** In-memory data for the tx history. */
struct GroupHistoryMemData {
    GroupHistoryStats stats;
    /** Whether to index scripts by scripthash */
    bool is_member_hash_index_enabled = false;

    GroupHistoryMemData() = default;
    explicit GroupHistoryMemData(const GroupHistorySettings &settings)
        : is_member_hash_index_enabled(
              settings.is_member_hash_index_enabled) {}
};

/** Decode num_txs; "Inconsistent DB: Bad num_txs size: [..]" otherwise. */
NumTxs BytesToNumTxs(ByteView bytes);

/** `member_ser || page_num BE4` */
Bytes KeyForMemberPage(ByteView member_ser, PageNum page_num);

/** The history conf of the group; throws if it has none. */
GroupHistoryConf RequireHistoryConf(const GroupDef &group);

/** Write txs grouped and paginated to the DB. */
class GroupHistoryWriter {
public:
    GroupHistoryWriter(const KvStore &store, const GroupDef &group);

    /** Group the txs, then insert them to into each member of the group. */
    void Insert(WriteTxn &txn, std::span<const IndexTx> txs,
                const GroupAux *aux, GroupHistoryMemData &mem_data) const;

    /** Group the txs, then delete them from each member of the group. */
    void Delete(WriteTxn &txn, std::span<const IndexTx> txs,
                const GroupAux *aux, GroupHistoryMemData &mem_data) const;

    /** Clear all history data from the DB */
    void Wipe(WriteTxn &txn) const;

    /** Clear member_hash data from the DB */
    void WipeMemberHash(WriteTxn &txn) const;

    /**
     * Compute the script hash index (Rust `reindex_member_hash`), committing
     * its own write txns, the first after the first entry and then every
     * 1,000,000 entries. Checks `shutdown_requested` every 10,000 entries.
     * `log(msg, no_rate_limit)` receives the Rust log lines.
     */
    void ReindexMemberHash(
        KvStore &store,
        const std::function<Bytes(ByteView)> &decompress_script,
        const std::function<bool()> &shutdown_requested,
        const std::function<void(const std::string &, bool)> &log) const;

private:
    struct Fetched {
        std::vector<NumTxs> members_num_txs;
        std::vector<std::pair<Bytes, std::vector<TxNum>>> grouped_txs;
        std::vector<Bytes> ser_members;
    };

    Fetched FetchMembersNumTxs(const ReadTxn &txn,
                               std::span<const IndexTx> txs,
                               const GroupAux *aux,
                               GroupHistoryMemData &mem_data) const;

    std::vector<std::pair<Bytes, std::vector<TxNum>>>
    GroupTxs(std::span<const IndexTx> txs, const GroupAux *aux) const;

    const GroupDef &m_group;
    GroupHistoryConf m_conf;
    TableId m_cf_page;
    TableId m_cf_num_txs;
    std::optional<TableId> m_cf_member_hash;
};

/** Read pages of grouped txs from the DB. */
class GroupHistoryReader {
public:
    GroupHistoryReader(const KvStore &store, const ReadTxn &txn,
                       const GroupDef &group);

    /**
     * Read the tx_nums for the given member on the given page, or nullopt if
     * the page doesn't exist in the DB.
     */
    std::optional<std::vector<TxNum>> PageTxs(ByteView member_ser,
                                              PageNum page_num) const;

    /** Total number of pages and txs: (num_pages, num_txs). */
    std::pair<size_t, size_t> MemberNumPagesAndTxs(ByteView member_ser) const;

    /** Size of pages the data is stored in. */
    size_t PageSize() const { return m_conf.page_size; }

    /**
     * Serialized member from the member hash (big-endian bytes, Rust
     * `Sha256::to_be_bytes`); only for groups with a member hash table.
     */
    std::optional<Bytes>
    MemberSerByMemberHash(const std::array<uint8_t, 32> &member_hash) const;

private:
    const ReadTxn &m_txn;
    GroupHistoryConf m_conf;
    TableId m_cf_page;
    TableId m_cf_num_txs;
    std::optional<TableId> m_cf_member_hash;
};

} // namespace chronik::native::index

#endif // CHRONIK_NATIVE_INDEX_GROUP_HISTORY_H
