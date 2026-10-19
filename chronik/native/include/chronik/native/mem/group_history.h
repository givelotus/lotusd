// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_MEM_GROUP_HISTORY_H
#define CHRONIK_NATIVE_MEM_GROUP_HISTORY_H

#include <chronik/native/extension.h>
#include <chronik/native/mem/mempool_tx.h>
#include <chronik/native/types.h>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <utility>

/** Port of chronik-db mem/group_history.rs. */
namespace chronik::native::mem {

/** Index the mempool tx history of a group. */
class MempoolGroupHistory {
public:
    /** (time_first_seen, txid), so we sort by time */
    using History = std::set<std::pair<int64_t, TxId>>;

    /** The group must outlive this; it must have a history conf. */
    explicit MempoolGroupHistory(const GroupDef &group);

    /** Index the given MempoolTx by this group. */
    void Insert(const MempoolTx &tx, const GroupAux *aux);

    /** Remove the given MempoolTx from the history index. */
    void Remove(const MempoolTx &tx, const GroupAux *aux);

    /**
     * The history of a given serialized member, ordered, or nullptr if
     * there are no entries.
     */
    const History *MemberHistory(ByteView member_ser) const;

    /**
     * Serialized member from member_hash (big-endian bytes); only relevant
     * for groups with a member hash table (MempoolScriptHistory).
     */
    std::optional<ByteView>
    MemberSerByMemberHash(const std::array<uint8_t, 32> &member_hash) const;

    /** All members (for tests/diagnostics). */
    const std::map<Bytes, History, std::less<>> &All() const {
        return m_history;
    }

private:
    std::map<Bytes, History, std::less<>> m_history;
    /** Script hash -> script, nullopt for non-script groups */
    std::optional<std::map<Bytes, Bytes, std::less<>>> m_member_hash_index;
    const GroupDef &m_group;
};

} // namespace chronik::native::mem

#endif // CHRONIK_NATIVE_MEM_GROUP_HISTORY_H
