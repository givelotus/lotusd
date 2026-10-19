// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/mem/group_history.h>

#include <chronik/native/index/group_history.h>

namespace chronik::native::mem {

MempoolGroupHistory::MempoolGroupHistory(const GroupDef &group)
    : m_group(group) {
    const GroupHistoryConf conf = index::RequireHistoryConf(group);
    if (conf.cf_member_hash_name) {
        m_member_hash_index.emplace();
    }
}

void MempoolGroupHistory::Insert(const MempoolTx &tx, const GroupAux *aux) {
    const GroupQuery query{false, tx.tx.get()};
    for (const Bytes &member : TxMembersForGroup(m_group, query, aux)) {
        Bytes member_ser = m_group.SerMember(member);
        auto it = m_history.find(member_ser);
        if (it == m_history.end()) {
            if (m_member_hash_index) {
                const auto member_hash = m_group.SerHashMember(member);
                (*m_member_hash_index)[Bytes(member_hash.begin(),
                                             member_hash.end())] = member_ser;
            }
            it = m_history.emplace(std::move(member_ser), History{}).first;
        }
        it->second.emplace(tx.time_first_seen, tx.tx->txid);
    }
}

void MempoolGroupHistory::Remove(const MempoolTx &tx, const GroupAux *aux) {
    const GroupQuery query{false, tx.tx.get()};
    for (const Bytes &member : TxMembersForGroup(m_group, query, aux)) {
        const Bytes member_ser = m_group.SerMember(member);
        auto it = m_history.find(member_ser);
        if (it == m_history.end()) {
            continue;
        }
        it->second.erase({tx.time_first_seen, tx.tx->txid});
        if (it->second.empty()) {
            m_history.erase(it);
            if (m_member_hash_index) {
                const auto member_hash = m_group.SerHashMember(member);
                m_member_hash_index->erase(
                    Bytes(member_hash.begin(), member_hash.end()));
            }
        }
    }
}

const MempoolGroupHistory::History *
MempoolGroupHistory::MemberHistory(ByteView member_ser) const {
    const auto it = m_history.find(Bytes(member_ser.begin(), member_ser.end()));
    return it == m_history.end() ? nullptr : &it->second;
}

std::optional<ByteView> MempoolGroupHistory::MemberSerByMemberHash(
    const std::array<uint8_t, 32> &member_hash) const {
    if (!m_member_hash_index) {
        return std::nullopt;
    }
    const auto it = m_member_hash_index->find(
        Bytes(member_hash.begin(), member_hash.end()));
    if (it == m_member_hash_index->end()) {
        return std::nullopt;
    }
    return ByteView(it->second);
}

} // namespace chronik::native::mem
