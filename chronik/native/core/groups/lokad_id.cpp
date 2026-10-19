// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/groups/lokad_id.h>

#include <chronik/native/schema.h>
#include <chronik/native/token/lokad_id.h>

namespace chronik::native::groups {

void LokadIdGroup::InputMembers(const GroupQuery &, const GroupAux *,
                                std::vector<MemberItem> &) const {
    // Don't use; actual parsing happens in OutputMembers
}

void LokadIdGroup::OutputMembers(const GroupQuery &query, const GroupAux *,
                                 std::vector<MemberItem> &out) const {
    // LOKAD ID is per-tx not per-utxo, so we only use OutputMembers
    const auto lokad_ids = token::ParseTxLokadIds(*query.tx);
    for (size_t idx = 0; idx < lokad_ids.size(); ++idx) {
        out.push_back(
            MemberItem{idx, Bytes(lokad_ids[idx].begin(), lokad_ids[idx].end())});
    }
}

Bytes LokadIdGroup::SerMember(ByteView member) const {
    return Bytes(member.begin(), member.end());
}

std::optional<GroupHistoryConf> LokadIdGroup::TxHistoryConf() const {
    return GroupHistoryConf{schema::kLokadIdHistory,
                            schema::kLokadIdHistoryNumTxs, 1000, std::nullopt};
}

} // namespace chronik::native::groups
