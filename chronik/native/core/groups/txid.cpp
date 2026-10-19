// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/groups/txid.h>

namespace chronik::native::groups {

void TxIdGroup::InputMembers(const GroupQuery &, const GroupAux *,
                             std::vector<MemberItem> &) const {
    // Don't use; actual parsing happens in OutputMembers
}

void TxIdGroup::OutputMembers(const GroupQuery &query, const GroupAux *,
                              std::vector<MemberItem> &out) const {
    const TxId &txid = query.tx->txid;
    out.push_back(MemberItem{0, Bytes(txid.b.begin(), txid.b.end())});
}

Bytes TxIdGroup::SerMember(ByteView member) const {
    // member.hash().to_be_bytes()
    const auto reversed = Hash32::FromBytes(member).Reversed();
    return Bytes(reversed.begin(), reversed.end());
}

} // namespace chronik::native::groups
