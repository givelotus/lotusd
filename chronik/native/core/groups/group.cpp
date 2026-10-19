// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/extension.h>

#include <chronik/native/error.h>

namespace chronik::native {

std::optional<uint32_t> UtxoFixedDupSize(UtxoDataKind kind) {
    if (kind == UtxoDataKind::Value) {
        return 20;
    }
    return std::nullopt;
}

std::array<uint8_t, 32> GroupDef::SerHashMember(ByteView) const {
    throw ChronikError("There is no use case for hashing " +
                       std::string(Name()));
}

std::vector<Bytes> TxMembersForGroup(const GroupDef &group,
                                     const GroupQuery &query,
                                     const GroupAux *aux) {
    std::vector<MemberItem> items;
    group.InputMembers(query, aux, items);
    group.OutputMembers(query, aux, items);
    std::vector<Bytes> members;
    members.reserve(items.size());
    for (MemberItem &item : items) {
        members.push_back(std::move(item.member));
    }
    return members;
}

std::vector<TableSpec> GroupTableSpecs(const GroupDef &group) {
    std::vector<TableSpec> specs;
    if (const std::optional<GroupHistoryConf> conf = group.TxHistoryConf()) {
        specs.push_back(TableSpec{conf->cf_page_name, TableSpec::Kind::Plain,
                                  std::nullopt});
        specs.push_back(TableSpec{conf->cf_num_txs_name,
                                  TableSpec::Kind::Plain, std::nullopt});
        if (conf->cf_member_hash_name) {
            specs.push_back(TableSpec{*conf->cf_member_hash_name,
                                      TableSpec::Kind::Plain, std::nullopt});
        }
    }
    if (const std::optional<GroupUtxoConf> conf = group.UtxoConf()) {
        specs.push_back(TableSpec{conf->cf_name, TableSpec::Kind::Dup,
                                  UtxoFixedDupSize(group.UtxoData())});
    }
    return specs;
}

} // namespace chronik::native
