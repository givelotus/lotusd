// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TEST_INDEX_VALUE_GROUP_H
#define CHRONIK_NATIVE_TEST_INDEX_VALUE_GROUP_H

#include <chronik/native/codec/bytes.h>
#include <chronik/native/extension.h>
#include <chronik/native/schema.h>

/**
 * Port of chronik-db test/value_group.rs ValueGroup: groups inputs/outputs by
 * their sats value (member = i64 BE8), with page size 4 to exercise paging.
 */
namespace chronik::native::test {

inline Bytes SerValue(int64_t sats) {
    const auto be = ToBe<int64_t>(sats);
    return Bytes(be.begin(), be.end());
}

/** The group's tables that the eCash schema doesn't already have. */
inline std::vector<TableSpec> ExtraGroupTables(const GroupDef &group) {
    const schema::Schema schema;
    std::vector<TableSpec> extra;
    for (const TableSpec &spec : GroupTableSpecs(group)) {
        bool known = false;
        for (const TableSpec &table : schema.Tables()) {
            known |= table.name == spec.name;
        }
        if (!known) {
            extra.push_back(spec);
        }
    }
    return extra;
}

class ValueGroup final : public GroupDef {
public:
    std::string_view Name() const override { return "ValueGroup"; }
    void InputMembers(const GroupQuery &query, const GroupAux *,
                      std::vector<MemberItem> &out) const override {
        if (query.is_coinbase) {
            return;
        }
        for (size_t idx = 0; idx < query.tx->inputs.size(); ++idx) {
            const TxInput &input = query.tx->inputs[idx];
            if (input.coin) {
                out.push_back(MemberItem{idx, SerValue(input.coin->output.sats)});
            }
        }
    }
    void OutputMembers(const GroupQuery &query, const GroupAux *,
                       std::vector<MemberItem> &out) const override {
        for (size_t idx = 0; idx < query.tx->outputs.size(); ++idx) {
            out.push_back(
                MemberItem{idx, SerValue(query.tx->outputs[idx].sats)});
        }
    }
    Bytes SerMember(ByteView member) const override {
        return Bytes(member.begin(), member.end());
    }
    std::optional<GroupHistoryConf> TxHistoryConf() const override {
        return GroupHistoryConf{"value_history", "value_history_num_txs", 4,
                                std::nullopt};
    }
    std::optional<GroupUtxoConf> UtxoConf() const override {
        return GroupUtxoConf{"value_utxo"};
    }
    UtxoDataKind UtxoData() const override { return UtxoDataKind::Value; }
};

} // namespace chronik::native::test

#endif // CHRONIK_NATIVE_TEST_INDEX_VALUE_GROUP_H
