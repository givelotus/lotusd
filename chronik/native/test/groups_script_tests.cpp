// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db groups/script.rs tests, plus LokadIdGroup, TxIdGroup and
// group table specs.

#include <chronik/native/groups/lokad_id.h>
#include <chronik/native/groups/script.h>
#include <chronik/native/groups/txid.h>
#include <chronik/native/schema.h>

#include <test/index_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::groups;

namespace {

ScriptGroup MakeScriptGroup() {
    return ScriptGroup(
        [](ByteView data, uint8_t out[32]) { test::TestSha256(data, out); });
}

std::vector<MemberItem> Inputs(const GroupDef &group, const GroupQuery &q) {
    std::vector<MemberItem> out;
    group.InputMembers(q, nullptr, out);
    return out;
}

std::vector<MemberItem> Outputs(const GroupDef &group, const GroupQuery &q) {
    std::vector<MemberItem> out;
    group.OutputMembers(q, nullptr, out);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(groups_script_tests)

BOOST_AUTO_TEST_CASE(test_script_group) {
    const ScriptGroup script_group = MakeScriptGroup();
    Tx tx;
    for (const Bytes &script : {Bytes{0x51}, Bytes{0x52}}) {
        TxInput input;
        Coin coin;
        coin.output.script = script;
        input.coin = coin;
        tx.inputs.push_back(input);
    }
    for (const Bytes &script :
         {Bytes{0x53}, Bytes{0x6a}, Bytes{0x6a}, Bytes{0x51}, Bytes{0x6a}}) {
        TxOutput output;
        output.script = script;
        tx.outputs.push_back(output);
    }

    GroupQuery query{false, &tx};
    BOOST_CHECK(TxMembersForGroup(script_group, query, nullptr) ==
                (std::vector<Bytes>{{0x51}, {0x52}, {0x53}, {0x51}}));
    BOOST_CHECK(Inputs(script_group, query) ==
                (std::vector<MemberItem>{{0, {0x51}}, {1, {0x52}}}));
    BOOST_CHECK(Outputs(script_group, query) ==
                (std::vector<MemberItem>{{0, {0x53}}, {3, {0x51}}}));

    query = GroupQuery{true, &tx};
    BOOST_CHECK(TxMembersForGroup(script_group, query, nullptr) ==
                (std::vector<Bytes>{{0x53}, {0x51}}));
    BOOST_CHECK(Inputs(script_group, query).empty());
    BOOST_CHECK(Outputs(script_group, query) ==
                (std::vector<MemberItem>{{0, {0x53}}, {3, {0x51}}}));

    BOOST_CHECK(script_group.SerMember(Bytes{0x53}) == (Bytes{0x07, 0x53}));
}

BOOST_AUTO_TEST_CASE(test_script_group_inputs_stop_at_missing_coin) {
    const ScriptGroup script_group = MakeScriptGroup();
    Tx tx;
    tx.inputs.resize(3);
    tx.inputs[0].coin = Coin{TxOutput{1, {0x51}}, 0, false};
    tx.inputs[2].coin = Coin{TxOutput{1, {0x52}}, 0, false};
    const GroupQuery query{false, &tx};
    BOOST_CHECK(Inputs(script_group, query) ==
                (std::vector<MemberItem>{{0, {0x51}}}));
    // sha256("") as big-endian bytes
    const auto hash = script_group.SerHashMember(Bytes{});
    BOOST_CHECK_EQUAL(hash[0], 0x55);
    BOOST_CHECK_EQUAL(hash[31], 0xe3);
    BOOST_CHECK(script_group.IsHashMemberSupported());
}

BOOST_AUTO_TEST_CASE(test_lokad_id_and_txid_groups) {
    const LokadIdGroup lokad_id_group;
    const TxIdGroup txid_group;
    Tx tx;
    tx.txid = test::TxIdNum(7);
    tx.txid.b[0] = 1;
    tx.inputs.resize(1);
    TxOutput opreturn;
    // OP_RETURN "ABCD"
    opreturn.script = {0x6a, 0x04, 'A', 'B', 'C', 'D'};
    tx.outputs.push_back(opreturn);
    const GroupQuery query{false, &tx};

    BOOST_CHECK(Inputs(lokad_id_group, query).empty());
    BOOST_CHECK(Outputs(lokad_id_group, query) ==
                (std::vector<MemberItem>{{0, {'A', 'B', 'C', 'D'}}}));
    BOOST_CHECK(lokad_id_group.SerMember(Bytes{'A', 'B', 'C', 'D'}) ==
                (Bytes{'A', 'B', 'C', 'D'}));
    BOOST_CHECK(!lokad_id_group.IsHashMemberSupported());
    BOOST_CHECK(!lokad_id_group.UtxoConf());

    BOOST_CHECK(Inputs(txid_group, query).empty());
    const std::vector<MemberItem> txid_items = Outputs(txid_group, query);
    BOOST_REQUIRE_EQUAL(txid_items.size(), 1U);
    BOOST_CHECK(txid_items[0].member == Bytes(tx.txid.b.begin(),
                                              tx.txid.b.end()));
    const Bytes txid_ser = txid_group.SerMember(txid_items[0].member);
    BOOST_CHECK_EQUAL(txid_ser.front(), 7);
    BOOST_CHECK_EQUAL(txid_ser.back(), 1);
    BOOST_CHECK(GroupTableSpecs(txid_group).empty());
}

BOOST_AUTO_TEST_CASE(test_group_table_specs) {
    const auto script_specs = GroupTableSpecs(MakeScriptGroup());
    BOOST_REQUIRE_EQUAL(script_specs.size(), 4U);
    BOOST_CHECK(script_specs[0].name == schema::kScriptHistory);
    BOOST_CHECK(script_specs[1].name == schema::kScriptHistoryNumTxs);
    BOOST_CHECK(script_specs[2].name == schema::kScripthash);
    BOOST_CHECK(script_specs[3].name == schema::kScriptUtxo);
    BOOST_CHECK(script_specs[3].kind == TableSpec::Kind::Dup);
    BOOST_CHECK(script_specs[3].dup_fixed_size == uint32_t(20));

    const auto lokad_specs = GroupTableSpecs(LokadIdGroup());
    BOOST_REQUIRE_EQUAL(lokad_specs.size(), 2U);
    BOOST_CHECK(lokad_specs[0].name == schema::kLokadIdHistory);
    BOOST_CHECK(lokad_specs[1].name == schema::kLokadIdHistoryNumTxs);

    // The specs match the schema's tables
    schema::Schema schema;
    for (const TableSpec &spec : script_specs) {
        bool found = false;
        for (const TableSpec &table : schema.Tables()) {
            if (table.name == spec.name) {
                found = true;
                BOOST_CHECK(table.kind == spec.kind);
                BOOST_CHECK(table.dup_fixed_size == spec.dup_fixed_size);
            }
        }
        BOOST_CHECK(found);
    }
}

BOOST_AUTO_TEST_SUITE_END()
