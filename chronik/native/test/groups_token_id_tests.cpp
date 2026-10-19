// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// chronik-db groups/token_id.rs has no Rust tests; these check the group's
// members/serialization/tables, TokenIdGroupAux::from_{batch,db,probed_tx}
// and the token_id_history / token_id_utxo rows (eCash "Output" dup encoding)
// written through the group engine, the way the Rust indexer drives them.

#include <chronik/native/codec/hex.h>
#include <chronik/native/groups/token_id.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/index/group_utxos.h>
#include <chronik/native/schema.h>
#include <chronik/native/token/parse.h>
#include <chronik/native/token_io/io.h>

#include <test/index_test_util.h>
#include <test/token_io_mock.h>
#include <test/token_test_helpers.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::token;
using chronik::native::groups::TokenIdGroup;
using chronik::native::groups::TokenIdGroupAux;
using chronik::native::test::ErrorMsg;
using chronik::native::test::make_tx;
using chronik::native::test::TestDb;
using chronik::native::test::token_id;
using chronik::native::test::TxIdNum;

namespace {

Bytes Slp(const script::Script &script) {
    return script.bytecode();
}

Bytes Be(const TokenId &id) {
    const auto be = id.ToBeBytes();
    return Bytes(be.begin(), be.end());
}

Bytes Le(const TokenId &id) {
    return Bytes(id.txid.b.begin(), id.txid.b.end());
}

/** The Rust indexer's per-block token/token ID steps (indexer.rs). */
struct TokenIndexer {
    KvStore &store;
    TokenIdGroup group;
    index::BlockHeight block_height = -1;
    index::GroupHistoryMemData history_mem;
    index::GroupUtxoMemData utxo_mem;

    explicit TokenIndexer(KvStore &store_) : store(store_) {}

    TokenIdGroupAux Connect(const std::vector<Tx> &txs) {
        const index::TxWriter tx_writer(store);
        const token_io::TokenWriter token_writer(store);
        const index::GroupHistoryWriter history_writer(store, group);
        const index::GroupUtxoWriter utxo_writer(store, group);
        auto txn = store.BeginWrite();
        index::TxsMemData txs_mem;
        const index::TxNum first_tx_num = tx_writer.Insert(
            *txn, chronik::native::test::MockTokenDb::TxsBatch(txs, block_height + 1), txs_mem);
        const auto index_txs =
            index::PrepareIndexedTxs(store, *txn, first_tx_num, txs);
        const auto processed = token_writer.Insert(*txn, index_txs);
        TokenIdGroupAux aux = TokenIdGroupAux::FromBatch(index_txs, processed);
        history_writer.Insert(*txn, index_txs, &aux, history_mem);
        utxo_writer.Insert(*txn, index_txs, &aux, utxo_mem);
        txn->Commit();
        block_height += 1;
        return aux;
    }

    TokenIdGroupAux Disconnect(const std::vector<Tx> &txs) {
        const index::TxWriter tx_writer(store);
        const token_io::TokenWriter token_writer(store);
        const index::GroupHistoryWriter history_writer(store, group);
        const index::GroupUtxoWriter utxo_writer(store, group);
        auto txn = store.BeginWrite();
        index::TxsMemData txs_mem;
        const index::TxNum first_tx_num = tx_writer.Delete(
            *txn, chronik::native::test::MockTokenDb::TxsBatch(txs, block_height), txs_mem);
        const auto index_txs =
            index::PrepareIndexedTxs(store, *txn, first_tx_num, txs);
        // Read aux before deleting the token data (same txn)
        TokenIdGroupAux aux = TokenIdGroupAux::FromDb(index_txs, store, *txn);
        history_writer.Delete(*txn, index_txs, &aux, history_mem);
        utxo_writer.Delete(*txn, index_txs, &aux, utxo_mem);
        token_writer.Delete(*txn, index_txs);
        txn->Commit();
        block_height -= 1;
        return aux;
    }
};

std::vector<Bytes> RawDups(KvStore &store, std::string_view table,
                           const Bytes &key) {
    auto txn = store.BeginRead();
    auto cursor = txn->OpenDupCursor(store.Table(table));
    std::vector<Bytes> dups;
    if (cursor->Seek(key)) {
        do {
            const ByteView v = cursor->Value();
            dups.emplace_back(v.begin(), v.end());
        } while (cursor->Next());
    }
    return dups;
}

std::optional<std::vector<index::TxNum>> Page(KvStore &store,
                                              const GroupDef &group,
                                              const Bytes &member_ser) {
    auto txn = store.BeginRead();
    return index::GroupHistoryReader(store, *txn, group)
        .PageTxs(member_ser, 0);
}

} // namespace

BOOST_AUTO_TEST_SUITE(groups_token_id_tests)

BOOST_AUTO_TEST_CASE(test_token_id_group_def) {
    const TokenIdGroup group;
    BOOST_CHECK_EQUAL(group.Name(), "TokenIdGroup");
    BOOST_CHECK(!group.IsHashMemberSupported());
    BOOST_CHECK_EQUAL(ErrorMsg([&] { group.SerHashMember(Bytes(32)); }),
                      "There is no use case for hashing TokenIdGroup");
    TokenId id;
    for (size_t i = 0; i < 32; ++i) {
        id.txid.b[i] = uint8_t(i);
    }
    BOOST_CHECK(group.SerMember(Le(id)) == Be(id));
    BOOST_CHECK_EQUAL(group.SerMember(Le(id))[0], 31);
    const auto history = group.TxHistoryConf();
    BOOST_REQUIRE(history);
    BOOST_CHECK_EQUAL(history->cf_page_name, "token_id_history");
    BOOST_CHECK_EQUAL(history->cf_num_txs_name, "token_id_history_num_txs");
    BOOST_CHECK_EQUAL(history->page_size, 1000u);
    BOOST_CHECK(!history->cf_member_hash_name);
    const auto utxo = group.UtxoConf();
    BOOST_REQUIRE(utxo);
    BOOST_CHECK_EQUAL(utxo->cf_name, "token_id_utxo");
    BOOST_CHECK(group.UtxoData() == UtxoDataKind::Output);
    const auto specs = GroupTableSpecs(group);
    BOOST_REQUIRE_EQUAL(specs.size(), 3u);
    BOOST_CHECK_EQUAL(specs[2].name, "token_id_utxo");
    BOOST_CHECK(specs[2].kind == TableSpec::Kind::Dup);
    BOOST_CHECK(!specs[2].dup_fixed_size);
}

BOOST_AUTO_TEST_CASE(test_token_id_group_members) {
    const TokenIdGroup group;
    Tx tx = make_tx(7, {{1, 0}, {2, 0}}, 2, {});
    TokenIdGroupAux aux;
    aux.txs[tx.txid] = {{token_id(1), std::nullopt},
                        {std::nullopt, token_id(2), token_id(1)}};
    std::vector<MemberItem> out;
    group.InputMembers(GroupQuery{false, &tx}, &aux, out);
    BOOST_CHECK(out == (std::vector<MemberItem>{{0, Le(token_id(1))}}));
    out.clear();
    group.OutputMembers(GroupQuery{false, &tx}, &aux, out);
    BOOST_CHECK(out == (std::vector<MemberItem>{{1, Le(token_id(2))},
                                                {2, Le(token_id(1))}}));
    // Coinbase: no input members, but outputs still
    out.clear();
    group.InputMembers(GroupQuery{true, &tx}, &aux, out);
    BOOST_CHECK(out.empty());
    group.OutputMembers(GroupQuery{true, &tx}, &aux, out);
    BOOST_CHECK_EQUAL(out.size(), 2u);
    // Unknown tx / no aux
    out.clear();
    Tx other = make_tx(8, {}, 1, {});
    group.InputMembers(GroupQuery{false, &other}, &aux, out);
    group.OutputMembers(GroupQuery{false, &other}, &aux, out);
    group.InputMembers(GroupQuery{false, &tx}, nullptr, out);
    group.OutputMembers(GroupQuery{false, &tx}, nullptr, out);
    BOOST_CHECK(out.empty());
    // tx_members_for_group: inputs first
    const auto members = TxMembersForGroup(group, GroupQuery{false, &tx}, &aux);
    BOOST_CHECK(members == (std::vector<Bytes>{Le(token_id(1)),
                                               Le(token_id(2)),
                                               Le(token_id(1))}));
    // Also usable as the subscription hub's aux
    const TokenIdSubsAux &subs_aux = aux;
    BOOST_CHECK_EQUAL(subs_aux.txs.size(), 1u);
}

BOOST_AUTO_TEST_CASE(test_token_id_aux_from_probed_tx) {
    TokenTx token_tx;
    TokenTxEntry entry;
    entry.meta = token::test::meta_slp(token_id(3), SlpTokenType::Fungible());
    token_tx.entries.push_back(entry);
    token_tx.outputs = {std::nullopt, token::test::token_atoms<0>(5)};
    const std::vector<std::optional<SpentToken>> spent{
        std::nullopt,
        token::test::spent_atoms(
            token::test::meta_slp(token_id(4), SlpTokenType::Fungible()), 1)};
    const TokenIdGroupAux aux =
        TokenIdGroupAux::FromProbedTx(TxIdNum(9), token_tx, spent);
    BOOST_REQUIRE_EQUAL(aux.txs.count(TxIdNum(9)), 1u);
    const auto &[inputs, outputs] = aux.txs.at(TxIdNum(9));
    BOOST_CHECK(inputs ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt, token_id(4)}));
    BOOST_CHECK(outputs ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt, token_id(3)}));
}

BOOST_AUTO_TEST_CASE(test_token_id_index_connect_disconnect) {
    TestDb db("token_id_index");
    TokenIndexer indexer(*db);
    const TokenIdGroup &group = indexer.group;

    Tx genesis = make_tx(1, {}, 2,
                         Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                                  SlpTokenType::Fungible(), 2,
                                                  1000)));
    genesis.outputs[1] = TxOutput{546, {0x51}};
    genesis.outputs[2] = TxOutput{1000, {0x52, 0x53}};
    const std::vector<Tx> block0{make_tx(0, {{0xff, 0}}, 1, {}), genesis};
    const TokenIdGroupAux aux0 = indexer.Connect(block0);
    BOOST_CHECK_EQUAL(aux0.txs.size(), 1u);
    BOOST_CHECK(aux0.txs.at(TxIdNum(1)).second ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt, token_id(1),
                                               token_id(1)}));

    const Bytes key = Be(token_id(1));
    // token_id_utxo: tx_num BE8 || out_idx BE4 || sats LE8 || raw script
    {
        const auto dups = RawDups(*db, schema::kTokenIdUtxo, key);
        BOOST_REQUIRE_EQUAL(dups.size(), 2u);
        BOOST_CHECK_EQUAL(HexEncode(dups[0]), "0000000000000001"
                                              "00000001"
                                              "2202000000000000"
                                              "51");
        BOOST_CHECK_EQUAL(HexEncode(dups[1]), "0000000000000001"
                                              "00000002"
                                              "e803000000000000"
                                              "5253");
    }
    BOOST_CHECK(Page(*db, group, key) == (std::vector<index::TxNum>{1}));

    Tx send = make_tx(3, {{1, 1}}, 1,
                      Slp(slp::SendOpreturn(token_id(1),
                                            SlpTokenType::Fungible(), {1000})));
    send.outputs[1] = TxOutput{700, {0x54}};
    const std::vector<Tx> block1{make_tx(2, {{0xff, 0}}, 1, {}), send};
    const TokenIdGroupAux aux1 = indexer.Connect(block1);
    BOOST_CHECK(aux1.txs.at(TxIdNum(3)).first ==
                (TokenIdSubsAux::MaybeTokenIds{token_id(1)}));
    {
        const auto dups = RawDups(*db, schema::kTokenIdUtxo, key);
        BOOST_REQUIRE_EQUAL(dups.size(), 2u);
        BOOST_CHECK_EQUAL(HexEncode(dups[0]), "0000000000000001"
                                              "00000002"
                                              "e803000000000000"
                                              "5253");
        BOOST_CHECK_EQUAL(HexEncode(dups[1]), "0000000000000003"
                                              "00000001"
                                              "bc02000000000000"
                                              "54");
    }
    BOOST_CHECK(Page(*db, group, key) == (std::vector<index::TxNum>{1, 3}));

    // Disconnect block1: FromDb gives the same aux as FromBatch
    const TokenIdGroupAux aux1_db = indexer.Disconnect(block1);
    BOOST_CHECK(aux1_db.txs == aux1.txs);
    {
        const auto dups = RawDups(*db, schema::kTokenIdUtxo, key);
        BOOST_REQUIRE_EQUAL(dups.size(), 2u);
        BOOST_CHECK_EQUAL(HexEncode(dups[0]).substr(0, 24),
                          "000000000000000100000001");
    }
    BOOST_CHECK(Page(*db, group, key) == (std::vector<index::TxNum>{1}));

    // Disconnect block0: everything gone
    indexer.Disconnect(block0);
    BOOST_CHECK(RawDups(*db, schema::kTokenIdUtxo, key).empty());
    BOOST_CHECK(!Page(*db, group, key));
}

BOOST_AUTO_TEST_CASE(test_token_id_aux_unknown_tokens) {
    // Rust quirk preserved: from_batch maps spent unknown tokens to
    // TokenId::default() (all zeros), from_db maps them to None.
    TestDb db("token_id_unknown");
    TokenIndexer indexer(*db);
    indexer.Connect({make_tx(0, {{0xff, 0}}, 1, {}),
                     make_tx(1, {}, 2,
                             Slp(slp::GenesisOpreturn(
                                 GenesisInfo::EmptySlp(),
                                 SlpTokenType::Fungible(), std::nullopt,
                                 1000)))});
    const std::vector<Tx> block1{
        make_tx(2, {{0xff, 0}}, 1, {}),
        make_tx(3, {}, 2,
                Bytes{0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01, 0x44, 0x01,
                      0x01}),
        make_tx(4, {{3, 1}}, 1, {}),
    };
    const TokenIdGroupAux aux = indexer.Connect(block1);
    BOOST_CHECK(aux.txs.at(TxIdNum(4)).first ==
                (TokenIdSubsAux::MaybeTokenIds{TokenId{}}));
    // Unknown outputs map to the entry's meta (zero token ID for SLP unknown)
    BOOST_REQUIRE_EQUAL(aux.txs.count(TxIdNum(3)), 1u);
    const TokenIdGroupAux aux_db = indexer.Disconnect(block1);
    BOOST_CHECK(aux_db.txs.at(TxIdNum(4)).first ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt}));
    BOOST_CHECK(aux_db.txs.at(TxIdNum(3)).second ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt, std::nullopt,
                                               std::nullopt}));
}

BOOST_AUTO_TEST_SUITE_END()
