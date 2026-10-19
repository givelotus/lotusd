// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-db io/token/tests/test_batch_*.rs (all 11 #[test]s), plus
// the postcard encodings of the token tables and the TokenIndexError /
// BatchError texts.

#include <chronik/native/codec/hex.h>
#include <chronik/native/schema.h>
#include <chronik/native/token/parse.h>
#include <chronik/native/token_io/batch.h>
#include <chronik/native/token_io/data.h>
#include <chronik/native/token_io/io.h>
#include <chronik/native/token_io/token_index.h>
#include <chronik/native/groups/token_id.h>
#include <chronik/native/mem/tokens.h>

#include <test/index_test_util.h>
#include <test/token_io_mock.h>
#include <test/token_test_helpers.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native;
using namespace chronik::native::token;
using namespace chronik::native::token_io;
using chronik::native::test::CheckTokenTx;
using chronik::native::test::db_atoms;
using chronik::native::test::db_baton;
using chronik::native::test::ErrorMsg;
using chronik::native::test::make_tx;
using chronik::native::test::make_tx_with_scripts;
using chronik::native::test::MakeDbTokenTx;
using chronik::native::test::MockTokenDb;
using chronik::native::test::MockTokenReader;
using chronik::native::test::NoToken;
using chronik::native::test::TestDb;
using chronik::native::test::token_id;
using token::test::meta_alp;
using token::test::meta_slp;

namespace {

const Bytes EMPTY{};

GenesisInfo MakeInfo(Bytes ticker, Bytes name, Bytes url,
                     std::optional<std::array<uint8_t, 32>> hash,
                     uint8_t decimals) {
    GenesisInfo info;
    info.token_ticker = std::move(ticker);
    info.token_name = std::move(name);
    info.url = std::move(url);
    info.hash = hash;
    info.decimals = decimals;
    return info;
}

std::array<uint8_t, 32> Arr32(uint8_t b) {
    std::array<uint8_t, 32> a;
    a.fill(b);
    return a;
}

Bytes Slp(const script::Script &script) {
    return script.bytecode();
}

Bytes Alp(const std::vector<Bytes> &sections) {
    return alp::SectionsOpreturn(sections).bytecode();
}

using chronik::native::token::test::B;

} // namespace

BOOST_AUTO_TEST_SUITE(token_io_tests)

// ---- test_batch_common.rs ----

BOOST_AUTO_TEST_CASE(test_batch_skip_validation) {
    TestDb db("token_skip");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    // No token txs, and no tokens in the DB -> skipped validation
    auto processed = mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 4, EMPTY),
        make_tx(1, {{0, 1}}, 3, EMPTY),
        make_tx(2, {{0, 2}}, 3, EMPTY),
    });
    BOOST_CHECK(!processed.did_validation);

    // Empty SLP GENESIS -> does validation
    processed = mock_db.Connect({
        make_tx(3, {{0xff, 0}}, 4, EMPTY),
        make_tx(4, {{1, 1}}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                         SlpTokenType::Fungible(),
                                         std::nullopt, 0))),
    });
    BOOST_CHECK(processed.did_validation);
    CheckTokenTx(token_reader.token_tx(4),
                 MakeDbTokenTx({4}, {NoToken}, {NoToken, NoToken, NoToken}));

    // Empty ALP GENESIS -> does validation
    processed = mock_db.Connect({
        make_tx(5, {{0xff, 0}}, 4, EMPTY),
        make_tx(6, {{1, 2}}, 2,
                Alp({alp::GenesisSection(AlpTokenType::Standard(),
                                         GenesisInfo{}, ParsedMintData{})})),
    });
    BOOST_CHECK(processed.did_validation);
    CheckTokenTx(token_reader.token_tx(6),
                 MakeDbTokenTx({6}, {NoToken}, {NoToken, NoToken, NoToken}));
}

BOOST_AUTO_TEST_CASE(test_batch_cycle) {
    TestDb db("token_cycle");
    MockTokenDb mock_db(*db);

    // Cycle invalid, GENESIS depends on SEND of its own token
    // (can't happen in practice, but better test for it)
    const std::string msg = ErrorMsg([&] {
        mock_db.Connect({
            make_tx(3, {{0xff, 0}}, 2, EMPTY),
            make_tx(4, {{5, 0}}, 1,
                    Slp(slp::GenesisOpreturn(GenesisInfo{},
                                             SlpTokenType::Fungible(),
                                             std::nullopt, 0))),
            make_tx(5, {{4, 0}}, 1,
                    Slp(slp::SendOpreturn(token_id(4),
                                          SlpTokenType::Fungible(), {20}))),
        });
    });
    BOOST_CHECK_EQUAL(msg, "Cycle in SLP txs");
    // Also typed
    BOOST_CHECK_THROW(
        {
            MockTokenDb mock_db2(*db);
            mock_db2.Connect({
                make_tx(3, {{0xff, 0}}, 2, EMPTY),
                make_tx(4, {{5, 0}}, 1,
                        Slp(slp::GenesisOpreturn(GenesisInfo{},
                                                 SlpTokenType::Fungible(),
                                                 std::nullopt, 0))),
                make_tx(5, {{4, 0}}, 1,
                        Slp(slp::SendOpreturn(
                            token_id(4), SlpTokenType::Fungible(), {20}))),
            });
        },
        BatchError);
}

BOOST_AUTO_TEST_CASE(test_batch_topological_sort) {
    TestDb db("token_topo");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    const GenesisInfo genesis_info =
        MakeInfo(B("SLP FUNGIBLE"), B("Fungible "), B(""), Arr32(4), 4);
    // Valid: GENESIS SLP token and use it in the same batch; but txs aren't
    // ordered topologically.
    const auto processed = mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 2, EMPTY),
        // 4th tx: Non-token tx burns tokens
        make_tx(1, {{3, 1}}, 2, EMPTY),
        // 2nd tx: SEND tokens from GENESIS
        make_tx(2, {{4, 1}}, 1,
                Slp(slp::SendOpreturn(token_id(4), SlpTokenType::Fungible(),
                                      {400}))),
        // 3rd tx: SEND tokens again
        make_tx(3, {{2, 1}}, 2,
                Slp(slp::SendOpreturn(token_id(4), SlpTokenType::Fungible(),
                                      {300, 100}))),
        // 1st tx: GENESIS SLP token
        make_tx(4, {}, 2,
                Slp(slp::GenesisOpreturn(genesis_info,
                                         SlpTokenType::Fungible(), 2, 1000))),
    });
    BOOST_CHECK(processed.did_validation);

    // GENESIS SLP
    CheckTokenTx(token_reader.token_tx(4),
                 MakeDbTokenTx({4}, {},
                               {NoToken, db_atoms<0>(1000), db_baton<0>()}));
    BOOST_CHECK(token_reader.genesis_info(4) == genesis_info);
    BOOST_CHECK(token_reader.token_meta(4) ==
                meta_slp(token_id(4), SlpTokenType::Fungible()));
    // SEND from GENESIS
    CheckTokenTx(token_reader.token_tx(2),
                 MakeDbTokenTx({4}, {db_atoms<0>(1000)},
                               {NoToken, db_atoms<0>(400)}));
    BOOST_CHECK(!token_reader.genesis_info(2));
    BOOST_CHECK(!token_reader.token_meta(2));
    // SEND again
    CheckTokenTx(token_reader.token_tx(3),
                 MakeDbTokenTx({4}, {db_atoms<0>(400)},
                               {NoToken, db_atoms<0>(300), db_atoms<0>(100)}));
    BOOST_CHECK(!token_reader.genesis_info(3));
    BOOST_CHECK(!token_reader.token_meta(3));
    // Non-token tx burns the tokens
    CheckTokenTx(token_reader.token_tx(1),
                 MakeDbTokenTx({4}, {db_atoms<0>(300)},
                               {NoToken, NoToken, NoToken}));
    BOOST_CHECK(!token_reader.genesis_info(1));
    BOOST_CHECK(!token_reader.token_meta(1));
}

// ---- test_batch_alp.rs ----

BOOST_AUTO_TEST_CASE(test_batch_alp) {
    TestDb db("token_alp");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};
    const AlpTokenType STD = AlpTokenType::Standard();

    GenesisInfo genesis_info = MakeInfo(B("ALP STD"), B("ALP Standard"),
                                        B("https://example.com"),
                                        std::nullopt, 4);
    genesis_info.data = B("data");
    genesis_info.auth_pubkey = B("auth_pubkey");
    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 1, EMPTY),
        // GENESIS ALP
        make_tx(1, {}, 5,
                Alp({alp::GenesisSection(STD, genesis_info,
                                         ParsedMintData{{1, 0, 3}, 2})})),
        // MINT ALP in the same batch
        make_tx(2, {{1, 4}}, 5,
                Alp({alp::MintSection(token_id(1), STD,
                                      ParsedMintData{{4, 0, 0, 5}, 1})})),
        // SEND ALP in the same batch
        make_tx(3, {{1, 3}, {2, 1}}, 3,
                Alp({alp::SendSection(token_id(1), STD, {1, 0, 6})})),
    });
    // GENESIS ALP
    CheckTokenTx(token_reader.token_tx(1),
                 MakeDbTokenTx({1}, {},
                               {NoToken, db_atoms<0>(1), NoToken,
                                db_atoms<0>(3), db_baton<0>(),
                                db_baton<0>()}));
    BOOST_CHECK(token_reader.genesis_info(1) == genesis_info);
    BOOST_CHECK(token_reader.token_meta(1) == meta_alp(token_id(1)));
    // MINT ALP
    CheckTokenTx(token_reader.token_tx(2),
                 MakeDbTokenTx({1}, {db_baton<0>()},
                               {NoToken, db_atoms<0>(4), NoToken, NoToken,
                                db_atoms<0>(5), db_baton<0>()}));
    BOOST_CHECK(!token_reader.genesis_info(2));
    BOOST_CHECK(!token_reader.token_meta(2));
    // SEND ALP
    CheckTokenTx(token_reader.token_tx(3),
                 MakeDbTokenTx({1}, {db_atoms<0>(3), db_atoms<0>(4)},
                               {NoToken, db_atoms<0>(1), NoToken,
                                db_atoms<0>(6)}));
    BOOST_CHECK(!token_reader.genesis_info(3));
    BOOST_CHECK(!token_reader.token_meta(3));

    mock_db.Connect({
        make_tx(4, {{0xff, 0}}, 1, EMPTY),
        // another GENESIS ALP + a MINT of token 1
        make_tx(5, {{2, 5}, {1, 1}}, 5,
                Alp({alp::GenesisSection(STD, GenesisInfo{},
                                         ParsedMintData{{100, 0, 200}, 1}),
                     alp::MintSection(token_id(1), STD,
                                      ParsedMintData{{0, 4, 0, 0}, 1})})),
    });
    // GENESIS + MINT
    CheckTokenTx(token_reader.token_tx(5),
                 MakeDbTokenTx({5, 1}, {db_baton<1>(), db_atoms<1>(1)},
                               {NoToken, db_atoms<0>(100), db_atoms<1>(4),
                                db_atoms<0>(200), db_baton<0>(),
                                db_baton<1>()}));
    BOOST_CHECK(token_reader.genesis_info(5) == GenesisInfo::EmptyAlp());
    BOOST_CHECK(token_reader.token_meta(5) == meta_alp(token_id(5)));
}

// ---- test_batch_burn.rs ----

BOOST_AUTO_TEST_CASE(test_batch_burn) {
    TestDb db("token_burn");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};
    const AlpTokenType STD = AlpTokenType::Standard();
    const SlpTokenType FUNGIBLE = SlpTokenType::Fungible();

    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 1, EMPTY),
        // Empty SLP BURN with no inputs (not recorded in DB at all)
        make_tx(1, {}, 0, Slp(slp::BurnOpreturn(token_id(3), FUNGIBLE, 20))),
        // Empty ALP BURN with no inputs (not recorded in DB at all)
        make_tx(2, {}, 0, Alp({alp::BurnSection(token_id(4), STD, 20)})),
        // GENESIS SLP
        make_tx(3, {}, 1,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(), FUNGIBLE,
                                         std::nullopt, 1000))),
        // GENESIS ALP
        make_tx(4, {}, 2,
                Alp({alp::GenesisSection(STD, GenesisInfo::EmptyAlp(),
                                         ParsedMintData{{1000, 2000}, 0})})),
        // Actual SLP BURN, recorded in DB
        make_tx(5, {{3, 1}}, 0,
                Slp(slp::BurnOpreturn(token_id(3), FUNGIBLE, 1000))),
        // Actual ALP BURN, recorded in DB
        make_tx(6, {{4, 1}}, 0, Alp({alp::BurnSection(token_id(4), STD, 1000)})),
    });

    // Empty SLP BURN not recorded
    CheckTokenTx(token_reader.token_tx(1), std::nullopt);
    // Empty ALP BURN not recorded
    CheckTokenTx(token_reader.token_tx(2), std::nullopt);
    // Actual SLP BURN
    CheckTokenTx(token_reader.token_tx(5),
                 MakeDbTokenTx({3}, {db_atoms<0>(1000)}, {NoToken}));
    // Actual ALP BURN
    CheckTokenTx(token_reader.token_tx(6),
                 MakeDbTokenTx({4}, {db_atoms<0>(1000)}, {NoToken}));
}

// ---- test_batch_disconnect_block.rs ----

BOOST_AUTO_TEST_CASE(test_batch_disconnect) {
    TestDb db("token_disconnect");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};
    const AlpTokenType STD = AlpTokenType::Standard();
    const SlpTokenType FUNGIBLE = SlpTokenType::Fungible();

    const std::vector<Tx> block0{
        make_tx(0, {{0xff, 0}}, 2, EMPTY),
        // GENESIS SLP token
        make_tx(1, {}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(), FUNGIBLE, 2,
                                         1000))),
        // MINT SLP
        make_tx(2, {{1, 2}}, 2,
                Slp(slp::MintOpreturn(token_id(1), FUNGIBLE, 2, 500))),
        // SEND SLP
        make_tx(3, {{1, 1}, {2, 1}}, 2,
                Slp(slp::SendOpreturn(token_id(1), FUNGIBLE, {400, 1100}))),
        // GENESIS ALP
        make_tx(4, {}, 5,
                Alp({alp::GenesisSection(STD, GenesisInfo::EmptyAlp(),
                                         ParsedMintData{{1, 0, 3}, 2})})),
        // MINT ALP
        make_tx(5, {{4, 4}}, 5,
                Alp({alp::MintSection(token_id(4), STD,
                                      ParsedMintData{{4, 0, 0, 5}, 1})})),
        // SEND ALP
        make_tx(6, {{4, 3}, {5, 1}}, 3,
                Alp({alp::SendSection(token_id(4), STD, {1, 0, 6})})),
    };
    mock_db.Connect(block0);

    // Verify tokens have been added
    BOOST_CHECK(token_reader.genesis_info(1).has_value());
    BOOST_CHECK(token_reader.token_meta(1) == meta_slp(token_id(1), FUNGIBLE));
    BOOST_CHECK(token_reader.genesis_info(4).has_value());
    BOOST_CHECK(token_reader.token_meta(4) == meta_alp(token_id(4)));
    for (TxNum tx_num = 1; tx_num <= 6; ++tx_num) {
        BOOST_CHECK(token_reader.token_tx(tx_num).has_value());
    }

    const std::vector<Tx> block1{
        make_tx(7, {{0xff, 0}}, 2, EMPTY),
        // GENESIS another SLP token
        make_tx(8, {}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                         SlpTokenType::Nft1Group(), 2, 1000))),
        // MINT that SLP token
        make_tx(9, {{8, 2}}, 2,
                Slp(slp::MintOpreturn(token_id(8), SlpTokenType::Nft1Group(),
                                      2, 500))),
    };
    mock_db.Connect(block1);
    BOOST_CHECK(token_reader.genesis_info(1) == GenesisInfo::EmptySlp());
    BOOST_CHECK(token_reader.token_meta(8) ==
                meta_slp(token_id(8), SlpTokenType::Nft1Group()));

    // Disconnect block1, only removes last two txs
    mock_db.Disconnect(block1);
    for (TxNum tx_num = 8; tx_num <= 9; ++tx_num) {
        BOOST_CHECK(!token_reader.token_tx(tx_num));
        BOOST_CHECK(!token_reader.genesis_info(tx_num));
        BOOST_CHECK(!token_reader.token_meta(tx_num));
    }
    // Token data of block0 is still there
    BOOST_CHECK(token_reader.genesis_info(1).has_value());
    BOOST_CHECK(token_reader.token_meta(1) == meta_slp(token_id(1), FUNGIBLE));
    BOOST_CHECK(token_reader.genesis_info(4).has_value());
    BOOST_CHECK(token_reader.token_meta(4) == meta_alp(token_id(4)));
    for (TxNum tx_num = 1; tx_num <= 6; ++tx_num) {
        BOOST_CHECK(token_reader.token_tx(tx_num).has_value());
    }

    // Disconnect block0; now everything is empty
    mock_db.Disconnect(block0);
    for (TxNum tx_num = 1; tx_num <= 9; ++tx_num) {
        BOOST_CHECK(!token_reader.token_tx(tx_num));
        BOOST_CHECK(!token_reader.genesis_info(tx_num));
        BOOST_CHECK(!token_reader.token_meta(tx_num));
    }
}

// ---- test_batch_genesis.rs ----

BOOST_AUTO_TEST_CASE(test_batch_genesis_slp_fungible) {
    TestDb db("token_genesis_slp");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    const GenesisInfo genesis_info =
        MakeInfo(B("SLP FUNGIBLE"), B("Fungible"), B("https://example.com"),
                 Arr32(4), 4);
    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 4, EMPTY),
        make_tx(1, {}, 3,
                Slp(slp::GenesisOpreturn(genesis_info,
                                         SlpTokenType::Fungible(), 3, 1000))),
    });
    CheckTokenTx(token_reader.token_tx(1),
                 MakeDbTokenTx({1}, {},
                               {NoToken, db_atoms<0>(1000), NoToken,
                                db_baton<0>()}));
    BOOST_CHECK(token_reader.token_meta(1) ==
                meta_slp(token_id(1), SlpTokenType::Fungible()));
    BOOST_CHECK(token_reader.genesis_info(1) == genesis_info);
}

BOOST_AUTO_TEST_CASE(test_batch_genesis_alp) {
    TestDb db("token_genesis_alp");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    GenesisInfo genesis_info = MakeInfo(B("ALP STD"), B("ALP Standard"),
                                        B("https://example.com"),
                                        std::nullopt, 4);
    genesis_info.data = B("data");
    genesis_info.auth_pubkey = B("auth_pubkey");
    const auto processed = mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 4, EMPTY),
        make_tx(1, {}, 5,
                Alp({alp::GenesisSection(AlpTokenType::Standard(),
                                         genesis_info,
                                         ParsedMintData{{100, 0, 200}, 2})})),
    });
    BOOST_CHECK(processed.did_validation);
    CheckTokenTx(token_reader.token_tx(1),
                 MakeDbTokenTx({1}, {},
                               {NoToken, db_atoms<0>(100), NoToken,
                                db_atoms<0>(200), db_baton<0>(),
                                db_baton<0>()}));
    BOOST_CHECK(token_reader.token_meta(1) == meta_alp(token_id(1)));
    BOOST_CHECK(token_reader.genesis_info(1) == genesis_info);
}

// ---- test_batch_nft.rs ----

BOOST_AUTO_TEST_CASE(test_batch_slp_nft1) {
    TestDb db("token_nft1");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};
    const SlpTokenType GROUP = SlpTokenType::Nft1Group();
    const SlpTokenType CHILD = SlpTokenType::Nft1Child();
    const auto info = [](Bytes ticker) {
        GenesisInfo i = GenesisInfo::EmptySlp();
        i.token_ticker = std::move(ticker);
        return i;
    };

    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 4, EMPTY),
        make_tx(1, {}, 2,
                Slp(slp::GenesisOpreturn(info(B("NFT GROUP")), GROUP, 2,
                                         1000))),
        make_tx(2, {{1, 1}}, 5,
                Slp(slp::SendOpreturn(token_id(1), GROUP,
                                      {1, 1, 1, 1, 996}))),
        make_tx(3, {{2, 1}}, 1,
                Slp(slp::GenesisOpreturn(info(B("NFT CHILD 1")), CHILD,
                                         std::nullopt, 1))),
        make_tx(4, {{2, 2}}, 1,
                Slp(slp::GenesisOpreturn(info(B("NFT CHILD 2")), CHILD,
                                         std::nullopt, 1))),
        make_tx(5, {}, 1,
                Slp(slp::GenesisOpreturn(info(B("NFT CHILD 3")), CHILD,
                                         std::nullopt, 1))),
    });
    CheckTokenTx(token_reader.token_tx(1),
                 MakeDbTokenTx({1}, {},
                               {NoToken, db_atoms<0>(1000), db_baton<0>()}));
    BOOST_CHECK(token_reader.token_meta(1) == meta_slp(token_id(1), GROUP));
    BOOST_CHECK(token_reader.genesis_info(1) == info(B("NFT GROUP")));

    CheckTokenTx(token_reader.token_tx(2),
                 MakeDbTokenTx({1}, {db_atoms<0>(1000)},
                               {NoToken, db_atoms<0>(1), db_atoms<0>(1),
                                db_atoms<0>(1), db_atoms<0>(1),
                                db_atoms<0>(996)}));
    BOOST_CHECK(!token_reader.token_meta(2));
    BOOST_CHECK(!token_reader.genesis_info(2));

    CheckTokenTx(token_reader.token_tx(3),
                 MakeDbTokenTx({3, 1}, {db_atoms<1>(1)},
                               {NoToken, db_atoms<0>(1)}, {{0, 1}}));
    BOOST_CHECK(token_reader.token_meta(3) == meta_slp(token_id(3), CHILD));
    BOOST_CHECK(token_reader.genesis_info(3) == info(B("NFT CHILD 1")));

    CheckTokenTx(token_reader.token_tx(4),
                 MakeDbTokenTx({4, 1}, {db_atoms<1>(1)},
                               {NoToken, db_atoms<0>(1)}, {{0, 1}}));
    BOOST_CHECK(token_reader.token_meta(4) == meta_slp(token_id(4), CHILD));
    BOOST_CHECK(token_reader.genesis_info(4) == info(B("NFT CHILD 2")));

    CheckTokenTx(token_reader.token_tx(5),
                 MakeDbTokenTx({}, {}, {NoToken, NoToken}));
    BOOST_CHECK(!token_reader.token_meta(5));
    BOOST_CHECK(!token_reader.genesis_info(5));

    mock_db.Connect({
        make_tx(6, {{0xff, 0}}, 4, EMPTY),
        make_tx(7, {{2, 3}}, 1,
                Slp(slp::GenesisOpreturn(info(B("NFT CHILD 4")), CHILD,
                                         std::nullopt, 1))),
        make_tx(8, {{2, 4}, {3, 1}, {5, 1}, {7, 1}}, 1, EMPTY),
    });

    CheckTokenTx(token_reader.token_tx(7),
                 MakeDbTokenTx({7, 1}, {db_atoms<1>(1)},
                               {NoToken, db_atoms<0>(1)}, {{0, 1}}));
    BOOST_CHECK(token_reader.token_meta(7) == meta_slp(token_id(7), CHILD));
    BOOST_CHECK(token_reader.genesis_info(7) == info(B("NFT CHILD 4")));

    CheckTokenTx(token_reader.token_tx(8),
                 MakeDbTokenTx({1, 3, 7},
                               {db_atoms<0>(1), db_atoms<1>(1), NoToken,
                                db_atoms<2>(1)},
                               {NoToken, NoToken}, {{1, 0}, {2, 0}}));
    BOOST_CHECK(!token_reader.token_meta(8));
    BOOST_CHECK(!token_reader.genesis_info(8));
}

// ---- test_batch_unknown.rs ----

BOOST_AUTO_TEST_CASE(test_batch_unknown) {
    TestDb db("token_unknown");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    const std::vector<Tx> block0{
        make_tx(0, {{0xff, 0}}, 1, EMPTY),
        make_tx(1, {}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                         SlpTokenType::Fungible(),
                                         std::nullopt, 1000))),
    };
    mock_db.Connect(block0);
    // Unknown token types
    const std::vector<Tx> block1{
        make_tx(2, {{0xff, 0}}, 1, EMPTY),
        // Unknown ALP outputs
        make_tx(3, {{1, 1}}, 2, Alp({Bytes{'S', 'L', 'P', '2', 0x22}})),
        // Unknown SLP outputs
        make_tx(4, {}, 2,
                Bytes{0x6a, 0x04, 'S', 'L', 'P', 0x00, 0x01, 0x44, 0x01,
                      0x01}),
        // Unknown ALP/SLP inputs from the same batch
        make_tx(5, {{3, 1}, {4, 1}}, 1, EMPTY),
    };
    mock_db.Connect(block1);
    CheckTokenTx(token_reader.token_tx(3),
                 MakeDbTokenTx({1}, {db_atoms<0>(1000)},
                               {NoToken, DbToken::UnknownAlp(0x22),
                                DbToken::UnknownAlp(0x22)}));
    CheckTokenTx(token_reader.token_tx(4),
                 MakeDbTokenTx({}, {},
                               {NoToken, DbToken::UnknownSlp(0x44),
                                DbToken::UnknownSlp(0x44)}));
    CheckTokenTx(token_reader.token_tx(5),
                 MakeDbTokenTx({},
                               {DbToken::UnknownAlp(0x22),
                                DbToken::UnknownSlp(0x44)},
                               {NoToken, NoToken}));

    const std::vector<Tx> block2{
        make_tx(6, {{0xff, 0}}, 1, EMPTY),
        // Unknown ALP/SLP inputs from the DB
        make_tx(7, {{3, 2}, {4, 2}}, 1, EMPTY),
    };
    mock_db.Connect(block2);
    CheckTokenTx(token_reader.token_tx(7),
                 MakeDbTokenTx({},
                               {DbToken::UnknownAlp(0x22),
                                DbToken::UnknownSlp(0x44)},
                               {NoToken, NoToken}));

    mock_db.Disconnect(block2);
    mock_db.Disconnect(block1);
    mock_db.Disconnect(block0);
}

// ---- test_batch_vault.rs ----

BOOST_AUTO_TEST_CASE(test_batch_vault) {
    TestDb db("token_vault");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};

    script::ShaRmd160 vault_scripthash;
    vault_scripthash.fill(0x44);
    const Bytes p2sh_vault = script::Script::P2sh(vault_scripthash).bytecode();
    GenesisInfo vault_genesis_info;
    vault_genesis_info.token_ticker = B("SLP VAULT");
    vault_genesis_info.token_name = B("Fungible ");
    vault_genesis_info.mint_vault_scripthash = vault_scripthash;
    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 3, EMPTY),
        // Invalid: MINT SLP V2 in the same block (GENESIS depends on this
        // MINT)
        make_tx_with_scripts(
            1, {{0, 0, p2sh_vault}}, 2,
            Slp(slp::MintVaultOpreturn(token_id(2), {3000, 4000}))),
        // GENESIS SLP V2 Mint Vault
        make_tx(2, {{1, 0}}, 1,
                Slp(slp::GenesisOpreturn(vault_genesis_info,
                                         SlpTokenType::MintVault(),
                                         std::nullopt, 2000))),
        // Invalid: MINT SLP V2 in the same block
        make_tx_with_scripts(
            3, {{1, 1, p2sh_vault}}, 2,
            Slp(slp::MintVaultOpreturn(token_id(2), {3000, 4000}))),
    });
    CheckTokenTx(token_reader.token_tx(1), std::nullopt);
    BOOST_CHECK(!token_reader.genesis_info(1));
    BOOST_CHECK(!token_reader.token_meta(1));

    CheckTokenTx(token_reader.token_tx(2),
                 MakeDbTokenTx({2}, {NoToken}, {NoToken, db_atoms<0>(2000)}));
    BOOST_CHECK(token_reader.token_meta(2) ==
                meta_slp(token_id(2), SlpTokenType::MintVault()));
    BOOST_CHECK(token_reader.genesis_info(2) == vault_genesis_info);

    CheckTokenTx(token_reader.token_tx(3), std::nullopt);
    BOOST_CHECK(!token_reader.genesis_info(3));
    BOOST_CHECK(!token_reader.token_meta(3));

    mock_db.Connect({
        make_tx(4, {{0xff, 0}}, 1, EMPTY),
        // MINT SLP V2 (valid: is from another block)
        make_tx_with_scripts(
            5, {{0, 2, p2sh_vault}}, 2,
            Slp(slp::MintVaultOpreturn(token_id(2), {3000, 4000}))),
        // Invalid MINT SLP V2 without valid mint vault
        make_tx(6, {{0, 2}}, 1,
                Slp(slp::MintVaultOpreturn(token_id(2), {7777}))),
        // Use both DB token in SLP SEND and token from this batch
        make_tx(7, {{2, 1}, {5, 1}}, 2,
                Slp(slp::SendOpreturn(token_id(2), SlpTokenType::MintVault(),
                                      {4500, 500}))),
    });
    CheckTokenTx(token_reader.token_tx(5),
                 MakeDbTokenTx({2}, {NoToken},
                               {NoToken, db_atoms<0>(3000), db_atoms<0>(4000)},
                               {}, FLAGS_HAS_MINT_VAULT));
    CheckTokenTx(token_reader.token_tx(6), std::nullopt);
    CheckTokenTx(token_reader.token_tx(7),
                 MakeDbTokenTx({2}, {db_atoms<0>(2000), db_atoms<0>(3000)},
                               {NoToken, db_atoms<0>(4500), db_atoms<0>(500)},
                               {}, 0));
}

// ---- Additional: byte-exact postcard encodings ----

BOOST_AUTO_TEST_CASE(test_db_token_tx_encoding) {
    const DbTokenTx tx = MakeDbTokenTx({4}, {db_atoms<0>(1000)},
                                       {NoToken, db_atoms<0>(400)});
    const Bytes ser = SerializeDbTokenTx(tx);
    BOOST_CHECK_EQUAL(HexEncode(ser),
                      "0104" "00" "010100e807" "020001009003" "00");
    BOOST_CHECK(DeserializeDbTokenTx(ser) == tx);

    const DbTokenTx tx2 = MakeDbTokenTx(
        {3, 300}, {db_atoms<1>(1)},
        {NoToken, db_atoms<0>(1), db_baton<0>(), DbToken::UnknownSlp(0x44),
         DbToken::UnknownAlp(0x22)},
        {{0, 1}}, FLAGS_HAS_MINT_VAULT);
    const Bytes ser2 = SerializeDbTokenTx(tx2);
    BOOST_CHECK_EQUAL(HexEncode(ser2), "0203ac02"
                                       "010001"
                                       "01010101"
                                       "05"
                                       "00"
                                       "010001"
                                       "0200"
                                       "0344"
                                       "0422"
                                       "01");
    BOOST_CHECK(DeserializeDbTokenTx(ser2) == tx2);
    BOOST_CHECK(DeserializeDbTokenTx(SerializeDbTokenTx(DbTokenTx{})) ==
                DbTokenTx{});
    BOOST_CHECK_EQUAL(HexEncode(SerializeDbTokenTx(DbTokenTx{})), "0000000000");
}

BOOST_AUTO_TEST_CASE(test_token_meta_encoding) {
    const std::string id4(64, '4');
    const auto hex = [](const TokenMeta &meta) {
        return HexEncode(SerializeTokenMeta(meta));
    };
    const std::string id_hex = [] {
        std::string s;
        for (int i = 0; i < 32; ++i) {
            s += "04";
        }
        return s;
    }();
    BOOST_CHECK_EQUAL(hex(meta_slp(token_id(4), SlpTokenType::Fungible())),
                      id_hex + "0000");
    BOOST_CHECK_EQUAL(hex(meta_slp(token_id(4), SlpTokenType::MintVault())),
                      id_hex + "0001");
    BOOST_CHECK_EQUAL(hex(meta_slp(token_id(4), SlpTokenType::Nft1Group())),
                      id_hex + "0002");
    BOOST_CHECK_EQUAL(hex(meta_slp(token_id(4), SlpTokenType::Nft1Child())),
                      id_hex + "0003");
    BOOST_CHECK_EQUAL(
        hex(meta_slp(token_id(4), SlpTokenType::Unknown(0x99))),
        id_hex + "000499");
    BOOST_CHECK_EQUAL(hex(meta_alp(token_id(4))), id_hex + "0100");
    BOOST_CHECK_EQUAL(hex(token::test::meta_alp_unknown(token_id(4), 0x22)),
                      id_hex + "010122");
    // Internal (LE) byte order of the token ID
    TokenId mixed;
    for (size_t i = 0; i < 32; ++i) {
        mixed.txid.b[i] = uint8_t(i);
    }
    const TokenMeta meta = meta_alp(mixed);
    const Bytes ser = SerializeTokenMeta(meta);
    BOOST_CHECK_EQUAL(ser[0], 0);
    BOOST_CHECK_EQUAL(ser[31], 31);
    BOOST_CHECK(DeserializeTokenMeta(ser) == meta);
    for (const auto &m :
         {meta_slp(token_id(1), SlpTokenType::Unknown(7)),
          token::test::meta_alp_unknown(token_id(2), 9),
          meta_slp(token_id(3), SlpTokenType::Nft1Child())}) {
        BOOST_CHECK(DeserializeTokenMeta(SerializeTokenMeta(m)) == m);
    }
}

BOOST_AUTO_TEST_CASE(test_genesis_info_encoding) {
    GenesisInfo info;
    info.token_ticker = B("ABC");
    info.mint_vault_scripthash = script::ShaRmd160{};
    info.mint_vault_scripthash->fill(2);
    info.url = B("u");
    info.data = B("d");
    info.decimals = 4;
    std::string expected = "03414243" "00" "01";
    for (int i = 0; i < 20; ++i) {
        expected += "02";
    }
    expected += "0175" "00" "010164" "00" "04";
    BOOST_CHECK_EQUAL(HexEncode(SerializeGenesisInfo(info)), expected);
    BOOST_CHECK(DeserializeGenesisInfo(SerializeGenesisInfo(info)) == info);

    // empty_slp / empty_alp
    BOOST_CHECK_EQUAL(HexEncode(SerializeGenesisInfo(GenesisInfo::EmptySlp())),
                      "00000000000000" "00");
    BOOST_CHECK_EQUAL(HexEncode(SerializeGenesisInfo(GenesisInfo::EmptyAlp())),
                      "000000000001000100" "00");
    GenesisInfo with_hash = GenesisInfo::EmptyAlp();
    with_hash.hash = Arr32(0xab);
    with_hash.auth_pubkey = B("auth_pubkey");
    BOOST_CHECK(DeserializeGenesisInfo(SerializeGenesisInfo(with_hash)) ==
                with_hash);
}

BOOST_AUTO_TEST_CASE(test_token_deserialize_errors) {
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DeserializeDbTokenTx(Bytes{0x05}); }),
        "Inconsistent DB: Cannot deserialize byte sequence as "
        "chronik_db::io::token::data::DbTokenTx: Hit the end of buffer, "
        "expected more data. Byte sequence: 05");
    Bytes leftover = SerializeDbTokenTx(DbTokenTx{});
    leftover.push_back(0xff);
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { DeserializeDbTokenTx(leftover); }),
        "Inconsistent DB: Deserializing as "
        "chronik_db::io::token::data::DbTokenTx has leftover data: "
        "0000000000[ff]");
    // DbToken variant 5 doesn't exist
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DeserializeDbTokenTx(Bytes{0x00, 0x00, 0x01, 0x05}); }),
        "Inconsistent DB: Cannot deserialize byte sequence as "
        "chronik_db::io::token::data::DbTokenTx: Serde Deserialization Error. "
        "Byte sequence: 00000105");
    Bytes bad_meta(32, 0);
    bad_meta.push_back(0x02);
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { DeserializeTokenMeta(bad_meta); }),
        "Inconsistent DB: Cannot deserialize byte sequence as "
        "bitcoinsuite_slp::structs::TokenMeta: Serde Deserialization Error. "
        "Byte sequence: " +
            HexEncode(bad_meta));
    BOOST_CHECK_EQUAL(
        ErrorMsg([] { DeserializeGenesisInfo(Bytes{0x00, 0x00, 0x02}); }),
        "Inconsistent DB: Cannot deserialize byte sequence as "
        "bitcoinsuite_slp::structs::GenesisInfo: Found an Option "
        "discriminant that wasn't 0 or 1. Byte sequence: 000002");
}

BOOST_AUTO_TEST_CASE(test_token_error_texts) {
    BOOST_CHECK_EQUAL(TokenIndexError::TokenTxNumNotFound(4).what(),
                      std::string("Inconsistent DB: Token TxNum 4 not found in "
                                  "DB"));
    BOOST_CHECK_EQUAL(BatchError::Cycle().what(),
                      std::string("Cycle in SLP txs"));
    BOOST_CHECK_EQUAL(BatchError::MissingTokenTxNum(7).what(),
                      std::string("Inconsistent BatchDbData: Missing TokenId "
                                  "for token tx num 7"));
    OutPoint outpoint{chronik::native::test::TxIdNum(1), 2};
    BOOST_CHECK_EQUAL(
        BatchError::MissingTxInputCoin(outpoint).what(),
        "Inconsistent Tx: Missing coin for TxInput OutPoint { txid: TxId(" +
            std::string(64, '0').replace(0, 64, [] {
                std::string s;
                for (int i = 0; i < 32; ++i) {
                    s += "01";
                }
                return s;
            }()) +
            "), out_idx: 2 }");
}

BOOST_AUTO_TEST_CASE(test_token_db_tables_and_wipe) {
    TestDb db("token_tables");
    MockTokenDb mock_db(*db);
    MockTokenReader token_reader{*db};
    mock_db.Connect({
        make_tx(0, {{0xff, 0}}, 1, EMPTY),
        make_tx(1, {}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                         SlpTokenType::Fungible(), 2, 10))),
    });
    // Raw keys/values exactly as the Rust stores them
    {
        auto txn = db->BeginRead();
        const auto key = index::TxNumToBytes(1);
        const auto raw_tx =
            txn->Get(db->Table(schema::kTokenTx), ByteView(key));
        BOOST_REQUIRE(raw_tx);
        BOOST_CHECK_EQUAL(HexEncode(*raw_tx),
                          "0101" "00" "00" "03" "00" "01000a" "0200" "00");
        const auto raw_meta =
            txn->Get(db->Table(schema::kTokenMeta), ByteView(key));
        BOOST_REQUIRE(raw_meta);
        BOOST_CHECK_EQUAL(HexEncode(*raw_meta),
                          std::string(64, '0').replace(0, 64, [] {
                              std::string s;
                              for (int i = 0; i < 32; ++i) {
                                  s += "01";
                              }
                              return s;
                          }()) + "0000");
        const auto raw_info =
            txn->Get(db->Table(schema::kTokenGenesisInfo), ByteView(key));
        BOOST_REQUIRE(raw_info);
        BOOST_CHECK_EQUAL(HexEncode(*raw_info), "0000000000000000");
        BOOST_CHECK(TokenReader(*db, *txn).HasAnyTokens());
        const auto spent = TokenReader(*db, *txn).SpentTokensAndDbTx(1);
        BOOST_REQUIRE(spent);
        BOOST_CHECK(spent->first.empty());
        BOOST_CHECK(!TokenReader(*db, *txn).SpentTokensAndDbTx(0));
    }
    {
        auto txn = db->BeginWrite();
        TokenWriter(*db).Wipe(*txn);
        txn->Commit();
    }
    BOOST_CHECK(!token_reader.token_tx(1));
    BOOST_CHECK(!token_reader.token_meta(1));
    BOOST_CHECK(!token_reader.genesis_info(1));
    auto txn = db->BeginRead();
    BOOST_CHECK(!TokenReader(*db, *txn).HasAnyTokens());
    BOOST_CHECK_EQUAL(
        ErrorMsg([&] { TokenReader(*db, *txn).TokenMetas({1}); }),
        "Inconsistent DB: Token TxNum 1 not found in DB");
}

BOOST_AUTO_TEST_CASE(test_ecash_token_index_seam) {
    TestDb db("token_index_seam");
    const auto token_index = MakeEcashTokenIndex(*db);
    BOOST_CHECK_EQUAL(token_index->TokenIdGroup().Name(), "TokenIdGroup");
    const auto hook = token_index->MakeMempoolHook();
    BOOST_CHECK(mem::MempoolTokens::FromHook(hook.get()) != nullptr);

    const std::vector<Tx> txs{
        make_tx(0, {{0xff, 0}}, 1, EMPTY),
        make_tx(1, {}, 2,
                Slp(slp::GenesisOpreturn(GenesisInfo::EmptySlp(),
                                         SlpTokenType::Fungible(), 2, 10))),
    };
    auto txn = db->BeginWrite();
    index::TxsMemData txs_mem;
    const index::TxNum first = index::TxWriter(*db).Insert(
        *txn, MockTokenDb::TxsBatch(txs, 0), txs_mem);
    const auto index_txs = index::PrepareIndexedTxs(*db, *txn, first, txs);
    const auto aux = token_index->ConnectBlock(*db, *txn, index_txs);
    const TokenIdSubsAux subs = token_index->SubsAux(aux.get());
    BOOST_REQUIRE_EQUAL(subs.txs.size(), 1u);
    BOOST_CHECK(subs.txs.at(chronik::native::test::TxIdNum(1)).second ==
                (TokenIdSubsAux::MaybeTokenIds{std::nullopt, token_id(1),
                                               token_id(1)}));
    const auto aux_db = token_index->AuxFromDb(*db, *txn, index_txs);
    BOOST_CHECK(token_index->SubsAux(aux_db.get()).txs == subs.txs);
    BOOST_CHECK(token_index->SubsAux(nullptr).txs.empty());
    token_index->DisconnectBlock(*db, *txn, index_txs);
    BOOST_CHECK(!TokenReader(*db, *txn).TokenTx(1));
    BOOST_CHECK(!TokenReader(*db, *txn).HasAnyTokens());
}

BOOST_AUTO_TEST_SUITE_END()
