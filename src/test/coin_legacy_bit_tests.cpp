// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Whether a coin was created by a legacy transaction. The coin's output
// representation is the bit (Coin::IsLegacy): a legacy transaction creates
// legacy outputs, a version 7 transaction V2 outputs, and every store keeps
// the representation.

#include <coins.h>
#include <lotus_v2/legacy_coin.h>
#include <lotus_v2/sparse_state.h>
#include <primitives/transaction.h>
#include <primitives/v2_outputs.h>
#include <streams.h>
#include <txdb.h>
#include <undo.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(coin_legacy_bit_tests, BasicTestingSetup)

namespace {
const CScript kP2PKH = CScript() << OP_DUP << OP_HASH160
                                 << std::vector<uint8_t>(20, 0xab)
                                 << OP_EQUALVERIFY << OP_CHECKSIG;

CTransaction LegacyTx() {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint(TxId(uint256S("01")), 0),
                         CScript() << OP_TRUE);
    mtx.vout.emplace_back(1000 * SATOSHI, kP2PKH);
    mtx.vout.emplace_back(2000 * SATOSHI, CScript() << OP_TRUE);
    return CTransaction(mtx);
}

CTransaction V7Tx() {
    CMutableTransaction mtx;
    mtx.nVersion = 7;
    CTxIn in(COutPoint(TxId(uint256S("02")), 0), CScript(),
             CTxIn::SEQUENCE_FINAL);
    in.nFlags = 1;
    lotus::v2::BranchWitness w;
    w.script = {V2_OP_TRUE};
    in.vWitnesses = {w};
    mtx.vin.push_back(in);
    mtx.vout.push_back(OpTrueOutput(1000 * SATOSHI));
    mtx.vout.push_back(V0LeafOutput(2000 * SATOSHI, kP2PKH));
    return CTransaction(mtx);
}

template <typename T> T RoundTrip(const T &value) {
    DataStream s{};
    s << value;
    T back;
    s >> back;
    BOOST_CHECK(s.empty());
    return back;
}
} // namespace

BOOST_AUTO_TEST_CASE(transaction_version_selects_the_coin_kind) {
    CCoinsView empty;
    CCoinsViewCache cache(&empty);
    const CTransaction legacy = LegacyTx();
    const CTransaction v7 = V7Tx();
    AddCoins(cache, legacy, 10);
    AddCoins(cache, v7, 10);
    for (uint32_t n = 0; n < 2; ++n) {
        BOOST_CHECK(cache.AccessCoin(COutPoint(legacy.GetId(), n)).IsLegacy());
        BOOST_CHECK(!cache.AccessCoin(COutPoint(v7.GetId(), n)).IsLegacy());
    }
}

BOOST_AUTO_TEST_CASE(coin_serialization_keeps_the_kind) {
    const CTransaction legacy = LegacyTx();
    const CTransaction v7 = V7Tx();
    for (const CTxOut &out : {legacy.vout[0], legacy.vout[1], v7.vout[0],
                              v7.vout[1]}) {
        const Coin coin(out, 64, false);
        const Coin back = RoundTrip(coin);
        BOOST_CHECK_EQUAL(back.IsLegacy(), coin.IsLegacy());
        BOOST_CHECK(back.GetTxOut() == out);
        BOOST_CHECK(back.GetTxOut().scriptPubKey == out.scriptPubKey);
        BOOST_CHECK_EQUAL(back.GetHeight(), 64U);
    }
    // A V2 output whose scriptPubKey bytes equal a legacy script's would
    // have been ambiguous if stored by its script; it is stored by its
    // fields, so a V2 output built without its scriptPubKey comes back V2
    // with its encoding.
    CTxOut bare = v7.vout[1];
    bare.scriptPubKey.clear();
    const Coin back = RoundTrip(Coin(bare, 5, true));
    BOOST_CHECK(!back.IsLegacy());
    BOOST_CHECK(back.GetTxOut() == v7.vout[1]);
    BOOST_CHECK(back.GetTxOut().scriptPubKey == v7.vout[1].scriptPubKey);
    // A legacy coin whose script is a V2 output's wire encoding stays legacy.
    const CTxOut lookalike(1000 * SATOSHI, v7.vout[0].scriptPubKey);
    BOOST_CHECK(lookalike.IsLegacy());
    BOOST_CHECK(RoundTrip(Coin(lookalike, 5, false)).IsLegacy());
}

BOOST_AUTO_TEST_CASE(undo_keeps_the_kind) {
    CTxUndo undo;
    undo.vprevout.emplace_back(LegacyTx().vout[0], 100, true);
    undo.vprevout.emplace_back(V7Tx().vout[1], 200, false);
    const CTxUndo back = RoundTrip(undo);
    BOOST_REQUIRE_EQUAL(back.vprevout.size(), 2U);
    BOOST_CHECK(back.vprevout[0].IsLegacy());
    BOOST_CHECK(!back.vprevout[1].IsLegacy());
    BOOST_CHECK(back.vprevout[1].GetTxOut() == V7Tx().vout[1]);
}

BOOST_AUTO_TEST_CASE(coins_db_keeps_the_kind) {
    CCoinsViewDB db{
        {.path = "coin_legacy_bit", .cache_bytes = 1 << 20,
         .memory_only = true},
        {}};
    const CTransaction legacy = LegacyTx();
    const CTransaction v7 = V7Tx();
    {
        CCoinsViewCache cache(&db);
        AddCoins(cache, legacy, 3);
        AddCoins(cache, v7, 3);
        cache.SetBestBlock(BlockHash(uint256S("03")));
        cache.Flush();
    }
    CCoinsViewCache reload(&db);
    for (uint32_t n = 0; n < 2; ++n) {
        const Coin &l = reload.AccessCoin(COutPoint(legacy.GetId(), n));
        const Coin &v = reload.AccessCoin(COutPoint(v7.GetId(), n));
        BOOST_REQUIRE(!l.IsSpent() && !v.IsSpent());
        BOOST_CHECK(l.IsLegacy());
        BOOST_CHECK(!v.IsLegacy());
        BOOST_CHECK(l.GetTxOut() == legacy.vout[n]);
        BOOST_CHECK(v.GetTxOut() == v7.vout[n]);
    }
}

BOOST_AUTO_TEST_CASE(state_records_legacy_coins_as_legacy) {
    // The V2 state records a legacy coin with its legacy script (the 0x80
    // EncodeCoin record), a V2 coin with its V2 output.
    const CTxOut legacy = LegacyTx().vout[0];
    const lotus::v2::Output state = legacy.ToV2Output();
    const lotus::v2::Output expected = lotus::v2::LegacyStateOutput(legacy);
    BOOST_CHECK(state == expected);
    BOOST_CHECK(state.legacy_script.has_value());
    BOOST_CHECK(state.branches.empty());
    BOOST_CHECK(lotus::v2::LegacyTxOutput(state) == legacy);

    const CTxOut v2 = V7Tx().vout[1];
    BOOST_CHECK(!v2.ToV2Output().legacy_script.has_value());
    BOOST_CHECK(CTxOut::FromV2Output(v2.ToV2Output()) == v2);
}

BOOST_AUTO_TEST_CASE(state_coin_round_trip_is_exact) {
    // Fast-sync import rebuilds each chainstate coin from its V2 state coin
    // (ActivateVerifiedFastSyncPivot: FromV2Output of the decoded state
    // output), so CTxOut -> state coin bytes -> CTxOut must be the identity,
    // for legacy scripts of every shape as for V2 outputs. Otherwise the
    // imported UTXO set hashes differently from the one it was built from.
    std::vector<CTxOut> outs;
    const std::vector<uint8_t> long_script(600, OP_TRUE);
    for (const CScript &script :
         {kP2PKH,
          CScript() << OP_HASH160 << std::vector<uint8_t>(20, 0xcd)
                    << OP_EQUAL,
          CScript() << std::vector<uint8_t>(33, 0x02) << OP_CHECKSIG,
          CScript() << OP_TRUE, CScript(),
          CScript() << OP_RETURN << std::vector<uint8_t>(80, 0x11),
          CScript(long_script.begin(), long_script.end())}) {
        outs.emplace_back(4321 * SATOSHI, script);
    }
    outs.push_back(V7Tx().vout[0]);
    outs.push_back(V7Tx().vout[1]);
    for (const CTxOut &out : outs) {
        lotus::v2::Coin coin;
        coin.outpoint.tx_id.fill(0x42);
        coin.outpoint.index = 1;
        coin.output = out.ToV2Output();
        coin.creation_height = 7;
        std::vector<uint8_t> bytes;
        BOOST_REQUIRE(lotus::v2::EncodeCoin(coin, bytes));
        lotus::v2::Coin back;
        BOOST_REQUIRE(lotus::v2::DecodeCoinBytes(bytes, back));
        const CTxOut rebuilt = CTxOut::FromV2Output(back.output);
        BOOST_CHECK(rebuilt == out);
        BOOST_CHECK(rebuilt.scriptPubKey == out.scriptPubKey);
        BOOST_CHECK_EQUAL(rebuilt.IsLegacy(), out.IsLegacy());
        BOOST_CHECK(CTxOut::FromV2Output(out.ToV2Output()) == out);
    }
}

BOOST_AUTO_TEST_SUITE_END()
