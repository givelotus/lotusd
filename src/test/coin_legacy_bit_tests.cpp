// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Whether a coin was created by a legacy transaction. The coin's output
// representation is the bit (Coin::IsLegacy): a legacy transaction creates
// legacy outputs, a version 7 transaction V2 outputs, and every store keeps
// the representation.

#include <coins.h>
#include <lotus_v2/block_cost.h>
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/legacy_coin.h>
#include <lotus_v2/output.h>
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

        // The coin wire alone, as other state codecs read it.
        std::vector<uint8_t> wire;
        std::string error;
        BOOST_REQUIRE(lotus::v2::EncodeCoinOutput(coin.output, wire, error));
        lotus::v2::Output decoded;
        BOOST_REQUIRE_MESSAGE(lotus::v2::DecodeCoinOutput(wire, decoded, error),
                              error);
        BOOST_CHECK(decoded == coin.output);
    }

    // Fast sync carries the same coins in utxoshard messages.
    lotus::v2::UtxoShardMessage shard;
    shard.pivot_block_id.fill(0x11);
    for (size_t i = 0; i < outs.size(); ++i) {
        lotus::v2::Coin coin;
        coin.outpoint.tx_id.fill(uint8_t(i + 1));
        coin.output = outs[i].ToV2Output();
        shard.coins.push_back(coin);
    }
    std::vector<uint8_t> payload;
    std::string error;
    BOOST_REQUIRE_MESSAGE(lotus::v2::EncodeUtxoShardMessage(shard, payload, error),
                          error);
    lotus::v2::UtxoShardMessage back;
    BOOST_REQUIRE_MESSAGE(lotus::v2::DecodeUtxoShardMessage(payload, back, error),
                          error);
    BOOST_REQUIRE_EQUAL(back.coins.size(), outs.size());
    for (size_t i = 0; i < outs.size(); ++i) {
        BOOST_CHECK(CTxOut::FromV2Output(back.coins[i].output) == outs[i]);
    }
}

// The legacy coin wire decodes only in its canonical form.
BOOST_AUTO_TEST_CASE(legacy_coin_wire_is_canonical) {
    lotus::v2::Output out;
    std::string error;
    // 0x80 || value || CompactSize(1) || OP_TRUE.
    std::vector<uint8_t> wire{0x80, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x51};
    BOOST_CHECK(lotus::v2::DecodeCoinOutput(wire, out, error));
    BOOST_CHECK(out.legacy_script == std::vector<uint8_t>{0x51});
    // Trailing byte, short script, non-minimal CompactSize.
    std::vector<uint8_t> bad = wire;
    bad.push_back(0);
    BOOST_CHECK(!lotus::v2::DecodeCoinOutput(bad, out, error));
    bad = wire;
    bad.pop_back();
    BOOST_CHECK(!lotus::v2::DecodeCoinOutput(bad, out, error));
    bad = {0x80, 1, 0, 0, 0, 0, 0, 0, 0, 253, 1, 0, 0x51};
    BOOST_CHECK(!lotus::v2::DecodeCoinOutput(bad, out, error));
    // A script over the legacy limit.
    bad = {0x80, 1, 0, 0, 0, 0, 0, 0, 0, 253, 0x11, 0x27};
    bad.resize(bad.size() + 10001, 0x51);
    BOOST_CHECK(!lotus::v2::DecodeCoinOutput(bad, out, error));
}

BOOST_AUTO_TEST_CASE(resolved_legacy_coin_cost_uses_coin_wire) {
    const auto tx = V7Tx().ToV2Transaction();
    lotus::v2::Coin resolved;
    resolved.outpoint = {tx.inputs[0].prev_txid, tx.inputs[0].prev_index};
    resolved.output = LegacyTx().vout[0].ToV2Output();
    BOOST_REQUIRE(resolved.output.legacy_script.has_value());
    resolved.creation_height = 7;
    resolved.creation_parent_mtp = 10;
    std::vector<uint8_t> wire;
    std::string error;
    BOOST_REQUIRE(lotus::v2::EncodeTransaction(
        tx, lotus::v2::DefaultTxProfile, wire, error));

    // Compare positive schedules differing only in resolution-byte charge. The
    // legacy P2PKH Coin is independently 36-byte outpoint + 1-byte frame
    // length + (discriminator + LE8 value + CS(script) + 25-byte script)
    // + 34-byte versioned provenance = 106 bytes.
    const lotus::v2::BlockCostProfile cost{1, 1, 1, 1};
    const lotus::v2::BlockCostProfile doubled_resolution{1, 1, 2, 1};
    const auto legacy = lotus::v2::AuthenticatedTransactionCostsResolved(
        tx, lotus::v2::DefaultTxProfile, {resolved}, 8, 11, 0, cost);
    const auto legacy_doubled = lotus::v2::AuthenticatedTransactionCostsResolved(
        tx, lotus::v2::DefaultTxProfile, {resolved}, 8, 11, 0,
        doubled_resolution);
    BOOST_CHECK_EQUAL(legacy_doubled.account_linear - legacy.account_linear, 106);
    BOOST_CHECK_EQUAL(legacy_doubled.enforce_linear - legacy.enforce_linear, 106);
    const uint64_t wire_bytes = wire.size();
    const auto cached = lotus::v2::AuthenticatedTransactionCostsResolved(
        tx, lotus::v2::DefaultTxProfile, {resolved}, 8, 11, 0, cost,
        &wire_bytes);
    BOOST_CHECK_EQUAL(cached.account_linear, legacy.account_linear);
    BOOST_CHECK_EQUAL(cached.enforce_linear, legacy.enforce_linear);

    // A native OP_TRUE Coin has a 45-byte output, so its corresponding
    // resolution charge is 36 + 1 + 45 + 34 = 116 bytes.
    resolved.output = OpTrueOutput(1000 * SATOSHI).ToV2Output();
    const auto native = lotus::v2::AuthenticatedTransactionCostsResolved(
        tx, lotus::v2::DefaultTxProfile, {resolved}, 8, 11, 0, cost);
    const auto native_doubled = lotus::v2::AuthenticatedTransactionCostsResolved(
        tx, lotus::v2::DefaultTxProfile, {resolved}, 8, 11, 0,
        doubled_resolution);
    BOOST_CHECK_EQUAL(native_doubled.account_linear - native.account_linear, 116);
    BOOST_CHECK_EQUAL(native_doubled.enforce_linear - native.enforce_linear, 116);
}

BOOST_AUTO_TEST_SUITE_END()
