// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-db/src/v2_asset_test.rs tests.

#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/branch.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::test;

namespace {

TxLocation Location(uint32_t index) {
    return TxLocation{Fill(9), 7, index, TxId{Fill(uint8_t(index + 10))},
                      TxHash{Fill(uint8_t(index + 20))}};
}

Output AssetOutput(uint8_t token, uint64_t value, bool burn) {
    Output o;
    o.flags = burn ? 3 : 1;
    o.value = value;
    o.token_id = Fill(token);
    o.branches = {Fill(8)};
    if (!burn) {
        o.paths = {{0}};
    }
    return o;
}

ResolvedCreation Coin(uint8_t token, uint64_t value, uint32_t index) {
    return ResolvedCreation{OutPoint{Location(0).txid, index},
                            AssetOutput(token, value, false), Location(0)};
}

AssetTxView View(std::span<const Output> outputs,
                 std::span<const ResolvedCreation> spends,
                 std::span<const Hash32> mints) {
    return AssetTxView{Location(1), outputs, spends, mints};
}

bool Throws(const std::function<void()> &f) { return ThrowsV2(f); }

void PutLocation(V2Env &db, const TxLocation &loc) {
    Bytes height_key{'e', 'H'};
    for (int i = 7; i >= 0; --i) {
        height_key.push_back(uint8_t(loc.height >> (8 * i)));
    }
    db.Put(height_key, loc.block_id.b);
    db.Put(PrefixKey('t', loc.txid.hash.b), codec::Encode(loc));
}

ReadSnapshot MakeReadSnapshot(const V2Env &db) {
    return ReadSnapshot(db.Snapshot(), Anchor{B32(9), 7}, TestBinding());
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_asset_tests)

BOOST_AUTO_TEST_CASE(full_union_input_only_implicit_burn_and_exact_positions) {
    const std::vector<Output> outputs{AssetOutput(2, 0, true),
                                      AssetOutput(3, 12, false),
                                      AssetOutput(3, 8, true)};
    const std::vector<ResolvedCreation> spends{Coin(1, 55, 0), Coin(3, 13, 1)};
    const std::vector<Hash32> mints{Fill(3)};
    const auto events = DeriveAssetEvents(View(outputs, spends, mints));
    BOOST_REQUIRE_EQUAL(events.size(), 3u);
    for (size_t i = 0; i < 3; ++i) {
        BOOST_CHECK_EQUAL(events[i].token_id.b[0], i + 1);
    }
    BOOST_CHECK(events[0].spent_units == 55);
    BOOST_CHECK(events[0].implicit_burn_units == 55);
    BOOST_CHECK(events[0].output_units == 0);
    BOOST_CHECK(events[2].minted_units == 7);
    BOOST_CHECK(events[2].explicit_burn_units == 8);
    for (const AssetEvent &e : events) {
        BOOST_CHECK(e.location == Location(1));
    }
    OldAssetSummaries old;
    for (const AssetEvent &e : events) {
        old.emplace(e.token_id, std::nullopt);
    }
    const auto plan = PlanAssetTx(View(outputs, spends, mints), old);
    BOOST_CHECK_EQUAL(plan.size(), 9u);
    const Bytes key = AssetOutputKey(Fill(3), Location(1), 2);
    const auto it = std::find_if(plan.begin(), plan.end(),
                                 [&](const auto &kv) { return kv.first == key; });
    BOOST_REQUIRE(it != plan.end());
    const Bytes &bytes = it->second;
    BOOST_REQUIRE_EQUAL(bytes.size(), 36u);
    BOOST_CHECK(std::equal(bytes.begin(), bytes.begin() + 32,
                           Location(1).txid.hash.b.begin()));
    BOOST_CHECK(Bytes(bytes.begin() + 32, bytes.end()) == (Bytes{0, 0, 0, 2}));
}

BOOST_AUTO_TEST_CASE(multimint_and_quantities_exceeding_u64_are_exact) {
    const std::vector<Output> outputs{AssetOutput(2, UINT64_MAX, false),
                                      AssetOutput(2, UINT64_MAX, true),
                                      AssetOutput(1, 1, false)};
    const std::vector<Hash32> mints{Fill(2), Fill(1)};
    const auto events = DeriveAssetEvents(View(outputs, {}, mints));
    BOOST_CHECK(events[1].minted_units == 2 * U128(UINT64_MAX));
    BOOST_CHECK(events[1].explicit_burn_units == U128(UINT64_MAX));
    BOOST_CHECK(events[0].minted_units == 1);
}

BOOST_AUTO_TEST_CASE(
    mint_bijection_rejects_duplicate_missing_extra_and_zero_selectors) {
    const std::vector<Output> outputs{AssetOutput(1, 1, false)};
    for (const std::vector<Hash32> &mints : std::vector<std::vector<Hash32>>{
             {}, {Fill(1), Fill(1)}, {Fill(1), Fill(2)}, {Hash32{}}}) {
        BOOST_CHECK(Throws([&] { DeriveAssetEvents(View(outputs, {}, mints)); }));
    }
    const std::vector<Output> burn{AssetOutput(1, 0, true)};
    const std::vector<Hash32> one{Fill(1)};
    BOOST_CHECK(Throws([&] { DeriveAssetEvents(View(burn, {}, one)); }));
}

BOOST_AUTO_TEST_CASE(explicit_and_implicit_burns_remain_distinct) {
    const std::vector<Output> burn{AssetOutput(1, 4, true)};
    const std::vector<ResolvedCreation> spends{Coin(1, 10, 0)};
    const auto events = DeriveAssetEvents(View(burn, spends, {}));
    BOOST_CHECK(events[0].spent_units == 10);
    BOOST_CHECK(events[0].output_units == 4);
    BOOST_CHECK(events[0].explicit_burn_units == 4);
    BOOST_CHECK(events[0].implicit_burn_units == 6);
    const std::vector<Output> zero_burn{AssetOutput(2, 0, true)};
    const auto zero = DeriveAssetEvents(View(zero_burn, {}, {}));
    BOOST_REQUIRE_EQUAL(zero.size(), 1u);
    BOOST_CHECK(zero[0].output_units == 0);
}

BOOST_AUTO_TEST_CASE(malformed_duplicate_spends_and_burn_inputs_are_rejected) {
    ResolvedCreation c = Coin(1, 0, 0);
    const std::vector<ResolvedCreation> dup{c, c};
    BOOST_CHECK(Throws([&] { DeriveAssetEvents(View({}, dup, {})); }));
    c.output = AssetOutput(1, 0, true);
    const std::vector<ResolvedCreation> burn_input{c};
    BOOST_CHECK(Throws([&] { DeriveAssetEvents(View({}, burn_input, {})); }));
    Output malformed = AssetOutput(1, 0, false);
    malformed.flags |= 4;
    const std::vector<Output> bad{malformed};
    BOOST_CHECK(Throws([&] { DeriveAssetEvents(View(bad, {}, {})); }));
}

BOOST_AUTO_TEST_CASE(
    summary_checked_counts_first_seen_and_reconnect_plan_parity) {
    const std::vector<Output> outputs{AssetOutput(1, 0, true),
                                      AssetOutput(1, 0, false)};
    const AssetTxView tx = View(outputs, {}, {});
    const Hash32 token = Fill(1);
    const OldAssetSummaries old{{token, std::nullopt}};
    const auto initial = PlanAssetTx(tx, old);
    // Disconnect restores the exact old values, then reconnect recomputes the
    // identical plan. This is model parity; the parent owns durable undo tests.
    BOOST_CHECK(initial == PlanAssetTx(tx, old));
    const AssetSummary summary =
        AssetDecode<AssetSummary>(initial[0].second);
    BOOST_CHECK_EQUAL(summary.event_count, 1u);
    BOOST_CHECK_EQUAL(summary.output_count, 2u);
    AssetTxView later = tx;
    later.location = Location(2);
    const auto updated = PlanAssetTx(later, {{token, summary}});
    const AssetSummary next = AssetDecode<AssetSummary>(updated[0].second);
    BOOST_CHECK(next.first_seen == summary.first_seen);
    BOOST_CHECK_EQUAL(next.event_count, 2u);
    BOOST_CHECK_EQUAL(next.output_count, 4u);
    AssetSummary bad = summary;
    bad.event_count = UINT64_MAX;
    BOOST_CHECK(Throws([&] { PlanAssetTx(later, {{token, bad}}); }));
    bad = summary;
    bad.output_count = UINT64_MAX;
    BOOST_CHECK(Throws([&] { PlanAssetTx(later, {{token, bad}}); }));
}

BOOST_AUTO_TEST_CASE(amount_addition_detects_u128_overflow) {
    U128 units = ~U128(0);
    BOOST_CHECK(Throws([&] { AssetAddUnits(units, 1); }));
    BOOST_CHECK(units == ~U128(0));
}

// Dedicated temporary storage fixtures exercise the real persisted reader
// boundary; they do not open any application index or production directory.
BOOST_AUTO_TEST_CASE(
    persisted_summary_and_event_reject_forged_same_position_identity) {
    V2TempDir dir("v2-asset-canonical-join");
    V2Env db(dir.path);
    const TxLocation canonical = Location(1);
    PutLocation(db, canonical);
    const Hash32 token = Fill(1);
    for (int field = 0; field < 3; ++field) {
        TxLocation forged = canonical;
        switch (field) {
            case 0:
                forged.block_id = Fill(99);
                break;
            case 1:
                forged.txid = TxId{Fill(99)};
                break;
            default:
                forged.txhash = TxHash{Fill(99)};
        }
        db.Put(AssetSummaryKey(token),
               AssetEncode(AssetSummary{token, forged, 1, 1}));
        AssetEvent event;
        event.token_id = token;
        event.location = forged;
        event.spent_units = 1;
        event.output_units = 1;
        db.Put(AssetEventKey(token, forged), AssetEncode(event));
        const ReadSnapshot snapshot = MakeReadSnapshot(db);
        BOOST_CHECK(ThrowsCorrupt([&] { snapshot.GetAssetSummary(token); }));
        BOOST_CHECK(
            ThrowsCorrupt([&] { snapshot.NextAssetSummary(std::nullopt); }));
        BOOST_CHECK(ThrowsCorrupt(
            [&] { snapshot.NextAssetEvent(token, std::nullopt); }));
    }
}

BOOST_AUTO_TEST_CASE(
    persisted_iterator_budget_counts_initial_join_and_exclusive_reread) {
    V2TempDir dir("v2-asset-read-budget");
    V2Env db(dir.path);
    const TxLocation loc = Location(1);
    PutLocation(db, loc);
    for (uint8_t byte = 1; byte <= 2; ++byte) {
        const Hash32 token = Fill(byte);
        db.Put(AssetSummaryKey(token),
               AssetEncode(AssetSummary{token, loc, 1, 0}));
    }
    const ReadSnapshot snapshot = MakeReadSnapshot(db);
    AssetReadBudget budget(9);
    const auto first = snapshot.NextAssetSummaryCounted(std::nullopt, budget);
    BOOST_REQUIRE(first);
    // First iterator item + canonical transaction/height gets.
    BOOST_CHECK_EQUAL(budget.Reads(), 3u);
    const auto second =
        snapshot.NextAssetSummaryCounted(ByteView(first->first), budget);
    BOOST_REQUIRE(second);
    // Exclusive reread + next item + canonical transaction/height gets.
    BOOST_CHECK_EQUAL(budget.Reads(), 7u);
    BOOST_CHECK(
        !snapshot.NextAssetSummaryCounted(ByteView(second->first), budget));
    // Exclusive reread + exhausted next.
    BOOST_CHECK_EQUAL(budget.Reads(), 9u);
    BOOST_CHECK_EQUAL(budget.Remaining(), 0u);
    AssetReadBudget short_budget(1);
    BOOST_CHECK(
        Throws([&] { snapshot.AssetSummaryCounted(Fill(1), short_budget); }));
    // Canonical read refused before storage.
    BOOST_CHECK_EQUAL(short_budget.Reads(), 1u);
}

BOOST_AUTO_TEST_SUITE_END()
