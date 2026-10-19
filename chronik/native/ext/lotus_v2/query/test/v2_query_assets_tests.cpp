// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-indexer/src/query/v2_assets_test.rs tests.

#include <ext/lotus_v2/db/asset.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/query/assets.h>

#include <boost/test/unit_test.hpp>

#include <map>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::query_assets;
using chronik::native::lotus_v2::test::Bytes;
using chronik::native::lotus_v2::test::ByteView;
using chronik::native::lotus_v2::test::Fill;

namespace {

TxLocation Location(uint32_t i) {
    return TxLocation{Fill(9), 7, i, TxId{Fill(uint8_t(i + 10))},
                      TxHash{Fill(uint8_t(i + 20))}};
}

template <typename T>
std::optional<std::pair<Bytes, T>> Next(const std::map<Bytes, T> &map,
                                        std::optional<ByteView> after) {
    for (const auto &[k, v] : map) {
        if (!after || std::lexicographical_compare(after->begin(), after->end(),
                                                   k.begin(), k.end())) {
            return std::make_pair(k, v);
        }
    }
    return std::nullopt;
}

struct Memory final : Source {
    std::map<Bytes, AssetSummary> summaries;
    std::map<Bytes, OutPoint> postings;
    std::map<OutPoint, OutputRecord> outputs;
    mutable size_t calls = 0;

    void Charge(AssetReadBudget &budget) const {
        try {
            budget.Charge();
        } catch (const V2Error &) {
            throw Error(Error::Kind::Source);
        }
        ++calls;
    }
    template <typename T>
    static bool Contains(const std::map<Bytes, T> &map,
                         std::optional<ByteView> a) {
        return a && map.count(Bytes(a->begin(), a->end()));
    }

    std::optional<std::pair<Bytes, AssetSummary>>
    Summary(std::optional<ByteView> a, AssetReadBudget &budget) const override {
        Charge(budget);
        if (Contains(summaries, a)) {
            Charge(budget);
        }
        auto item = Next(summaries, a);
        if (item) {
            Charge(budget);
            Charge(budget);
        }
        return item;
    }
    std::optional<std::pair<Bytes, AssetEvent>>
    Event(const Hash32 &, std::optional<ByteView>,
          AssetReadBudget &) const override {
        BOOST_FAIL("unreachable");
        return std::nullopt;
    }
    std::optional<std::pair<Bytes, OutPoint>>
    Posting(const Hash32 &t, std::optional<ByteView> a,
            AssetReadBudget &budget) const override {
        Charge(budget);
        if (Contains(postings, a)) {
            Charge(budget);
        }
        auto item = Next(postings, a);
        if (item && !std::equal(t.b.begin(), t.b.end(),
                                item->first.begin() + 2)) {
            return std::nullopt;
        }
        return item;
    }
    std::optional<OutputRecord>
    GetOutput(const OutPoint &op, AssetReadBudget &budget) const override {
        Charge(budget);
        const auto it = outputs.find(op);
        if (it == outputs.end()) {
            return std::nullopt;
        }
        const OutputRecord &record = it->second;
        Charge(budget);
        Charge(budget);
        if (!(record.creation == Location(record.creation.tx_index))) {
            throw Error(Error::Kind::Source);
        }
        if (record.spend) {
            Charge(budget);
            Charge(budget);
        }
        return record;
    }
};

std::optional<ByteView> View(const std::optional<Bytes> &b) {
    if (!b) {
        return std::nullopt;
    }
    return ByteView(*b);
}

bool ThrowsKind(const std::function<void()> &f, Error::Kind kind) {
    try {
        f();
    } catch (const Error &e) {
        return e.kind() == kind;
    }
    return false;
}

Output TokenOutput(const Hash32 &token, bool burn) {
    Output o;
    o.flags = burn ? 3 : 1;
    o.token_id = token;
    o.branches = {Fill(8)};
    if (!burn) {
        o.paths = {{0}};
    }
    return o;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_query_assets_tests)

BOOST_AUTO_TEST_CASE(registry_pages_equal_full_ordered_scan) {
    Memory m;
    for (uint8_t t = 29; t >= 1; --t) {
        const Hash32 token = Fill(t);
        m.summaries[AssetSummaryKey(token)] =
            AssetSummary{token, Location(0), 1, 0};
    }
    std::optional<Bytes> after;
    std::vector<Hash32> all;
    Limits limits;
    limits.page_size = 3;
    while (true) {
        const auto p = Assets(m, View(after), limits);
        BOOST_CHECK(p.reads <= 12);
        BOOST_CHECK(p.examined <= 3);
        for (const AssetSummary &s : p.items) {
            all.push_back(s.token_id);
        }
        if (p.exhausted) {
            break;
        }
        BOOST_CHECK(after != p.next_key);
        after = p.next_key;
    }
    std::vector<Hash32> expected;
    for (const auto &[k, s] : m.summaries) {
        expected.push_back(s.token_id);
    }
    BOOST_CHECK(all == expected);
}

BOOST_AUTO_TEST_CASE(empty_unspent_page_advances_and_history_keeps_zero_burns) {
    Memory m;
    const Hash32 token = Fill(1);
    for (uint32_t i = 0; i < 5; ++i) {
        const TxLocation creation = Location(i);
        const OutPoint op{creation.txid, 0};
        m.postings[AssetOutputKey(token, creation, 0)] = op;
        m.outputs[op] = OutputRecord{op, TokenOutput(token, i < 4), creation,
                                     std::nullopt};
    }
    Limits limits;
    limits.examined = 2;
    limits.reads = 12;
    const auto p = Outputs(m, token, true, std::nullopt, limits);
    BOOST_CHECK(p.items.empty());
    BOOST_CHECK(!p.exhausted);
    BOOST_CHECK_EQUAL(p.reads, 9u);
    BOOST_CHECK_EQUAL(m.calls, 9u);
    const auto q = Outputs(m, token, true, View(p.next_key), limits);
    BOOST_CHECK(q.items.empty());
    BOOST_CHECK(q.next_key > p.next_key);
    const auto r = Outputs(m, token, true, View(q.next_key), limits);
    BOOST_CHECK_EQUAL(r.items.size(), 1u);
    BOOST_CHECK(r.exhausted);
    BOOST_CHECK_EQUAL(r.reads, 7u);
    const auto full = Outputs(m, token, false, std::nullopt, Limits{});
    BOOST_CHECK_EQUAL(full.items.size(), 5u);
}

BOOST_AUTO_TEST_CASE(malformed_cursor_join_or_indivisible_record_fails) {
    {
        const Memory m;
        const Bytes ee{'e', 'E'};
        BOOST_CHECK(ThrowsKind([&] { Assets(m, ByteView(ee), Limits{}); },
                               Error::Kind::InvalidCursor));
        Limits tiny;
        tiny.result_bytes = 1;
        BOOST_CHECK(ThrowsKind([&] { Assets(m, std::nullopt, tiny); },
                               Error::Kind::RecordLimit));
        BOOST_CHECK_EQUAL(m.calls, 0u);
    }
    Memory m;
    const Hash32 token = Fill(1);
    const TxLocation loc = Location(0);
    const OutPoint op{loc.txid, 0};
    m.postings[AssetOutputKey(token, loc, 0)] = op;
    BOOST_CHECK(ThrowsKind(
        [&] { Outputs(m, token, false, std::nullopt, Limits{}); },
        Error::Kind::Source));
}

BOOST_AUTO_TEST_CASE(
    output_creation_identity_and_join_read_budget_are_enforced) {
    Memory m;
    const Hash32 token = Fill(1);
    const TxLocation loc = Location(0);
    const OutPoint op{loc.txid, 0};
    m.postings[AssetOutputKey(token, loc, 0)] = op;
    TxLocation forged = loc;
    forged.txhash = TxHash{Fill(99)};
    m.outputs[op] =
        OutputRecord{op, TokenOutput(token, false), forged, std::nullopt};
    BOOST_CHECK(ThrowsKind(
        [&] { Outputs(m, token, false, std::nullopt, Limits{}); },
        Error::Kind::Source));
    // posting + output + canonical transaction/height creation
    BOOST_CHECK_EQUAL(m.calls, 4u);
    m.outputs[op].creation = loc;
    m.calls = 0;
    Limits limits;
    limits.reads = 7;
    const auto p = Outputs(m, token, false, std::nullopt, limits);
    BOOST_CHECK_EQUAL(p.reads, 4u);
    BOOST_CHECK_EQUAL(m.calls, 4u);
    BOOST_CHECK_EQUAL(p.items.size(), 1u);
    BOOST_CHECK(!p.exhausted);
    // The next indivisible candidate would require up to seven reads; no
    // speculative call runs with only three remaining. The cursor advances.
    BOOST_CHECK(p.next_key);
}

BOOST_AUTO_TEST_SUITE_END()
