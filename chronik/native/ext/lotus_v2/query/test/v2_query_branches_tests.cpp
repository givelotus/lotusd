// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-indexer/src/query/v2_branches_test/tests.rs tests.

#include <ext/lotus_v2/db/test/v2_test_util.h>
#include <ext/lotus_v2/query/branches.h>
#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <map>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::query_branches;
using chronik::native::lotus_v2::test::Fill;

namespace {

const Sha256Fn kSha256 = chronik::native::test::TestSha256;

Snapshot TestAnchor() { return Snapshot{Fill(1), Fill(2), Fill(3), 10}; }

/** Test-only scan oracle; production adapters must seek postings. */
struct Source final : PostingSource {
    std::map<OutPoint, OutputRecord> records;
    Snapshot GetSnapshot() const override { return TestAnchor(); }
    std::optional<OutPoint>
    NextPosting(const Hash32 &root, std::optional<uint8_t> pos,
                std::optional<OutPoint> after) const override {
        for (const auto &[k, r] : records) {
            if (after && !(k > *after)) {
                continue;
            }
            const auto &b = r.output.branches;
            const bool hit =
                pos ? (*pos < b.size() && b[*pos] == root)
                    : std::find(b.begin(), b.end(), root) != b.end();
            if (hit) {
                return k;
            }
        }
        return std::nullopt;
    }
    std::optional<OutputRecord> GetOutput(const OutPoint &key) const override {
        const auto it = records.find(key);
        if (it == records.end()) {
            return std::nullopt;
        }
        return it->second;
    }
};

Hash32 Root(uint8_t n) { return Fill(n); }

Source MakeSource() {
    Source s;
    for (uint8_t i = 0; i < 40; ++i) {
        const OutPoint key{TxId{Root(i)}, 0};
        Output output;
        output.flags = i % 7 == 0 ? 2 : 0;
        output.value = i;
        output.branches = {Root(i % 3), Root(8 + i % 2)};
        if (i % 7 != 0) {
            output.paths = {{0, 1}};
        }
        s.records[key] = OutputRecord{
            key, output, TxLocation{Root(3), 10, i, key.txid, TxHash{Root(i)}},
            std::nullopt};
    }
    return s;
}

Page Run(const PostingSource &s, const BranchFilter &f, QueryKind kind,
         const Limits &limits, const std::optional<Cursor> &cursor) {
    return Query(s, f, kind, limits, cursor, kSha256);
}

bool ThrowsKind(const std::function<void()> &f, QueryError::Kind kind) {
    try {
        f();
    } catch (const QueryError &e) {
        return e.kind() == kind;
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_query_branches_tests)

BOOST_AUTO_TEST_CASE(pagination_matches_same_output_oracle) {
    const Source s = MakeSource();
    for (const QueryKind kind : {QueryKind::Utxos(), QueryKind::History(true),
                                 QueryKind::History(false)}) {
        for (const BranchFilter &f : std::vector<BranchFilter>{
                 {{Root(0), Root(1), Root(0)}, {}},
                 {{}, {{1, {Root(9)}}, {0, {Root(0), Root(2)}}}},
                 {{Root(0)}, {{1, {Root(9)}}}}}) {
            std::vector<OutPoint> expected;
            for (const auto &[k, r] : s.records) {
                if (f.Matches(r.output) &&
                    (kind == QueryKind::History(true) || !r.output.IsBurn())) {
                    expected.push_back(r.outpoint);
                }
            }
            Limits limits;
            limits.page_size = 2;
            limits.posting_reads = 6;
            limits.work = 9;
            std::optional<Cursor> cursor;
            std::vector<OutPoint> actual;
            for (int i = 0; i < 100; ++i) {
                const Page p = Run(s, f, kind, limits, cursor);
                BOOST_CHECK(p.posting_reads <= limits.posting_reads &&
                            p.work <= limits.work);
                for (const Match &m : p.matches) {
                    actual.push_back(m.record.outpoint);
                }
                cursor = p.continuation;
                if (!cursor) {
                    break;
                }
            }
            BOOST_CHECK(!cursor);
            BOOST_CHECK(actual == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(bounds_canonical_digest_and_stale_cursor) {
    const Source s = MakeSource();
    const Limits limits;
    const BranchFilter f{{Root(1), Root(0), Root(1)}, {}};
    BranchFilter canonical = f;
    canonical.any_branch = {Root(0), Root(1)};
    BOOST_CHECK(f.Digest(QueryKind::Utxos(), limits, kSha256) ==
                canonical.Digest(QueryKind::Utxos(), limits, kSha256));
    for (const BranchFilter &bad : std::vector<BranchFilter>{
             {{}, {}},
             {{}, {{16, {Root(0)}}}},
             {{}, {{0, {}}}},
             {{}, {{0, {Root(0)}}, {0, {Root(0)}}}}}) {
        BOOST_CHECK(ThrowsKind([&] { bad.Canonicalize(limits); },
                               QueryError::Kind::InvalidFilter));
    }
    Limits two_roots = limits;
    two_roots.roots = 2;
    BOOST_CHECK(ThrowsKind([&] { f.Canonicalize(two_roots); },
                           QueryError::Kind::InvalidFilter));
    Limits one = limits;
    one.page_size = 1;
    const Page page = Run(s, f, QueryKind::Utxos(), one, std::nullopt);
    BOOST_REQUIRE(page.continuation);
    Cursor c = *page.continuation;
    c.snapshot.tip = Root(55);
    BOOST_CHECK(
        ThrowsKind([&] { Run(s, f, QueryKind::Utxos(), limits, c); },
                   QueryError::Kind::StaleCursor));
    Limits tiny = limits;
    tiny.result_bytes = 1;
    BOOST_CHECK(ThrowsKind(
        [&] { Run(s, f, QueryKind::Utxos(), tiny, std::nullopt); },
        QueryError::Kind::RecordTooLarge));
}

BOOST_AUTO_TEST_CASE(byte_continuation_and_all_positions) {
    Source s = MakeSource();
    OutputRecord &record = s.records.begin()->second;
    record.output.flags = 0;
    record.output.branches.clear();
    std::vector<uint8_t> path;
    BranchFilter all;
    for (uint8_t i = 0; i < 16; ++i) {
        record.output.branches.push_back(Root(i));
        path.push_back(i);
        all.positions.push_back(PositionClause{i, {Root(i)}});
    }
    record.output.paths = {path};
    BOOST_CHECK_EQUAL(
        Run(s, all, QueryKind::Utxos(), Limits{}, std::nullopt).matches.size(),
        1u);
    const BranchFilter f{{Root(0), Root(1), Root(2)}, {}};
    Limits limits;
    limits.result_bytes = 1000;
    std::optional<Cursor> cursor;
    std::vector<OutPoint> keys;
    while (true) {
        const Page p = Run(s, f, QueryKind::Utxos(), limits, cursor);
        for (const Match &m : p.matches) {
            keys.push_back(m.record.outpoint);
        }
        cursor = p.continuation;
        if (!cursor) {
            break;
        }
    }
    size_t unburnt = 0;
    for (const auto &[k, r] : s.records) {
        unburnt += !r.output.IsBurn();
    }
    BOOST_CHECK_EQUAL(keys.size(), unburnt);
}

BOOST_AUTO_TEST_CASE(spent_token_history_and_missing_positions) {
    Source s = MakeSource();
    OutputRecord &record = std::next(s.records.begin())->second;
    const OutPoint key = record.outpoint;
    record.output.flags = 1;
    record.output.token_id = Root(80);
    record.output.value = UINT64_MAX;
    record.spend = SpendLocation{record.creation, 7};
    const BranchFilter f{{Root(1)}, {}};
    const Page h =
        Run(s, f, QueryKind::History(true), Limits{}, std::nullopt);
    const auto found =
        std::find_if(h.matches.begin(), h.matches.end(),
                     [&](const Match &m) { return m.record.outpoint == key; });
    BOOST_REQUIRE(found != h.matches.end());
    BOOST_CHECK_EQUAL(found->record.output.value, UINT64_MAX);
    BOOST_CHECK_EQUAL(found->record.spend->input_index, 7u);
    const Page u = Run(s, f, QueryKind::Utxos(), Limits{}, std::nullopt);
    BOOST_CHECK(std::none_of(
        u.matches.begin(), u.matches.end(),
        [&](const Match &m) { return m.record.outpoint == key; }));
    const BranchFilter missing{{Root(1)}, {{15, {Root(9)}}}};
    BOOST_CHECK(Run(s, missing, QueryKind::History(true), Limits{},
                    std::nullopt)
                    .matches.empty());
}

BOOST_AUTO_TEST_CASE(all_snapshot_components_bind_cursor) {
    const Source s = MakeSource();
    const BranchFilter f{{Root(1)}, {}};
    Limits limits;
    limits.page_size = 1;
    const auto cursor =
        Run(s, f, QueryKind::Utxos(), limits, std::nullopt).continuation;
    BOOST_REQUIRE(cursor);
    for (int component = 0; component < 4; ++component) {
        Cursor changed = *cursor;
        switch (component) {
            case 0:
                changed.snapshot.chain_id = Root(90);
                break;
            case 1:
                changed.snapshot.profile_id = Root(90);
                break;
            case 2:
                changed.snapshot.tip = Root(90);
                break;
            default:
                changed.snapshot.height += 1;
        }
        BOOST_CHECK(ThrowsKind(
            [&] { Run(s, f, QueryKind::Utxos(), limits, changed); },
            QueryError::Kind::StaleCursor));
    }
}

BOOST_AUTO_TEST_CASE(matching_outputs_in_same_transaction_remain_distinct) {
    Source s = MakeSource();
    OutputRecord record = std::next(s.records.begin())->second;
    const OutPoint first = record.outpoint;
    record.outpoint.out_idx = 1;
    const OutPoint second = record.outpoint;
    s.records[second] = record;
    const BranchFilter f{{Root(1), Root(9)}, {}};
    Limits limits;
    limits.page_size = 1;
    std::optional<Cursor> cursor;
    std::vector<OutPoint> found;
    while (true) {
        const Page p = Run(s, f, QueryKind::History(true), limits, cursor);
        for (const Match &m : p.matches) {
            found.push_back(m.record.outpoint);
        }
        cursor = p.continuation;
        if (!cursor) {
            break;
        }
    }
    BOOST_CHECK_EQUAL(std::count(found.begin(), found.end(), first), 1);
    BOOST_CHECK_EQUAL(std::count(found.begin(), found.end(), second), 1);
    BOOST_CHECK(std::adjacent_find(found.begin(), found.end(),
                                   std::greater_equal<>()) == found.end());
}

BOOST_AUTO_TEST_SUITE_END()
