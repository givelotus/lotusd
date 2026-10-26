// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include <snowstorm/sketch.h>

using namespace snowstorm_test;
namespace {
void check_cache(const snowstorm::SketchCache &cache, const IdSet &ids,
                 snowstorm::Range range) {
    const auto expected = snowstorm_oracle::encode(ids, range.begin, range.end);
    std::vector<snowstorm::Cell> actual(expected.size()), direct(expected.size());
    const auto items = sorted_ids(ids);
    BOOST_REQUIRE(cache.encode(range, actual) == snowstorm::Error::ok);
    BOOST_REQUIRE(snowstorm::encode(items, range, direct) == snowstorm::Error::ok);
    for (std::size_t i = 0; i < actual.size(); ++i) {
        require_cell_equal(actual[i], expected[i]);
        require_cell_equal(direct[i], expected[i]);
    }
    const auto view = cache.view();
    BOOST_REQUIRE_EQUAL(view.indices.size(), view.counts.size());
    BOOST_REQUIRE_EQUAL(view.indices.size(), view.s1.size());
    BOOST_REQUIRE_EQUAL(view.indices.size(), view.s3.size());
    BOOST_REQUIRE_EQUAL(view.indices.size(), view.s5.size());
    BOOST_REQUIRE_EQUAL(reinterpret_cast<std::uintptr_t>(view.counts.data()) % 64, 0U);
    BOOST_REQUIRE_EQUAL(reinterpret_cast<std::uintptr_t>(view.s1.data()) % 64, 0U);
    BOOST_REQUIRE_EQUAL(reinterpret_cast<std::uintptr_t>(view.s3.data()) % 64, 0U);
    BOOST_REQUIRE_EQUAL(reinterpret_cast<std::uintptr_t>(view.s5.data()) % 64, 0U);
    for (std::size_t i = 0; i < view.indices.size(); ++i) {
        BOOST_REQUIRE_GE(view.indices[i], range.begin);
        BOOST_REQUIRE_LT(view.indices[i], range.end);
        const auto &cell = expected[view.indices[i] - range.begin];
        require_cell_equal({view.counts[i], view.s1[i], view.s3[i], view.s5[i]}, cell);
    }
}
}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T4_ten_thousand_random_incremental_sequences) {
    Rng rng(0x7434000000000001ULL);
    for (unsigned trial = 0; trial < 10000; ++trial) {
        snowstorm::SketchCache cache(64, 128, 255);
        IdSet ids;
        const auto begin = rng.bounded(192);
        BOOST_REQUIRE(cache.cache_range({begin, begin + 64}) == snowstorm::Error::ok);
        for (unsigned step = 0; step < 32; ++step) {
            const auto id = 1 + rng.bounded(48);
            const bool present = ids.contains(id);
            const auto result = present ? cache.remove(id) : cache.add(id);
            BOOST_REQUIRE(result == snowstorm::Error::ok);
            if (present) ids.erase(id); else ids.insert(id);
            BOOST_REQUIRE_EQUAL(cache.size(), ids.size());
            check_cache(cache, ids, {begin, begin + 64});
        }
    }
}
BOOST_AUTO_TEST_CASE(T4_duplicate_capacity_and_clear_are_atomic) {
    snowstorm::SketchCache cache(2, 4, 255);
    BOOST_REQUIRE(cache.cache_range({0, 4}) == snowstorm::Error::ok);
    BOOST_REQUIRE(cache.add(7) == snowstorm::Error::ok);
    BOOST_REQUIRE(cache.add(7) == snowstorm::Error::duplicate);
    check_cache(cache, {7}, {0, 4});
    BOOST_REQUIRE(cache.add(8) == snowstorm::Error::ok);
    BOOST_REQUIRE(cache.add(9) == snowstorm::Error::capacity);
    check_cache(cache, {7, 8}, {0, 4});
    BOOST_REQUIRE(cache.add(0) == snowstorm::Error::invalid_id);
    cache.clear();
    BOOST_REQUIRE_EQUAL(cache.size(), 0U);
    BOOST_REQUIRE(cache.cache_range({0, 4}) == snowstorm::Error::ok);
    check_cache(cache, {}, {0, 4});
}
BOOST_AUTO_TEST_SUITE_END()
