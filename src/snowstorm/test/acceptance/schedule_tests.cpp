// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../oracle/schedule.h"
#include <snowstorm/schedule.h>
#include <cmath>
#include <limits>

using namespace snowstorm_test;
namespace oracle = snowstorm_oracle;
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T3_ten_thousand_schedules_exact_first_256_indices) {
    Rng rng(0x7433000000000001ULL);
    for (std::size_t trial = 0; trial < 10'000; ++trial) {
        const auto item = rng.nonzero();
        // "First256 indices" is symbol positions0..255, not256 emitted
        // schedule positions: the schedule is logarithmically sparse.
        const auto expected = oracle::schedule(item, 255);
        snowstorm::ScheduleIterator iterator(item, 255);
        std::vector<std::uint64_t> actual;
        auto next = iterator.next();
        while (next.has_value()) {
            BOOST_REQUIRE_LE(*next, 255U);
            if (!actual.empty()) BOOST_REQUIRE_GT(*next, actual.back());
            actual.push_back(*next);
            next = iterator.next();
        }
        BOOST_REQUIRE(!iterator.next().has_value());
        BOOST_REQUIRE(!actual.empty());
        BOOST_REQUIRE_EQUAL(actual.front(), 0U);
        BOOST_REQUIRE(actual == expected);
        for (std::uint64_t index = 0; index < 256; ++index) {
            const bool present = std::binary_search(expected.begin(), expected.end(), index);
            BOOST_REQUIRE_EQUAL(snowstorm::schedule_includes(item, index), present);
        }
    }
}

BOOST_AUTO_TEST_CASE(T3_million_item_inclusion_frequencies) {
    constexpr std::size_t trials = 1'000'000;
    constexpr std::uint64_t seed = 0x7433000000000002ULL;
    constexpr std::array<std::uint64_t, 7> indices{1, 2, 4, 8, 16, 64, 256};
    std::array<std::size_t, indices.size()> counts{};
    Rng rng(seed);
    for (std::size_t trial = 0; trial < trials; ++trial) {
        const auto item = rng.nonzero();
        snowstorm::ScheduleIterator iterator(item, 256);
        BOOST_REQUIRE_EQUAL(iterator.next().value(), 0U);
        auto next = iterator.next();
        while (next.has_value()) {
            const auto found = std::lower_bound(indices.begin(), indices.end(), *next);
            if (found != indices.end() && *found == *next) {
                ++counts[static_cast<std::size_t>(found - indices.begin())];
            }
            next = iterator.next();
        }
    }
    for (std::size_t i = 0; i < indices.size(); ++i) {
        const double probability = 1.0 / (1.0 + double(indices[i]) / 2.0);
        const double mean = double(trials) * probability;
        const double four_sigma = 4.0 * std::sqrt(double(trials) * probability * (1.0 - probability));
        BOOST_TEST_MESSAGE("T3 seed=" << seed << " index=" << indices[i]
                           << " hits=" << counts[i] << " N=" << trials);
        BOOST_REQUIRE_LE(std::abs(double(counts[i]) - mean), four_sigma);
    }
}

BOOST_AUTO_TEST_CASE(T3_exact_integer_boundaries_and_exhaustion) {
    constexpr auto maximum = (std::uint64_t{1} << 39) - 1;
    constexpr std::array<std::uint64_t, 7> positions{
        0, 1, 2, 255, 65'535, maximum - 1, maximum};
    constexpr std::array<std::uint32_t, 7> draws{
        0, 1, 0x55555554U, 0x55555555U, 0x55555556U,
        0xfffffffeU, 0xffffffffU};
    for (const auto position : positions) {
        for (const auto draw : draws) {
            const auto expected = oracle::next_index(position, draw, maximum);
            std::uint64_t actual = 0xdeadbeef;
            const auto status = snowstorm::schedule_next(position, draw, maximum, actual);
            if (!expected) {
                BOOST_REQUIRE(status == snowstorm::Error::exhausted);
                continue;
            }
            BOOST_REQUIRE(status == snowstorm::Error::ok);
            BOOST_REQUIRE_EQUAL(actual, *expected);
            BOOST_REQUIRE_GT(actual, position);
        }
    }
    // At i=0, u=0 gives s=2^32 and j=1: 6*s>=2*2^32.
    // u=UINT32_MAX gives s=1 and the smallest j with(j+1)(j+2)>=2^33.
    std::uint64_t next{};
    BOOST_REQUIRE(snowstorm::schedule_next(0, 0, maximum, next) == snowstorm::Error::ok);
    BOOST_REQUIRE_EQUAL(next, 1U);
    snowstorm::ScheduleIterator only_zero(17, 0);
    BOOST_REQUIRE_EQUAL(only_zero.next().value(), 0U);
    BOOST_REQUIRE(!only_zero.next());
    BOOST_REQUIRE(!only_zero.next());
    BOOST_REQUIRE(only_zero.reset(0, 10) == snowstorm::Error::invalid_argument);
    BOOST_REQUIRE(!snowstorm::schedule_includes(0, 0));
    BOOST_REQUIRE(!snowstorm::schedule_includes(1, std::uint64_t{1} << 40));
}
BOOST_AUTO_TEST_SUITE_END()
