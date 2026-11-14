// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "fixture.h"
#include "../oracle/schedule.h"
#include <bit>
#include <limits>

using namespace snowstorm_test;
namespace oracle = snowstorm_oracle;
namespace {
void require_postcondition(const snowstorm::Cell &cell, std::uint64_t index,
                           const IdSet &refs,
                           const snowstorm::DecodeResult &result) {
    BOOST_REQUIRE_LE(result.size, 2U);
    if (result.kind == snowstorm::DecodeKind::undecodable) {
        BOOST_REQUIRE_EQUAL(result.size, 0U);
        return;
    }
    const auto items = to_oracle(result);
    BOOST_REQUIRE(oracle::verifies_decode(to_oracle(cell), index, items, refs));
    BOOST_REQUIRE_EQUAL(result.size,
        result.kind == snowstorm::DecodeKind::zero ? 0U :
        result.kind == snowstorm::DecodeKind::one ? 1U : 2U);
}
std::pair<oracle::Cell, IdSet> high_degree_cell(std::size_t degree, Rng &rng) {
    IdSet ids;
    while (ids.size() < degree) ids.insert(rng.nonzero());
    IdSet refs;
    oracle::Cell cell{};
    for (const auto id : ids) {
        const int sign = rng.bounded(2) ? -1 : 1;
        BOOST_REQUIRE(oracle::add(cell, id, sign));
        if (sign < 0) refs.insert(id);
    }
    return {cell, refs};
}
void check_small_cell(std::span<const std::uint64_t> ids,
                      unsigned sign_bits, unsigned reference_bits) {
    oracle::Cell original{};
    IdSet refs;
    int inferred_count = 0;
    for (std::size_t i = 0; i < ids.size(); ++i) {
        const int sign = (sign_bits & (1U << i)) ? -1 : 1;
        BOOST_REQUIRE(oracle::add(original, ids[i], sign));
        const bool present = reference_bits & (1U << i);
        if (present) refs.insert(ids[i]);
        inferred_count += present ? -1 : 1;
    }
    const auto result = snowstorm::decode(to_core(original), 0, reference(refs));
    require_postcondition(to_core(original), 0, refs, result);
    if (inferred_count != original.count) {
        BOOST_REQUIRE(result.kind == snowstorm::DecodeKind::undecodable);
        return;
    }
    BOOST_REQUIRE_EQUAL(result.size, ids.size());
    for (std::size_t i = 0; i < ids.size(); ++i) {
        BOOST_REQUIRE_EQUAL(result.items[i].item, ids[i]);
        BOOST_REQUIRE_EQUAL(static_cast<int>(result.items[i].sign),
                            refs.contains(ids[i]) ? -1 : 1);
    }
}
}
BOOST_AUTO_TEST_SUITE(snowstorm_acceptance)
BOOST_AUTO_TEST_CASE(T2_exhaustive_small_sign_reference_cells) {
    const IdSet nonempty{1, 3, 7};
    for (const IdSet &refs : {IdSet{}, nonempty}) {
        const auto zero = snowstorm::decode({}, 0, reference(refs));
        BOOST_REQUIRE(zero.kind == snowstorm::DecodeKind::zero);
        require_postcondition({}, 0, refs, zero);
    }
    for (std::uint64_t a = 1; a <= 8; ++a) {
        const std::array one{a};
        for (unsigned masks = 0; masks < 4; ++masks) {
            check_small_cell(one, masks & 1U, masks >> 1);
        }
    }
    for (std::uint64_t a = 1; a <= 8; ++a) {
        for (std::uint64_t b = a + 1; b <= 8; ++b) {
            const std::array pair{a, b};
            for (unsigned masks = 0; masks < 16; ++masks) {
                // XOR syndromes contain no sign bits. For count-zero pairs,
                // exchanging both signs yields the same cell; the exact signs
                // are defined by reference membership, as §4.1 requires.
                check_small_cell(pair, masks & 3U, masks >> 2);
            }
        }
    }
    Rng rng(0x7432000000000001ULL);
    for (std::size_t trial = 0; trial < 10'000; ++trial) {
        auto a = rng.nonzero();
        auto b = rng.nonzero();
        while (b == a) b = rng.nonzero();
        const std::array pair{std::min(a, b), std::max(a, b)};
        const auto signs = static_cast<unsigned>(rng.bounded(4));
        check_small_cell(pair, signs, signs);
    }
}

BOOST_AUTO_TEST_CASE(T2_reject_million_scale_high_degree_and_random_cells) {
    Rng rng(0x7432000000000002ULL);
    for (const std::size_t degree : {3U, 4U, 5U}) {
        for (std::size_t trial = 0; trial < 100'000; ++trial) {
            const auto [cell, refs] = high_degree_cell(degree, rng);
            BOOST_REQUIRE(snowstorm::decode(to_core(cell), 0, reference(refs)).kind ==
                          snowstorm::DecodeKind::undecodable);
        }
    }
    for (std::size_t trial = 0; trial < 1'000'000; ++trial) {
        const auto raw_count = static_cast<std::uint32_t>(rng.next());
        const snowstorm::Cell cell{std::bit_cast<std::int32_t>(raw_count),
                                    rng.next(), rng.next(), rng.next()};
        const IdSet refs{rng.nonzero(), rng.nonzero()};
        const auto index = rng.bounded(257);
        const auto result = snowstorm::decode(cell, index, reference(refs));
        require_postcondition(cell, index, refs, result);
    }
}

BOOST_AUTO_TEST_CASE(T2_schedule_integrity_overflow_and_wire) {
    const IdSet empty;
    oracle::Cell single{};
    BOOST_REQUIRE(oracle::add(single, 7, 1));
    std::uint64_t missing = 1;
    while (oracle::includes(7, missing)) ++missing;
    BOOST_REQUIRE(snowstorm::decode(to_core(single), missing, reference(empty)).kind ==
                  snowstorm::DecodeKind::undecodable);
    auto corrupt = to_core(single);
    corrupt.s5 ^= 1;
    BOOST_REQUIRE(snowstorm::decode(corrupt, 0, reference(empty)).kind ==
                  snowstorm::DecodeKind::undecodable);
    auto maximal = snowstorm::Cell{std::numeric_limits<std::int32_t>::max(), 1, 2, 3};
    const auto before_maximal = to_oracle(maximal);
    BOOST_REQUIRE(snowstorm::cell_add(maximal, 7, snowstorm::Sign::positive) ==
                  snowstorm::Error::overflow);
    require_cell_equal(maximal, before_maximal);
    auto minimal = snowstorm::Cell{-std::numeric_limits<std::int32_t>::max(), 1, 2, 3};
    const auto before_minimal = to_oracle(minimal);
    BOOST_REQUIRE(snowstorm::cell_add(minimal, 7, snowstorm::Sign::negative) ==
                  snowstorm::Error::overflow);
    require_cell_equal(minimal, before_minimal);
    BOOST_REQUIRE(snowstorm::cell_subtract(maximal, {-1, 0, 0, 0}) ==
                  snowstorm::Error::overflow);
    require_cell_equal(maximal, before_maximal);
    BOOST_REQUIRE(snowstorm::cell_add(maximal, 0, snowstorm::Sign::positive) ==
                  snowstorm::Error::invalid_id);
    require_cell_equal(maximal, before_maximal);
    const snowstorm::Cell wire{-2, 0x0807060504030201ULL,
                                0x1817161514131211ULL, 0x2827262524232221ULL};
    // Hand-written LE28 vector: -2 is feffffff, each u64 follows low byte first.
    const std::array<std::uint8_t, 28> expected{
        0xfe,0xff,0xff,0xff,1,2,3,4,5,6,7,8,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28};
    std::array<std::uint8_t, 28> bytes{};
    BOOST_REQUIRE(snowstorm::serialize_cell(wire, bytes) == snowstorm::Error::ok);
    BOOST_REQUIRE(bytes == expected);
    snowstorm::Cell parsed{};
    BOOST_REQUIRE(snowstorm::parse_cell(bytes, parsed) == snowstorm::Error::ok);
    require_cell_equal(parsed, to_oracle(wire));
    const auto before_parse = parsed;
    bytes[0] = 0; bytes[1] = 0; bytes[2] = 0; bytes[3] = 0x80;
    BOOST_REQUIRE(snowstorm::parse_cell(bytes, parsed) != snowstorm::Error::ok);
    require_cell_equal(parsed, to_oracle(before_parse));
    for (std::size_t length = 0; length < 28; ++length) {
        BOOST_REQUIRE(snowstorm::parse_cell(std::span(bytes).first(length), parsed) !=
                      snowstorm::Error::ok);
    }
}
BOOST_AUTO_TEST_SUITE_END()
