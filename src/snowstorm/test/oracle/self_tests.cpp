// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include "field.h"
#include "model.h"
#include "schedule.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using namespace snowstorm_oracle;

class Checks {
public:
    void require(bool condition, std::string_view label) {
        if (!condition) {
            throw std::runtime_error(std::string(label));
        }
        ++m_count;
    }

    template <class Exception, class Function>
    void throws(Function action, std::string_view label) {
        bool caught = false;
        try {
            action();
        } catch (const Exception &) {
            caught = true;
        }
        require(caught, label);
    }

    std::uint64_t count() const { return m_count; }

private:
    std::uint64_t m_count{0};
};

void field_vectors(Checks &checks) {
    // Hand arithmetic: polynomial zero/identity; x*x=x^2; (x+1)^2=x^2+1.
    checks.require(mul(0, 7) == 0, "zero polynomial product");
    checks.require(mul(1, 1) == 1, "one times one");
    checks.require(mul(2, 2) == 4, "x squared");
    checks.require(mul(3, 3) == 5, "(x+1) squared");
    checks.require(mul(3, 2) == 6, "(x+1) times x");
    // x^63*x=x^64=x^4+x^3+x+1 modulo P, encoded as 0x1b.
    checks.require(mul(std::uint64_t{1} << 63, 2) == 0x1b,
                   "high-bit polynomial reduction");
    checks.require(power(2, 64) == 0x1b, "x^64 reduction by exponentiation");
    // x*(x^63+x^3+x^2+1)=x^64+x^4+x^3+x = 1 modulo P.
    constexpr std::uint64_t inverse_of_x = 0x800000000000000dULL;
    checks.require(mul(2, inverse_of_x) == 1, "hand-derived inverse product");
    checks.require(inverse(2) == inverse_of_x, "inverse by exponentiation");
    checks.require(inverse(1) == 1, "inverse of identity");
    checks.require(!inverse(0), "zero has no inverse");
    checks.require(power(17, 0) == 1, "zero exponent");
    checks.require(power(0, 9) == 0, "positive power of zero");

    // Newton sums of P: coefficients a1..a59 vanish; a60=a61=a63=1.
    // Thus S1..S59=0, S60=0 (60 even), S61=1 (61 odd), S63=1.
    // Since the conjugates are alpha^(2^i), these power sums are field traces.
    checks.require(trace(0) == 0, "trace zero");
    checks.require(trace(1) == 0, "trace one is 64 mod 2");
    checks.require(trace(2) == 0, "Newton-sum trace x");
    checks.require(trace(std::uint64_t{1} << 61) == 1, "trace theta=x^61");
    checks.require(trace(std::uint64_t{1} << 63) == 1, "Newton-sum trace x^63");

    // y=x gives y^2+y=x^2+x=6; y=x+1 gives the same value.
    checks.require(verifies_root(6, 2), "direct quadratic root x");
    checks.require(verifies_root(6, 3), "direct quadratic root x+1");
    checks.require(!verifies_root(6, 1), "reject wrong quadratic root");
    checks.require(brute_force_root(6, 4) == 2, "exhaustive root enumeration");
    checks.require(!brute_force_root(6, 2), "bounded search cannot invent root");
    checks.require(brute_force_root(0, 1) == 0, "solve-zero hand vector");
    checks.require(!brute_force_root(0, 0), "empty exhaustive domain");
}

void field_algebra_checks(Checks &checks) {
    // Supplemental consistency checks do not replace the hand-derived vectors.
    for (std::uint64_t x = 1; x <= 128; ++x) {
        const auto inv = inverse(x);
        checks.require(inv && mul(x, *inv) == 1, "small inverse consistency");
        const auto d = mul(x, x) ^ x;
        checks.require(trace(d) == 0, "quadratic image has trace zero");
        checks.require(verifies_root(d, x ^ 1), "second quadratic root");
    }
}

void sqrt_vectors(Checks &checks) {
    // Hand floor roots, especially either side of perfect squares.
    constexpr std::array<std::uint64_t, 17> expected{
        0, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4};
    for (std::size_t value = 0; value < expected.size(); ++value) {
        checks.require(integer_sqrt(value) == expected[value], "small floor sqrt");
    }
    // sqrt(2^126)=2^63; sqrt(2^128-1)=2^64-1 exactly.
    checks.require(integer_sqrt(Uint128{1} << 126) == (Uint128{1} << 63),
                   "128-bit perfect-square root");
    checks.require(integer_sqrt(~Uint128{0}) == (Uint128{1} << 64) - 1,
                   "maximum 128-bit input root");
    // Independent exhaustive reference increments a candidate only on squares.
    std::uint64_t expected_root = 0;
    for (std::uint64_t value = 0; value < 65536; ++value) {
        if ((expected_root + 1) * (expected_root + 1) <= value) {
            ++expected_root;
        }
        checks.require(integer_sqrt(value) == expected_root,
                       "exhaustive 16-bit floor sqrt");
    }
}

void schedule_vectors(Checks &checks) {
    // Applying the published SplitMix64 add/xor/multiply constants by unsigned
    // arithmetic from state 0 gives e220a8397b1dcdaf, state 1 gives 910a2dec89025cc1.
    std::uint64_t state = 0;
    checks.require(splitmix_next(state) == 0xe220a8397b1dcdafULL,
                   "SplitMix seed-zero known answer");
    checks.require(state == 0x9e3779b97f4a7c15ULL, "one state advance per draw");
    state = 1;
    checks.require(splitmix_next(state) == 0x910a2dec89025cc1ULL,
                   "SplitMix seed-one known answer");
    // At i=0 the target is 2^33. j=1 is chosen iff 6*s>=2^33.
    // u=0xaaaaaaaa: s=1431655766, 6*s=8589934596 >= 8589934592.
    // u=0xaaaaaaab: s=1431655765, 6*s=8589934590 < 8589934592;
    // j=2 then satisfies 12*s>=2^33. No statistical tolerance is used here.
    checks.require(next_index(0, 0, 10) == 1, "zero draw advances to one");
    checks.require(next_index(0, 0xaaaaaaaaU, 10) == 1,
                   "exact inclusion threshold lower draw");
    checks.require(next_index(0, 0xaaaaaaabU, 10) == 2,
                   "exact inclusion threshold upper draw");
    // At u=2^32-1, s=1. (92681*92682)=8589860442 < 2^33;
    // (92682*92683)=8590045806 >= 2^33; hence least j is 92681.
    checks.require(next_index(0, 0xffffffffU, 100000) == 92681,
                   "maximum draw exact gap");
    checks.require(!next_index(0, 0xffffffffU, 92680), "gap past bound exhausts");
    checks.require(next_index(0, 0xffffffffU, 92681) == 92681,
                   "gap ending at bound included");
    checks.require(!next_index(10, 0, 10), "iterator bound is terminal");
    checks.require(next_index(10, 0, 11) == 11, "strict increment at zero draw");
    constexpr std::uint64_t high = (std::uint64_t{1} << 40) - 2;
    checks.require(next_index(high, 0, high + 1) == high + 1,
                   "u128 arithmetic near maximum index");
    checks.require(!next_index(high, 0xffffffffU, high + 1),
                   "large high-index gap exhausts without wrapping");
    // Seed one's first low word is 0x89025cc1 < 0xaaaaaaaa, so index 1 follows 0.
    checks.require(schedule(1, 1) == std::vector<std::uint64_t>({0, 1}),
                   "complete hand-derived two-position schedule");
    checks.require(schedule(1, 0) == std::vector<std::uint64_t>({0}),
                   "index zero always included");
    checks.require(includes(1, 1), "membership hand-derived included index");
    checks.throws<std::invalid_argument>([] { schedule(0, 1); },
                                        "zero item rejected");
    checks.throws<std::out_of_range>(
        [] { next_index(0, 0, std::uint64_t{1} << 40); },
        "out-of-domain index rejected");
}

void schedule_minimality_checks(Checks &checks) {
    constexpr std::array<std::uint32_t, 5> draws{
        0, 1, 0x80000000U, 0xaaaaaaaaU, 0xffffffffU};
    for (std::uint64_t index = 0; index < 32; ++index) {
        for (const auto draw : draws) {
            const auto next = next_index(index, draw, 10000000);
            checks.require(next.has_value(), "small-index step exists");
            const Uint128 s = (Uint128{1} << 32) - draw;
            const Uint128 rhs = (Uint128{1} << 32) * (index + 1) * (index + 2);
            checks.require(s * (*next + 1) * (*next + 2) >= rhs,
                           "step satisfies original undivided inequality");
            checks.require(*next == index + 1 || s * *next * (*next + 1) < rhs,
                           "previous eligible index fails inequality");
        }
    }
}

void cell_vectors(Checks &checks) {
    Cell cell{};
    checks.require(add(cell, 1, 1), "add first cell item");
    checks.require(cell == Cell{1, 1, 1, 1}, "one contributes all-one syndromes");
    checks.require(add(cell, 2, -1), "subtract second cell item");
    // x=2: x^3=8, x^5=32, so +1,-2 gives count0, s1=3,s3=9,s5=33.
    checks.require(cell == Cell{0, 3, 9, 33}, "hand mixed-sign cell");
    const std::array<SignedItem, 2> pair{{{1, 1}, {2, -1}}};
    checks.require(verifies_decode(cell, 0, pair, IdSet{2}),
                   "mixed-sign pair full postconditions");
    checks.require(!verifies_decode(cell, 0, pair, IdSet{1}),
                   "pair cannot use wrong reference signs");
    const std::array<SignedItem, 1> singleton{{{1, 1}}};
    checks.require(verifies_decode(Cell{1, 1, 1, 1}, 0, singleton, {}),
                   "singleton full postconditions");
    checks.require(!verifies_decode(Cell{1, 1, 1, 1}, 0, singleton, IdSet{1}),
                   "contradictory singleton membership rejected");
    checks.require(verifies_decode(Cell{}, 0, {}, {}), "zero cell postconditions");
    checks.require(!verifies_decode(Cell{0, 0, 0, 1}, 0, {}, {}),
                   "zero requires all syndromes zero");
    const auto before = cell;
    checks.require(!add(cell, 0, 1) && cell == before, "invalid zero add atomic");
    checks.require(!add(cell, 1, 0) && cell == before, "invalid sign add atomic");
    Cell upper{std::numeric_limits<std::int32_t>::max(), 7, 8, 9};
    const auto upper_before = upper;
    checks.require(!add(upper, 1, 1) && upper == upper_before,
                   "positive count overflow atomic");
    Cell lower{-std::numeric_limits<std::int32_t>::max(), 7, 8, 9};
    const auto lower_before = lower;
    checks.require(!add(lower, 1, -1) && lower == lower_before,
                   "negative count overflow atomic");
    checks.require(subtract(Cell{1, 1, 1, 1}, Cell{1, 2, 8, 32}) == before,
                   "independent raw minus reference");
}

void snapshot_vectors(Checks &checks) {
    const std::array<Operation, 6> log{{
        {1, 1, 1}, {2, 2, 1}, {3, 1, -1},
        {4, 2, 0}, {5, 1, 1}, {6, 2, -1}}};
    // Replay by hand: {},{1},{1,2},{2},{2},{1,2},{1}. Event4 changes a
    // collision body only, advancing seq without changing the ID sketch.
    const std::array<IdSet, 7> expected{
        IdSet{}, IdSet{1}, IdSet{1, 2}, IdSet{2},
        IdSet{2}, IdSet{1, 2}, IdSet{1}};
    for (std::uint64_t seq = 0; seq < expected.size(); ++seq) {
        checks.require(snapshot(log, seq) == expected[seq], "hand snapshot log");
    }
    checks.require(snapshot(log, 99) == IdSet{1}, "snapshot after final event");
    checks.require(snapshot(log, 0, IdSet{3}) == IdSet{3}, "initial snapshot state");
    // Index0 contains every ID; encode {1,2} has exactly the following sum.
    checks.require(encode(IdSet{1, 2}, 0, 1) == std::vector<Cell>({{2, 3, 9, 33}}),
                   "hand direct set encoding");
    const std::array<SignedItem, 2> difference{{{1, 1}, {2, -1}}};
    checks.require(encode_signed(difference, 0, 1) ==
                       std::vector<Cell>({{0, 3, 9, 33}}),
                   "hand direct signed encoding");
    checks.require(encode(IdSet{}, 0, 3) == std::vector<Cell>(3),
                   "empty set encodes zero cells");
    checks.require(encode(IdSet{1}, 0, 2) ==
                       std::vector<Cell>({{1, 1, 1, 1}, {1, 1, 1, 1}}),
                   "hand seed-one schedule encoding");
    checks.require(encode(IdSet{1, 2}, 3, 3).empty(), "empty range encoding");
    checks.throws<std::invalid_argument>([] { encode(IdSet{}, 2, 1); },
                                        "reversed range rejected");
    const std::array<Operation, 2> unordered{{{2, 1, 1}, {1, 2, 1}}};
    checks.throws<std::invalid_argument>([&] { snapshot(unordered, 2); },
                                        "unordered operation sequence rejected");
}
} // namespace

int main() {
    Checks checks;
    try {
        field_vectors(checks);
        field_algebra_checks(checks);
        sqrt_vectors(checks);
        schedule_vectors(checks);
        schedule_minimality_checks(checks);
        cell_vectors(checks);
        snapshot_vectors(checks);
    } catch (const std::exception &error) {
        std::cerr << "snowstorm independent oracle self-tests: FAIL after "
                  << checks.count() << " checks: " << error.what() << '\n';
        return 1;
    }
    std::cout << "snowstorm independent oracle self-tests: PASS " << checks.count()
              << " checks; field, trace, exhaustive root verification, u128 sqrt, "
                 "integer schedule, signed cells, and snapshot replay\n";
    return 0;
}
