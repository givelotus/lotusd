// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include "schedule.h"

#include <algorithm>
#include <stdexcept>

namespace snowstorm_oracle {
namespace {
constexpr std::uint64_t INDEX_LIMIT = (std::uint64_t{1} << 40) - 1;
constexpr Uint128 DRAW_SCALE = Uint128{1} << 32;

void check_index(std::uint64_t index) {
    if (index > INDEX_LIMIT) {
        throw std::out_of_range("oracle schedule index must be below 2^40");
    }
}

bool reaches(std::uint64_t index, std::uint64_t remaining_draw,
             Uint128 target) {
    const Uint128 first = Uint128{index} + 1;
    return Uint128{remaining_draw} * first * (first + 1) >= target;
}
} // namespace

Uint128 integer_sqrt(Uint128 value) {
    // Restoring base-four algorithm: consume one pair of input bits per step.
    // No floating arithmetic and no production square-root dependency.
    Uint128 root = 0;
    Uint128 place = Uint128{1} << 126;
    while (place != 0) {
        if (value >= root + place) {
            value -= root + place;
            root = (root >> 1) + place;
        } else {
            root >>= 1;
        }
        place >>= 2;
    }
    return root;
}

std::uint64_t splitmix_next(std::uint64_t &state) {
    state += 0x9e3779b97f4a7c15ULL;
    std::uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

std::optional<std::uint64_t> next_index(std::uint64_t index,
                                       std::uint32_t draw,
                                       std::uint64_t max_index) {
    check_index(index);
    check_index(max_index);
    if (index >= max_index) {
        return std::nullopt;
    }
    const std::uint64_t remaining = (std::uint64_t{1} << 32) - draw;
    const Uint128 target = DRAW_SCALE * (Uint128{index} + 1) *
                           (Uint128{index} + 2);
    // First solve j^2+3j+2 >= ceil(target/remaining), then verify against the
    // original undivided inequality. The final candidate is the LEAST j>i.
    const Uint128 quotient = (target + remaining - 1) / remaining;
    const Uint128 discriminant_root = integer_sqrt(1 + 4 * quotient);
    const auto estimate = static_cast<std::uint64_t>(
        (discriminant_root - 3) / 2);
    std::uint64_t candidate = std::max(index + 1, estimate);
    while (candidate > index + 1 && reaches(candidate - 1, remaining, target)) {
        --candidate;
    }
    while (!reaches(candidate, remaining, target)) {
        ++candidate;
    }
    if (candidate > max_index) {
        return std::nullopt;
    }
    return candidate;
}

std::vector<std::uint64_t> schedule(std::uint64_t item,
                                     std::uint64_t max_index) {
    check_index(max_index);
    if (item == 0) {
        throw std::invalid_argument("oracle schedule item must be nonzero");
    }
    std::vector<std::uint64_t> indices{0};
    std::uint64_t state = item;
    while (true) {
        const auto draw = static_cast<std::uint32_t>(splitmix_next(state));
        const auto next = next_index(indices.back(), draw, max_index);
        if (!next) {
            return indices;
        }
        indices.push_back(*next);
    }
}

bool includes(std::uint64_t item, std::uint64_t index) {
    const auto positions = schedule(item, index);
    return positions.back() == index;
}

} // namespace snowstorm_oracle
