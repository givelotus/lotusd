// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/schedule.h>
#include <algorithm>
#include <bit>

namespace snowstorm {
namespace {
using Wide = unsigned __int128;
constexpr unsigned INDEX_BITS = 40;
constexpr unsigned DRAW_BITS = 32;
constexpr unsigned WORD_BITS = 64;
constexpr auto INDEX_BOUND = std::uint64_t{1} << INDEX_BITS;
constexpr auto DRAW_SCALE = std::uint64_t{1} << DRAW_BITS;
constexpr std::uint64_t MIX_INCREMENT = 0x9e3779b97f4a7c15ULL;
constexpr std::uint64_t MIX_FIRST = 0xbf58476d1ce4e5b9ULL;
constexpr std::uint64_t MIX_SECOND = 0x94d049bb133111ebULL;
constexpr unsigned MIX_SHIFT_FIRST = 30;
constexpr unsigned MIX_SHIFT_SECOND = 27;
constexpr unsigned MIX_SHIFT_LAST = 31;

std::uint32_t draw_next(std::uint64_t &state) noexcept {
    state += MIX_INCREMENT;
    auto value = state;
    value = (value ^ (value >> MIX_SHIFT_FIRST)) * MIX_FIRST;
    value = (value ^ (value >> MIX_SHIFT_SECOND)) * MIX_SECOND;
    return static_cast<std::uint32_t>(value ^ (value >> MIX_SHIFT_LAST));
}
/** Newton iteration starts above sqrt and stops at the integer floor.
 * Schedule discriminants fit in 115 bits, so additions cannot overflow.
 */
Wide integer_sqrt(Wide value) noexcept {
    if (value == 0) return 0;
    const auto high = static_cast<std::uint64_t>(value >> WORD_BITS);
    const auto bits = high ? WORD_BITS + std::bit_width(high)
                           : std::bit_width(static_cast<std::uint64_t>(value));
    Wide root = Wide{1} << ((bits + 1) / 2);
    while (true) {
        const auto next = (root + value / root) / 2;
        if (next >= root) return root;
        root = next;
    }
}
bool reaches(SymbolIndex index, std::uint64_t remaining, Wide target) noexcept {
    return Wide{remaining} * (Wide{index} + 1) * (Wide{index} + 2) >= target;
}
}
Error schedule_next(SymbolIndex current, std::uint32_t draw,
                    SymbolIndex max_index, SymbolIndex &next) noexcept {
    if (current >= INDEX_BOUND || max_index >= INDEX_BOUND) return Error::invalid_range;
    if (current >= max_index) return Error::exhausted;
    const auto remaining = DRAW_SCALE - draw;
    const Wide target = Wide{DRAW_SCALE} * (Wide{current} + 1) * (Wide{current} + 2);
    if (!reaches(max_index, remaining, target)) return Error::exhausted;
    auto candidate = current + 1;
    if (!reaches(candidate, remaining, target)) {
        const auto threshold = (target + remaining - 1) / remaining;
        const auto root = integer_sqrt(4 * threshold + 1);
        candidate = std::max(candidate, static_cast<SymbolIndex>((root - 3) / 2));
        // The rounded quadratic estimate is at most one below the least solution.
        if (!reaches(candidate, remaining, target)) ++candidate;
        if (candidate > current + 1 && reaches(candidate - 1, remaining, target)) --candidate;
    }
    next = candidate;
    return Error::ok;
}
ScheduleIterator::ScheduleIterator(ShortId item, SymbolIndex max_index) {
    exhausted_ = true;
    // Invalid construction yields an exhausted iterator; reset reports the error.
    (void)reset(item, max_index);
}
Error ScheduleIterator::reset(ShortId item, SymbolIndex max_index) noexcept {
    if (item == 0 || max_index >= INDEX_BOUND) return Error::invalid_argument;
    state_ = item;
    index_ = 0;
    max_index_ = max_index;
    first_ = true;
    exhausted_ = false;
    return Error::ok;
}
std::optional<SymbolIndex> ScheduleIterator::next() noexcept {
    if (exhausted_) return std::nullopt;
    if (first_) {
        first_ = false;
        return index_;
    }
    const auto draw = draw_next(state_);
    if (schedule_next(index_, draw, max_index_, index_) != Error::ok) {
        exhausted_ = true;
        return std::nullopt;
    }
    return index_;
}
bool schedule_includes(ShortId item, SymbolIndex index) noexcept {
    if (item == 0 || index >= INDEX_BOUND) return false;
    ScheduleIterator iterator(item, index);
    while (const auto next = iterator.next()) {
        if (*next == index) return true;
    }
    return false;
}
} // namespace snowstorm
