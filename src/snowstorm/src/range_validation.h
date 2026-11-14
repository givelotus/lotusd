// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
#include <limits>
namespace snowstorm::detail {
inline Error check_range(Range range, SymbolIndex previous_end, const Limits &limits,
                  std::uint64_t &total) noexcept {
    if (range.begin >= range.end || range.begin < previous_end ||
        range.end - 1 > limits.max_symbol_index) return Error::invalid_range;
    const auto length = range.end - range.begin;
    if (length > std::numeric_limits<std::uint64_t>::max() - total) return Error::overflow;
    total += length;
    return total > limits.max_cells ? Error::capacity : Error::ok;
}
inline Error check_ranges(std::span<const Range> ranges, const Limits &limits, std::uint64_t &total) noexcept {
    if (ranges.empty()) return Error::malformed_message;
    if (ranges.size() > limits.max_ranges) return Error::capacity;
    SymbolIndex previous{};
    for (const auto range : ranges) {
        const auto error = check_range(range, previous, limits, total);
        if (error != Error::ok) return error;
        previous = range.end;
    }
    return Error::ok;
}
} // namespace snowstorm::detail
