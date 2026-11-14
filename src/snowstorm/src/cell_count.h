// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <cstdint>
#include <limits>
namespace snowstorm::detail {
inline constexpr std::int64_t CELL_MAX_COUNT = std::numeric_limits<std::int32_t>::max();
/** Normative signed-count domain excludes INT32_MIN on every ingress/update. */
inline constexpr bool valid_cell_count(std::int64_t count) noexcept {
    return count >= -CELL_MAX_COUNT && count <= CELL_MAX_COUNT;
}
} // namespace snowstorm::detail
