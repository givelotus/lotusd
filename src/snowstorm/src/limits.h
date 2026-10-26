// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
#include "params.h"
namespace snowstorm::detail {
// Phase A explicitly exempts normative formulas in limits.h from magic-number lint.
// NOLINTBEGIN(readability-magic-numbers)
// Derived Config ceiling: the entire exclusion list and initial framing must fit.
inline constexpr std::uint64_t MAX_SET_SIZE =
    (params::MESSAGE_BYTES - params::FIRST_MESSAGE_OVERHEAD) / sizeof(ShortId);
// Derived schedule-domain ceiling used by the normative minimum below.
inline constexpr std::uint64_t MAX_SYMBOL_INDEX = (std::uint64_t{1} << 39) - 1;
/** Exact derived collection counts. M is validated against MAX_SET_SIZE first,
 * so every polynomial below fits u64; unrestricted session operands use u128.
 */
inline constexpr std::uint64_t log_limit(std::uint64_t m) noexcept { return 8 * m + 64; }
inline constexpr std::uint64_t pending_limit(std::uint64_t m) noexcept { return 2 * m + 32; }
inline constexpr std::uint64_t failure_limit(std::uint64_t m) noexcept { return 8 * m + 128; }
inline constexpr std::uint64_t donor_limit(std::uint64_t m) noexcept { return 8 * (10 * m + 160); }
inline constexpr std::uint64_t membership_limit(std::uint64_t m) noexcept { return 4 * m + 64; }
inline constexpr std::uint64_t symbol_index_limit(std::uint64_t m) noexcept { return 64 * m + 4096; }
inline constexpr std::uint64_t cell_limit(std::uint64_t m) noexcept { return 6 * m + 32; }
inline constexpr std::uint64_t other_records(const Limits &limits) noexcept {
    return 16 * (limits.max_peers + 1) + 4 * limits.max_cells + 4 * limits.max_pending;
}
// NOLINTEND(readability-magic-numbers)
} // namespace snowstorm::detail
