// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
namespace snowstorm::detail {
/** Measure normal-symbol framing from the same wire grammar, without payload
 * allocation. Exclusion omission is distinct from a present empty list. */
Error normal_symbols_size(std::uint64_t ranges, std::uint64_t cells,
                          std::optional<std::uint64_t> exclusions,
                          const Limits &limits, std::size_t &bytes) noexcept;
} // namespace snowstorm::detail
