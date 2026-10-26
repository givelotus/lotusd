// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#ifndef LOTUS_SNOWSTORM_TEST_ORACLE_SCHEDULE_H
#define LOTUS_SNOWSTORM_TEST_ORACLE_SCHEDULE_H

#include <cstdint>
#include <optional>
#include <vector>

namespace snowstorm_oracle {

using Uint128 = unsigned __int128;
/** §4.2: independently written restoring integer square root, rounded down. */
Uint128 integer_sqrt(Uint128 value);
/** §4.2: next SplitMix64 draw, with explicit unsigned modular state arithmetic. */
std::uint64_t splitmix_next(std::uint64_t &state);
/** §4.2: exact inverse-CDF step for an explicit uint32 draw; nullopt past bound. */
std::optional<std::uint64_t> next_index(std::uint64_t index,
                                       std::uint32_t draw,
                                       std::uint64_t max_index);
/** §4.2: all included symbol positions in [0, max_index], including zero. */
std::vector<std::uint64_t> schedule(std::uint64_t item,
                                     std::uint64_t max_index);
/** §4.2: independent membership query by direct enumeration through index. */
bool includes(std::uint64_t item, std::uint64_t index);

} // namespace snowstorm_oracle
#endif
