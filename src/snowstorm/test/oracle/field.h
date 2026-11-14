// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#ifndef LOTUS_SNOWSTORM_TEST_ORACLE_FIELD_H
#define LOTUS_SNOWSTORM_TEST_ORACLE_FIELD_H

#include <cstdint>
#include <optional>

namespace snowstorm_oracle {

/** §2: independent, bit-by-bit polynomial multiplication modulo x^64+x^4+x^3+x+1. */
std::uint64_t mul(std::uint64_t a, std::uint64_t b);
/** §2: binary exponentiation using only the independent polynomial multiply. */
std::uint64_t power(std::uint64_t base, std::uint64_t exponent);
/** §2: x^(2^64-2); zero has no inverse and yields nullopt. */
std::optional<std::uint64_t> inverse(std::uint64_t x);
/** §2: sum x+x^2+...+x^(2^63), returned as field element 0 or 1. */
std::uint64_t trace(std::uint64_t x);
/** §2: directly substitutes a claimed root into y^2+y=D; no production solver. */
bool verifies_root(std::uint64_t d, std::uint64_t y);
/** §2: exhaustively searches [0, exclusive_limit), for small hand-checkable domains. */
std::optional<std::uint64_t> brute_force_root(std::uint64_t d,
                                              std::uint64_t exclusive_limit);

} // namespace snowstorm_oracle
#endif
