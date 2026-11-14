// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license; see COPYING.
#include "field.h"

#include <limits>

namespace snowstorm_oracle {

std::uint64_t mul(std::uint64_t a, std::uint64_t b) {
    std::uint64_t product = 0;
    // Polynomial long multiplication: each bit of b selects one shifted a.
    // A carry represents x^64, replaced by x^4+x^3+x+1, independently of any
    // production tables, carry-less instructions, or multiplication routines.
    for (unsigned bit = 0; bit < 64; ++bit) {
        if ((b & 1) != 0) {
            product ^= a;
        }
        const bool carry = (a >> 63) != 0;
        a <<= 1;
        if (carry) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return product;
}

std::uint64_t power(std::uint64_t base, std::uint64_t exponent) {
    std::uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    return result;
}

std::optional<std::uint64_t> inverse(std::uint64_t x) {
    if (x == 0) {
        return std::nullopt;
    }
    return power(x, std::numeric_limits<std::uint64_t>::max() - 1);
}

std::uint64_t trace(std::uint64_t x) {
    std::uint64_t sum = 0;
    for (unsigned degree = 0; degree < 64; ++degree) {
        sum ^= x;
        x = mul(x, x);
    }
    return sum;
}

bool verifies_root(std::uint64_t d, std::uint64_t y) {
    return (mul(y, y) ^ y) == d;
}

std::optional<std::uint64_t> brute_force_root(
    std::uint64_t d, std::uint64_t exclusive_limit) {
    for (std::uint64_t candidate = 0; candidate < exclusive_limit; ++candidate) {
        if (verifies_root(d, candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

} // namespace snowstorm_oracle
