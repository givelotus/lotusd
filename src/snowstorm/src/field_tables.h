// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#ifndef LOTUS_SNOWSTORM_FIELD_TABLES_H
#define LOTUS_SNOWSTORM_FIELD_TABLES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace snowstorm::gf64::detail {
inline constexpr unsigned FIELD_BITS = 64;
inline constexpr unsigned BYTE_BITS = 8;
inline constexpr unsigned FIELD_BYTES = FIELD_BITS / BYTE_BITS;
inline constexpr unsigned BYTE_VALUES = 1U << BYTE_BITS;
inline constexpr unsigned BYTE_MASK = BYTE_VALUES - 1;
inline constexpr std::uint64_t REDUCTION = 0x1b;
inline constexpr std::uint64_t THETA = std::uint64_t{1} << 61;
using Basis = std::array<std::uint64_t, FIELD_BITS>;
using ByteTable = std::array<std::array<std::uint64_t, BYTE_VALUES>, FIELD_BYTES>;

// Compile-time polynomial arithmetic constructs constants, never a runtime
// fallback. Runtime portable multiplication uses a four-bit window.
constexpr std::uint64_t table_product(std::uint64_t a, std::uint64_t b) {
    std::uint64_t result = 0;
    for (unsigned bit = 0; bit < FIELD_BITS; ++bit) {
        if ((b & 1) != 0) result ^= a;
        const auto carry = a >> (FIELD_BITS - 1);
        a = (a << 1) ^ (carry * REDUCTION);
        b >>= 1;
    }
    return result;
}

constexpr Basis square_basis() {
    Basis result{};
    for (unsigned bit = 0; bit < FIELD_BITS; ++bit) {
        const auto x = std::uint64_t{1} << bit;
        result[bit] = table_product(x, x);
    }
    return result;
}

// a_i = sum(theta^(2^j), j=i+1..63), a_63=0. Tr(theta)=1 gives
// a_0=1+theta and a_i = a_(i-1)^2+theta. Consequently L(D)^2+L(D)
// = D+theta*Tr(D) for L(D)=sum(a_i*D^(2^i)). This is an even-degree
// linear map, not the invalid even-degree half-trace formula.
constexpr std::uint64_t solve_basis_image(unsigned bit) {
    auto power = std::uint64_t{1} << bit;
    auto coefficient = THETA ^ 1;
    std::uint64_t result = 0;
    for (unsigned i = 0; i < FIELD_BITS - 1; ++i) {
        result ^= table_product(coefficient, power);
        coefficient = table_product(coefficient, coefficient) ^ THETA;
        power = table_product(power, power);
    }
    return result;
}

// Each independent constant has its own constexpr evaluation budget.
template <std::size_t Bit>
inline constexpr auto SOLVE_BASIS_IMAGE = solve_basis_image(Bit);

template <std::size_t... Bits>
constexpr Basis solve_basis(std::index_sequence<Bits...>) {
    return {SOLVE_BASIS_IMAGE<Bits>...};
}

constexpr ByteTable expand_bytes(const Basis &basis) {
    ByteTable result{};
    for (unsigned byte = 0; byte < FIELD_BYTES; ++byte) {
        for (unsigned value = 1; value < BYTE_VALUES; ++value) {
            // Removing the lowest set bit gives an already-computed entry.
            unsigned bit = 0;
            while (((value >> bit) & 1) == 0) ++bit;
            result[byte][value] = result[byte][value & (value - 1)] ^
                                  basis[byte * BYTE_BITS + bit];
        }
    }
    return result;
}

inline constexpr auto SQUARE_TABLE = expand_bytes(square_basis());
inline constexpr auto SOLVE_TABLE =
    expand_bytes(solve_basis(std::make_index_sequence<FIELD_BITS>{}));

inline std::uint64_t apply_table(const ByteTable &table, std::uint64_t x) noexcept {
    std::uint64_t result = 0;
    for (unsigned byte = 0; byte < FIELD_BYTES; ++byte) {
        result ^= table[byte][x & BYTE_MASK];
        x >>= BYTE_BITS;
    }
    return result;
}
} // namespace snowstorm::gf64::detail
#endif
