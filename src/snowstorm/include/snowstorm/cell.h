// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
/** @defgroup snowstorm_cell_contract Snowstorm cell public contract
 * §§4.1,4.3,6.1: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §4.1: logical cell; wire is exactly28B, independent of C++ padding. */
struct Cell {
    std::int32_t count{};
    std::uint64_t s1{};
    std::uint64_t s3{};
    std::uint64_t s5{};
};
/** §4.3: precomputed field powers reused by sketch hot paths. */
struct ItemPowers {
    ShortId item{};
    std::uint64_t cube{};
    std::uint64_t fifth{};
};
/** §4.1: complete decode outcome; Two outputs are unsigned-ID sorted. */
enum class DecodeKind : std::uint8_t { zero, one, two, undecodable };
/** §4.1: fixed-size, allocation-free decode result. */
struct DecodeResult {
    DecodeKind kind{DecodeKind::undecodable};
    std::array<SignedItem, 2> items{};
    std::uint8_t size{};
};
/** §4.3: calculate x,x^3,x^5 without heap allocation. */
ItemPowers item_powers(ShortId x) noexcept;
/** §4.1: atomic overflow-safe signed insertion, rejects zero IDs/invalid signs. */
Error cell_add(Cell &cell, ShortId x, Sign sign) noexcept;
/** §§4.1,4.3: precomputed-power insertion; same atomic checked semantics. */
Error cell_add(Cell &cell, const ItemPowers &x, Sign sign) noexcept;
/** §4.1: checked cell subtraction; destination unchanged on overflow. */
Error cell_subtract(Cell &cell, const Cell &other) noexcept;
/** §4.1: exact zero predicate, no count-only shortcut. */
bool cell_is_zero(const Cell &cell) noexcept;
/** §4.1: all algebraic, schedule and reference-sign postconditions. */
DecodeResult decode(const Cell &cell, SymbolIndex index,
                    ReferenceView reference) noexcept;
/** §§4.1,6.1: exactly28 canonical little-endian bytes into caller storage. */
Error serialize_cell(const Cell &cell, MutableByteSpan output) noexcept;
/** §§4.1,6.1: exactly28 bytes, no trailing data, prohibited INT32_MIN rejected. */
Error parse_cell(ByteSpan input, Cell &output) noexcept;
} // namespace snowstorm
/** @} */
