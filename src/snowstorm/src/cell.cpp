// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/cell.h>
#include <snowstorm/gf64.h>
#include "wire_bytes.h"
#include "cell_count.h"
#include <bit>
#include <limits>

namespace snowstorm {
namespace {
constexpr std::size_t COUNT_BYTES = sizeof(std::int32_t);
constexpr std::size_t SYNDROME_BYTES = sizeof(std::uint64_t);
constexpr std::size_t CELL_BYTES = COUNT_BYTES + 3 * SYNDROME_BYTES;
}
ItemPowers item_powers(ShortId x) noexcept {
    const auto squared = gf64::square(x);
    return {x, gf64::mul(squared, x), gf64::mul(gf64::square(squared), x)};
}
Error cell_add(Cell &cell, ShortId x, Sign sign) noexcept {
    return cell_add(cell, item_powers(x), sign);
}
Error cell_add(Cell &cell, const ItemPowers &x, Sign sign) noexcept {
    if (x.item == 0) return Error::invalid_id;
    if (sign != Sign::positive && sign != Sign::negative) return Error::invalid_argument;
    const auto count = std::int64_t{cell.count} + static_cast<int>(sign);
    if (!detail::valid_cell_count(cell.count) || !detail::valid_cell_count(count)) return Error::overflow;
    cell = {static_cast<std::int32_t>(count), cell.s1 ^ x.item,
            cell.s3 ^ x.cube, cell.s5 ^ x.fifth};
    return Error::ok;
}
Error cell_subtract(Cell &cell, const Cell &other) noexcept {
    const auto count = std::int64_t{cell.count} - other.count;
    if (!detail::valid_cell_count(cell.count) || !detail::valid_cell_count(other.count) || !detail::valid_cell_count(count)) {
        return Error::overflow;
    }
    cell = {static_cast<std::int32_t>(count), cell.s1 ^ other.s1,
            cell.s3 ^ other.s3, cell.s5 ^ other.s5};
    return Error::ok;
}
bool cell_is_zero(const Cell &cell) noexcept {
    return cell.count == 0 && cell.s1 == 0 && cell.s3 == 0 && cell.s5 == 0;
}
Error serialize_cell(const Cell &cell, MutableByteSpan output) noexcept {
    if (!detail::valid_cell_count(cell.count)) return Error::overflow;
    if (output.size() < CELL_BYTES) return Error::capacity;
    detail::write_le(std::bit_cast<std::uint32_t>(cell.count), output);
    detail::write_le(cell.s1, output.subspan(COUNT_BYTES));
    detail::write_le(cell.s3, output.subspan(COUNT_BYTES + SYNDROME_BYTES));
    detail::write_le(cell.s5, output.subspan(COUNT_BYTES + 2 * SYNDROME_BYTES));
    return Error::ok;
}
Error parse_cell(ByteSpan input, Cell &output) noexcept {
    if (input.size() != CELL_BYTES) return Error::malformed_message;
    const auto count = std::bit_cast<std::int32_t>(detail::read_le<std::uint32_t>(input));
    if (!detail::valid_cell_count(count)) return Error::overflow;
    output = {count, detail::read_le<std::uint64_t>(input.subspan(COUNT_BYTES)),
              detail::read_le<std::uint64_t>(input.subspan(COUNT_BYTES + SYNDROME_BYTES)),
              detail::read_le<std::uint64_t>(input.subspan(COUNT_BYTES + 2 * SYNDROME_BYTES))};
    return Error::ok;
}
} // namespace snowstorm
