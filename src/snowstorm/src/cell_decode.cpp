// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "cell_decode.h"
#include <snowstorm/gf64.h>
#include <snowstorm/schedule.h>
#include <algorithm>

namespace snowstorm {
namespace {
Sign reference_sign(ReferenceView reference, ShortId item) noexcept {
    return reference.contains(reference.context, item) ? Sign::negative : Sign::positive;
}
bool pair_count(std::int32_t count) noexcept {
    return count == -2 || count == 0 || count == 2;
}
}
namespace detail {
DecodeResult decode_singleton(const Cell &cell, SymbolIndex index,
                              ReferenceView reference) noexcept {
    if ((cell.count != -1 && cell.count != 1) || cell.s1 == 0 || !reference.contains) return {};
    const auto powers = item_powers(cell.s1);
    if (cell.s3 != powers.cube || cell.s5 != powers.fifth ||
        !schedule_includes(cell.s1, index)) return {};
    const auto sign = reference_sign(reference, cell.s1);
    if (static_cast<int>(sign) != cell.count) return {};
    return {DecodeKind::one, {{{cell.s1, sign}, {}}}, 1};
}
DecodeResult decode_pair(const Cell &cell, SymbolIndex index,
                         ReferenceView reference, std::uint64_t inverse_cube) noexcept {
    if (!pair_count(cell.count) || cell.s1 == 0 || !reference.contains) return {};
    const auto solution = gf64::solve(1 ^ gf64::mul(cell.s3, inverse_cube));
    if (!solution.solvable) return {};
    const auto root = gf64::mul(cell.s1, solution.value);
    const auto other = root ^ cell.s1;
    if (root == 0 || other == 0 || root == other) return {};
    const auto first = std::min(root, other);
    const auto second = std::max(root, other);
    if (cell.s5 != (item_powers(first).fifth ^ item_powers(second).fifth) ||
        !schedule_includes(first, index) || !schedule_includes(second, index)) return {};
    const auto first_sign = reference_sign(reference, first);
    const auto second_sign = reference_sign(reference, second);
    if (static_cast<int>(first_sign) + static_cast<int>(second_sign) != cell.count) return {};
    return {DecodeKind::two, {{{first, first_sign}, {second, second_sign}}}, 2};
}
} // namespace detail
DecodeResult decode(const Cell &cell, SymbolIndex index, ReferenceView reference) noexcept {
    if (cell_is_zero(cell)) return {DecodeKind::zero, {}, 0};
    if (cell.count == -1 || cell.count == 1) return detail::decode_singleton(cell, index, reference);
    if (!pair_count(cell.count) || cell.s1 == 0) return {};
    const auto inverse_cube = gf64::inv(item_powers(cell.s1).cube);
    return detail::decode_pair(cell, index, reference, inverse_cube.value);
}
} // namespace snowstorm
