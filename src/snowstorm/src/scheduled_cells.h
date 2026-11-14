// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
#include <snowstorm/schedule.h>
#include <algorithm>
namespace snowstorm::detail {
/** Apply each precomputed item once along its schedule to sorted indexed cells.
 * Records must expose index; select chooses the caller's staged Cell field.
 * Partial writes remain confined to caller-owned staging on any error.
 */
template <typename Record, typename Select>
Error apply_scheduled(std::span<const ItemPowers> items, std::span<Record> cells,
                      Sign sign, Select select) noexcept {
    if (cells.empty()) return Error::ok;
    const auto by_index = [](const Record &cell, SymbolIndex value) { return cell.index < value; };
    for (const auto &item : items) {
        ScheduleIterator iterator(item.item, cells.back().index);
        while (const auto index = iterator.next()) {
            const auto pos = std::lower_bound(cells.begin(), cells.end(), *index, by_index);
            if (pos == cells.end() || pos->index != *index) continue;
            const auto error = cell_add(select(*pos), item, sign);
            if (error != Error::ok) return error;
        }
    }
    return Error::ok;
}
} // namespace snowstorm::detail
