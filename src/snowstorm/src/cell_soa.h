// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include "aligned_array.h"
#include <snowstorm/cell.h>
namespace snowstorm::detail {
/** Physical aligned columns; growth is explicit and never performed by hot calls. */
class CellSoA {
    AlignedArray<std::int32_t> counts_;
    AlignedArray<std::uint64_t> first_, third_, fifth_;
    std::size_t capacity_{};
public:
    Cell get(std::size_t pos) const noexcept {
        return {counts_[pos], first_[pos], third_[pos], fifth_[pos]};
    }
    void put(std::size_t pos, const Cell &cell) noexcept {
        counts_[pos] = cell.count; first_[pos] = cell.s1;
        third_[pos] = cell.s3; fifth_[pos] = cell.s5;
    }
    void reserve(std::size_t capacity, std::size_t used) {
        if (capacity <= capacity_) return;
        CellSoA replacement;
        replacement.counts_ = aligned_array<std::int32_t>(capacity);
        replacement.first_ = aligned_array<std::uint64_t>(capacity);
        replacement.third_ = aligned_array<std::uint64_t>(capacity);
        replacement.fifth_ = aligned_array<std::uint64_t>(capacity);
        replacement.capacity_ = capacity;
        for (std::size_t i = 0; i < used; ++i) replacement.put(i, get(i));
        *this = std::move(replacement);
    }
    std::size_t allocated_bytes() const noexcept {
        return capacity_ * (sizeof(std::int32_t) + 3 * sizeof(std::uint64_t));
    }
};
} // namespace snowstorm::detail
