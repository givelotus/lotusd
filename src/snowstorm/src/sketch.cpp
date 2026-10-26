// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include <snowstorm/sketch.h>
#include <snowstorm/schedule.h>
#include "aligned_array.h"
#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

namespace snowstorm {
namespace {
constexpr unsigned INDEX_BITS = 40;
constexpr auto INDEX_BOUND = std::uint64_t{1} << INDEX_BITS;
constexpr auto MAX_ITEMS = std::numeric_limits<std::int32_t>::max();
Error check_range(Range range, SymbolIndex maximum, std::size_t slots) noexcept {
    if (range.begin > range.end || range.end > maximum + 1) return Error::invalid_range;
    if (range.end - range.begin != slots) return Error::capacity;
    return Error::ok;
}
void encode_item(const ItemPowers &powers, Range range, std::span<Cell> output) noexcept {
    if (range.begin == range.end) return;
    ScheduleIterator iterator(powers.item, range.end - 1);
    while (const auto index = iterator.next()) {
        if (*index >= range.begin) (void)cell_add(output[*index - range.begin], powers, Sign::positive);
    }
}
/** Fixed load <= 1/2, backwards-shift deletion: no tombstone accumulation. */
class ItemIndex {
    struct Slot { ShortId key{}; std::size_t value{}; };
    std::vector<Slot> slots_;
    std::size_t mask_;
    unsigned shift_;
    std::size_t home(ShortId item) const noexcept {
        constexpr std::uint64_t GOLDEN_RATIO = 0x9e3779b97f4a7c15ULL;
        return (item * GOLDEN_RATIO) >> shift_;
    }
    std::size_t position(ShortId item) const noexcept {
        auto pos = home(item);
        while (slots_[pos].key && slots_[pos].key != item) pos = (pos + 1) & mask_;
        return pos;
    }
public:
    explicit ItemIndex(std::size_t capacity)
        : slots_(std::bit_ceil(std::max(std::size_t{2}, capacity * 2))),
          mask_(slots_.size() - 1), shift_(std::numeric_limits<ShortId>::digits - std::countr_zero(slots_.size())) {}
    std::optional<std::size_t> find(ShortId item) const noexcept {
        if (item == 0) return std::nullopt;
        const auto &slot = slots_[position(item)];
        if (slot.key == 0) return std::nullopt;
        return slot.value;
    }
    void set(ShortId item, std::size_t value) noexcept { slots_[position(item)] = {item, value}; }
    void erase(ShortId item) noexcept {
        auto hole = position(item);
        auto pos = (hole + 1) & mask_;
        while (slots_[pos].key) {
            const auto origin = home(slots_[pos].key);
            if (((hole - origin) & mask_) < ((pos - origin) & mask_)) {
                slots_[hole] = slots_[pos];
                hole = pos;
            }
            pos = (pos + 1) & mask_;
        }
        slots_[hole] = {};
    }
    void clear() noexcept { std::fill(slots_.begin(), slots_.end(), Slot{}); }
};
}
Error encode(std::span<const ShortId> items, Range range, std::span<Cell> output) noexcept {
    const auto valid = check_range(range, INDEX_BOUND - 1, output.size());
    if (valid != Error::ok) return valid;
    if (items.size() > MAX_ITEMS) return Error::overflow;
    // The caller owns arbitrary-order IDs and no scratch is available in this API.
    // Check uniqueness before writing any output; cache encoding uses its index.
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (items[i] == 0) return Error::invalid_id;
        if (std::find(items.begin(), items.begin() + i, items[i]) != items.begin() + i) return Error::duplicate;
    }
    std::fill(output.begin(), output.end(), Cell{});
    for (const auto item : items) encode_item(item_powers(item), range, output);
    return Error::ok;
}
class SketchCache::Impl {
public:
    std::size_t max_items;
    std::size_t max_symbols;
    SymbolIndex maximum;
    std::vector<ItemPowers> items;
    ItemIndex lookup;
    detail::AlignedArray<SymbolIndex> indices;
    detail::AlignedArray<std::int32_t> counts;
    detail::AlignedArray<std::uint64_t> s1, s3, s5;
    std::size_t symbols{};
    Impl(std::size_t item_limit, std::size_t symbol_limit, SymbolIndex bound)
        : max_items(item_limit), max_symbols(symbol_limit), maximum(bound), lookup(item_limit),
          indices(detail::aligned_array<SymbolIndex>(symbol_limit)),
          counts(detail::aligned_array<std::int32_t>(symbol_limit)),
          s1(detail::aligned_array<std::uint64_t>(symbol_limit)),
          s3(detail::aligned_array<std::uint64_t>(symbol_limit)),
          s5(detail::aligned_array<std::uint64_t>(symbol_limit)) { items.reserve(item_limit); }
    std::size_t lower(SymbolIndex index) const noexcept {
        if (symbols == 0) return 0;
        return std::lower_bound(indices.get(), indices.get() + symbols, index) - indices.get();
    }
    Cell get(std::size_t pos) const noexcept { return {counts[pos], s1[pos], s3[pos], s5[pos]}; }
    void put(std::size_t pos, const Cell &cell) noexcept {
        counts[pos] = cell.count; s1[pos] = cell.s1; s3[pos] = cell.s3; s5[pos] = cell.s5;
    }
    void update(const ItemPowers &powers, Sign sign) noexcept {
        if (symbols == 0) return;
        ScheduleIterator iterator(powers.item, indices[symbols - 1]);
        while (const auto index = iterator.next()) {
            const auto pos = lower(*index);
            if (pos < symbols && indices[pos] == *index) {
                auto cell = get(pos);
                (void)cell_add(cell, powers, sign);
                put(pos, cell);
            }
        }
    }
    void insert_symbol(SymbolIndex index) noexcept {
        const auto pos = lower(index);
        if (pos < symbols && indices[pos] == index) return;
        Cell cell{};
        for (const auto &powers : items) {
            if (schedule_includes(powers.item, index)) (void)cell_add(cell, powers, Sign::positive);
        }
        for (auto dest = symbols; dest > pos; --dest) {
            indices[dest] = indices[dest - 1]; put(dest, get(dest - 1));
        }
        indices[pos] = index; put(pos, cell); ++symbols;
    }
};
SketchCache::SketchCache(std::size_t max_items, std::size_t max_symbols, SymbolIndex maximum) {
    if (max_items > MAX_ITEMS || maximum >= INDEX_BOUND || max_symbols > maximum + 1) {
        throw std::invalid_argument("invalid Snowstorm sketch capacity or index bound");
    }
    impl_ = std::make_unique<Impl>(max_items, max_symbols, maximum);
}
SketchCache::~SketchCache() = default;
SketchCache::SketchCache(SketchCache &&) noexcept = default;
SketchCache &SketchCache::operator=(SketchCache &&) noexcept = default;
void SketchCache::clear() noexcept {
    impl_->items.clear(); impl_->lookup.clear(); impl_->symbols = 0;
}
Error SketchCache::cache_range(Range range) noexcept {
    if (range.begin > range.end || range.end > impl_->maximum + 1) return Error::invalid_range;
    const auto already = impl_->lower(range.end) - impl_->lower(range.begin);
    if (range.end - range.begin - already > impl_->max_symbols - impl_->symbols) return Error::capacity;
    for (auto index = range.begin; index < range.end; ++index) impl_->insert_symbol(index);
    return Error::ok;
}
Error SketchCache::add(ShortId item) noexcept {
    if (item == 0) return Error::invalid_id;
    if (impl_->lookup.find(item)) return Error::duplicate;
    if (impl_->items.size() == impl_->max_items) return Error::capacity;
    const auto powers = item_powers(item);
    impl_->lookup.set(item, impl_->items.size()); impl_->items.push_back(powers);
    impl_->update(powers, Sign::positive);
    return Error::ok;
}
Error SketchCache::remove(ShortId item) noexcept {
    const auto pos = impl_->lookup.find(item);
    if (!pos) return Error::not_found;
    impl_->update(impl_->items[*pos], Sign::negative);
    impl_->lookup.erase(item);
    if (*pos + 1 != impl_->items.size()) {
        impl_->items[*pos] = impl_->items.back(); impl_->lookup.set(impl_->items[*pos].item, *pos);
    }
    impl_->items.pop_back();
    return Error::ok;
}
std::size_t SketchCache::size() const noexcept { return impl_->items.size(); }
bool SketchCache::contains(ShortId item) const noexcept { return impl_->lookup.find(item).has_value(); }
Error SketchCache::encode(Range range, std::span<Cell> output) const noexcept {
    const auto valid = check_range(range, impl_->maximum, output.size());
    if (valid != Error::ok) return valid;
    const auto first = impl_->lower(range.begin);
    if (impl_->lower(range.end) - first == output.size()) {
        for (std::size_t i = 0; i < output.size(); ++i) output[i] = impl_->get(first + i);
        return Error::ok;
    }
    std::fill(output.begin(), output.end(), Cell{});
    for (const auto &powers : impl_->items) encode_item(powers, range, output);
    return Error::ok;
}
SketchView SketchCache::view() const noexcept {
    const auto n = impl_->symbols;
    return {{impl_->indices.get(), n}, {impl_->counts.get(), n}, {impl_->s1.get(), n},
            {impl_->s3.get(), n}, {impl_->s5.get(), n}};
}
} // namespace snowstorm
