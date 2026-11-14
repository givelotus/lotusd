// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/sketch.h>
namespace snowstorm::detail {
/** Exact owned allocation layout, without caller/owner object storage. */
struct SketchMemory {
    std::size_t object_bytes{};
    std::size_t powers_capacity{};
    std::size_t index_capacity{};
    std::size_t index_record_bytes{};
    std::size_t symbol_capacity{};
    std::size_t requested_bytes() const noexcept {
        return object_bytes + powers_capacity * sizeof(ItemPowers) + index_capacity * index_record_bytes +
            symbol_capacity * (sizeof(SymbolIndex) + sizeof(std::int32_t) + 3 * sizeof(std::uint64_t));
    }
};
/** Single cache implementation shared by public SketchCache and SetStore.
 * Only explicit reserve_symbols may grow storage; updates/encode never allocate.
 */
class SketchEngine {
    class Impl;
    std::unique_ptr<Impl> impl_;
public:
    SketchEngine(std::size_t max_items, std::size_t max_symbols, SymbolIndex maximum);
    ~SketchEngine();
    SketchEngine(SketchEngine &&) noexcept;
    SketchEngine &operator=(SketchEngine &&) noexcept;
    void clear() noexcept;
    Error cache_range(Range range) noexcept;
    Error add(ShortId item) noexcept;
    Error remove(ShortId item) noexcept;
    std::size_t size() const noexcept;
    bool contains(ShortId item) const noexcept;
    Error encode(Range range, std::span<Cell> output) const noexcept;
    SketchView view() const noexcept;
    void reserve_symbols(std::size_t count);
    /** Owned heap bytes; excludes this engine object, counted by its owner. */
    std::size_t allocated_bytes() const noexcept;
    SketchMemory memory() const noexcept;
};
} // namespace snowstorm::detail
