// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
/** @defgroup snowstorm_sketch_contract Snowstorm sketch public contract
 * §4.3: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §4.3: borrowed 64-byte-aligned SoA arrays, valid until cache mutation. */
struct SketchView {
    std::span<const SymbolIndex> indices;
    std::span<const std::int32_t> counts;
    std::span<const std::uint64_t> s1;
    std::span<const std::uint64_t> s3;
    std::span<const std::uint64_t> s5;
};
/** §4.3: direct encoding into exactly range length caller slots; no allocation.
 * Input IDs must be distinct/nonzero; errors leave output unchanged.
 */
Error encode(std::span<const ShortId> items, Range range,
             std::span<Cell> output) noexcept;
/** §4.3: bounded incremental cache; construction reserves every hot-path array. */
class SketchCache {
public:
    /** §§4.3,6.4: reserve ID and symbol capacity; invalid local args throw. */
    SketchCache(std::size_t max_items, std::size_t max_symbols,
                SymbolIndex max_symbol_index);
    /** §4.3: release aligned SoA and precomputed powers. */
    ~SketchCache();
    /** §4.3: transfer reserved storage. */
    SketchCache(SketchCache &&) noexcept;
    /** §4.3: transfer reserved storage. */
    SketchCache &operator=(SketchCache &&) noexcept;
    /** §4.3: cache ownership is unique. */
    SketchCache(const SketchCache &) = delete;
    /** §4.3: cache ownership is unique. */
    SketchCache &operator=(const SketchCache &) = delete;
    /** §4.3: reset to empty without releasing reserved capacity. */
    void clear() noexcept;
    /** §4.3: cache all indices in range from current set within reserved capacity. */
    Error cache_range(Range range) noexcept;
    /** §4.3: add a distinct ID and update every cached scheduled index, no heap.
     * Existing ID returns Error::duplicate without mutation.
     */
    Error add(ShortId item) noexcept;
    /** §4.3: remove an existing ID and update cached indices, no heap.
     * Absent ID returns Error::not_found without mutation.
     */
    Error remove(ShortId item) noexcept;
    /** §4.3: current distinct-ID count. */
    std::size_t size() const noexcept;
    /** §4.3: local cached-set membership. */
    bool contains(ShortId item) const noexcept;
    /** §4.3: copy current set encoding; range need not already be cached. */
    Error encode(Range range, std::span<Cell> output) const noexcept;
    /** §§4.3,10: aligned physical arrays for independent cache/alignment checks. */
    SketchView view() const noexcept;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace snowstorm
/** @} */
