// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
/** @defgroup snowstorm_schedule_contract Snowstorm schedule public contract
 * §4.2: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §4.2: allocation-free bounded integer schedule, first next() returns0. */
class ScheduleIterator {
public:
    /** §4.2: nonzero item and inclusive index bound<2^40. */
    explicit ScheduleIterator(ShortId item,
                              SymbolIndex max_index = (std::uint64_t{1} << 39) - 1);
    /** §4.2: next increasing index; nullopt means permanently exhausted. */
    std::optional<SymbolIndex> next() noexcept;
    /** §4.2: restart the exact SplitMix stream with validated arguments. */
    Error reset(ShortId item, SymbolIndex max_index) noexcept;
private:
    std::uint64_t state_{};
    SymbolIndex index_{};
    SymbolIndex max_index_{};
    bool first_{true};
    bool exhausted_{};
};
/** §4.2: pure membership agrees with iterator; zero IDs/out-of-bound=false. */
bool schedule_includes(ShortId item, SymbolIndex index) noexcept;
/** §4.2: explicit draw-to-next-index primitive for exact boundary vectors.
 * draw is the single u32 draw, not a second PRNG. Returns exhausted at bound.
 */
Error schedule_next(SymbolIndex current, std::uint32_t draw,
                    SymbolIndex max_index, SymbolIndex &next) noexcept;
} // namespace snowstorm
/** @} */
