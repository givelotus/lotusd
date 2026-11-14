// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/cell.h>
namespace snowstorm::detail {
/** Shared with the peeler's singleton-first, batch-inverse passes. */
DecodeResult decode_singleton(const Cell &cell, SymbolIndex index,
                              ReferenceView reference) noexcept;
/** inverse_cube must be the inverse of the current nonzero cell.s1 cubed. */
DecodeResult decode_pair(const Cell &cell, SymbolIndex index,
                         ReferenceView reference, std::uint64_t inverse_cube) noexcept;
} // namespace snowstorm::detail
