// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#pragma once
#include <snowstorm/types.h>
/** @defgroup snowstorm_short_id_contract Snowstorm short_id public contract
 * §3: this scoped documentation group applies to every enclosed
 * declaration, including aliases, enumerators, data members and nested types.
 * Declaration-specific comments refine the contract within those sections.
 * @{
 */
namespace snowstorm {
/** §3: SipHash-2-4 over exactly canonical tx_hash bytes; remap zero to one. */
ShortId short_id(ShortIdKey key, const TxHash &tx_hash) noexcept;
/** §3: separately test the specified zero-output normalization. */
ShortId normalize_short_id(std::uint64_t siphash_result) noexcept;
} // namespace snowstorm
/** @} */
