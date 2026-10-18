// Copyright (c) 2026 The Lotus developers
// Local child-header template and bounded nonce search.
// No socket, daemon, pool, or network submission.
#ifndef LOTUS_V2_BLOCK_TEMPLATE_H
#define LOTUS_V2_BLOCK_TEMPLATE_H

#include "header.h"

#include <cstdint>
#include <optional>

namespace lotus::v2 {

// Child of `parent` for a miner that already hashes 134-byte headers.
// version is copied from the parent. prev_id is BlockId(chain_id, parent).
// nonce is 0. height is parent.height + 1. Roots, time, size, and bits are
// the supplied values.
// bits must be a canonical compact target that DecodeTarget accepts at or
// below the 256-bit ceiling. That ceiling is not a chain powLimit.
// Returns nullopt if time > MAX_TIME, DecodeTarget rejects bits, height
// would overflow uint64, or the parent block id cannot be computed.
std::optional<Header> BuildChildHeader(const Header &parent, const ChainId &chain_id,
                                       const Hash &tx_root, const Hash &state_root,
                                       uint64_t time, uint64_t size, uint32_t bits);

// Inclusive cap for one local SearchNonce call. A larger request fails
// before any hash and does not modify the caller's header.
constexpr uint64_t MAX_NONCE_ATTEMPTS = 256;

// Local search only. Tries start_nonce and then the following nonces, at
// most max_attempts, and does not wrap. Returns true and writes the first
// header whose BlockId meets target. Returns false, leaving header
// unchanged, when max_attempts exceeds MAX_NONCE_ATTEMPTS, the block id
// cannot be computed, or no attempt meets target.
bool SearchNonce(Header &header, const ChainId &chain_id, const Hash &target,
                 uint64_t start_nonce, uint64_t max_attempts);

} // namespace lotus::v2
#endif
