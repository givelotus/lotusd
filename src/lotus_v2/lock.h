// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LOTUS_V2_LOCK_H
#define LOTUS_V2_LOCK_H

#include <cstdint>

namespace lotus::v2 {

// The 64-bit V2 transaction lock is (value << 8) | kind. Kind 0 (only with
// value 0) is no lock, kind 1 is a height and kind 2 is a parent median time
// past. A locked transaction is final once the candidate block's height, or
// its parent's median time past, has reached the full 56-bit value. Input
// sequences never disable the lock.
inline bool AbsoluteLockSatisfied(uint64_t lock, uint64_t candidate_height,
                                  uint64_t parent_mtp) {
    const uint8_t kind = uint8_t(lock);
    const uint64_t value = lock >> 8;
    if (kind == 1) return candidate_height >= value;
    if (kind == 2) return parent_mtp >= value;
    return true;
}

} // namespace lotus::v2

#endif // LOTUS_V2_LOCK_H
