// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>
#include <util/hasher.h>

#include <limits>

namespace {
/**
 * Two salt words from one freshly seeded random context. Seeding a context
 * costs a hash of the RNG state under its mutex, which dominated the cost
 * of constructing a hasher (and so of every coins view and mempool
 * admission) when each word had its own context.
 */
std::array<uint64_t, 2> RandomSalt() {
    FastRandomContext rng;
    const uint64_t k0 = rng.rand64();
    return {k0, rng.rand64()};
}
} // namespace

SaltedUint256Hasher::SaltedUint256Hasher()
    : SaltedUint256Hasher(RandomSalt()) {}

SaltedOutpointHasher::SaltedOutpointHasher(bool deterministic)
    : SaltedOutpointHasher(
          deterministic
              ? std::array<uint64_t, 2>{0x8e819f2607a18de6, 0xf4020d2e3983b0eb}
              : RandomSalt()) {}

SaltedSipHasher::SaltedSipHasher() : SaltedSipHasher(RandomSalt()) {}

size_t SaltedSipHasher::operator()(const Span<const uint8_t> &script) const {
    return CSipHasher(m_k0, m_k1).Write(script).Finalize();
}
