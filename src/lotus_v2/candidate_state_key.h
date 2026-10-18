// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CANDIDATE_STATE_KEY_H
#define LOTUS_V2_CANDIDATE_STATE_KEY_H
#include <crypto/sha256.h>
#include <array>
#include <span>

namespace lotus::v2 {
// Local memoization key, not a consensus/wire hash. Fixed-width identities bind
// every byte and their order; the parent separates otherwise identical bodies.
class CandidateStateHasher {
    CSHA256 hasher;
public:
    explicit CandidateStateHasher(std::span<const uint8_t, 32> parent) {
        static constexpr uint8_t domain[] = "Lotus/V2/CandidateState/v1";
        hasher.Write(domain, sizeof(domain));
        hasher.Write(parent.data(), parent.size());
    }
    void Add(std::span<const uint8_t, 32> txid,
             std::span<const uint8_t, 32> txhash) {
        hasher.Write(txid.data(), txid.size());
        hasher.Write(txhash.data(), txhash.size());
    }
    std::array<uint8_t, 32> Finalize() {
        std::array<uint8_t, 32> digest;
        hasher.Finalize(digest.data());
        return digest;
    }
};
} // namespace lotus::v2
#endif
