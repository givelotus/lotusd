// Copyright (c) 2026 The Lotus developers
// P04 ASERT candidate. Not frozen mainnet consensus and not called from lotusd.
#ifndef LOTUS_V2_ASERT_CANDIDATE_H
#define LOTUS_V2_ASERT_CANDIDATE_H

#include <boost/multiprecision/cpp_int.hpp>

#include <cstdint>
#include <optional>

namespace lotus::v2 {

// Wide integer for targets and drift. Not a consensus global.
using AsertInteger = boost::multiprecision::cpp_int;

// Parent of the block whose required bits are being computed.
// Genesis itself is not an input to this candidate.
struct AsertParent {
    uint64_t time = 0;
    uint64_t height = 0;
};

// Half-life, spacing, genesis target, genesis time, and pow limit are
// caller arguments. This library does not store a half-life or spacing.
struct AsertCandidateResult {
    // Truncated toward zero. Not the floor used for the quotient.
    AsertInteger exponent;
    // floor(exponent / 65536). Negative exponents still yield fractional
    // in 0..65535.
    AsertInteger quotient;
    uint32_t fractional = 0;
    // floor(V * 2^(quotient-16)). A nonnegative shift of 256 or more stores
    // pow_limit and does not materialize the shift. A negative shift whose
    // magnitude is at least the bit length of V stores 0.
    AsertInteger raw_target;
    // min(pow_limit, max(1, raw_target)), then encoded in bits.
    AsertInteger clamped_target;
    uint32_t bits = 0;
};

// Canonical compact target. Rejects the sign bit, zero, a value that does
// not fit in 256 bits, a value above pow_limit, and a non-canonical encoding.
// Accepted bits re-encode to themselves.
std::optional<AsertInteger> DecodeCompactTarget(uint32_t bits,
                                                const AsertInteger &pow_limit);
std::optional<uint32_t> EncodeCompactTarget(const AsertInteger &target);

// Required compact bits of the child of `parent`. Not ConnectTip.
// Returns nullopt for a non-positive half-life or spacing, a non-positive genesis
// target, or a pow limit below 1 or wider than 256 bits.
std::optional<AsertCandidateResult> RequiredAsertCandidateBits(
    int64_t half_life_seconds, int64_t spacing_seconds,
    const AsertInteger &genesis_target, uint64_t genesis_time,
    const AsertInteger &pow_limit, AsertParent parent);

} // namespace lotus::v2

#endif
