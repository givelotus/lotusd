// Copyright (c) 2026 The Lotus developers
// Genesis-anchored ASERT candidate. Does not call CalculateASERT.
#include "asert_candidate.h"

namespace lotus::v2 {
namespace {

constexpr int64_t kFixedPoint = 65536;
constexpr unsigned kWordBits = 256;

std::size_t BitLength(const AsertInteger &value) {
    if (value <= 0) return 0;
    return static_cast<std::size_t>(boost::multiprecision::msb(value)) + 1;
}

bool FitsUnsignedWord(const AsertInteger &value) {
    return value > 0 && BitLength(value) <= kWordBits;
}

// Floor division. cpp_int operator/ truncates toward zero, which is a
// different operation for a negative numerator.
AsertInteger FloorDiv(const AsertInteger &numerator,
                      const AsertInteger &denominator) {
    AsertInteger quotient = numerator / denominator;
    if (numerator < 0 && numerator % denominator != 0) {
        --quotient;
    }
    return quotient;
}

AsertInteger PolynomialFactor(uint32_t fractional) {
    const AsertInteger f = fractional;
    const AsertInteger square = f * f;
    const AsertInteger cube = square * f;
    // Same coefficients as src/pow/aserti32d.cpp. The anchor is not that one.
    const AsertInteger scaled = AsertInteger(195766423245049ull) * f +
                                AsertInteger(971821376ull) * square +
                                AsertInteger(5127ull) * cube +
                                (AsertInteger(1) << 47);
    return AsertInteger(kFixedPoint) + (scaled >> 48);
}

} // namespace

std::optional<uint32_t> EncodeCompactTarget(const AsertInteger &target) {
    if (!FitsUnsignedWord(target)) return std::nullopt;
    unsigned exponent =
        static_cast<unsigned>((BitLength(target) + 7) / 8);
    AsertInteger mantissa;
    if (exponent <= 3) {
        mantissa = target << (8u * (3u - exponent));
    } else {
        mantissa = target >> (8u * (exponent - 3u));
    }
    // Bit 23 is the compact sign bit. Shift it out so the encoding is
    // nonnegative. That drops the low eight bits of the mantissa.
    if ((mantissa & (AsertInteger(1) << 23)) != 0) {
        mantissa >>= 8;
        ++exponent;
    }
    if (exponent > 255 || mantissa < 0 || mantissa >= (AsertInteger(1) << 23)) {
        return std::nullopt;
    }
    const auto significand = mantissa.convert_to<uint32_t>();
    return (static_cast<uint32_t>(exponent) << 24) | significand;
}

std::optional<AsertInteger> DecodeCompactTarget(uint32_t bits,
                                                const AsertInteger &pow_limit) {
    if (pow_limit < 1 || BitLength(pow_limit) > kWordBits) return std::nullopt;
    if ((bits & 0x00800000u) != 0) return std::nullopt;
    const unsigned exponent = bits >> 24;
    const uint32_t significand = bits & 0x007fffffu;
    if (significand == 0) return std::nullopt;
    AsertInteger target;
    if (exponent <= 3) {
        target = AsertInteger(significand) >> (8u * (3u - exponent));
    } else {
        const unsigned shift = 8u * (exponent - 3u);
        // A shift of 256 or more cannot fit in an unsigned 256-bit target.
        if (shift >= kWordBits) return std::nullopt;
        target = AsertInteger(significand) << shift;
        if (BitLength(target) > kWordBits) return std::nullopt;
    }
    if (target <= 0 || target > pow_limit) return std::nullopt;
    const auto encoded = EncodeCompactTarget(target);
    if (!encoded || *encoded != bits) return std::nullopt;
    return target;
}

std::optional<AsertCandidateResult> RequiredAsertCandidateBits(
    int64_t half_life_seconds, int64_t spacing_seconds,
    const AsertInteger &genesis_target, uint64_t genesis_time,
    const AsertInteger &pow_limit, AsertParent parent) {
    if (half_life_seconds <= 0 || spacing_seconds <= 0 || !FitsUnsignedWord(genesis_target)) {
        return std::nullopt;
    }
    if (pow_limit < 1 || BitLength(pow_limit) > kWordBits) return std::nullopt;

    // Signed drift. Timestamp and height fields are not subtracted as uint64.
    const AsertInteger drift =
        AsertInteger(parent.time) - AsertInteger(genesis_time) -
        AsertInteger(spacing_seconds) * AsertInteger(parent.height);
    // Toward zero, matching the candidate. Floor is used only to split q.
    // For parent.height >= 1 this exponent equals the historical
    // CalculateASERT exponent with height difference parent.height - 1.
    // Height 0 is evaluated here; that call would need a negative height
    // difference. This translation unit does not call it.
    const AsertInteger exponent =
        (AsertInteger(kFixedPoint) * drift) / AsertInteger(half_life_seconds);
    const AsertInteger quotient = FloorDiv(exponent, AsertInteger(kFixedPoint));
    const AsertInteger fractional =
        exponent - AsertInteger(kFixedPoint) * quotient;
    if (fractional < 0 || fractional >= kFixedPoint) return std::nullopt;

    const auto f = fractional.convert_to<uint32_t>();
    const AsertInteger factor = PolynomialFactor(f);
    const AsertInteger scaled = genesis_target * factor;
    AsertInteger raw;
    if (quotient >= AsertInteger(kWordBits + 16)) {
        // Nonnegative shift of at least 256 saturates before the shift.
        raw = pow_limit;
    } else if (quotient >= 16) {
        const auto shift = (quotient - 16).convert_to<unsigned>();
        raw = scaled << shift;
    } else {
        const AsertInteger magnitude = AsertInteger(16) - quotient;
        if (magnitude >= AsertInteger(BitLength(scaled))) {
            raw = 0;
        } else {
            raw = scaled >> magnitude.convert_to<unsigned>();
        }
    }

    AsertInteger clamped = raw;
    if (clamped < 1) clamped = 1;
    if (clamped > pow_limit) clamped = pow_limit;
    const auto bits = EncodeCompactTarget(clamped);
    if (!bits) return std::nullopt;
    AsertCandidateResult result;
    result.exponent = exponent;
    result.quotient = quotient;
    result.fractional = f;
    result.raw_target = raw;
    result.clamped_target = clamped;
    result.bits = *bits;
    return result;
}

} // namespace lotus::v2
