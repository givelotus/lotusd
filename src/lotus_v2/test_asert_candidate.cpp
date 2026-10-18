// Copyright (c) 2026 The Lotus developers
// Standalone P04 candidate checks. This does not start lotusd.
#include "asert_candidate.h"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace lotus::v2;

namespace {

// Working candidate supplied by the caller. Not a consensus global and
// not written into chainparams. Half-life is two days; spacing is 120s.
constexpr int64_t kWorkingCandidateHalfLifeSeconds = 172800;
constexpr int64_t kWorkingCandidateSpacingSeconds = 120;

void Check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}

AsertInteger Factor(uint32_t fractional) {
    const AsertInteger f = fractional;
    const AsertInteger square = f * f;
    const AsertInteger scaled = AsertInteger(195766423245049ull) * f +
                                AsertInteger(971821376ull) * square +
                                AsertInteger(5127ull) * square * f +
                                (AsertInteger(1) << 47);
    return AsertInteger(65536) + (scaled >> 48);
}

std::optional<AsertCandidateResult> Child(const AsertInteger &genesis_target,
                                          uint64_t genesis_time,
                                          const AsertInteger &pow_limit,
                                          uint64_t parent_time,
                                          uint64_t parent_height) {
    return RequiredAsertCandidateBits(
        kWorkingCandidateHalfLifeSeconds, kWorkingCandidateSpacingSeconds,
        genesis_target, genesis_time, pow_limit,
        AsertParent{parent_time, parent_height});
}

} // namespace

int main() {
    try {
        const AsertInteger wide_limit = (AsertInteger(1) << 256) - 1;
        const auto genesis = DecodeCompactTarget(0x1d00ffffu, wide_limit);
        Check(genesis.has_value(), "decode development-genesis bits");
        const AsertInteger genesis_target = *genesis;
        Check(EncodeCompactTarget(genesis_target) == 0x1d00ffffu,
              "development-genesis bits round-trip");
        Check(genesis_target == (AsertInteger(0xffff) << 208),
              "development-genesis target value");

        const AsertInteger pow_limit = genesis_target;
        constexpr uint64_t kGenesisTime = 1000000000;
        const auto height_zero =
            Child(genesis_target, kGenesisTime, pow_limit, kGenesisTime, 0);
        Check(height_zero && height_zero->exponent == 0 &&
                  height_zero->raw_target == genesis_target &&
                  height_zero->clamped_target == genesis_target &&
                  height_zero->bits == 0x1d00ffffu,
              "height 0 at genesis time keeps T0");

        constexpr uint64_t kHeight = 9;
        const uint64_t on_schedule =
            kGenesisTime +
            static_cast<uint64_t>(kWorkingCandidateSpacingSeconds) * kHeight;
        const auto scheduled =
            Child(genesis_target, kGenesisTime, wide_limit, on_schedule, kHeight);
        Check(scheduled && scheduled->exponent == 0 &&
                  scheduled->raw_target == genesis_target &&
                  scheduled->bits == 0x1d00ffffu,
              "on-schedule parent keeps T0");

        const uint64_t doubled_time =
            kGenesisTime +
            static_cast<uint64_t>(kWorkingCandidateHalfLifeSeconds);
        const auto doubled =
            Child(genesis_target, kGenesisTime, wide_limit, doubled_time, 0);
        Check(doubled && doubled->exponent == 65536 && doubled->quotient == 1 &&
                  doubled->fractional == 0 &&
                  doubled->raw_target == genesis_target * 2 &&
                  doubled->clamped_target == genesis_target * 2 &&
                  doubled->bits == 0x1d01fffeu,
              "exact +half-life doubles before compact rounding");
        const auto clamped_double =
            Child(genesis_target, kGenesisTime, pow_limit, doubled_time, 0);
        Check(clamped_double && clamped_double->raw_target == genesis_target * 2 &&
                  clamped_double->clamped_target == pow_limit &&
                  clamped_double->bits == 0x1d00ffffu,
              "exact +half-life clamps at pow_limit");

        const uint64_t halved_time =
            kGenesisTime -
            static_cast<uint64_t>(kWorkingCandidateHalfLifeSeconds);
        const auto halved =
            Child(genesis_target, kGenesisTime, pow_limit, halved_time, 0);
        Check(halved && halved->exponent == -65536 && halved->quotient == -1 &&
                  halved->fractional == 0 &&
                  halved->raw_target == genesis_target / 2 &&
                  halved->clamped_target == genesis_target / 2 &&
                  halved->bits == 0x1c7fff80u,
              "exact -half-life halves the target");

        // parent.time < genesis time. Unsigned subtraction would wrap.
        constexpr uint64_t kEarlierParent = kGenesisTime - 3;
        const auto negative = Child(genesis_target, kGenesisTime, wide_limit,
                                    kEarlierParent, 0);
        const AsertInteger negative_raw = (genesis_target * Factor(65535)) >> 17;
        Check(negative && negative->exponent == -1 && negative->quotient == -1 &&
                  negative->fractional == 65535 &&
                  negative->raw_target == negative_raw &&
                  negative->clamped_target == negative_raw &&
                  negative_raw > 1 && negative_raw < genesis_target,
              "negative fractional exponent keeps f in 0..65535");

        constexpr uint64_t kAnchorHeight = 4;
        const uint64_t anchor_time =
            kGenesisTime +
            static_cast<uint64_t>(kWorkingCandidateSpacingSeconds) * kAnchorHeight -
            3;
        const auto anchored = Child(genesis_target, kGenesisTime, wide_limit,
                                    anchor_time, kAnchorHeight);
        const int64_t time_diff = static_cast<int64_t>(anchor_time) -
                                  static_cast<int64_t>(kGenesisTime);
        const int64_t height_diff = static_cast<int64_t>(kAnchorHeight) - 1;
        const int64_t historical_exponent =
            ((time_diff - kWorkingCandidateSpacingSeconds * (height_diff + 1)) *
             65536) /
            kWorkingCandidateHalfLifeSeconds;
        Check(anchored && height_diff >= 0 &&
                  anchored->exponent == historical_exponent &&
                  anchored->quotient == -1 && anchored->fractional == 65535,
              "height >= 1 matches the historical exponent anchor");

        const auto minimum = Child(genesis_target, kGenesisTime, pow_limit,
                                   kGenesisTime,
                                   std::numeric_limits<uint64_t>::max());
        Check(minimum && minimum->raw_target == 0 &&
                  minimum->clamped_target == 1 && minimum->bits == 0x01010000u,
              "large negative drift clamps to target 1");

        const auto saturated =
            Child(genesis_target, 0, pow_limit,
                  std::numeric_limits<uint64_t>::max(), 0);
        Check(saturated && saturated->quotient - 16 >= 256 &&
                  saturated->raw_target == pow_limit &&
                  saturated->clamped_target == pow_limit &&
                  saturated->bits == 0x1d00ffffu,
              "large positive drift saturates without a giant shift");

        const AsertInteger awkward(0x800001);
        Check(EncodeCompactTarget(awkward) == 0x04008000u,
              "compact rounding drops the low byte");
        const auto rounded = DecodeCompactTarget(0x04008000u, awkward);
        Check(rounded && *rounded == 0x800000 &&
                  EncodeCompactTarget(*rounded) == 0x04008000u,
              "rounded compact bits round-trip");
        Check(!DecodeCompactTarget(0x1d80ffffu, wide_limit), "reject sign bit");
        Check(!DecodeCompactTarget(0x1d000000u, wide_limit), "reject zero");
        Check(!DecodeCompactTarget(0x22010000u, wide_limit),
              "reject overflow beyond 256 bits");
        Check(!DecodeCompactTarget(0x03000001u, wide_limit),
              "reject noncanonical compact");
        Check(!DecodeCompactTarget(0x1d00ffffu, AsertInteger(1)),
              "reject target above pow_limit");
        Check(!RequiredAsertCandidateBits(0, kWorkingCandidateSpacingSeconds,
                                          genesis_target, kGenesisTime, pow_limit,
                                          AsertParent{kGenesisTime, 0}),
              "reject a non-positive half-life");

        std::cout << "V2 ASERT candidate checks passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
