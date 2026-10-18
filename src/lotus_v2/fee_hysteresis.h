// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_FEE_HYSTERESIS_H
#define LOTUS_V2_FEE_HYSTERESIS_H

#include <cstdint>
#include <deque>
#include <mutex>

namespace lotus::v2 {

enum class FeeTier : uint8_t {
    RpcAdmission = 1,
    P2pRelay = 2,
    // Historical API name: eCash uses a relay-policy floor, not consensus.
    ConsensusFloor = 3,
};

constexpr uint64_t DEFAULT_CONSENSUS_FLOOR_PER_KCU = 1000;
constexpr int64_t DEFAULT_HYSTERESIS_WINDOW_MS = 30000;
constexpr uint64_t DEFAULT_HYSTERESIS_DISCOUNT_PERMILLE = 150;
constexpr uint64_t DEFAULT_SDK_CUSHION_PERMILLE = 50;
constexpr uint64_t DEFAULT_TARGET_UTILIZATION_CU = 25'000'000;

struct FeeHysteresisConfig {
    uint64_t consensus_floor_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    int64_t hysteresis_window_ms = DEFAULT_HYSTERESIS_WINDOW_MS;
    uint64_t hysteresis_discount_permille = DEFAULT_HYSTERESIS_DISCOUNT_PERMILLE;
    uint64_t sdk_cushion_permille = DEFAULT_SDK_CUSHION_PERMILLE;
    uint64_t target_utilization_cu = DEFAULT_TARGET_UTILIZATION_CU;
};

struct FeeRateInfo {
    uint64_t consensus_floor_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t p2p_relay_feerate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t rpc_admission_feerate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t recommended_sdk_feerate_per_kcu = 1050;
    int64_t hysteresis_window_ms = DEFAULT_HYSTERESIS_WINDOW_MS;
    uint64_t hysteresis_discount_permille = DEFAULT_HYSTERESIS_DISCOUNT_PERMILLE;
};

struct FeeCheckResult {
    bool accepted = false;
    FeeTier tier = FeeTier::RpcAdmission;
    uint64_t tx_cu = 0;
    uint64_t paid_fee_sats = 0;
    uint64_t required_fee_sats = 0;
    uint64_t required_rate_per_kcu = 0;
    uint64_t recommended_sdk_fee_sats = 0;
};

class FeeHysteresisController {
public:
    explicit FeeHysteresisController(
        FeeHysteresisConfig config = FeeHysteresisConfig{});

    uint64_t GetConsensusFloorPerKCu() const noexcept;
    uint64_t GetRpcAdmissionRatePerKCu(int64_t now_ms) const;
    uint64_t GetRecommendedSdkRatePerKCu(int64_t now_ms) const;
    uint64_t GetP2pRelayRatePerKCu(int64_t now_ms) const;

    FeeRateInfo GetFeeRateInfo(int64_t now_ms) const;

    uint64_t UpdateCongestion(uint64_t active_utilization,
                              uint64_t target_capacity, int64_t now_ms);
    void SetRpcAdmissionRatePerKCu(uint64_t rpc_rate_per_kcu, int64_t now_ms);
    void Reset(int64_t now_ms = 0);

    FeeCheckResult EvaluateTransactionFee(FeeTier tier, uint64_t tx_cu,
                                          uint64_t paid_fee_sats,
                                          int64_t now_ms) const;

    static uint64_t ComputeFeeForCu(uint64_t tx_cu,
                                    uint64_t rate_per_kcu) noexcept;

private:
    struct RateSample {
        int64_t timestamp_ms = 0;
        uint64_t rpc_rate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    };

    void PruneLocked(int64_t now_ms) const;
    uint64_t RollingMinRpcRateLocked(int64_t now_ms) const;

    FeeHysteresisConfig config_;
    mutable std::mutex mutex_;
    mutable std::deque<RateSample> samples_;
    uint64_t current_rpc_rate_per_kcu_ = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
};

FeeHysteresisController &GetGlobalFeeHysteresisController();

} // namespace lotus::v2

#endif // LOTUS_V2_FEE_HYSTERESIS_H
