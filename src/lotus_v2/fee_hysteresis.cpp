// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "fee_hysteresis.h"

#include <arith_uint256.h>

#include <algorithm>
#include <limits>

namespace lotus::v2 {

namespace {
using UInt128 = unsigned __int128;

uint64_t ClampU128ToU64(UInt128 v) noexcept {
    if (v > UInt128(std::numeric_limits<uint64_t>::max())) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(v);
}
uint64_t ClampWideToU64(const arith_uint256 &v) noexcept {
    const arith_uint256 limit{std::numeric_limits<uint64_t>::max()};
    return v > limit ? std::numeric_limits<uint64_t>::max() : v.GetLow64();
}
} // namespace

FeeHysteresisController::FeeHysteresisController(FeeHysteresisConfig config)
    : config_(config),
      current_rpc_rate_per_kcu_(std::max<uint64_t>(
          1, config.consensus_floor_per_kcu)) {
    config_.consensus_floor_per_kcu = current_rpc_rate_per_kcu_;
    if (config_.hysteresis_window_ms < 0) {
        config_.hysteresis_window_ms = 0;
    }
    if (config_.hysteresis_discount_permille > 1000) {
        config_.hysteresis_discount_permille = 1000;
    }
    samples_.push_back(RateSample{0, current_rpc_rate_per_kcu_});
}

uint64_t FeeHysteresisController::GetConsensusFloorPerKCu() const noexcept {
    return config_.consensus_floor_per_kcu;
}

void FeeHysteresisController::PruneLocked(int64_t now_ms) const {
    const int64_t cutoff_ms = now_ms - config_.hysteresis_window_ms;
    while (!samples_.empty() && samples_.front().timestamp_ms < cutoff_ms) {
        samples_.pop_front();
    }
}

uint64_t FeeHysteresisController::RollingMinRpcRateLocked(int64_t now_ms) const {
    PruneLocked(now_ms);
    uint64_t min_rate = current_rpc_rate_per_kcu_;
    for (const auto &s : samples_) {
        if (s.timestamp_ms <= now_ms) {
            min_rate = std::min(min_rate, s.rpc_rate_per_kcu);
        }
    }
    return std::max(config_.consensus_floor_per_kcu, min_rate);
}

uint64_t FeeHysteresisController::GetRpcAdmissionRatePerKCu(
    int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    PruneLocked(now_ms);
    return current_rpc_rate_per_kcu_;
}

uint64_t FeeHysteresisController::GetRecommendedSdkRatePerKCu(
    int64_t now_ms) const {
    const uint64_t rpc_rate = GetRpcAdmissionRatePerKCu(now_ms);
    const arith_uint256 num = arith_uint256{rpc_rate} *
        (arith_uint256{1000} + arith_uint256{config_.sdk_cushion_permille});
    return ClampWideToU64((num + arith_uint256{999}) / arith_uint256{1000});
}

uint64_t FeeHysteresisController::GetP2pRelayRatePerKCu(int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t min_rpc = RollingMinRpcRateLocked(now_ms);
    const uint64_t keep_permille = 1000 - config_.hysteresis_discount_permille;
    const uint64_t discounted = static_cast<uint64_t>(
        (UInt128(min_rpc) * UInt128(keep_permille)) / 1000);
    return std::max(config_.consensus_floor_per_kcu, discounted);
}

FeeRateInfo FeeHysteresisController::GetFeeRateInfo(int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t rpc_rate = current_rpc_rate_per_kcu_;
    const uint64_t min_rpc = RollingMinRpcRateLocked(now_ms);
    const uint64_t keep_permille = 1000 - config_.hysteresis_discount_permille;
    const uint64_t discounted = static_cast<uint64_t>(
        (UInt128(min_rpc) * UInt128(keep_permille)) / 1000);
    const uint64_t p2p_rate =
        std::max(config_.consensus_floor_per_kcu, discounted);
    const arith_uint256 sdk_num = arith_uint256{rpc_rate} *
        (arith_uint256{1000} + arith_uint256{config_.sdk_cushion_permille});
    const uint64_t sdk_rate = ClampWideToU64(
        (sdk_num + arith_uint256{999}) / arith_uint256{1000});

    return FeeRateInfo{
        .consensus_floor_per_kcu = config_.consensus_floor_per_kcu,
        .p2p_relay_feerate_per_kcu = p2p_rate,
        .rpc_admission_feerate_per_kcu = rpc_rate,
        .recommended_sdk_feerate_per_kcu = sdk_rate,
        .hysteresis_window_ms = config_.hysteresis_window_ms,
        .hysteresis_discount_permille = config_.hysteresis_discount_permille,
    };
}

void FeeHysteresisController::SetRpcAdmissionRatePerKCu(
    uint64_t rpc_rate_per_kcu, int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t clamped =
        std::max(config_.consensus_floor_per_kcu, rpc_rate_per_kcu);
    current_rpc_rate_per_kcu_ = clamped;
    PruneLocked(now_ms);
    if (!samples_.empty() && samples_.back().timestamp_ms == now_ms) {
        samples_.back().rpc_rate_per_kcu = clamped;
    } else {
        samples_.push_back(RateSample{now_ms, clamped});
    }
}

uint64_t FeeHysteresisController::UpdateCongestion(uint64_t active_utilization,
                                                   uint64_t target_capacity,
                                                   int64_t now_ms) {
    const uint64_t target =
        target_capacity > 0 ? target_capacity : config_.target_utilization_cu;
    uint64_t next_rate = config_.consensus_floor_per_kcu;
    if (target > 0 && active_utilization > target) {
        const arith_uint256 excess{active_utilization - target};
        const arith_uint256 floor{config_.consensus_floor_per_kcu};
        const arith_uint256 capacity{target};
        const arith_uint256 linear_term = (floor * excess) / capacity;
        const arith_uint256 quad_term =
            (floor * excess * excess) / (capacity * capacity);
        next_rate = ClampWideToU64(floor + linear_term + quad_term);
    }
    SetRpcAdmissionRatePerKCu(next_rate, now_ms);
    return next_rate;
}

void FeeHysteresisController::Reset(int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
    current_rpc_rate_per_kcu_ = config_.consensus_floor_per_kcu;
    samples_.push_back(RateSample{now_ms, current_rpc_rate_per_kcu_});
}

uint64_t FeeHysteresisController::ComputeFeeForCu(
    uint64_t tx_cu, uint64_t rate_per_kcu) noexcept {
    if (tx_cu == 0 || rate_per_kcu == 0) {
        return 0;
    }
    const UInt128 prod = UInt128(tx_cu) * UInt128(rate_per_kcu);
    return ClampU128ToU64((prod + 999) / 1000);
}

FeeCheckResult FeeHysteresisController::EvaluateTransactionFee(
    FeeTier tier, uint64_t tx_cu, uint64_t paid_fee_sats,
    int64_t now_ms) const {
    const FeeRateInfo info = GetFeeRateInfo(now_ms);
    uint64_t required_rate = info.consensus_floor_per_kcu;
    switch (tier) {
        case FeeTier::RpcAdmission:
            required_rate = info.rpc_admission_feerate_per_kcu;
            break;
        case FeeTier::P2pRelay:
            required_rate = info.p2p_relay_feerate_per_kcu;
            break;
        case FeeTier::ConsensusFloor:
            required_rate = info.consensus_floor_per_kcu;
            break;
    }
    const uint64_t required_fee = ComputeFeeForCu(tx_cu, required_rate);
    const uint64_t recommended_sdk_fee =
        ComputeFeeForCu(tx_cu, info.recommended_sdk_feerate_per_kcu);
    return FeeCheckResult{
        .accepted = paid_fee_sats >= required_fee,
        .tier = tier,
        .tx_cu = tx_cu,
        .paid_fee_sats = paid_fee_sats,
        .required_fee_sats = required_fee,
        .required_rate_per_kcu = required_rate,
        .recommended_sdk_fee_sats = std::max(required_fee, recommended_sdk_fee),
    };
}

FeeHysteresisController &GetGlobalFeeHysteresisController() {
    static FeeHysteresisController instance{};
    return instance;
}

} // namespace lotus::v2
