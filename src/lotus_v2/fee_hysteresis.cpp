// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "fee_hysteresis.h"

#include <arith_uint256.h>
#include <chain.h>
#include <chrono>
#include <logging.h>
#include <util/time.h>
#include <vector>

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
    : config_(config), current_rpc_rate_per_kcu_(std::max<uint64_t>(
                           1, config.consensus_floor_per_kcu)) {
    config_.consensus_floor_per_kcu = current_rpc_rate_per_kcu_;
    if (config_.hysteresis_window_ms < 0) {
        config_.hysteresis_window_ms = 0;
    }
    if (config_.hysteresis_discount_permille > 1000) {
        config_.hysteresis_discount_permille = 1000;
    }
    if (config_.min_adaptive_target_bytes == 0) {
        config_.min_adaptive_target_bytes = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    }
    if (config_.min_adaptive_max_block_bytes <
        config_.min_adaptive_target_bytes) {
        config_.min_adaptive_max_block_bytes =
            std::max<uint64_t>(DEFAULT_MIN_ADAPTIVE_MAX_BLOCK_BYTES,
                               config_.min_adaptive_target_bytes * 2);
    }
    if (config_.max_adaptive_block_bytes <
        config_.min_adaptive_max_block_bytes) {
        config_.max_adaptive_block_bytes = config_.min_adaptive_max_block_bytes;
    }
    if (config_.adaptive_headroom_multiplier == 0) {
        config_.adaptive_headroom_multiplier =
            DEFAULT_ADAPTIVE_HEADROOM_MULTIPLIER;
    }
    if (config_.adaptive_ema_shift > 16) {
        config_.adaptive_ema_shift = 16;
    }
    ema_block_size_bytes_ = config_.min_adaptive_target_bytes;
    published_rpc_rate_.store(current_rpc_rate_per_kcu_,
                              std::memory_order_relaxed);
    samples_.push_back(RateSample{0, current_rpc_rate_per_kcu_});
}

uint64_t FeeHysteresisController::GetConsensusFloorPerKCu() const noexcept {
    return config_.consensus_floor_per_kcu;
}

uint64_t FeeHysteresisController::ComputeAdaptiveTargetLocked() const noexcept {
    return std::clamp(ema_block_size_bytes_,
                      config_.min_adaptive_target_bytes,
                      config_.max_adaptive_block_bytes);
}

uint64_t FeeHysteresisController::ComputeAdaptiveMaxGeneratedBlockSizeLocked()
    const noexcept {
    const uint64_t target = ComputeAdaptiveTargetLocked();
    const uint64_t demand_headroom =
        mempool_backlog_bytes_ > 0
            ? ClampU128ToU64(UInt128(mempool_backlog_bytes_) + 1'000'000)
            : 0ULL;
    const uint64_t ema_expanded =
        ema_block_size_bytes_ > config_.min_adaptive_target_bytes
            ? ClampU128ToU64(UInt128(target) * 2)
            : target;
    const uint64_t desired = std::max(ema_expanded, demand_headroom);
    const uint64_t upper =
        config_.max_adaptive_block_bytes > 1000
            ? config_.max_adaptive_block_bytes - 1000
            : config_.max_adaptive_block_bytes;
    return std::clamp(desired, config_.min_adaptive_target_bytes, upper);
}

uint64_t
FeeHysteresisController::ComputeAdaptiveMaxBlockSizeLocked() const noexcept {
    const uint64_t target = ComputeAdaptiveTargetLocked();
    const uint64_t ema_headroom =
        ema_block_size_bytes_ > config_.min_adaptive_target_bytes
            ? ClampU128ToU64(UInt128(target) *
                             UInt128(config_.adaptive_headroom_multiplier))
            : config_.min_adaptive_max_block_bytes;
    // Capacity is a function of active-chain history, never local mempool
    // contents.
    const uint64_t desired =
        std::max(config_.min_adaptive_max_block_bytes, ema_headroom);
    return std::clamp(desired, config_.min_adaptive_max_block_bytes,
                      config_.max_adaptive_block_bytes);
}

bool FeeHysteresisController::HasCompleteAdaptiveHistory() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return adaptive_history_available_;
}

uint64_t FeeHysteresisController::GetEmaBlockSizeBytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return ema_block_size_bytes_;
}

uint64_t FeeHysteresisController::GetAdaptiveTargetBlockSize() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return ComputeAdaptiveTargetLocked();
}

uint64_t FeeHysteresisController::GetAdaptiveMaxBlockSize() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return ComputeAdaptiveMaxBlockSizeLocked();
}

uint64_t
FeeHysteresisController::GetAdaptiveMaxGeneratedBlockSize() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return ComputeAdaptiveMaxGeneratedBlockSizeLocked();
}

uint64_t FeeHysteresisController::GetMempoolBacklogBytes() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return mempool_backlog_bytes_;
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

uint64_t
FeeHysteresisController::GetRpcAdmissionRatePerKCu(int64_t /*now_ms*/) const {
    // Independent local policy scalar: stale is acceptable, tearing is not.
    // Relaxed ordering publishes no other state. No controller mutex or
    // pruning.
    return published_rpc_rate_.load(std::memory_order_relaxed);
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
    if (asynchronous_policy_.load(std::memory_order_acquire)) {
        // RPC diagnostics need a coherent group, unlike the independent hot
        // admission scalar. This short copy never takes the calculation lock.
        std::lock_guard<std::mutex> lock(publication_mutex_);
        return published_info_;
    }
    return ComputeFeeRateInfo(now_ms);
}

void FeeHysteresisController::PublishPolicy(int64_t now_ms) {
    const auto info = ComputeFeeRateInfo(now_ms);
    std::lock_guard<std::mutex> lock(publication_mutex_);
    published_info_ = info;
}

FeeRateInfo FeeHysteresisController::ComputeFeeRateInfo(int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t rpc_rate = current_rpc_rate_per_kcu_;
    const uint64_t min_rpc = RollingMinRpcRateLocked(now_ms);
    const uint64_t keep_permille = 1000 - config_.hysteresis_discount_permille;
    const uint64_t discounted = static_cast<uint64_t>(
        (UInt128(min_rpc) * UInt128(keep_permille)) / 1000);
    const uint64_t p2p_rate =
        std::max(config_.consensus_floor_per_kcu, discounted);
    const arith_uint256 sdk_num =
        arith_uint256{rpc_rate} *
        (arith_uint256{1000} + arith_uint256{config_.sdk_cushion_permille});
    const uint64_t sdk_rate =
        ClampWideToU64((sdk_num + arith_uint256{999}) / arith_uint256{1000});
    const uint64_t active_cost =
        std::max(last_block_size_bytes_, mempool_backlog_bytes_);
    const uint64_t marginal_burn = ComputeMarginalBurnFeeRatePerKCu(
        active_cost, ema_block_size_bytes_, config_.burn_linear_shift,
        config_.burn_quad_shift, config_.burn_ema_min);

    return FeeRateInfo{
        .consensus_floor_per_kcu = config_.consensus_floor_per_kcu,
        .p2p_relay_feerate_per_kcu = p2p_rate,
        .rpc_admission_feerate_per_kcu = rpc_rate,
        .recommended_sdk_feerate_per_kcu = sdk_rate,
        .marginal_burn_feerate_per_kcu = marginal_burn,
        .adaptive_history_available = adaptive_history_available_,
        .hysteresis_window_ms = config_.hysteresis_window_ms,
        .hysteresis_discount_permille = config_.hysteresis_discount_permille,
        .ema_block_size_bytes = ema_block_size_bytes_,
        .adaptive_target_block_size = ComputeAdaptiveTargetLocked(),
        .adaptive_max_block_size = ComputeAdaptiveMaxBlockSizeLocked(),
        .adaptive_max_generated_block_size =
            ComputeAdaptiveMaxGeneratedBlockSizeLocked(),
        .mempool_backlog_bytes = mempool_backlog_bytes_,
    };
}

void FeeHysteresisController::SetRpcAdmissionRatePerKCu(
    uint64_t rpc_rate_per_kcu, int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    SetRpcAdmissionRateLocked(rpc_rate_per_kcu, now_ms);
}

void FeeHysteresisController::SetRpcAdmissionRateLocked(
    uint64_t rpc_rate_per_kcu, int64_t now_ms) {
    const uint64_t clamped =
        std::max(config_.consensus_floor_per_kcu, rpc_rate_per_kcu);
    current_rpc_rate_per_kcu_ = clamped;
    published_rpc_rate_.store(clamped, std::memory_order_relaxed);
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
    std::lock_guard<std::mutex> lock(mutex_);
    return UpdateCongestionLocked(active_utilization, target_capacity, now_ms);
}

uint64_t FeeHysteresisController::UpdateCongestionLocked(
    uint64_t active_utilization, uint64_t target_capacity, int64_t now_ms) {
    uint64_t target = target_capacity;
    uint64_t marginal_burn = 0;
    {
        if (target == 0) {
            const uint64_t adaptive_target = ComputeAdaptiveTargetLocked();
            target =
                ema_block_size_bytes_ > config_.target_utilization_cu
                    ? std::max(config_.target_utilization_cu, adaptive_target)
                    : (config_.target_utilization_cu > 0
                           ? config_.target_utilization_cu
                           : adaptive_target);
        }
        marginal_burn = ComputeMarginalBurnFeeRatePerKCu(
            active_utilization, ema_block_size_bytes_,
            config_.burn_linear_shift, config_.burn_quad_shift,
            config_.burn_ema_min);
    }
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
    next_rate = std::max(next_rate, marginal_burn);
    SetRpcAdmissionRateLocked(next_rate, now_ms);
    return next_rate;
}

uint64_t FeeHysteresisController::RecordConnectedBlock(
    uint64_t block_size_bytes, int64_t now_ms) {
    uint64_t target_after = 0;
    uint64_t adaptive_max = 0;
    uint64_t active_utilization = block_size_bytes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_block_size_bytes_ = block_size_bytes;
        AdvanceEmaLocked(block_size_bytes);
        if (mempool_backlog_bytes_ > block_size_bytes) {
            mempool_backlog_bytes_ -= block_size_bytes;
        } else {
            mempool_backlog_bytes_ = 0;
        }
        target_after = ComputeAdaptiveTargetLocked();
        adaptive_max = ComputeAdaptiveMaxBlockSizeLocked();
        active_utilization =
            std::max(last_block_size_bytes_, mempool_backlog_bytes_);
    }
    UpdateCongestion(active_utilization, target_after, now_ms);
    return adaptive_max;
}

void FeeHysteresisController::AdvanceEmaLocked(uint64_t block_size_bytes) {
    const uint32_t shift = config_.adaptive_ema_shift;
    if (block_size_bytes > ema_block_size_bytes_) {
        const uint32_t up_shift = std::max<uint32_t>(1, shift / 2);
        const uint64_t delta =
            (block_size_bytes - ema_block_size_bytes_) >> up_shift;
        ema_block_size_bytes_ = std::max(
            ema_block_size_bytes_ + std::max<uint64_t>(1, delta),
            block_size_bytes / 2);
    } else if (block_size_bytes < ema_block_size_bytes_) {
        const uint64_t delta =
            (ema_block_size_bytes_ - block_size_bytes) >> shift;
        ema_block_size_bytes_ =
            ema_block_size_bytes_ > delta
                ? ema_block_size_bytes_ - delta
                : config_.min_adaptive_target_bytes;
    }
    ema_block_size_bytes_ = std::clamp(
        ema_block_size_bytes_, config_.min_adaptive_target_bytes,
        config_.max_adaptive_block_bytes);
}

void FeeHysteresisController::SyncActiveTip(const CBlockIndex *tip,
                                            int64_t now_ms) {
    if (!tip) return;
    uint64_t target, utilization;
    std::lock_guard<std::mutex> lock(mutex_);
    {
        if (active_tip_hash_ == tip->GetBlockHash()) return;
        const bool extends =
            tip->pprev && active_tip_hash_ == tip->pprev->GetBlockHash();
        if (!extends) {
            // An orphan's fee history must not survive a rollback or a restart.
            policy_generation_.fetch_add(1, std::memory_order_relaxed);
            samples_.clear();
            current_rpc_rate_per_kcu_ = config_.consensus_floor_per_kcu;
            published_rpc_rate_.store(current_rpc_rate_per_kcu_,
                                      std::memory_order_relaxed);
        }
        std::vector<const CBlockIndex *> missing;
        const CBlockIndex *ancestor = tip;
        while (ancestor && !chain_ema_cache_.count(ancestor->GetBlockHash())) {
            missing.push_back(ancestor);
            ancestor = ancestor->pprev;
        }
        adaptive_history_available_ =
            ancestor ? chain_ema_cache_.at(ancestor->GetBlockHash()).complete
                     : true;
        ema_block_size_bytes_ =
            ancestor ? chain_ema_cache_.at(ancestor->GetBlockHash()).ema
                     : config_.min_adaptive_target_bytes;
        for (auto it = missing.rbegin(); it != missing.rend(); ++it) {
            if ((*it)->nHeight > 0 && (*it)->nSize == 0)
                adaptive_history_available_ = false;
            if (adaptive_history_available_)
                AdvanceEmaLocked((*it)->nSize);
            else
                ema_block_size_bytes_ = config_.min_adaptive_target_bytes;
            const auto hash = (*it)->GetBlockHash();
            chain_ema_cache_.emplace(
                hash,
                ChainEma{ema_block_size_bytes_, adaptive_history_available_});
            chain_ema_cache_order_.push_back(hash);
            // Bounded memory; old/deep reorgs rebuild from immutable
            // block-index sizes.
            if (chain_ema_cache_order_.size() > 4096) {
                chain_ema_cache_.erase(chain_ema_cache_order_.front());
                chain_ema_cache_order_.pop_front();
            }
        }
        last_block_size_bytes_ = tip->nSize;
        active_tip_hash_ = tip->GetBlockHash();
        target = ComputeAdaptiveTargetLocked();
        utilization = std::max(last_block_size_bytes_, mempool_backlog_bytes_);
    }
    UpdateCongestionLocked(utilization, target, now_ms);
}

void FeeHysteresisController::RecordMempoolBacklog(uint64_t mempool_bytes,
                                                   int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    mempool_backlog_bytes_ = mempool_bytes;
    UpdateCongestionLocked(std::max(last_block_size_bytes_, mempool_bytes),
                           ComputeAdaptiveTargetLocked(), now_ms);
}

void FeeHysteresisController::RecordBacklogForGeneration(uint64_t bytes,
                                                         int64_t now_ms,
                                                         uint64_t generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != policy_generation_.load(std::memory_order_relaxed))
        return;
    mempool_backlog_bytes_ = bytes;
    UpdateCongestionLocked(std::max(last_block_size_bytes_, bytes),
                           ComputeAdaptiveTargetLocked(), now_ms);
}

void FeeHysteresisController::Reset(int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_generation_.fetch_add(1, std::memory_order_relaxed);
    samples_.clear();
    chain_ema_cache_.clear();
    chain_ema_cache_order_.clear();
    active_tip_hash_.SetNull();
    adaptive_history_available_ = true;
    current_rpc_rate_per_kcu_ = config_.consensus_floor_per_kcu;
    published_rpc_rate_.store(current_rpc_rate_per_kcu_,
                              std::memory_order_relaxed);
    ema_block_size_bytes_ = config_.min_adaptive_target_bytes;
    last_block_size_bytes_ = 0;
    mempool_backlog_bytes_ = 0;
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

uint64_t FeeHysteresisController::ComputeMarginalBurnFeeRatePerKCu(
    uint64_t active_block_cost, uint64_t ema_block_cost, uint32_t linear_shift,
    uint32_t quad_shift, uint64_t ema_min) noexcept {
    const uint64_t eff_ema = std::max(ema_block_cost, ema_min);
    auto burn_at = [&](uint64_t cost) -> UInt128 {
        const UInt128 c = UInt128(cost);
        const UInt128 e = UInt128(eff_ema);
        const UInt128 lin =
            linear_shift >= 128 ? UInt128(0) : ((c * e) >> linear_shift);
        const UInt128 quad =
            quad_shift >= 128 ? UInt128(0) : ((c * c) >> quad_shift);
        return lin + quad;
    };
    const uint64_t next_cost =
        active_block_cost > std::numeric_limits<uint64_t>::max() - 1000
            ? std::numeric_limits<uint64_t>::max()
            : active_block_cost + 1000;
    const UInt128 delta_burn = burn_at(next_cost) - burn_at(active_block_cost);
    // 50% of ordinary fees are burned (burned_fees = remaining - remaining /
    // 2), so total fee rate per 1,000 CU must be 2 * delta_burn to cover
    // marginal burn.
    return ClampU128ToU64(delta_burn * 2);
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

FeePolicyWorker::FeePolicyWorker(FeeHysteresisController &controller)
    : controller_(controller) {}

FeePolicyWorker::~FeePolicyWorker() {
    Stop();
}

void FeePolicyWorker::Start() {
    if (thread_.joinable()) return;
    stopping_.store(false, std::memory_order_relaxed);
    const auto now =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    controller_.PublishPolicy(now);
    controller_.asynchronous_policy_.store(true, std::memory_order_release);
    try {
        thread_ = std::thread(&FeePolicyWorker::Run, this);
    } catch (...) {
        controller_.asynchronous_policy_.store(false,
                                               std::memory_order_release);
        throw;
    }
}

void FeePolicyWorker::Stop() {
    stopping_.store(true, std::memory_order_relaxed);
    wake_.notify_one();
    if (thread_.joinable()) thread_.join();
    controller_.asynchronous_policy_.store(false, std::memory_order_release);
}

void FeePolicyWorker::RecordBacklog(uint64_t bytes, int64_t now_ms) noexcept {
    const Sample sample{bytes, now_ms,
        controller_.policy_generation_.load(std::memory_order_relaxed)};
    // Fixed storage, no consumer lock or allocation. On overflow retain the
    // newest absolute total by evicting an older sample. Boost's queue is MPMC,
    // so a producer may safely remove a sample concurrently with the worker.
    // CAS retries are lock-free; they never wait for the consumer to run.
    while (!queue_.push(sample)) {
        Sample discarded;
        if (queue_.pop(discarded)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // No producer/consumer wake mutex on the admission path. Poll at most
    // every 20 ms; staleness of local admission policy is intentional.
}

void FeePolicyWorker::Run() {
    for (;;) {
        try {
            Sample sample;
            for (unsigned n = 0; n < 1024 && queue_.pop(sample); ++n) {
                controller_.RecordBacklogForGeneration(
                    sample.bytes, sample.timestamp_ms, sample.generation);
            }
            const auto now =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            controller_.PublishPolicy(now);
        } catch (const std::exception &) {
            // Keep the last complete published policy, retry next tick. This
            // local-policy failure cannot change authoritative chain capacity.
            if (failures_.fetch_add(1, std::memory_order_relaxed) == 0) {
                LogWarning("Local fee policy worker failed; retaining last "
                           "published policy and retrying.\n");
            }
        }
        if (stopping_.load(std::memory_order_relaxed)) break;
        std::unique_lock<std::mutex> lock(wake_mutex_);
        wake_.wait_for(lock, std::chrono::milliseconds(20), [this] {
            return stopping_.load(std::memory_order_relaxed);
        });
    }
}

FeeHysteresisController &GetGlobalFeeHysteresisController() {
    static FeeHysteresisController instance{};
    return instance;
}

} // namespace lotus::v2
