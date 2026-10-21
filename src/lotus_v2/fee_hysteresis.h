// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LOTUS_V2_FEE_HYSTERESIS_H
#define LOTUS_V2_FEE_HYSTERESIS_H

#include <atomic>
#include <boost/lockfree/queue.hpp>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <primitives/blockhash.h>
#include <thread>

class CBlockIndex;
class Config;

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
constexpr uint64_t DEFAULT_MIN_ADAPTIVE_TARGET_BYTES = 16'000'000;
constexpr uint64_t DEFAULT_MIN_ADAPTIVE_MAX_BLOCK_BYTES = 32'000'000;
constexpr uint64_t DEFAULT_ADAPTIVE_MAX_BLOCK_CEILING = 1'000'000'000;
constexpr uint64_t DEFAULT_ADAPTIVE_HEADROOM_MULTIPLIER = 4;
constexpr uint32_t DEFAULT_ADAPTIVE_EMA_SHIFT = 4;
constexpr uint32_t DEFAULT_BURN_LINEAR_SHIFT = 32;
constexpr uint32_t DEFAULT_BURN_QUAD_SHIFT = 60;
constexpr uint64_t DEFAULT_BURN_EMA_MIN = 4;

struct FeeHysteresisConfig {
    uint64_t consensus_floor_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    int64_t hysteresis_window_ms = DEFAULT_HYSTERESIS_WINDOW_MS;
    uint64_t hysteresis_discount_permille = DEFAULT_HYSTERESIS_DISCOUNT_PERMILLE;
    uint64_t sdk_cushion_permille = DEFAULT_SDK_CUSHION_PERMILLE;
    uint64_t target_utilization_cu = DEFAULT_TARGET_UTILIZATION_CU;
    uint64_t min_adaptive_target_bytes = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    uint64_t min_adaptive_max_block_bytes = DEFAULT_MIN_ADAPTIVE_MAX_BLOCK_BYTES;
    uint64_t max_adaptive_block_bytes = DEFAULT_ADAPTIVE_MAX_BLOCK_CEILING;
    uint64_t adaptive_headroom_multiplier = DEFAULT_ADAPTIVE_HEADROOM_MULTIPLIER;
    uint32_t adaptive_ema_shift = DEFAULT_ADAPTIVE_EMA_SHIFT;
    uint32_t burn_linear_shift = DEFAULT_BURN_LINEAR_SHIFT;
    uint32_t burn_quad_shift = DEFAULT_BURN_QUAD_SHIFT;
    uint64_t burn_ema_min = DEFAULT_BURN_EMA_MIN;
};

struct FeeRateInfo {
    uint64_t consensus_floor_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t p2p_relay_feerate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t rpc_admission_feerate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t recommended_sdk_feerate_per_kcu = 1050;
    uint64_t marginal_burn_feerate_per_kcu = 0;
    bool adaptive_history_available = true;
    int64_t hysteresis_window_ms = DEFAULT_HYSTERESIS_WINDOW_MS;
    uint64_t hysteresis_discount_permille = DEFAULT_HYSTERESIS_DISCOUNT_PERMILLE;
    uint64_t ema_block_size_bytes = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    uint64_t adaptive_target_block_size = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    uint64_t adaptive_max_block_size = DEFAULT_MIN_ADAPTIVE_MAX_BLOCK_BYTES;
    uint64_t adaptive_max_generated_block_size = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    uint64_t mempool_backlog_bytes = 0;
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

class FeePolicyWorker;

class FeeHysteresisController {
public:
    explicit FeeHysteresisController(
        FeeHysteresisConfig config = FeeHysteresisConfig{});

    uint64_t GetConsensusFloorPerKCu() const noexcept;
    uint64_t GetRpcAdmissionRatePerKCu(int64_t now_ms) const;
    uint64_t GetRecommendedSdkRatePerKCu(int64_t now_ms) const;
    uint64_t GetP2pRelayRatePerKCu(int64_t now_ms) const;

    bool HasCompleteAdaptiveHistory() const noexcept;
    uint64_t GetEmaBlockSizeBytes() const noexcept;
    uint64_t GetAdaptiveTargetBlockSize() const noexcept;
    uint64_t GetAdaptiveMaxBlockSize() const noexcept;
    uint64_t GetAdaptiveMaxGeneratedBlockSize() const noexcept;
    uint64_t GetMempoolBacklogBytes() const noexcept;

    FeeRateInfo GetFeeRateInfo(int64_t now_ms) const;

    uint64_t UpdateCongestion(uint64_t active_utilization,
                              uint64_t target_capacity, int64_t now_ms);
    uint64_t RecordConnectedBlock(uint64_t block_size_bytes, int64_t now_ms);
    /** Publish active ancestry only; callers hold cs_main. Cache misses rebuild
     * deterministically. */
    void SyncActiveTip(const CBlockIndex *tip, int64_t now_ms);
    void RecordMempoolBacklog(uint64_t mempool_bytes, int64_t now_ms);
    void SetRpcAdmissionRatePerKCu(uint64_t rpc_rate_per_kcu, int64_t now_ms);
    void Reset(int64_t now_ms = 0);

    FeeCheckResult EvaluateTransactionFee(FeeTier tier, uint64_t tx_cu,
                                          uint64_t paid_fee_sats,
                                          int64_t now_ms) const;

    static uint64_t ComputeFeeForCu(uint64_t tx_cu,
                                    uint64_t rate_per_kcu) noexcept;
    static uint64_t ComputeMarginalBurnFeeRatePerKCu(
        uint64_t active_block_cost, uint64_t ema_block_cost,
        uint32_t linear_shift = DEFAULT_BURN_LINEAR_SHIFT,
        uint32_t quad_shift = DEFAULT_BURN_QUAD_SHIFT,
        uint64_t ema_min = DEFAULT_BURN_EMA_MIN) noexcept;

private:
    friend class FeePolicyWorker;
    friend struct FeePolicyTestAccess;
    FeeRateInfo ComputeFeeRateInfo(int64_t now_ms) const;
    void PublishPolicy(int64_t now_ms);
    void SetRpcAdmissionRateLocked(uint64_t rate, int64_t now_ms);
    uint64_t UpdateCongestionLocked(uint64_t utilization, uint64_t capacity,
                                    int64_t now_ms);
    void RecordBacklogForGeneration(uint64_t bytes, int64_t now_ms,
                                    uint64_t generation);
    std::atomic<uint64_t> policy_generation_{0};
    std::atomic<uint64_t> published_rpc_rate_{DEFAULT_CONSENSUS_FLOOR_PER_KCU};
    std::atomic<bool> asynchronous_policy_{false};
    mutable std::mutex publication_mutex_;
    FeeRateInfo published_info_;

    struct RateSample {
        int64_t timestamp_ms = 0;
        uint64_t rpc_rate_per_kcu = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    };

    void PruneLocked(int64_t now_ms) const;
    uint64_t RollingMinRpcRateLocked(int64_t now_ms) const;
    uint64_t ComputeAdaptiveTargetLocked() const noexcept;
    uint64_t ComputeAdaptiveMaxBlockSizeLocked() const noexcept;
    uint64_t ComputeAdaptiveMaxGeneratedBlockSizeLocked() const noexcept;

    void AdvanceEmaLocked(uint64_t block_size_bytes);
    struct ChainEma { uint64_t ema; bool complete; };
    bool adaptive_history_available_{true};
    std::map<BlockHash, ChainEma> chain_ema_cache_;
    std::deque<BlockHash> chain_ema_cache_order_;
    BlockHash active_tip_hash_;

    FeeHysteresisConfig config_;
    mutable std::mutex mutex_;
    mutable std::deque<RateSample> samples_;
    uint64_t current_rpc_rate_per_kcu_ = DEFAULT_CONSENSUS_FLOOR_PER_KCU;
    uint64_t ema_block_size_bytes_ = DEFAULT_MIN_ADAPTIVE_TARGET_BYTES;
    uint64_t last_block_size_bytes_ = 0;
    uint64_t mempool_backlog_bytes_ = 0;
};

/** Node-owned local admission policy worker. Never owns chain or mempool
 * objects. Producers enqueue absolute backlog samples without allocation or
 * waiting for the consumer. On overflow an old queued sample is evicted to
 * retain the newest absolute total; lost samples cannot accumulate lost
 * admit/remove deltas. Consensus EMA remains synchronous.
 */
class FeePolicyWorker {
public:
    explicit FeePolicyWorker(FeeHysteresisController &controller);
    ~FeePolicyWorker();
    void Start();
    void Stop();
    void RecordBacklog(uint64_t bytes, int64_t now_ms) noexcept;
    uint64_t DroppedSamples() const noexcept {
        return dropped_.load(std::memory_order_relaxed);
    }
    uint64_t Failures() const noexcept {
        return failures_.load(std::memory_order_relaxed);
    }

private:
    struct Sample {
        uint64_t bytes;
        int64_t timestamp_ms;
        uint64_t generation;
    };
    void Run();
    FeeHysteresisController &controller_;
    boost::lockfree::queue<Sample, boost::lockfree::capacity<1024>> queue_;
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> failures_{0};
    std::atomic<bool> stopping_{false};
    std::mutex wake_mutex_;
    std::condition_variable wake_;
    std::thread thread_;
};

FeeHysteresisController &GetGlobalFeeHysteresisController();

/** Resource bound for block-bearing messages and raw disk payloads, with 256
 * KiB headroom. */
uint64_t GetBlockPayloadLimit(const Config &config);

} // namespace lotus::v2

#endif // LOTUS_V2_FEE_HYSTERESIS_H
