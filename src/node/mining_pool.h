// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MINING_POOL_H
#define BITCOIN_NODE_MINING_POOL_H

#include <consensus/amount.h>
#include <lotus_v2/header.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <uint256.h>
#include <univalue.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class ArgsManager;
class Config;
namespace Consensus {
struct Params;
} // namespace Consensus

namespace node {
struct NodeContext;
} // namespace node

namespace lotus::v2::node {

static constexpr bool DEFAULT_MINING_POOL_ENABLED = true;
static constexpr size_t DEFAULT_POOL_PPLNS_WINDOW = 1000;
static constexpr int64_t DEFAULT_POOL_TARGET_SPACING_SEC = 5;
static constexpr size_t POOL_JOB_RING_SIZE = 64;

/**
 * Active mining job cached in the pool's bounded ring buffer.
 */
struct PoolJob {
    uint64_t job_id{0};
    uint64_t template_id{0};
    CBlockHeader header_134;
    CTransactionRef coinbase_tx;
    std::vector<CTransactionRef> template_txs;
    lotus::v2::Hash subtree_a_root{};
    lotus::v2::Hash body_hash{};
    BlockHash parent_id{BlockHash()};
    uint32_t nBits{0};
    uint256 network_target;
    int64_t created_time{0};
    uint64_t block_size{0};
    Amount block_reward{Amount::zero()};
    bool block_sealed{false};
    std::unordered_set<uint64_t> submitted_nonces;
};

/**
 * Per-worker state tracked by the built-in mining pool.
 */
struct PoolWorker {
    std::string worker_id;
    uint32_t nonce_prefix{0};
    CTxOut payout;
    bool is_newsletter_subscriber{false};
    uint256 share_target;
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t blocks_found{0};
    double cumulative_work{0.0};
    double newsletter_credits_usd_cents{0.0};
    int64_t last_share_time_ms{0};
    std::deque<int64_t> recent_share_intervals_ms;
};

/**
 * Sliding PPLNS window entry representing a validated share.
 */
struct PPLNSShare {
    std::string worker_id;
    CTxOut payout;
    double weight{1.0};
    bool is_newsletter_subscriber{false};
};

/**
 * Result of submitting a share to the built-in mining pool.
 */
struct ShareSubmissionResult {
    bool accepted{false};
    std::string reason;
    bool block_found{false};
    BlockHash block_hash{BlockHash()};
    BlockHash share_hash{BlockHash()};
    uint256 share_target;
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    double newsletter_credits_usd_cents{0.0};
    bool subscription_unlocked{false};

    UniValue ToUniValue() const;
};

/**
 * Built-in non-custodial HTTP/SSE PPLNS Mining Pool & Newsletter Hashpower
 * Paywall Engine for lotusd.
 */
class MiningPoolManager {
public:
    MiningPoolManager();

    /** Configure pool settings from CLI/config arguments. */
    void Configure(const ArgsManager &args, const Config &config);

    /** Reset all pool state (jobs, workers, PPLNS window). Useful for tests. */
    void Reset();

    /** Return whether the built-in mining pool is enabled. */
    bool IsEnabled() const;

    /** Reject new node-dependent work, then drain accepted work before
     * teardown. */
    void Interrupt();
    void Stop();

    /** Register or retrieve a worker and build a current V2 mining job. */
    UniValue GetMiningJobJSON(const Config &config, ::node::NodeContext &node,
                              const std::string &worker_id,
                              PoolJob *out_job = nullptr,
                              PoolWorker *out_worker = nullptr);

    /** Format a job JSON string as an SSE `event: job\ndata: ...\n\n` frame. */
    static std::string FormatSSEJobEvent(const UniValue &job_json);

    /** Validate a submitted share, update PPLNS/vardiff, and seal blocks. */
    ShareSubmissionResult SubmitShare(const Config &config,
                                      ::node::NodeContext &node,
                                      uint64_t job_id,
                                      const std::string &worker_id,
                                      std::optional<uint64_t> nTime,
                                      uint64_t nNonce);

    /** Return overall pool statistics as a UniValue JSON object. */
    UniValue GetPoolInfoJSON() const;

    /** Return statistics for a specific worker (or combined stats). */
    UniValue GetWorkerStatsJSON(const std::string &worker_id) const;

    /** Explicitly override a worker's share target (useful for testing). */
    void SetWorkerShareTarget(const std::string &worker_id,
                              const uint256 &target,
                              const Config &config);

    /** Override target spacing in seconds for vardiff. */
    void SetTargetSpacingSec(int64_t spacing_sec);

    /** Override PPLNS sliding window size. */
    void SetPPLNSWindowSize(size_t window_size);

private:
    // A request retains its NodeContext dependencies until its operation ends.
    // Never wait for operations or acquire cs_main while holding m_mutex.
    class Operation {
    public:
        explicit Operation(MiningPoolManager &pool);
        ~Operation();
        Operation(const Operation &) = delete;
        Operation &operator=(const Operation &) = delete;

    private:
        MiningPoolManager &m_pool;
    };
    mutable std::mutex m_mutex;
    std::condition_variable m_drained;
    size_t m_active_operations{0};
    bool m_stopping{false};
    bool m_staking_rewards{false};
    bool m_treasury_rewards{true};
    uint256 m_initial_share_target;
    bool m_configured{false};
    bool m_enabled{DEFAULT_MINING_POOL_ENABLED};
    std::string m_pool_address_arg;
    std::optional<CTxOut> m_fallback_payout;
    std::string m_payout_error;
    size_t m_pplns_window_size{DEFAULT_POOL_PPLNS_WINDOW};
    int64_t m_target_spacing_sec{DEFAULT_POOL_TARGET_SPACING_SEC};

    uint64_t m_next_job_id{1};
    uint32_t m_next_nonce_prefix{1};
    std::array<PoolJob, POOL_JOB_RING_SIZE> m_jobs;
    std::unordered_map<std::string, PoolWorker> m_workers;
    std::deque<PPLNSShare> m_pplns_window;

    uint64_t m_total_accepted_shares{0};
    uint64_t m_total_rejected_shares{0};
    uint64_t m_blocks_found{0};
    double m_total_work{0.0};

    PoolWorker &GetOrCreateWorkerLocked(const std::string &worker_id,
                                        const Config &config);
    CTxOut ResolveWorkerPayoutLocked(const std::string &worker_id,
                                            const Config &config,
                                            bool &is_newsletter_out) const;
    CTxOut GetFallbackPayoutLocked() const;
    static uint256 GetInitialShareTarget(const Consensus::Params &params);
    static double ComputeShareDifficulty(const uint256 &share_target,
                                         const uint256 &pow_limit);
    void UpdateVarDiffLocked(PoolWorker &worker, int64_t now_ms,
                             const Consensus::Params &params);
    double EstimateWorkerHashrateLocked(const PoolWorker &worker) const;
    double ComputeWorkerPPLNSWeightLocked(const std::string &worker_id) const;
};

} // namespace lotus::v2::node

namespace node {
using lotus::v2::node::MiningPoolManager;

/** Startup/shutdown run serially; publication and handler acquisition are
 * atomic. */
std::shared_ptr<MiningPoolManager> GetMiningPool(const NodeContext &node);
void StartMiningPool(NodeContext &node, const Config &config);
void InterruptMiningPool(NodeContext &node);
void StopMiningPool(NodeContext &node);
} // namespace node

#endif // BITCOIN_NODE_MINING_POOL_H
