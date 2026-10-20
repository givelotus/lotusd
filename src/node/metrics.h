// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_METRICS_H
#define BITCOIN_NODE_METRICS_H

#include <metrics/metrics.h>
#include <util/chaintype.h>
#include <util/result.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

//! Serve /metrics (to -rpcallowip clients, without authentication)
static constexpr bool DEFAULT_METRICS{false};
//! Repeated scrapes within this interval get the previous rendering
static constexpr std::chrono::milliseconds METRICS_MIN_SCRAPE_INTERVAL{1000};
//! One P2P message in this many has its handling time measured
static constexpr uint32_t METRICS_P2P_TIMING_SAMPLE{16};

/**
 * Prefix of every node metric name. One constant, so that the namespace is
 * trivial to change; metrics with a name defined by Prometheus conventions
 * (process_*) do not take it. See doc/metrics.md.
 */
inline constexpr std::string_view METRICS_NAMESPACE{"fullnode_"};
//! Labels the node sets on every series; -metricslabel cannot use them
inline constexpr std::array<std::string_view, 2> METRICS_RESERVED_LABELS{
    "client", "network"};
//! Maximum length of a -metricslabel value, in bytes
static constexpr size_t METRICS_LABEL_VALUE_MAX{128};
//! Maximum number of -metricslabel options
static constexpr size_t METRICS_LABELS_MAX{16};

namespace node {

/** METRICS_NAMESPACE + name */
std::string MetricName(std::string_view name);

/** Value of the client label: the daemon this build is (e.g. "ecashd") */
std::string MetricsClientLabel();
/**
 * Value of the network label, "<chain>-<network>": e.g. "ecash-mainnet",
 * "ecash-testnet", "ecash-regtest". The chain part is the build's
 * (FULLNODE_CHAIN), so that each daemon reports its own.
 */
std::string MetricsNetworkLabel(ChainType chain);

/**
 * Parse -metricslabel=<name>=<value> options into constant labels. Names
 * follow Prometheus rules and must not be reserved (client, network, le,
 * quantile, or starting with "__") or repeated; values are 1 to
 * METRICS_LABEL_VALUE_MAX bytes without control characters.
 */
util::Result<std::vector<std::pair<std::string, std::string>>>
ParseMetricsLabels(const std::vector<std::string> &options);

/** Label values of the node's metrics (index = enum value where noted) */
namespace metric_labels {
    //! P2P message types, sorted, then "other"
    const std::vector<std::string> &MsgTypes();
    //! Index = Network (netaddress.h)
    const std::vector<std::string> &Networks();
    //! Index = P2PWebSocketCompression (net_websocket.h)
    const std::vector<std::string> &WebSocketCompressions();
    //! 0 = inbound, 1 = outbound
    const std::vector<std::string> &Directions();
    //! 0 = tcp, 1 = websocket
    const std::vector<std::string> &Transports();
    //! HTTP endpoint classes (see HTTPEndpoint)
    const std::vector<std::string> &HTTPEndpoints();
    //! 0 = 1xx ... 4 = 5xx, 5 = other
    const std::vector<std::string> &HTTPCodeClasses();
    //! Avalanche vote item types, index = avalanche::AnyVoteItem's variant
    //! index (proof, block, contender, transaction, batch, state_anchor)
    const std::vector<std::string> &AvalancheItemTypes();
    //! Index = AvalancheItemOutcome
    const std::vector<std::string> &AvalancheItemOutcomes();
    //! Index = AvalancheVoteSeries()
    const std::vector<std::string> &AvalancheVotes();
    //! Index = AvalancheProofPool
    const std::vector<std::string> &AvalancheProofPools();
    //! Index = TxValidationResult - 1 (TX_RESULT_UNSET counts as unknown)
    const std::vector<std::string> &MempoolRejectReasons();
    //! Index = MemPoolRemovalReason
    const std::vector<std::string> &MempoolRemovalReasons();
    //! 0 = orphan, 1 = conflicting (TxPool kinds)
    const std::vector<std::string> &TxPools();
    //! Index = BlockStage
    const std::vector<std::string> &BlockStages();
    //! Index = BlockParkReason
    const std::vector<std::string> &BlockParkReasons();
} // namespace metric_labels

enum class HTTPEndpoint : size_t {
    RPC,
    WALLET,
    REST,
    CHRONIK,
    HEALTH,
    METRICS,
    OTHER,
};

/** The node's metrics. Exists only with -metrics (see GetNodeMetrics). */
struct NodeMetrics {
    explicit NodeMetrics(std::vector<std::string> rpc_methods);
    metrics::Registry registry;

    // P2P traffic, by message type (index: MetricMsgTypeIndex)
    metrics::Counter &p2p_received_bytes;
    metrics::Counter &p2p_sent_bytes;
    metrics::Counter &p2p_received_messages;
    metrics::Counter &p2p_sent_messages;
    //! 1 in METRICS_P2P_TIMING_SAMPLE messages
    metrics::EventHistogram &p2p_message_handling_seconds;

    // Peers (CNode objects), by direction x transport x network
    metrics::Gauge &peers;
    metrics::Counter &p2p_connections;
    //! WebSocket peers, by compression x tls (0 = plain, 1 = TLS)
    metrics::Gauge &websocket_peers;

    // Chain
    metrics::Gauge &tip_height;
    metrics::Gauge &tip_timestamp;
    metrics::Gauge &tip_age;
    metrics::Gauge &initial_block_download;
    metrics::EventHistogram &block_connect_seconds;

    // Mempool
    metrics::Gauge &mempool_transactions;
    metrics::Gauge &mempool_bytes;

    // HTTP and RPC
    metrics::Counter &http_requests;
    metrics::EventHistogram &http_request_seconds;
    metrics::Counter &http_tls_handshakes;
    metrics::EventHistogram &rpc_request_seconds;

    metrics::Gauge &process_start_time;
    //! Always 1; labelled with version and commit
    metrics::Gauge &build_info;

    // Avalanche
    metrics::Gauge &avalanche_quorum_established;
    metrics::Gauge &avalanche_quorum_nodes;
    //! By scope: 0 = total, 1 = connected
    metrics::Gauge &avalanche_quorum_score;
    //! By AvalancheProofPool
    metrics::Gauge &avalanche_proofs;
    metrics::Counter &avalanche_polls_sent;
    metrics::Counter &avalanche_poll_items_sent;
    //! By outcome: 0 = answered, 1 = ignored (cooldown)
    metrics::Counter &avalanche_polls_received;
    //! Votes in responses to our polls, by AvalancheVoteSeries()
    metrics::Counter &avalanche_votes_received;
    //! By item type x AvalancheItemOutcome
    metrics::Counter &avalanche_items;
    //! By item type: time from first poll registration to finalization
    metrics::EventHistogram &avalanche_finalization_seconds;

    // Mempool admission
    metrics::Counter &mempool_accepted;
    //! By MempoolRejectReasons
    metrics::Counter &mempool_rejected;
    //! Accepted transactions' own fee rate, in satoshis per 1000 bytes
    metrics::EventHistogram &mempool_accepted_fee_rate;
    //! By MemPoolRemovalReason
    metrics::Counter &mempool_removed;
    //! By kind: 0 = rolling (mempool full), 1 = effective admission floor
    metrics::Gauge &mempool_min_fee_rate;
    //! By TxPools
    metrics::Gauge &tx_pool_transactions;
    //! By TxPools x reason (0 = expired, 1 = evicted)
    metrics::Counter &tx_pool_removed;

    // Validation and UTXO
    //! By BlockStage
    metrics::EventHistogram &block_stage_seconds;
    //! Per block: transactions whose scripts were checked in parallel
    metrics::EventHistogram &script_check_transactions;
    //! Per block: script check workers used
    metrics::EventHistogram &script_check_workers;
    //! By cache (0 = signature, 1 = script_execution) x result (0 = hit,
    //! 1 = miss)
    metrics::Counter &validation_cache_lookups;
    metrics::Gauge &utxo_cache_bytes;
    metrics::Gauge &utxo_cache_entries;
    //! Lookups in the chainstate's UTXO cache: 0 = hit, 1 = miss (read
    //! from the database), 2 = absent
    metrics::Counter &utxo_cache_lookups;
    //! By mode: 0 = flush (cache emptied), 1 = sync (cache kept)
    metrics::EventHistogram &utxo_flush_seconds;
    metrics::Counter &chain_reorgs;
    //! Blocks disconnected per reorganization
    metrics::EventHistogram &chain_reorg_depth;
    //! By source: 0 = validation, 1 = invalidateblock
    metrics::Counter &blocks_invalid;
    //! By BlockParkReason
    metrics::Counter &blocks_parked;

    /** Label index of an RPC method ("other" if not in the set) */
    size_t RPCMethodIndex(std::string_view method) const noexcept;

    size_t PeerSeries(bool inbound, bool websocket,
                      size_t network) const noexcept;

private:
    //! Sorted, then "other"
    const std::vector<std::string> m_rpc_methods;
};

namespace detail {
    extern std::atomic<NodeMetrics *> g_node_metrics;
}

/**
 * The node's metrics, or nullptr when they are off. Recording sites do
 * `if (auto *m{node::GetNodeMetrics()}) m->...`, so disabled metrics cost
 * one load and a branch. Once created, the object is never freed (like
 * the logger), so a pointer obtained here stays valid.
 */
inline NodeMetrics *GetNodeMetrics() noexcept {
    return detail::g_node_metrics.load(std::memory_order_acquire);
}

/**
 * Create the metrics (once), set the constant labels on every series
 * (client, network, then the operator's), start the drain thread and give
 * new threads their rings. rpc_methods: every registered RPC command.
 * Fails if an operator label is also the name of a metric's label.
 */
util::Result<NodeMetrics *> StartNodeMetrics(
    std::vector<std::string> rpc_methods, ChainType chain,
    const std::vector<std::pair<std::string, std::string>> &operator_labels);
/** Stop the drain thread (recording still works, into full rings) */
void StopNodeMetrics();

enum class AvalancheItemOutcome : size_t { FINALIZED, INVALIDATED, STALE };
enum class AvalancheProofPool : size_t {
    VALID,
    CONFLICTING,
    IMMATURE,
    DANGLING
};

/**
 * Series of avalanche_votes_received for a vote's error code, as
 * VoteRecord::registerVote counts it: 0 is yes, a positive error a no (e.g.
 * invalid, parked), a negative one neutral (e.g. unknown, missing).
 */
inline size_t AvalancheVoteSeries(uint32_t error) noexcept {
    if (error == 0) {
        return 0;
    }
    return int32_t(error) > 0 ? 1 : 2;
}

/** Series of mempool_rejected for a TxValidationResult (as an integer) */
inline size_t MempoolRejectSeries(int result) noexcept {
    // TX_RESULT_UNSET (0) and out-of-range values count as the last
    // ("unknown", TX_UNKNOWN)
    constexpr int LAST{13};
    return size_t((result >= 1 && result <= LAST ? result : LAST) - 1);
}

enum class BlockStage : size_t {
    // ConnectBlock
    CHECK,
    FORKS,
    CONNECT,
    VERIFY,
    INDEX,
    // ConnectTip
    LOAD,
    FLUSH,
    CHAINSTATE,
    POST_CONNECT,
};
enum class BlockParkReason : size_t {
    POLICY,
    FINALIZATION_CONFLICT,
    DEEP_REORG,
    REQUESTED,
};

inline void RecordBlockStage(BlockStage stage,
                             std::chrono::steady_clock::duration d) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->block_stage_seconds.RecordDuration(d, size_t(stage));
    }
}

inline void CountParkedBlock(BlockParkReason reason) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->blocks_parked.Add(size_t(reason));
    }
}

/** Count a signature or script execution cache lookup */
inline void CountValidationCacheLookup(bool script_execution,
                                       bool hit) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->validation_cache_lookups.Add((script_execution ? 2 : 0) +
                                        (hit ? 0 : 1));
    }
}

/** Count a transaction pool's (orphans, conflicting) removals */
void RecordTxPoolRemovals(std::string_view pool_kind, unsigned expired,
                          unsigned evicted) noexcept;

/** Label index of a P2P message type ("other" for unknown types) */
size_t MetricMsgTypeIndex(std::string_view msg_type) noexcept;

/** Set the mempool gauges (call with the mempool lock held) */
inline void SetMempoolMetrics(size_t transactions, uint64_t bytes) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->mempool_transactions.Set(double(transactions));
        m->mempool_bytes.Set(double(bytes));
    }
}

/** Set the chain tip gauges (call with cs_main held, where the tip changes) */
inline void SetTipMetrics(int height, int64_t block_time) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->tip_height.Set(double(height));
        m->tip_timestamp.Set(double(block_time));
    }
}

} // namespace node

#endif // BITCOIN_NODE_METRICS_H
