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
    //! 0 = tcp, 1 = ws (WebSocket), 2 = wss (WebSocket over TLS)
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
    //! Databases, index = MetricDatabaseIndex()
    const std::vector<std::string> &Databases();
    //! Index = SealedHeaderOutcome
    const std::vector<std::string> &SealedHeaderOutcomes();
    //! Index = SnapshotKind
    const std::vector<std::string> &SnapshotKinds();
    //! Index = lotus::v2::net::FastSyncSwarmState
    const std::vector<std::string> &SnapshotSyncStates();
    //! Index = AdaptiveLimit
    const std::vector<std::string> &AdaptiveLimits();
    //! Index = MisbehaviorReason
    const std::vector<std::string> &MisbehaviorReasons();
    //! Index = DiscourageOutcome
    const std::vector<std::string> &DiscourageOutcomes();
    //! Chronik HTTP endpoints, index = ChronikEndpointIndex()
    const std::vector<std::string> &ChronikEndpoints();
    //! 0 = 2xx, 1 = 4xx, 2 = 5xx, 3 = other
    const std::vector<std::string> &ChronikCodeClasses();
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

    // Storage (MDBX), by database (MetricDatabaseIndex)
    metrics::Gauge &db_size;
    metrics::EventHistogram &db_commit_seconds;

    // This tier's features
    //! By SealedHeaderOutcome
    metrics::Counter &sealed_headers;
    //! By round (0 = summary, 1 = bucket) x result (0 = matched, 1 = differ)
    metrics::Counter &merklix_rounds;
    //! By round: short ids found missing, in rounds that found some
    metrics::EventHistogram &merklix_differences;
    //! Sub-buckets with too many differences to decode (bisected)
    metrics::Counter &merklix_overflows;
    //! By SnapshotKind
    metrics::Counter &snapshot_publications;
    metrics::EventHistogram &snapshot_publish_seconds;
    //! One-hot by SnapshotSyncStates
    metrics::Gauge &snapshot_sync_state;
    metrics::Gauge &snapshot_sync_pivot_height;
    //! By status: 0 = total, 1 = verified, 2 = pending, 3 = in_flight
    metrics::Gauge &snapshot_sync_shards;
    metrics::Gauge &snapshot_sync_coins_imported;
    metrics::Gauge &snapshot_sync_blocks_peeled;
    //! By status: 0 = active, 1 = banned
    metrics::Gauge &snapshot_sync_peers;
    //! By stage: 0 = select, 1 = validity, 2 = total
    metrics::EventHistogram &block_template_seconds;
    //! By AdaptiveLimit
    metrics::Gauge &adaptive_block_size;
    metrics::Gauge &adaptive_block_size_history_complete;

    // P2P health
    //! By direction x transport: connection to verack
    metrics::EventHistogram &p2p_handshake_seconds;
    //! By transport
    metrics::EventHistogram &p2p_ping_seconds;
    //! By table: 0 = new, 1 = tried
    metrics::Gauge &addrman_addresses;
    metrics::Counter &p2p_bans;
    metrics::Gauge &p2p_banned;
    //! By DiscourageOutcome
    metrics::Counter &p2p_discouragements;
    //! By MisbehaviorReason
    metrics::Counter &p2p_misbehavior;

    // Chronik
    //! By endpoint x status class
    metrics::Counter &chronik_requests;
    //! By endpoint
    metrics::EventHistogram &chronik_request_seconds;
    metrics::Gauge &chronik_ws_connections;
    metrics::Gauge &chronik_ws_subscriptions;
    metrics::Gauge &chronik_indexed_height;
    //! Chain tip height minus chronik_indexed_height, at scrape time
    metrics::Gauge &chronik_lag;
    //! Whether Chronik reported its height (it runs)
    std::atomic<bool> chronik_indexed_height_known{false};

    /** Label index of an RPC method ("other" if not in the set) */
    size_t RPCMethodIndex(std::string_view method) const noexcept;

    /** transport: 0 = tcp, 1 = ws, 2 = wss (metric_labels::Transports) */
    size_t PeerSeries(bool inbound, size_t transport,
                      size_t network) const noexcept;
    /** Series of the direction x transport metrics */
    size_t DirectionTransportSeries(bool inbound,
                                    size_t transport) const noexcept;

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

/**
 * Label index (metric_labels::Databases) of a database from its path:
 * chainstate, block_index, txindex, blockfilterindex, coinstatsindex,
 * other.
 */
size_t MetricDatabaseIndex(const std::string &path) noexcept;

enum class SealedHeaderOutcome : size_t {
    REBUILT,
    ALREADY_HAVE,
    FALLBACK,
    INVALID,
    REJECTED,
};
enum class SnapshotKind : size_t { CHAIN_TIP, BEST_HEADER, MEMPOOL };
enum class AdaptiveLimit : size_t { MAX, TARGET, MAX_GENERATED, EMA };

inline void CountSealedHeader(SealedHeaderOutcome outcome) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->sealed_headers.Add(size_t(outcome));
    }
}

/** Start time of a snapshot publication, or the epoch without metrics */
inline std::chrono::steady_clock::time_point SnapshotPublishStart() noexcept {
    return GetNodeMetrics() ? std::chrono::steady_clock::now()
                            : std::chrono::steady_clock::time_point{};
}
/** Count a snapshot publication begun at start */
inline void RecordSnapshotPublication(
    SnapshotKind kind, std::chrono::steady_clock::time_point start) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->snapshot_publications.Add(size_t(kind));
        if (start != std::chrono::steady_clock::time_point{}) {
            m->snapshot_publish_seconds.RecordDuration(
                std::chrono::steady_clock::now() - start, size_t(kind));
        }
    }
}

enum class MisbehaviorReason : size_t {
    HANDSHAKE,
    OVERSIZED_MESSAGE,
    INVALID_HEADER,
    INVALID_BLOCK,
    INVALID_COMPACT_BLOCK,
    INVALID_TX,
    BLOOM_FILTER,
    AVALANCHE,
    AVALANCHE_PROOF,
    OTHER,
};
enum class DiscourageOutcome : size_t {
    DISCOURAGED,
    DISCONNECTED_LOCAL,
    EXEMPT_NOBAN,
    EXEMPT_MANUAL,
};

/**
 * The reason class of a Misbehaving() message, from the fixed set of
 * messages net_processing uses (OTHER for anything else).
 */
MisbehaviorReason ClassifyMisbehavior(std::string_view message) noexcept;

/**
 * Label index (metric_labels::ChronikEndpoints) of a Chronik HTTP route
 * template, as axum matched it (e.g. "/script/:type/:payload/history" is
 * "script"); "" when no route matched (not_found).
 */
size_t ChronikEndpointIndex(std::string_view route) noexcept;

/** Count a Chronik HTTP request (called by Chronik's HTTP server) */
void RecordChronikRequest(std::string_view route, uint16_t status,
                          uint64_t nanos) noexcept;

/** Chronik indexed up to height (connected), or rewound to it */
inline void SetChronikIndexedHeight(int height) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        m->chronik_indexed_height.Set(double(height));
        m->chronik_indexed_height_known.store(true, std::memory_order_relaxed);
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
