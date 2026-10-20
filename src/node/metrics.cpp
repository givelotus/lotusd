// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics.h>

#include <clientversion.h>
#include <config/bitcoin-config.h>
#include <logging.h>
#include <metrics/process.h>
#include <protocol.h>
#include <tinyformat.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <memory>

namespace node {

namespace detail {
    std::atomic<NodeMetrics *> g_node_metrics{nullptr};
}

namespace metric_labels {
    const std::vector<std::string> &MsgTypes() {
        static const std::vector<std::string> labels{[] {
            std::vector<std::string> v{getAllNetMessageTypes()};
            std::sort(v.begin(), v.end());
            v.push_back("other");
            return v;
        }()};
        return labels;
    }
    const std::vector<std::string> &Networks() {
        static const std::vector<std::string> labels{
            "unroutable", "ipv4",  "ipv6",     "onion",
            "i2p",        "cjdns", "internal", "wss"};
        return labels;
    }
    const std::vector<std::string> &WebSocketCompressions() {
        static const std::vector<std::string> labels{
            "none", "permessage-deflate", "zstd", "zstd-dict"};
        return labels;
    }
    const std::vector<std::string> &Directions() {
        static const std::vector<std::string> labels{"inbound", "outbound"};
        return labels;
    }
    const std::vector<std::string> &Transports() {
        static const std::vector<std::string> labels{"tcp", "ws", "wss"};
        return labels;
    }
    const std::vector<std::string> &HTTPEndpoints() {
        static const std::vector<std::string> labels{
            "rpc", "wallet", "rest", "chronik", "health", "metrics", "other"};
        return labels;
    }
    const std::vector<std::string> &AvalancheItemTypes() {
        static const std::vector<std::string> labels{
            "proof",       "block", "contender",
            "transaction", "batch", "state_anchor"};
        return labels;
    }
    const std::vector<std::string> &AvalancheItemOutcomes() {
        static const std::vector<std::string> labels{"finalized", "invalidated",
                                                     "stale"};
        return labels;
    }
    const std::vector<std::string> &AvalancheVotes() {
        static const std::vector<std::string> labels{"yes", "no", "neutral"};
        return labels;
    }
    const std::vector<std::string> &AvalancheProofPools() {
        static const std::vector<std::string> labels{"valid", "conflicting",
                                                     "immature", "dangling"};
        return labels;
    }
    const std::vector<std::string> &MempoolRejectReasons() {
        static const std::vector<std::string> labels{"consensus",
                                                     "inputs_not_standard",
                                                     "not_standard",
                                                     "missing_inputs",
                                                     "premature_spend",
                                                     "duplicate",
                                                     "conflict",
                                                     "child_before_parent",
                                                     "mempool_policy",
                                                     "no_mempool",
                                                     "package_reconsiderable",
                                                     "avalanche_reconsiderable",
                                                     "unknown"};
        return labels;
    }
    const std::vector<std::string> &MempoolRemovalReasons() {
        static const std::vector<std::string> labels{
            "expiry",   "sizelimit", "reorg", "block",
            "conflict", "avalanche", "manual"};
        return labels;
    }
    const std::vector<std::string> &TxPools() {
        static const std::vector<std::string> labels{"orphan", "conflicting"};
        return labels;
    }
    const std::vector<std::string> &BlockStages() {
        static const std::vector<std::string> labels{
            "check", "forks", "connect",    "verify",      "index",
            "load",  "flush", "chainstate", "post_connect"};
        return labels;
    }
    const std::vector<std::string> &BlockParkReasons() {
        static const std::vector<std::string> labels{
            "policy", "finalization_conflict", "deep_reorg", "requested"};
        return labels;
    }
    const std::vector<std::string> &Databases() {
        static const std::vector<std::string> labels{
            "chainstate",       "block_index",    "txindex",
            "blockfilterindex", "coinstatsindex", "other"};
        return labels;
    }
    const std::vector<std::string> &SealedHeaderOutcomes() {
        static const std::vector<std::string> labels{
            "rebuilt", "already_have", "fallback", "invalid", "rejected"};
        return labels;
    }
    const std::vector<std::string> &SnapshotKinds() {
        static const std::vector<std::string> labels{"chain_tip", "best_header",
                                                     "mempool"};
        return labels;
    }
    const std::vector<std::string> &SnapshotSyncStates() {
        static const std::vector<std::string> labels{"idle",
                                                     "fetching_roots",
                                                     "fetching_shards",
                                                     "pivot_active_peeling",
                                                     "completed",
                                                     "failed"};
        return labels;
    }
    const std::vector<std::string> &AdaptiveLimits() {
        static const std::vector<std::string> labels{"max", "target",
                                                     "max_generated", "ema"};
        return labels;
    }
    const std::vector<std::string> &MisbehaviorReasons() {
        static const std::vector<std::string> labels{"handshake",
                                                     "oversized_message",
                                                     "invalid_header",
                                                     "invalid_block",
                                                     "invalid_compact_block",
                                                     "invalid_tx",
                                                     "bloom_filter",
                                                     "avalanche",
                                                     "avalanche_proof",
                                                     "other"};
        return labels;
    }
    const std::vector<std::string> &DiscourageOutcomes() {
        static const std::vector<std::string> labels{
            "discouraged", "disconnected_local", "exempt_noban",
            "exempt_manual"};
        return labels;
    }
    const std::vector<std::string> &ChronikEndpoints() {
        // Route families of chronik-http's router (server.rs), by first
        // path segment, then not_found (no route) and other.
        static const std::vector<std::string> labels{"blockchain_info",
                                                     "block",
                                                     "block_header",
                                                     "block_txs",
                                                     "blocks",
                                                     "block_headers",
                                                     "unconfirmed_txs",
                                                     "chronik_info",
                                                     "tx",
                                                     "token",
                                                     "raw_tx",
                                                     "validate_tx",
                                                     "broadcast_tx",
                                                     "broadcast_txs",
                                                     "script_batch",
                                                     "script",
                                                     "token_id",
                                                     "lokad_id",
                                                     "plugin",
                                                     "ws",
                                                     "pause",
                                                     "resume",
                                                     "not_found",
                                                     "other"};
        return labels;
    }
    const std::vector<std::string> &ChronikCodeClasses() {
        static const std::vector<std::string> labels{"2xx", "4xx", "5xx",
                                                     "other"};
        return labels;
    }
    const std::vector<std::string> &HTTPCodeClasses() {
        static const std::vector<std::string> labels{"1xx", "2xx", "3xx",
                                                     "4xx", "5xx", "other"};
        return labels;
    }
} // namespace metric_labels

namespace {
    using metrics::Counter;
    using metrics::EventHistogram;
    using metrics::Gauge;
    using metrics::LabelDim;
    namespace L = metric_labels;

    //! Seconds; from an empty regtest block (~0.2 ms) to a large one (minutes)
    const std::vector<double> BLOCK_CONNECT_BUCKETS{
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
        0.1,    0.25,    0.5,    1,     2.5,    5,     10,   30,    60};
    //! Seconds; P2P message handling, from a ping to a large block
    const std::vector<double> MESSAGE_BUCKETS{
        0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005,
        0.001,   0.0025,   0.005,   0.01,   0.025,   0.05,
        0.1,     0.25,     0.5,     1,      2.5,     10};
    //! Seconds; Avalanche finalization, from a few poll rounds (~100 ms on
    //! a fast quorum) to stalled items (minutes)
    const std::vector<double> FINALIZATION_BUCKETS{
        0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 7.5, 10, 15, 30, 60, 120, 300, 600};
    //! Satoshis per byte (recorded per 1000 bytes); from free relay to
    //! fees far above the 1 sat/byte default floor
    const std::vector<double> FEE_RATE_BUCKETS{
        0, 0.5, 1,  1.01, 1.1, 1.25, 1.5, 2,    3,
        5, 10,  20, 50,   100, 200,  500, 1000, 10000};
    //! Seconds; block validation stages, from microseconds (an empty
    //! regtest block's checks) to minutes (a huge block's scripts)
    const std::vector<double> STAGE_BUCKETS{
        0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001,
        0.0025,  0.005,    0.01,    0.025,  0.05,    0.1,    0.25,
        0.5,     1,        2.5,     5,      10,      30,     60};
    //! Seconds; UTXO cache flushes, from an almost clean cache to gigabytes
    const std::vector<double> FLUSH_BUCKETS{0.001, 0.005, 0.01, 0.05, 0.1,
                                            0.25,  0.5,   1,    2.5,  5,
                                            10,    30,    60,   120,  300};
    //! Counts per block (transactions, workers); powers of two
    const std::vector<double> COUNT_BUCKETS{
        1,   2,    4,    8,    16,   32,    64,    128,   256,
        512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072};
    //! Seconds; database commits, from a small index write to a large
    //! UTXO flush with fsync
    const std::vector<double> DB_COMMIT_BUCKETS{
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
        0.01,    0.025,  0.05,    0.1,    0.25,  0.5,    1,
        2.5,     5,      10,      30,     120};
    //! Seconds; snapshot publications and block templates, from a small
    //! mempool's microseconds to a large one's seconds
    const std::vector<double> FAST_BUCKETS{
        0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005,
        0.001,    0.0025,  0.005,    0.01,    0.025,  0.05,    0.1,
        0.25,     0.5,     1,        2.5,     5,      10};
    //! Seconds; P2P handshakes and ping round trips, from loopback to
    //! slow links (and peers slow to answer)
    const std::vector<double> NETWORK_BUCKETS{
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
        0.1,    0.25,    0.5,    1,     2.5,    5,     10,   30,    60};
    //! Blocks
    const std::vector<double> REORG_DEPTH_BUCKETS{1, 2,  3,  4,  5,   6,
                                                  8, 10, 20, 50, 100, 1000};
    //! Seconds; HTTP and RPC requests (long polls can take minutes)
    const std::vector<double> REQUEST_BUCKETS{
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
        0.25,   0.5,     1,      2.5,   5,      10,    30,   60,    300};

    std::vector<std::string> SortedWithOther(std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
        v.push_back("other");
        return v;
    }

    /** Index of s in sorted[0, size-1), else size-1 ("other") */
    size_t SortedIndex(const std::vector<std::string> &sorted,
                       std::string_view s) noexcept {
        const auto end{sorted.end() - 1};
        const auto it{std::lower_bound(
            sorted.begin(), end, s,
            [](const std::string &a, std::string_view b) { return a < b; })};
        if (it != end && *it == s) {
            return size_t(it - sorted.begin());
        }
        return sorted.size() - 1;
    }

    template <typename T, typename... Args>
    T &Add(metrics::Registry &reg, Args &&...args) {
        return reg.Add(std::make_unique<T>(std::forward<Args>(args)...));
    }
} // namespace

size_t MetricDatabaseIndex(const std::string &path) noexcept {
    const auto has{[&](std::string_view part) {
        return path.find(part) != std::string::npos;
    }};
    if (has("indexes/txindex")) {
        return 2;
    }
    if (has("indexes/blockfilter")) {
        return 3;
    }
    if (has("indexes/coinstats")) {
        return 4;
    }
    if (path.ends_with("blocks/index") || path.ends_with("blocks/index/")) {
        return 1;
    }
    const size_t slash{path.find_last_of('/', path.size() - 2)};
    const std::string_view last{std::string_view{path}.substr(
        slash == std::string::npos ? 0 : slash + 1)};
    if (last.starts_with("chainstate")) {
        return 0;
    }
    return 5;
}

size_t ChronikEndpointIndex(std::string_view route) noexcept {
    const auto &labels{L::ChronikEndpoints()};
    const auto index_of{[&](std::string_view name) {
        for (size_t i = 0; i < labels.size(); ++i) {
            if (labels[i] == name) {
                return i;
            }
        }
        return labels.size() - 1;
    }};
    if (route.empty()) {
        return index_of("not_found");
    }
    if (route.starts_with("/script/batch/")) {
        return index_of("script_batch");
    }
    // First path segment, with '-' as '_'
    std::string segment;
    for (size_t i = route.starts_with('/') ? 1 : 0;
         i < route.size() && route[i] != '/'; ++i) {
        segment += route[i] == '-' ? '_' : route[i];
    }
    const size_t i{index_of(segment)};
    // The two catch-alls are not route families
    return labels[i] == "not_found" ? labels.size() - 1 : i;
}

void RecordChronikRequest(std::string_view route, uint16_t status,
                          uint64_t nanos) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        const size_t endpoint{ChronikEndpointIndex(route)};
        const size_t code{status >= 200 && status < 300   ? 0U
                          : status >= 400 && status < 500 ? 1U
                          : status >= 500 && status < 600 ? 2U
                                                          : 3U};
        const std::array<size_t, 2> idx{endpoint, code};
        m->chronik_requests.Add(m->chronik_requests.SeriesIndex(idx));
        m->chronik_request_seconds.Record(nanos, endpoint);
    }
}

void RecordTxPoolRemovals(std::string_view pool_kind, unsigned expired,
                          unsigned evicted) noexcept {
    if (auto *m{GetNodeMetrics()}) {
        const size_t pool{pool_kind == "orphan" ? 0U : 1U};
        if (expired) {
            const std::array<size_t, 2> idx{pool, 0};
            m->tx_pool_removed.Add(m->tx_pool_removed.SeriesIndex(idx),
                                   expired);
        }
        if (evicted) {
            const std::array<size_t, 2> idx{pool, 1};
            m->tx_pool_removed.Add(m->tx_pool_removed.SeriesIndex(idx),
                                   evicted);
        }
    }
}

size_t MetricMsgTypeIndex(std::string_view msg_type) noexcept {
    return SortedIndex(L::MsgTypes(), msg_type);
}

std::string MetricName(std::string_view name) {
    std::string out{METRICS_NAMESPACE};
    out += name;
    return out;
}

std::string MetricsClientLabel() {
    return FULLNODE_CLIENT;
}

std::string MetricsNetworkLabel(ChainType chain) {
    const std::string out{FULLNODE_CHAIN};
    switch (chain) {
        case ChainType::MAIN:
            return out + "-mainnet";
        case ChainType::TESTNET:
            return out + "-testnet";
        case ChainType::REGTEST:
            return out + "-regtest";
    }
    assert(false);
}

util::Result<std::vector<std::pair<std::string, std::string>>>
ParseMetricsLabels(const std::vector<std::string> &options) {
    std::vector<std::pair<std::string, std::string>> labels;
    if (options.size() > METRICS_LABELS_MAX) {
        return util::Error{
            strprintf(_("At most %u -metricslabel options are allowed"),
                      METRICS_LABELS_MAX)};
    }
    for (const std::string &option : options) {
        const size_t eq{option.find('=')};
        if (eq == std::string::npos) {
            return util::Error{strprintf(
                _("-metricslabel=%s: expected <name>=<value>"), option)};
        }
        std::string name{option.substr(0, eq)};
        std::string value{option.substr(eq + 1)};
        if (!metrics::IsValidLabelName(name) || name == "le" ||
            name == "quantile") {
            return util::Error{strprintf(
                _("-metricslabel=%s: \"%s\" is not a valid label name "
                  "([a-zA-Z_][a-zA-Z0-9_]*, not le, quantile or __*)"),
                option, name)};
        }
        if (std::find(METRICS_RESERVED_LABELS.begin(),
                      METRICS_RESERVED_LABELS.end(),
                      name) != METRICS_RESERVED_LABELS.end()) {
            return util::Error{strprintf(
                _("-metricslabel=%s: the label \"%s\" is set by the node"),
                option, name)};
        }
        if (value.empty() || value.size() > METRICS_LABEL_VALUE_MAX ||
            std::any_of(value.begin(), value.end(), [](char c) {
                return (unsigned char)c < 0x20 || c == 0x7f;
            })) {
            return util::Error{strprintf(
                _("-metricslabel=%s: the value must be 1 to %u bytes without "
                  "control characters"),
                option, METRICS_LABEL_VALUE_MAX)};
        }
        for (const auto &label : labels) {
            if (label.first == name) {
                return util::Error{strprintf(
                    _("-metricslabel: the label \"%s\" is given twice"), name)};
            }
        }
        labels.emplace_back(std::move(name), std::move(value));
    }
    return labels;
}

NodeMetrics::NodeMetrics(std::vector<std::string> rpc_methods)
    : registry{MetricName("")},
      p2p_received_bytes{Add<Counter>(
          registry, MetricName("p2p_received_bytes_total"),
          "P2P bytes received (header and payload), by message type.",
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_sent_bytes{Add<Counter>(
          registry, MetricName("p2p_sent_bytes_total"),
          "P2P bytes queued for sending (header and payload), by message "
          "type.",
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_received_messages{
          Add<Counter>(registry, MetricName("p2p_received_messages_total"),
                       "P2P messages received, by message type.",
                       std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_sent_messages{
          Add<Counter>(registry, MetricName("p2p_sent_messages_total"),
                       "P2P messages queued for sending, by message type.",
                       std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_message_handling_seconds{Add<EventHistogram>(
          registry, MetricName("p2p_message_handling_seconds"),
          "Time to process a received P2P message or coalesced batch, by "
          "initial message type. Only "
          "one dispatch turn in 16 is timed: _count is a sample, use "
          "fullnode_p2p_received_messages_total for totals.",
          MESSAGE_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      peers{Add<Gauge>(registry, MetricName("peers"),
                       "Connected peers, by direction, transport and network.",
                       std::vector<LabelDim>{{"direction", L::Directions()},
                                             {"transport", L::Transports()},
                                             {"peer_network", L::Networks()}})},
      p2p_connections{Add<Counter>(
          registry, MetricName("p2p_connections_total"),
          "P2P connections established, by direction and transport.",
          std::vector<LabelDim>{{"direction", L::Directions()},
                                {"transport", L::Transports()}})},
      websocket_peers{Add<Gauge>(
          registry, MetricName("p2p_websocket_peers"),
          "Connected P2P WebSocket peers, by compression and TLS.",
          std::vector<LabelDim>{{"compression", L::WebSocketCompressions()},
                                {"tls", {"false", "true"}}})},
      websocket_independent_frames{Add<Counter>(
          registry, MetricName("p2p_websocket_independent_frames_total"),
          "Independent (compress-once) WebSocket frames, by direction.",
          std::vector<LabelDim>{{"direction", {"sent", "received"}}})},
      p2p_compress_once_cache_hits{Add<Counter>(
          registry, MetricName("p2p_compress_once_cache_hits_total"),
          "Block messages served from the compress-once frame cache "
          "(including waits for a compression in progress).")},
      p2p_compress_once_cache_misses{Add<Counter>(
          registry, MetricName("p2p_compress_once_cache_misses_total"),
          "Block messages that had to be compressed for the compress-once "
          "frame cache.")},
      p2p_compress_once_cache_evictions{Add<Counter>(
          registry, MetricName("p2p_compress_once_cache_evictions_total"),
          "Frames evicted from the compress-once frame cache.")},
      p2p_compress_once_cache_bytes{Add<Gauge>(
          registry, MetricName("p2p_compress_once_cache_bytes"),
          "Allocated bytes of the frames in the compress-once frame cache.")},
      p2p_compress_once_cache_entries{
          Add<Gauge>(registry, MetricName("p2p_compress_once_cache_entries"),
                     "Frames in the compress-once frame cache.")},
      p2p_compress_once_encodes{Add<Counter>(
          registry, MetricName("p2p_compress_once_encodes_total"),
          "Independent frames compressed (each cached block once).")},
      tip_height{Add<Gauge>(registry, MetricName("chain_tip_height"),
                            "Height of the active chain tip.")},
      tip_timestamp{
          Add<Gauge>(registry, MetricName("chain_tip_timestamp_seconds"),
                     "Block timestamp of the active chain tip (Unix time).")},
      tip_age{Add<Gauge>(registry, MetricName("chain_tip_age_seconds"),
                         "Seconds since the active chain tip's block "
                         "timestamp, at scrape time.")},
      initial_block_download{
          Add<Gauge>(registry, MetricName("initial_block_download"),
                     "1 while in initial block download, else 0.")},
      block_connect_seconds{Add<EventHistogram>(
          registry, MetricName("block_connect_seconds"),
          "Time to connect a block to the chain tip (ConnectBlock: "
          "validating it and updating the UTXO view).",
          BLOCK_CONNECT_BUCKETS, /*divisor=*/1e9)},
      mempool_transactions{Add<Gauge>(registry,
                                      MetricName("mempool_transactions"),
                                      "Transactions in the mempool.")},
      mempool_bytes{Add<Gauge>(registry, MetricName("mempool_bytes"),
                               "Total size of the mempool's transactions.")},
      http_requests{Add<Counter>(
          registry, MetricName("http_requests_total"),
          "HTTP requests answered (not WebSocket sessions), by endpoint and "
          "status class.",
          std::vector<LabelDim>{{"endpoint", L::HTTPEndpoints()},
                                {"code", L::HTTPCodeClasses()}})},
      http_request_seconds{Add<EventHistogram>(
          registry, MetricName("http_request_duration_seconds"),
          "Time from receiving an HTTP request's header to writing its "
          "response, by endpoint.",
          REQUEST_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"endpoint", L::HTTPEndpoints()}})},
      http_tls_handshakes{
          Add<Counter>(registry, MetricName("http_tls_handshakes_total"),
                       "TLS handshakes on the HTTP listeners, by result.",
                       std::vector<LabelDim>{{"result", {"ok", "failed"}}})},
      rpc_request_seconds{
          Add<EventHistogram>(
              registry, MetricName("rpc_request_duration_seconds"),
              "Time to execute an RPC command, by method (methods appear "
              "once called).",
              REQUEST_BUCKETS, /*divisor=*/1e9,
              std::vector<LabelDim>{{"method", SortedWithOther(rpc_methods)}})
              .HideEmptySeries()},
      process_start_time{Add<Gauge>(registry, "process_start_time_seconds",
                                    "Start time of the process (Unix time).")},
      build_info{Add<Gauge>(
          registry, MetricName("build_info"),
          "Always 1, labelled with the build's version and commit (empty if "
          "unknown).",
          std::vector<LabelDim>{{"version", {FormatVersion(CLIENT_VERSION)}},
                                {"commit", {FormatBuildCommit()}}})},
      avalanche_quorum_established{Add<Gauge>(
          registry, MetricName("avalanche_quorum_established"),
          "1 once the Avalanche quorum is established (latched, as long as "
          "at least 8 nodes are connected), else 0.")},
      avalanche_quorum_nodes{
          Add<Gauge>(registry, MetricName("avalanche_quorum_nodes"),
                     "Avalanche nodes (connected peers with a proof) counted "
                     "for the quorum.")},
      avalanche_quorum_score{Add<Gauge>(
          registry, MetricName("avalanche_quorum_score"),
          "Stake score of the Avalanche peers known (total) and of those "
          "with a connected node (connected).",
          std::vector<LabelDim>{{"scope", {"total", "connected"}}})},
      avalanche_proofs{Add<Gauge>(
          registry, MetricName("avalanche_proofs"),
          "Avalanche proofs in the proof pools, by pool.",
          std::vector<LabelDim>{{"pool", L::AvalancheProofPools()}})},
      avalanche_polls_sent{
          Add<Counter>(registry, MetricName("avalanche_polls_sent_total"),
                       "Avalanche polls sent to peers.")},
      avalanche_poll_items_sent{
          Add<Counter>(registry, MetricName("avalanche_poll_items_sent_total"),
                       "Items asked for in the Avalanche polls sent.")},
      avalanche_polls_received{Add<Counter>(
          registry, MetricName("avalanche_polls_received_total"),
          "Avalanche polls received from peers: answered, or ignored because "
          "the peer's cooldown had not elapsed.",
          std::vector<LabelDim>{{"outcome", {"answered", "ignored"}}})},
      avalanche_votes_received{Add<Counter>(
          registry, MetricName("avalanche_votes_received_total"),
          "Votes in the responses to our Avalanche polls, by vote: yes, no "
          "(e.g. invalid, parked) or neutral (e.g. unknown, missing).",
          std::vector<LabelDim>{{"vote", L::AvalancheVotes()}})},
      avalanche_items{Add<Counter>(
          registry, MetricName("avalanche_items_total"),
          "Items whose Avalanche vote ended, by item type and outcome "
          "(finalized, invalidated, or dropped as stale).",
          std::vector<LabelDim>{{"type", L::AvalancheItemTypes()},
                                {"outcome", L::AvalancheItemOutcomes()}})},
      avalanche_finalization_seconds{Add<EventHistogram>(
          registry, MetricName("avalanche_finalization_seconds"),
          "Time from an item's registration for polling to its finalization, "
          "by item type.",
          FINALIZATION_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"type", L::AvalancheItemTypes()}})},
      mempool_accepted{Add<Counter>(
          registry, MetricName("mempool_accepted_total"),
          "Transactions accepted to the mempool (from peers, RPC, reorgs "
          "and the mempool file; test acceptances excluded).")},
      mempool_rejected{Add<Counter>(
          registry, MetricName("mempool_rejected_total"),
          "Transactions refused by the mempool, by validation result "
          "(test acceptances excluded).",
          std::vector<LabelDim>{{"reason", L::MempoolRejectReasons()}})},
      mempool_accepted_fee_rate{Add<EventHistogram>(
          registry, MetricName("mempool_accepted_fee_rate_sats_per_byte"),
          "Fee rate of accepted transactions: base fee over virtual size "
          "(size adjusted for sigchecks), without fee deltas.",
          FEE_RATE_BUCKETS, /*divisor=*/1000)},
      mempool_removed{Add<Counter>(
          registry, MetricName("mempool_removed_total"),
          "Transactions removed from the mempool, by reason (expiry and "
          "sizelimit are evictions).",
          std::vector<LabelDim>{{"reason", L::MempoolRemovalReasons()}})},
      mempool_min_fee_rate{Add<Gauge>(
          registry, MetricName("mempool_min_fee_rate_sats_per_byte"),
          "Minimum fee rate: rolling (raised when the mempool is full, as "
          "getmempoolinfo's mempoolminfee) and effective (the admission "
          "floor: the highest of the minimum relay fee, the rolling minimum "
          "and the fee hysteresis rate).",
          std::vector<LabelDim>{{"kind", {"rolling", "effective"}}})},
      tx_pool_transactions{Add<Gauge>(
          registry, MetricName("tx_pool_transactions"),
          "Transactions held outside the mempool: orphans (missing inputs) "
          "and conflicting (awaiting an Avalanche vote).",
          std::vector<LabelDim>{{"pool", L::TxPools()}})},
      tx_pool_removed{Add<Counter>(
          registry, MetricName("tx_pool_removed_total"),
          "Transactions dropped from the orphan and conflicting pools when "
          "they expired, or evicted at random when the pool was full.",
          std::vector<LabelDim>{{"pool", L::TxPools()},
                                {"reason", {"expired", "evicted"}}})},
      block_stage_seconds{Add<EventHistogram>(
          registry, MetricName("block_validation_stage_seconds"),
          "Time spent connecting a block, by stage. ConnectBlock: check "
          "(sanity checks), forks (deployment and policy checks), connect "
          "(spending inputs), verify (script and signature checks), index "
          "(undo data and index); ConnectTip: load (reading the block), flush "
          "(into the UTXO cache), chainstate (writing it if needed), "
          "post_connect (mempool update, new tip). Blocks that fail are not "
          "counted.",
          STAGE_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"stage", L::BlockStages()}})},
      script_check_transactions{Add<EventHistogram>(
          registry, MetricName("script_check_transactions"),
          "Transactions whose scripts a block had to check (those not in the "
          "script cache): the parallel script check queue's depth, per "
          "block.",
          COUNT_BUCKETS, /*divisor=*/1)},
      script_check_workers{Add<EventHistogram>(
          registry, MetricName("script_check_workers"),
          "Script check workers used per block (its parallelism: one per "
          "transaction up to the hardware threads).",
          COUNT_BUCKETS, /*divisor=*/1)},
      validation_cache_lookups{Add<Counter>(
          registry, MetricName("validation_cache_lookups_total"),
          "Lookups in the signature cache and the script execution cache, "
          "by result.",
          std::vector<LabelDim>{{"cache", {"signature", "script_execution"}},
                                {"result", {"hit", "miss"}}})},
      utxo_cache_bytes{
          Add<Gauge>(registry, MetricName("utxo_cache_bytes"),
                     "Memory used by the chainstate's UTXO cache, as of its "
                     "last flush check (each block, and periodically).")},
      utxo_cache_entries{
          Add<Gauge>(registry, MetricName("utxo_cache_entries"),
                     "Coins in the chainstate's UTXO cache, as of its last "
                     "flush check.")},
      utxo_cache_lookups{Add<Counter>(
          registry, MetricName("utxo_cache_lookups_total"),
          "Coin lookups in the chainstate's UTXO cache: hit, miss (read from "
          "the database) or absent (in neither).",
          std::vector<LabelDim>{{"result", {"hit", "miss", "absent"}}})},
      utxo_flush_seconds{Add<EventHistogram>(
          registry, MetricName("utxo_cache_flush_seconds"),
          "Time to write the UTXO cache to the database, by mode: flush "
          "(emptying the cache) or sync (keeping it). _count is the number "
          "of flushes.",
          FLUSH_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"mode", {"flush", "sync"}}})},
      chain_reorgs{Add<Counter>(registry, MetricName("chain_reorgs_total"),
                                "Chain reorganizations: tip changes that "
                                "disconnected blocks.")},
      chain_reorg_depth{Add<EventHistogram>(
          registry, MetricName("chain_reorg_depth_blocks"),
          "Blocks disconnected by each chain reorganization.",
          REORG_DEPTH_BUCKETS, /*divisor=*/1)},
      blocks_invalid{Add<Counter>(
          registry, MetricName("blocks_invalid_total"),
          "Blocks marked invalid: by validation, or by invalidateblock.",
          std::vector<LabelDim>{
              {"source", {"validation", "invalidateblock"}}})},
      blocks_parked{Add<Counter>(
          registry, MetricName("blocks_parked_total"),
          "Blocks parked, by reason: policy (a block policy failed), "
          "finalization_conflict (forks below the Avalanche-finalized tip), "
          "deep_reorg (-parkdeepreorg), requested (parkblock, or an "
          "Avalanche rejection).",
          std::vector<LabelDim>{{"reason", L::BlockParkReasons()}})},
      db_size{Add<Gauge>(
          registry, MetricName("db_size_bytes"),
          "Size of each MDBX database (its data file's current geometry), "
          "as of its last commit.",
          std::vector<LabelDim>{{"db", L::Databases()}})},
      db_commit_seconds{Add<EventHistogram>(
          registry, MetricName("db_commit_seconds"),
          "Time to write and commit a batch to an MDBX database (and sync "
          "it when asked), by database. _count is the number of commits.",
          DB_COMMIT_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"db", L::Databases()}})},
      sealed_headers{Add<Counter>(
          registry, MetricName("sealed_headers_total"),
          "Sealed headers received, by outcome: rebuilt (the block was "
          "rebuilt from the mempool overlay), already_have (its data was "
          "here), fallback (the compact block was requested instead), "
          "invalid (malformed), rejected (header or coinbase refused).",
          std::vector<LabelDim>{{"outcome", L::SealedHeaderOutcomes()}})},
      merklix_rounds{Add<Counter>(
          registry, MetricName("merklix_rounds_total"),
          "Merklix set reconciliation rounds received from peers: summary "
          "(merklixsync) and bucket (merklixbuck) rounds, by whether they "
          "matched our set or found differences.",
          std::vector<LabelDim>{{"round", {"summary", "bucket"}},
                                {"result", {"matched", "differences"}}})},
      merklix_differences{Add<EventHistogram>(
          registry, MetricName("merklix_difference_size"),
          "Short ids found missing locally per reconciliation round that "
          "decoded some (then requested with getshorttx), by round.",
          COUNT_BUCKETS, /*divisor=*/1,
          std::vector<LabelDim>{{"round", {"summary", "bucket"}}})},
      merklix_overflows{Add<Counter>(
          registry, MetricName("merklix_overflows_total"),
          "Merklix sub-buckets with more differences than their sketch "
          "decodes (bisected into deeper buckets, or left unresolved at "
          "the deepest level).")},
      snapshot_publications{Add<Counter>(
          registry, MetricName("snapshot_publications_total"),
          "Chain and mempool snapshots published for lock-free RPC reads, by "
          "trigger: chain_tip, best_header, mempool.",
          std::vector<LabelDim>{{"kind", L::SnapshotKinds()}})},
      snapshot_publish_seconds{Add<EventHistogram>(
          registry, MetricName("snapshot_publish_seconds"),
          "Time to build and publish a snapshot, by trigger.", FAST_BUCKETS,
          /*divisor=*/1e9,
          std::vector<LabelDim>{{"kind", L::SnapshotKinds()}})},
      snapshot_sync_state{Add<Gauge>(
          registry, MetricName("snapshot_sync_state"),
          "UTXO snapshot (fast) sync swarm state: 1 for the current state.",
          std::vector<LabelDim>{{"state", L::SnapshotSyncStates()}})},
      snapshot_sync_pivot_height{
          Add<Gauge>(registry, MetricName("snapshot_sync_pivot_height"),
                     "Height of the fast sync pivot block (0 if none).")},
      snapshot_sync_shards{Add<Gauge>(
          registry, MetricName("snapshot_sync_shards"),
          "Fast sync UTXO shards: total (non-empty), verified, pending, "
          "in_flight.",
          std::vector<LabelDim>{
              {"status", {"total", "verified", "pending", "in_flight"}}})},
      snapshot_sync_coins_imported{
          Add<Gauge>(registry, MetricName("snapshot_sync_coins_imported"),
                     "Coins imported by the current fast sync session.")},
      snapshot_sync_blocks_peeled{
          Add<Gauge>(registry, MetricName("snapshot_sync_blocks_peeled"),
                     "Blocks peeled back from the pivot by the current fast "
                     "sync session.")},
      snapshot_sync_peers{
          Add<Gauge>(registry, MetricName("snapshot_sync_peers"),
                     "Fast sync swarm peers: active, banned.",
                     std::vector<LabelDim>{{"status", {"active", "banned"}}})},
      block_template_seconds{Add<EventHistogram>(
          registry, MetricName("block_template_build_seconds"),
          "Time to build a block template (CreateNewBlock): select "
          "(choosing transactions), validity (TestBlockValidity), total.",
          FAST_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"stage", {"select", "validity", "total"}}})},
      adaptive_block_size{Add<Gauge>(
          registry, MetricName("adaptive_block_size_bytes"),
          "Adaptive block capacity: max (the consensus limit it allows), "
          "target, max_generated (the mining limit with -adaptiveblocksize), "
          "ema (moving average of block sizes).",
          std::vector<LabelDim>{{"limit", L::AdaptiveLimits()}})},
      adaptive_block_size_history_complete{Add<Gauge>(
          registry, MetricName("adaptive_block_size_history_complete"),
          "1 once the adaptive block capacity has a complete history of "
          "blocks, else 0.")},
      p2p_handshake_seconds{Add<EventHistogram>(
          registry, MetricName("p2p_handshake_seconds"),
          "Time from a P2P connection's creation to its verack (version "
          "handshake), by direction and transport. For outbound WebSocket "
          "peers the TCP, TLS and upgrade precede the connection's creation "
          "and are not included.",
          NETWORK_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"direction", L::Directions()},
                                {"transport", L::Transports()}})},
      p2p_ping_seconds{Add<EventHistogram>(
          registry, MetricName("p2p_ping_seconds"),
          "Round trip of P2P pings (ping to matching pong), by transport.",
          NETWORK_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"transport", L::Transports()}})},
      addrman_addresses{
          Add<Gauge>(registry, MetricName("addrman_addresses"),
                     "Addresses in the address manager's new and tried tables.",
                     std::vector<LabelDim>{{"table", {"new", "tried"}}})},
      p2p_bans{Add<Counter>(registry, MetricName("p2p_bans_total"),
                            "Subnets banned (setban, or a ban by the node).")},
      p2p_banned{Add<Gauge>(registry, MetricName("p2p_banned_subnets"),
                            "Subnets currently on the ban list.")},
      p2p_discouragements{Add<Counter>(
          registry, MetricName("p2p_discouragements_total"),
          "Peers punished for misbehaving: discouraged (disconnected, and "
          "their address discouraged), disconnected_local (local or onion "
          "peers, not discouraged), or exempt (noban permission, manual "
          "connection).",
          std::vector<LabelDim>{{"outcome", L::DiscourageOutcomes()}})},
      p2p_misbehavior{Add<Counter>(
          registry, MetricName("p2p_misbehavior_total"),
          "Peer misbehavior events, by reason class.",
          std::vector<LabelDim>{{"reason", L::MisbehaviorReasons()}})},
      chronik_requests{Add<Counter>(
          registry, MetricName("chronik_requests_total"),
          "Requests to Chronik's HTTP server, by endpoint (route family) "
          "and status class.",
          std::vector<LabelDim>{{"endpoint", L::ChronikEndpoints()},
                                {"code", L::ChronikCodeClasses()}})},
      chronik_request_seconds{Add<EventHistogram>(
          registry, MetricName("chronik_request_duration_seconds"),
          "Time for Chronik's HTTP server to answer a request, by endpoint.",
          REQUEST_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"endpoint", L::ChronikEndpoints()}})},
      chronik_ws_connections{Add<Gauge>(registry,
                                        MetricName("chronik_ws_connections"),
                                        "Open Chronik WebSocket connections.")},
      chronik_ws_subscriptions{Add<Gauge>(
          registry, MetricName("chronik_ws_subscriptions"),
          "Active Chronik WebSocket subscriptions (scripts, token ids, "
          "blocks, ...), over all connections.")},
      chronik_indexed_height{
          Add<Gauge>(registry, MetricName("chronik_indexed_height"),
                     "Height of the last block Chronik indexed (absent without "
                     "Chronik: 0).")},
      chronik_lag{Add<Gauge>(
          registry, MetricName("chronik_lag_blocks"),
          "Blocks Chronik's index is behind the chain tip, at scrape time "
          "(0 without Chronik).")},
      rpc_work_queue_depth{
          Add<Gauge>(registry, MetricName("rpc_work_queue_depth"),
                     "HTTP requests (RPC, REST, ...) queued for a worker.")},
      rpc_work_queue_capacity{
          Add<Gauge>(registry, MetricName("rpc_work_queue_capacity"),
                     "Requests the work queue holds before refusing more "
                     "(-rpcworkqueue).")},
      rpc_work_in_flight{Add<Gauge>(registry, MetricName("rpc_work_in_flight"),
                                    "HTTP requests queued or being handled.")},
      rpc_work_suspended{Add<Gauge>(
          registry, MetricName("rpc_work_suspended"),
          "HTTP requests suspended without a worker (long polls such as "
          "waitforblockheight).")},
      rpc_work_queue_rejected{Add<Counter>(
          registry, MetricName("rpc_work_queue_rejected_total"),
          "HTTP requests refused (503) because the work queue was full.")},
      process_resident_memory{Add<Gauge>(registry,
                                         "process_resident_memory_bytes",
                                         "Resident memory size in bytes.")},
      process_virtual_memory{Add<Gauge>(registry,
                                        "process_virtual_memory_bytes",
                                        "Virtual memory size in bytes.")},
      process_open_fds{Add<Gauge>(registry, "process_open_fds",
                                  "Number of open file descriptors.")},
      process_max_fds{
          Add<Gauge>(registry, "process_max_fds",
                     "Maximum number of open file descriptors (soft limit).")},
      m_rpc_methods{SortedWithOther(std::move(rpc_methods))} {
    build_info.Set(1);
    registry.Add(std::make_unique<metrics::FunctionCounter>(
        MetricName("log_dropped_lines_total"),
        "Debug and info log lines dropped because the logging thread could "
        "not keep up (the log says so too).",
        [] { return LogInstance().DroppedLines(); }));
    registry.Add(std::make_unique<metrics::FunctionCounter>(
        MetricName("log_journal_failures_total"),
        "Journal sends that failed and fell back to stderr.",
        [] { return LogInstance().JournalFailures(); }));
    initial_block_download.Set(1);
    registry.AddCollector([this] {
        const auto process{metrics::ReadProcessStats()};
        const auto set{[](Gauge &g, const std::optional<uint64_t> &v) {
            if (v) {
                g.Set(double(*v));
            }
        }};
        set(process_resident_memory, process.resident_bytes);
        set(process_virtual_memory, process.virtual_bytes);
        set(process_open_fds, process.open_fds);
        set(process_max_fds, process.max_fds);
    });
    registry.AddCollector([this] {
        if (chronik_indexed_height_known.load(std::memory_order_relaxed)) {
            chronik_lag.Set(std::max(0.0, tip_height.Value() -
                                              chronik_indexed_height.Value()));
        }
        const double tip{tip_timestamp.Value()};
        if (tip > 0) {
            tip_age.Set(double(TicksSinceEpoch<std::chrono::seconds>(
                            NodeClock::now())) -
                        tip);
        }
    });
}

size_t NodeMetrics::RPCMethodIndex(std::string_view method) const noexcept {
    return SortedIndex(m_rpc_methods, method);
}

size_t NodeMetrics::PeerSeries(bool inbound, size_t transport,
                               size_t network) const noexcept {
    const std::array<size_t, 3> idx{
        inbound ? 0U : 1U, std::min(transport, L::Transports().size() - 1),
        std::min(network, L::Networks().size() - 1)};
    return peers.SeriesIndex(idx);
}

size_t NodeMetrics::DirectionTransportSeries(bool inbound,
                                             size_t transport) const noexcept {
    const std::array<size_t, 2> idx{
        inbound ? 0U : 1U, std::min(transport, L::Transports().size() - 1)};
    return p2p_connections.SeriesIndex(idx);
}

MisbehaviorReason ClassifyMisbehavior(std::string_view message) noexcept {
    using R = MisbehaviorReason;
    const auto has{[&](std::string_view s) {
        return message.find(s) != std::string_view::npos;
    }};
    if (has("handshake") || has("version message")) {
        return R::HANDSHAKE;
    }
    if (has("message size =")) {
        return R::OVERSIZED_MESSAGE;
    }
    if (has("header")) {
        return R::INVALID_HEADER;
    }
    if (has("cmpctblock") || has("compact block") || has("getblocktxn")) {
        return R::INVALID_COMPACT_BLOCK;
    }
    if (has("block")) {
        return R::INVALID_BLOCK;
    }
    if (has("TX message")) {
        return R::INVALID_TX;
    }
    if (has("bloom filter") || has("filteradd")) {
        return R::BLOOM_FILTER;
    }
    if (has("avaproof")) {
        return R::AVALANCHE_PROOF;
    }
    if (has("ava") || has("delegation")) {
        return R::AVALANCHE;
    }
    return R::OTHER;
}

util::Result<NodeMetrics *> StartNodeMetrics(
    std::vector<std::string> rpc_methods, ChainType chain,
    const std::vector<std::pair<std::string, std::string>> &operator_labels) {
    NodeMetrics *m{GetNodeMetrics()};
    if (!m) {
        // Never freed: recording threads may hold the pointer.
        m = new NodeMetrics(std::move(rpc_methods));
        detail::g_node_metrics.store(m, std::memory_order_release);
    }
    std::vector<std::pair<std::string, std::string>> labels{
        {"client", MetricsClientLabel()},
        {"network", MetricsNetworkLabel(chain)}};
    labels.insert(labels.end(), operator_labels.begin(), operator_labels.end());
    if (auto error{m->registry.SetConstLabels(std::move(labels))}) {
        return util::Error{
            Untranslated(strprintf("-metricslabel: %s", *error))};
    }
    m->registry.Start();
    metrics::SetThreadRegistry(&m->registry);
    return m;
}

void StopNodeMetrics() {
    if (NodeMetrics * m{GetNodeMetrics()}) {
        metrics::SetThreadRegistry(nullptr);
        m->registry.Stop();
    }
}

} // namespace node
