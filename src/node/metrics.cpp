// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics.h>

#include <clientversion.h>
#include <config/bitcoin-config.h>
#include <logging.h>
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
        static const std::vector<std::string> labels{"tcp", "websocket"};
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

size_t NodeMetrics::PeerSeries(bool inbound, bool websocket,
                               size_t network) const noexcept {
    const std::array<size_t, 3> idx{
        inbound ? 0U : 1U, websocket ? 1U : 0U,
        std::min(network, L::Networks().size() - 1)};
    return peers.SeriesIndex(idx);
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
