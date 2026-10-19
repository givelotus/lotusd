// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/metrics.h>

#include <protocol.h>
#include <util/time.h>

#include <algorithm>
#include <array>
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
    //! Seconds; HTTP and RPC requests (long polls can take minutes)
    const std::vector<double> REQUEST_BUCKETS{
        0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
        0.25,   0.5,     1,      2.5,   5,      10,    30,   60,    300};

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

size_t MetricMsgTypeIndex(std::string_view msg_type) noexcept {
    return SortedIndex(L::MsgTypes(), msg_type);
}

NodeMetrics::NodeMetrics()
    : p2p_received_bytes{Add<Counter>(
          registry, "lotus_p2p_received_bytes_total",
          "P2P bytes received (header and payload), by message type.",
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_sent_bytes{Add<Counter>(
          registry, "lotus_p2p_sent_bytes_total",
          "P2P bytes queued for sending (header and payload), by message "
          "type.",
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_received_messages{
          Add<Counter>(registry, "lotus_p2p_received_messages_total",
                       "P2P messages received, by message type.",
                       std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_sent_messages{
          Add<Counter>(registry, "lotus_p2p_sent_messages_total",
                       "P2P messages queued for sending, by message type.",
                       std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      p2p_message_handling_seconds{Add<EventHistogram>(
          registry, "lotus_p2p_message_handling_seconds",
          "Time to process a received P2P message or coalesced batch, by initial message type. Only "
          "one dispatch turn in 16 is timed: _count is a sample, use "
          "lotus_p2p_received_messages_total for totals.",
          MESSAGE_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"type", L::MsgTypes()}})},
      peers{Add<Gauge>(registry, "lotus_peers",
                       "Connected peers, by direction, transport and network.",
                       std::vector<LabelDim>{{"direction", L::Directions()},
                                             {"transport", L::Transports()},
                                             {"network", L::Networks()}})},
      p2p_connections{Add<Counter>(
          registry, "lotus_p2p_connections_total",
          "P2P connections established, by direction and transport.",
          std::vector<LabelDim>{{"direction", L::Directions()},
                                {"transport", L::Transports()}})},
      websocket_peers{Add<Gauge>(
          registry, "lotus_p2p_websocket_peers",
          "Connected P2P WebSocket peers, by compression and TLS.",
          std::vector<LabelDim>{{"compression", L::WebSocketCompressions()},
                                {"tls", {"false", "true"}}})},
      tip_height{Add<Gauge>(registry, "lotus_chain_tip_height",
                            "Height of the active chain tip.")},
      tip_timestamp{
          Add<Gauge>(registry, "lotus_chain_tip_timestamp_seconds",
                     "Block timestamp of the active chain tip (Unix time).")},
      tip_age{Add<Gauge>(registry, "lotus_chain_tip_age_seconds",
                         "Seconds since the active chain tip's block "
                         "timestamp, at scrape time.")},
      initial_block_download{
          Add<Gauge>(registry, "lotus_initial_block_download",
                     "1 while in initial block download, else 0.")},
      block_connect_seconds{Add<EventHistogram>(
          registry, "lotus_block_connect_seconds",
          "Time to connect a block to the chain tip (ConnectBlock: "
          "validating it and updating the UTXO view).",
          BLOCK_CONNECT_BUCKETS, /*divisor=*/1e9)},
      mempool_transactions{Add<Gauge>(registry, "lotus_mempool_transactions",
                                      "Transactions in the mempool.")},
      mempool_bytes{Add<Gauge>(registry, "lotus_mempool_bytes",
                               "Total size of the mempool's transactions.")},
      http_requests{Add<Counter>(
          registry, "lotus_http_requests_total",
          "HTTP requests answered (not WebSocket sessions), by endpoint and "
          "status class.",
          std::vector<LabelDim>{{"endpoint", L::HTTPEndpoints()},
                                {"code", L::HTTPCodeClasses()}})},
      http_request_seconds{Add<EventHistogram>(
          registry, "lotus_http_request_duration_seconds",
          "Time from receiving an HTTP request's header to writing its "
          "response, by endpoint.",
          REQUEST_BUCKETS, /*divisor=*/1e9,
          std::vector<LabelDim>{{"endpoint", L::HTTPEndpoints()}})},
      http_tls_handshakes{
          Add<Counter>(registry, "lotus_http_tls_handshakes_total",
                       "TLS handshakes on the HTTP listeners, by result.",
                       std::vector<LabelDim>{{"result", {"ok", "failed"}}})} {
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

size_t NodeMetrics::PeerSeries(bool inbound, bool websocket,
                               size_t network) const noexcept {
    const std::array<size_t, 3> idx{
        inbound ? 0U : 1U, websocket ? 1U : 0U,
        std::min(network, L::Networks().size() - 1)};
    return peers.SeriesIndex(idx);
}

NodeMetrics &StartNodeMetrics() {
    NodeMetrics *m{GetNodeMetrics()};
    if (!m) {
        // Never freed: recording threads may hold the pointer.
        m = new NodeMetrics();
        detail::g_node_metrics.store(m, std::memory_order_release);
    }
    m->registry.Start();
    return *m;
}

void StopNodeMetrics() {
    if (NodeMetrics * m{GetNodeMetrics()}) {
        m->registry.Stop();
    }
}

} // namespace node
