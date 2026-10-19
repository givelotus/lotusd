// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_METRICS_H
#define BITCOIN_NODE_METRICS_H

#include <metrics/metrics.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

//! Serve /metrics (to -rpcallowip clients, without authentication)
static constexpr bool DEFAULT_METRICS{false};
//! Repeated scrapes within this interval get the previous rendering
static constexpr std::chrono::milliseconds METRICS_MIN_SCRAPE_INTERVAL{1000};

namespace node {

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
    NodeMetrics();
    metrics::Registry registry;

    // P2P traffic, by message type (index: MetricMsgTypeIndex)
    metrics::Counter &p2p_received_bytes;
    metrics::Counter &p2p_sent_bytes;
    metrics::Counter &p2p_received_messages;
    metrics::Counter &p2p_sent_messages;

    // Peers (CNode objects), by direction x transport x network
    metrics::Gauge &peers;
    metrics::Counter &p2p_connections;
    //! WebSocket peers, by compression x tls (0 = plain, 1 = TLS)
    metrics::Gauge &websocket_peers;

    // HTTP and RPC
    metrics::Counter &http_requests;
    metrics::EventHistogram &http_request_seconds;
    metrics::Counter &http_tls_handshakes;

    size_t PeerSeries(bool inbound, bool websocket,
                      size_t network) const noexcept;
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

/** Create the metrics (once) and start the drain thread */
NodeMetrics &StartNodeMetrics();
/** Stop the drain thread (recording still works, into full rings) */
void StopNodeMetrics();

/** Label index of a P2P message type ("other" for unknown types) */
size_t MetricMsgTypeIndex(std::string_view msg_type) noexcept;

} // namespace node

#endif // BITCOIN_NODE_METRICS_H
