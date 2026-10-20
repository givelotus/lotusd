// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_METRICS_H
#define BITCOIN_TEST_UTIL_METRICS_H

#include <node/metrics.h>

#include <cassert>
#include <string>

/**
 * Turn the node's metrics on for a scope (as -metrics does), without the
 * drain thread or constant labels. Off again afterwards; the metrics object
 * is not freed, since threads of the test setup may still hold it (as in
 * the node, where it lives until exit).
 */
struct ScopedNodeMetrics {
    node::NodeMetrics &m;
    ScopedNodeMetrics() : m{*new node::NodeMetrics({})} {
        assert(!node::GetNodeMetrics());
        node::detail::g_node_metrics.store(&m, std::memory_order_release);
    }
    ~ScopedNodeMetrics() {
        node::detail::g_node_metrics.store(nullptr, std::memory_order_release);
    }
    ScopedNodeMetrics(const ScopedNodeMetrics &) = delete;
    ScopedNodeMetrics &operator=(const ScopedNodeMetrics &) = delete;

    /** The rendering (drains the event rings first) */
    std::string Render() { return m.registry.Render(); }
};

#endif // BITCOIN_TEST_UTIL_METRICS_H
