// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_METRICS_COLLECTORS_H
#define BITCOIN_NODE_METRICS_COLLECTORS_H

namespace node {

struct NodeContext;

/**
 * Add the scrape-time collectors that read the node's subsystems
 * (Avalanche, mempool, peers, ...) into the metrics, once they exist (at
 * the end of AppInitMain). No-op without -metrics. Collectors only read
 * values kept lock-free, or take a subsystem's lock briefly once per
 * rendering (at most once a second): never cs_main.
 */
void StartNodeMetricsCollectors(NodeContext &node);
/** Remove them, before the subsystems they read are destroyed */
void StopNodeMetricsCollectors();

} // namespace node

#endif // BITCOIN_NODE_METRICS_COLLECTORS_H
