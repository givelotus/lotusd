// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPMETRICS_H
#define BITCOIN_HTTPMETRICS_H

/**
 * Start the node's metrics (node/metrics.h) and serve them at /metrics on
 * the RPC listeners. Call before StartHTTPServer, after the RPC commands
 * are registered.
 */
void StartHTTPMetrics();
/** Stop serving /metrics and stop the metrics' drain thread */
void StopHTTPMetrics();

#endif // BITCOIN_HTTPMETRICS_H
