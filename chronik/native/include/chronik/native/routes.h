// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_ROUTES_H
#define CHRONIK_NATIVE_ROUTES_H

#include <chronik/native/host.h>
#include <chronik/native/http.h>

#include <cstddef>
#include <memory>

/**
 * HTTP route registration of the native Chronik (chronik-http server.rs
 * make_router). The Service builds one Router and calls RegisterCoreRoutes,
 * then registers /pause, /resume and /ws itself, then the extensions'
 * routes.
 *
 * For the "query" worker: add the remaining server.rs routes (blocks, txs,
 * broadcast, script/token-id/lokad-id groups, plugin errors) by extending
 * RegisterCoreRoutes in core/indexer/routes.cpp (e.g. by calling a
 * RegisterQueryRoutes(router, ctx) of your own). Handlers run on the query
 * pool; each takes one IndexerSnapshot (see indexer_impl.h for the rules).
 */
namespace chronik::native {

class IndexerImpl;
class SubscriptionLimiter;

struct RouteContext {
    /** The indexer's read API (and its SubsHub). */
    const IndexerImpl &indexer;
    const Host &host;
    /** Shared WS/Electrum-style subscription limiter. */
    std::shared_ptr<SubscriptionLimiter> limiter;
};

/** /blockchain-info, /chronik-info (and, later, the query routes). */
void RegisterCoreRoutes(Router &router, const RouteContext &ctx);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_ROUTES_H
