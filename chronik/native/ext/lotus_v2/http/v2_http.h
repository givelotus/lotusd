// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_V2_HTTP_H
#define CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_V2_HTTP_H

#include <chronik/native/http.h>

#include <ext/lotus_v2/query/branches.h>
#include <ext/lotus_v2/service/authority.h>

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>

/**
 * The opt-in confirmed V2 JSON API (port of chronik-http/src/v2.rs) and the
 * explorer schema 1 (v2_explorer.rs), on the native router:
 *
 *   GET  /v2/status
 *   POST /v2/branches/utxos
 *   POST /v2/branches/outputs
 *   GET  /v2/utxos/:txid/:out_idx
 *   GET  /v2/explorer/v1/{status, blocks, blocks/by-height/:height,
 *        blocks/:block_id, blocks/:block_id/transactions,
 *        transactions/by-id/:txid, transactions/by-hash/:txhash,
 *        transactions/by-id/:txid/{inputs,outputs,witnesses,wire},
 *        outputs/:txid/:out_idx, assets, assets/:token_id,
 *        assets/:token_id/{events,outputs}}
 *   POST /v2/explorer/v1/branches/{outputs,utxos}
 *
 * Responses are byte-identical to Rust's serde_json output.
 */
namespace chronik::native::lotus_v2 {
struct SharedV2Db;
class V2Service;
} // namespace chronik::native::lotus_v2

namespace chronik::native::lotus_v2::http {

/** chronik_http::v2::V2HttpState */
struct V2HttpState {
    /** Operational transition failure; cleared only by successful indexing. */
    std::shared_ptr<std::atomic<bool>> index_error;
    /** Per-service-open entropy. */
    std::array<uint8_t, 16> service_epoch{};
    /** Confirmed database; reads answer 503 if another owner holds it. */
    std::shared_ptr<SharedV2Db> db;
    /** Coherent stamped node observation; empty when unavailable. */
    std::function<AuthoritativeState()> node_anchor;
    /** Host SHA-256 (branch filter and explorer cursor digests). */
    query_branches::Sha256Fn sha256;
};

/** The state of an open service (chronik-lib v2.rs http_state). */
V2HttpState MakeV2HttpState(const V2Service &service,
                            query_branches::Sha256Fn sha256);

/**
 * Current state per request; nullopt while the service is closed, which
 * every route answers as index_unavailable.
 */
using V2HttpStateProvider = std::function<std::optional<V2HttpState>()>;

/** Register /v2 (v2.rs router) and /v2/explorer/v1 (v2_explorer.rs). */
void RegisterV2Routes(Router &router, V2HttpStateProvider provider);
void RegisterV2ExplorerRoutes(Router &router, V2HttpStateProvider provider);

} // namespace chronik::native::lotus_v2::http

#endif // CHRONIK_NATIVE_EXT_LOTUS_V2_HTTP_V2_HTTP_H
