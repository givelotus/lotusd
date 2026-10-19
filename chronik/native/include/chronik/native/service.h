// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_SERVICE_H
#define CHRONIK_NATIVE_SERVICE_H

#include <chronik/native/host.h>
#include <chronik/native/indexer.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace chronik::native {

struct HttpRequest;
struct HttpResponse;
class WsSession;
class WsHandler;

/** Port of SetupParams minus Electrum/plugins (chronik-lib bridge.rs). */
struct ServiceParams {
    IndexerParams indexer;
    /** -chronikbind values ("ip" or "ip:port"); empty => no listener. */
    std::vector<std::string> hosts;
    uint16_t default_port = 0;
    bool is_pause_allowed = false;
    std::chrono::seconds ws_ping_interval{45};
    bool enable_cors = false;
    size_t max_subs = 10'000'000;
    size_t max_subs_per_ip = 75'000;
    size_t subscription_max_script_size = 201;
    /** -chroniksubsmaxpluginsize (plugins are unsupported; only the
     * PluginGroupTooLarge check uses it) */
    size_t subscription_max_plugin_size = 100;
    /** 0 => min(8, hardware_concurrency / 2), at least 1 */
    size_t query_workers = 0;
    /** Optional immutable observers, installed before Start. They must be
     * noexcept, non-blocking and must not take host/indexer/registry locks.
     * Owned by the service and drained before the host destroys metrics. */
    std::function<void(std::string_view, uint16_t, uint64_t)> observe_request;
    std::function<void(int32_t)> observe_ws_connections;
    std::function<void(int32_t)> observe_ws_subscriptions;
    std::function<void(int32_t)> observe_indexed_height;
};

class ServiceImpl;

/**
 * Port of Node::ok_or_abort: run `func`; on exception, log it (debug) and
 * call Host::FatalError("ERROR Chronik in <func_name>", <error message>).
 * Returns false on failure.
 */
inline bool OkOrAbort(const Host &host, std::string_view func_name,
                      const std::function<void()> &func) {
    try {
        func();
        return true;
    } catch (const std::exception &e) {
        host.Log(LogLevel::Debug, std::string(e.what()) + "\n");
        host.FatalError("ERROR Chronik in " + std::string(func_name),
                        e.what());
        return false;
    }
}

/**
 * A running native Chronik: indexer + HTTP router + WebSocket hub + query
 * pool + standalone listeners. Port of chronik-lib's `Chronik` and
 * `try_setup_chronik`.
 */
class Service {
public:
    /**
     * Open the indexer, resync it, start the listeners. Returns nullptr if
     * shutdown was requested during resync. Throws ChronikError with the
     * init error message on failure.
     */
    static std::unique_ptr<Service>
    Start(const Host &host, ServiceParams params,
          std::vector<std::unique_ptr<Extension>> exts = {});
    ~Service();

    // ---- events, forwarded to the indexer (writer thread) ----
    // Each blocks while Chronik is paused (-chronikallowpause) and throws on
    // failure; host adapters wrap the call (and their own conversion) in
    // OkOrAbort with the Rust handler name, e.g. "handle_block_connected".
    void HandleTxAddedToMempool(TxRef tx, int64_t time_first_seen);
    void HandleTxRemovedFromMempool(const TxId &txid);
    void HandleBlockConnected(Block block);
    void HandleBlockDisconnected(Block block);
    void HandleBlockFinalized(const BlockInfo &info);
    void HandleBlockInvalidated(Block block);
    void HandleTxFinalized(const TxId &txid);
    void HandleTxInvalidated(TxRef tx);

    /**
     * In-process HTTP entry (host Beast server, /chronik prefix stripped).
     * Runs the request on the query pool and calls `done` from a pool
     * thread.
     */
    void HandleHttpAsync(HttpRequest req,
                         std::function<void(HttpResponse)> done);
    /**
     * In-process WebSocket upgrade check (Router::IsWebSocketUpgrade): the
     * extra 101 response headers (CORS) if `req` is a valid upgrade of a
     * WebSocket route, nullopt to answer it as an HTTP request instead.
     */
    std::optional<std::vector<std::pair<std::string, std::string>>>
    CheckWsUpgrade(const HttpRequest &req) const;
    /**
     * In-process WebSocket entry: create a handler for a new session. Must be
     * called on the executor returned by MakeSerialExecutor() for that
     * session (WsHandler calls never run on io threads).
     */
    std::unique_ptr<WsHandler> AcceptWs(std::shared_ptr<WsSession> session);
    /**
     * A serial executor on the query pool (a strand): posted tasks run one at
     * a time, in order. Used by in-process transports for WsHandler calls.
     */
    std::function<void(std::function<void()>)> MakeSerialExecutor();
    /** Idle interval before Chronik pings a WebSocket (-chronik params). */
    std::chrono::milliseconds WsPingInterval() const;

    /** Stop listeners and sessions; queries answer 503 afterwards. */
    void Interrupt();
    /** Interrupt, then close the indexer. */
    void Stop();

    ServiceImpl &Impl() { return *m_impl; }

private:
    explicit Service(std::unique_ptr<ServiceImpl> impl);
    std::unique_ptr<ServiceImpl> m_impl;
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_SERVICE_H
