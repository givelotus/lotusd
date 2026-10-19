// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TRANSPORT_BEAST_LISTENER_H
#define CHRONIK_NATIVE_TRANSPORT_BEAST_LISTENER_H

#include <chronik/native/http.h>
#include <chronik/native/ws.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace chronik::native {

class QueryPool;

struct ListenerBind {
    /** IPv4 or IPv6 literal, e.g. "127.0.0.1" or "::1" */
    std::string ip;
    uint16_t port = 0;
};

struct ListenerOptions {
    std::vector<ListenerBind> binds;
    /** Own io_context threads (design: 2) */
    size_t io_threads = 2;
    /** Idle interval before Chronik pings a WebSocket (45 s; 5 s regtest) */
    std::chrono::milliseconds ws_ping_interval{std::chrono::seconds{45}};
    /** Max WebSocket message (and frame) size */
    size_t ws_max_message_size = 20'000;
    /** Request bodies above this are flagged body_too_large (not read). */
    size_t max_body_size = MAX_REQUEST_BODY_SIZE;
    /** Max request header bytes */
    size_t max_header_size = 64 * 1024;
    /** Close idle keep-alive HTTP connections after this long. */
    std::chrono::seconds http_idle_timeout{std::chrono::seconds{120}};
};

/**
 * Standalone Boost.Beast HTTP/1.1 listener for -chronikbind (replaces axum):
 * keep-alive, multiple binds, own io_context, request handling posted to the
 * QueryPool, WebSocket upgrade on WebSocket routes of the Router handed to
 * `ws_accept`. No TLS, no compression.
 */
class BeastListener {
public:
    BeastListener(const Router &router, QueryPool &pool, WsAccept ws_accept,
                  ListenerOptions opts);
    ~BeastListener();
    BeastListener(const BeastListener &) = delete;
    BeastListener &operator=(const BeastListener &) = delete;

    /**
     * Bind all addresses and start serving. Throws ChronikError
     * "Chronik failed binding to <addr>: <os error>" (server.rs
     * FailedBindingAddress) if a bind fails.
     */
    void Start();
    /** Actual bound ports, in bind order (useful with port 0). */
    std::vector<uint16_t> BoundPorts() const;
    /** Stop accepting, close all HTTP and WebSocket sessions, join. */
    void Stop();

    /** Number of currently open WebSocket sessions. */
    size_t NumWsSessions() const;

    struct Impl;
    struct IoHolder;

private:
    // Destroyed after m_impl: destroying the io_context destroys pending
    // coroutine frames, which release their references to the Impl.
    std::unique_ptr<IoHolder> m_io;
    std::shared_ptr<Impl> m_impl;
};

/** Rust SocketAddr Display: "1.2.3.4:80" or "[::1]:80" */
std::string FormatSocketAddr(const std::string &ip, uint16_t port);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_TRANSPORT_BEAST_LISTENER_H
