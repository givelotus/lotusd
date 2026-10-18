// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHRONIK_CPP_CHRONIK_INPROCESS_H
#define BITCOIN_CHRONIK_CPP_CHRONIK_INPROCESS_H

#include <rust/cxx.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

struct InProcessHTTPResponse;
class InProcessWebSocket;

namespace chronik_bridge {

struct InProcessHeader;
struct InProcessServer;

/**
 * Completion of an in-process /chronik request (see httpserver.h). Answers
 * 503 if destroyed before complete() was called, e.g. when Chronik's runtime
 * shuts down with the request pending.
 */
class InProcessHttpDone {
public:
    explicit InProcessHttpDone(
        std::function<void(InProcessHTTPResponse)> done);
    ~InProcessHttpDone();
    InProcessHttpDone(const InProcessHttpDone &) = delete;
    InProcessHttpDone &operator=(const InProcessHttpDone &) = delete;

    void complete(uint16_t status, rust::Slice<const InProcessHeader> headers,
                  rust::Slice<const uint8_t> body) const;

private:
    mutable std::function<void(InProcessHTTPResponse)> m_done;
};

/** Sending side of an in-process /chronik/ws session; thread-safe. */
class InProcessWsSink {
public:
    explicit InProcessWsSink(std::shared_ptr<InProcessWebSocket> ws);

    void send_binary(rust::Slice<const uint8_t> msg) const;
    void close() const;

private:
    std::shared_ptr<InProcessWebSocket> m_ws;
};

} // namespace chronik_bridge

namespace chronik {

/**
 * Serve /chronik on the node's HTTP server with Chronik's endpoints (called
 * by setup_chronik).
 */
void RegisterChronikInProcess(
    rust::Box<chronik_bridge::InProcessServer> server,
    uint64_t ws_ping_interval_ms, rust::Slice<const uint8_t> ws_ping_payload,
    size_t ws_max_message_size);

/**
 * Stop serving /chronik on the node's HTTP server; closes its open WebSocket
 * sessions.
 */
void UnregisterChronikInProcess();

} // namespace chronik

#endif // BITCOIN_CHRONIK_CPP_CHRONIK_INPROCESS_H
