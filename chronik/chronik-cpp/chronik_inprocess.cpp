// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik-cpp/chronik_inprocess.h>

#include <httpserver.h>

#include <chronik_lib/src/ffi.rs.h>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace chronik_bridge {

InProcessHttpDone::InProcessHttpDone(
    std::function<void(InProcessHTTPResponse)> done)
    : m_done(std::move(done)) {}

InProcessHttpDone::~InProcessHttpDone() {
    if (m_done) {
        InProcessHTTPResponse resp;
        resp.status = 503;
        resp.headers.emplace_back("content-type", "text/plain");
        resp.body = "Chronik is shutting down";
        m_done(std::move(resp));
    }
}

void InProcessHttpDone::complete(uint16_t status,
                                 rust::Slice<const InProcessHeader> headers,
                                 rust::Slice<const uint8_t> body) const {
    auto done = std::move(m_done);
    m_done = nullptr;
    if (!done) {
        return;
    }
    InProcessHTTPResponse resp;
    resp.status = status;
    for (const auto &header : headers) {
        resp.headers.emplace_back(std::string(header.name),
                                  std::string(header.value));
    }
    resp.body.assign(reinterpret_cast<const char *>(body.data()), body.size());
    done(std::move(resp));
}

InProcessWsSink::InProcessWsSink(std::shared_ptr<InProcessWebSocket> ws)
    : m_ws(std::move(ws)) {}

void InProcessWsSink::send_binary(rust::Slice<const uint8_t> msg) const {
    m_ws->SendBinary(
        std::string(reinterpret_cast<const char *>(msg.data()), msg.size()));
}

void InProcessWsSink::close() const {
    m_ws->Close();
}

} // namespace chronik_bridge

namespace chronik {

namespace {

using Server = rust::Box<chronik_bridge::InProcessServer>;
using Headers = std::vector<std::pair<std::string, std::string>>;

rust::Vec<chronik_bridge::InProcessHeader> ToRustHeaders(const Headers &in) {
    rust::Vec<chronik_bridge::InProcessHeader> out;
    out.reserve(in.size());
    for (const auto &[name, value] : in) {
        // Header bytes need not be UTF-8.
        out.push_back(chronik_bridge::InProcessHeader{
            rust::String::lossy(name), rust::String::lossy(value)});
    }
    return out;
}

/** Forwards the HTTP server's session callbacks to the Rust session */
class RustWsHandler final : public InProcessWebSocketHandler {
public:
    explicit RustWsHandler(
        rust::Box<chronik_bridge::InProcessWsSession> session)
        : m_session(std::move(session)) {}
    void OnBinary(std::string msg) override {
        m_session->on_binary(rust::Slice<const uint8_t>(
            reinterpret_cast<const uint8_t *>(msg.data()), msg.size()));
    }
    void OnText() override { m_session->on_text(); }
    void OnClosed() override { m_session->on_closed(); }

private:
    rust::Box<chronik_bridge::InProcessWsSession> m_session;
};

} // namespace

void RegisterChronikInProcess(Server server_box, uint64_t ws_ping_interval_ms,
                              rust::Slice<const uint8_t> ws_ping_payload,
                              size_t ws_max_message_size) {
    auto server = std::make_shared<Server>(std::move(server_box));
    auto handlers = std::make_shared<ChronikInProcessHandlers>();
    handlers->http = [server](InProcessHTTPRequest req,
                              std::function<void(InProcessHTTPResponse)>
                                  done) {
        (*server)->http(
            rust::String::lossy(req.method), rust::String::lossy(req.target),
            ToRustHeaders(req.headers),
            rust::Slice<const uint8_t>(
                reinterpret_cast<const uint8_t *>(req.body.data()),
                req.body.size()),
            req.peer_ip,
            std::make_unique<chronik_bridge::InProcessHttpDone>(
                std::move(done)));
    };
    handlers->ws_check =
        [server](const InProcessHTTPRequest &req) -> std::optional<Headers> {
        rust::Vec<chronik_bridge::InProcessHeader> extra;
        if (!(*server)->ws_check(rust::String::lossy(req.method),
                                 rust::String::lossy(req.target),
                                 ToRustHeaders(req.headers), extra)) {
            return std::nullopt;
        }
        Headers out;
        for (const auto &header : extra) {
            out.emplace_back(std::string(header.name),
                             std::string(header.value));
        }
        return out;
    };
    handlers->ws_open = [server](std::shared_ptr<InProcessWebSocket> ws,
                                 const std::string &peer_ip)
        -> std::unique_ptr<InProcessWebSocketHandler> {
        return std::make_unique<RustWsHandler>((*server)->ws_open(
            peer_ip,
            std::make_unique<chronik_bridge::InProcessWsSink>(std::move(ws))));
    };
    handlers->ws_ping_interval = std::chrono::milliseconds{ws_ping_interval_ms};
    handlers->ws_ping_payload.assign(
        reinterpret_cast<const char *>(ws_ping_payload.data()),
        ws_ping_payload.size());
    handlers->ws_max_message_size = ws_max_message_size;
    SetChronikInProcessHandlers(std::move(handlers));
}

void UnregisterChronikInProcess() {
    SetChronikInProcessHandlers(nullptr);
}

} // namespace chronik
