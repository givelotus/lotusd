// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// In-process /chronik transport on the node's HTTP server (design §6.4
// host_beast_bridge): converts between the HTTP server's in-process types and
// the native Router/WsSession interfaces, and moves all Chronik work onto the
// query pool so the server's io threads never block.

#include <hosts/abc/abc_http.h>

#include <chronik/native/http.h>
#include <chronik/native/service.h>
#include <chronik/native/ws.h>

#include <httpserver.h>

#include <cstring>
#include <mutex>

namespace chronik::native::abc {

namespace {

HttpRequest ToNativeRequest(InProcessHTTPRequest in) {
    HttpRequest out;
    out.method = std::move(in.method);
    const size_t q = in.target.find('?');
    if (q == std::string::npos) {
        out.path = std::move(in.target);
    } else {
        out.path = in.target.substr(0, q);
        out.query_string = in.target.substr(q + 1);
        out.has_query = true;
    }
    out.headers = std::move(in.headers);
    out.body.assign(in.body.begin(), in.body.end());
    out.peer_ip = std::move(in.peer_ip);
    return out;
}

InProcessHTTPResponse ToInProcessResponse(HttpResponse in) {
    InProcessHTTPResponse out;
    out.status = in.status;
    out.headers = std::move(in.headers);
    out.body.assign(in.body.begin(), in.body.end());
    return out;
}

/**
 * Calls the HTTP server's completion exactly once: with the response, or
 * with 503 if the query pool drops the request (shutdown), so no server
 * coroutine waits forever.
 */
class DoneOnce {
public:
    explicit DoneOnce(std::function<void(InProcessHTTPResponse)> done)
        : m_done(std::move(done)) {}
    ~DoneOnce() {
        if (m_done) {
            InProcessHTTPResponse resp;
            resp.status = 503;
            resp.headers.emplace_back("content-type",
                                      std::string(CONTENT_TYPE_TEXT));
            resp.body = "Chronik is shutting down";
            m_done(std::move(resp));
        }
    }
    void Call(InProcessHTTPResponse resp) {
        auto done = std::move(m_done);
        m_done = nullptr;
        done(std::move(resp));
    }

private:
    std::function<void(InProcessHTTPResponse)> m_done;
};

/** Native WsSession over the HTTP server's in-process WebSocket. */
class NodeWsSession final : public WsSession {
public:
    NodeWsSession(std::shared_ptr<InProcessWebSocket> ws, std::string peer_ip)
        : m_ws(std::move(ws)), m_peer_ip(std::move(peer_ip)) {}
    void SendBinary(Bytes msg) override {
        m_ws->SendBinary(std::string(msg.begin(), msg.end()));
    }
    void Close() override { m_ws->Close(); }
    const std::string &PeerIp() const override { return m_peer_ip; }
    void NotifyActivity() override { m_ws->NotifyActivity(); }

private:
    std::shared_ptr<InProcessWebSocket> m_ws;
    std::string m_peer_ip;
};

/**
 * Receives the server's session callbacks (io thread) and replays them, in
 * order, on a query-pool strand where the native WsHandler lives.
 */
class StrandWsHandler final : public InProcessWebSocketHandler {
public:
    StrandWsHandler(std::shared_ptr<Service> service,
                    std::shared_ptr<WsSession> session)
        : m_state(std::make_shared<State>()) {
        m_state->post = service->MakeSerialExecutor();
        m_state->post([state = m_state, service = std::move(service),
                       session = std::move(session)]() mutable {
            if (!state->closed) {
                state->handler = service->AcceptWs(std::move(session));
            }
        });
    }
    void OnBinary(std::string msg) override {
        m_state->post([state = m_state, msg = std::move(msg)] {
            if (state->handler) {
                state->handler->OnBinary(std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t *>(msg.data()),
                    msg.size()));
            }
        });
    }
    void OnText() override {
        m_state->post([state = m_state] {
            if (state->handler) {
                state->handler->OnText();
            }
        });
    }
    void OnClosed() override {
        m_state->post([state = m_state] {
            state->closed = true;
            if (state->handler) {
                state->handler->OnClosed();
                state->handler.reset();
            }
        });
    }

private:
    struct State {
        std::function<void(std::function<void()>)> post;
        // Only touched on the strand
        std::unique_ptr<WsHandler> handler;
        bool closed = false;
    };
    std::shared_ptr<State> m_state;
};

std::mutex g_mutex;
bool g_registered = false;

} // namespace

void RegisterInProcessHttp(std::shared_ptr<Service> service) {
    auto handlers = std::make_shared<ChronikInProcessHandlers>();
    handlers->http = [service](InProcessHTTPRequest req,
                               std::function<void(InProcessHTTPResponse)>
                                   done) {
        auto once = std::make_shared<DoneOnce>(std::move(done));
        service->HandleHttpAsync(ToNativeRequest(std::move(req)),
                                 [once](HttpResponse resp) {
                                     once->Call(
                                         ToInProcessResponse(std::move(resp)));
                                 });
    };
    handlers->ws_check = [service](const InProcessHTTPRequest &req) {
        return service->CheckWsUpgrade(ToNativeRequest(req));
    };
    handlers->ws_open = [service](std::shared_ptr<InProcessWebSocket> ws,
                                  const std::string &peer_ip)
        -> std::unique_ptr<InProcessWebSocketHandler> {
        auto session = std::make_shared<NodeWsSession>(std::move(ws), peer_ip);
        return std::make_unique<StrandWsHandler>(service, std::move(session));
    };
    handlers->ws_ping_interval = service->WsPingInterval();
    handlers->ws_ping_payload = WS_PING_PAYLOAD;
    handlers->ws_max_message_size = 20'000;
    {
        std::lock_guard lock(g_mutex);
        g_registered = true;
    }
    SetChronikInProcessHandlers(std::move(handlers));
}

void UnregisterInProcessHttp() {
    {
        std::lock_guard lock(g_mutex);
        if (!g_registered) {
            return;
        }
        g_registered = false;
    }
    SetChronikInProcessHandlers(nullptr);
}

} // namespace chronik::native::abc
