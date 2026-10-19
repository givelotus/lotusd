// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Standalone Boost.Beast HTTP/1.1 + WebSocket listener for -chronikbind.
//
// Each connection runs as a coroutine on its own strand of the listener's
// io_context. Request handling (Router::Handle) and WebSocket handler calls
// run on the QueryPool, never on io threads.

#include <chronik/native/error.h>
#include <chronik/native/transport/beast_listener.h>
#include <chronik/native/transport/query_pool.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <array>
#include <atomic>
#include <cstring>
#include <deque>
#include <list>
#include <mutex>
#include <thread>

namespace chronik::native {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;

namespace {

constexpr auto use_nothrow = asio::as_tuple(asio::use_awaitable);

std::string OsErrorString(const boost::system::error_code &ec) {
    // Rust io::Error Display: "<strerror> (os error N)"
    if (ec.category() == boost::system::system_category() ||
        ec.category() == boost::system::generic_category()) {
        return std::string(std::strerror(ec.value())) + " (os error " +
               std::to_string(ec.value()) + ")";
    }
    return ec.message();
}

} // namespace

std::string FormatSocketAddr(const std::string &ip, uint16_t port) {
    if (ip.find(':') != std::string::npos) {
        return "[" + ip + "]:" + std::to_string(port);
    }
    return ip + ":" + std::to_string(port);
}

class BeastWsSession;

struct BeastListener::Impl : std::enable_shared_from_this<Impl> {
    const Router &router;
    QueryPool &pool;
    WsAccept ws_accept;
    ListenerOptions opts;

    asio::io_context &ioc;
    std::vector<std::unique_ptr<tcp::acceptor>> acceptors;
    std::vector<uint16_t> ports;
    std::vector<std::thread> threads;
    std::atomic<bool> stopping{false};

    mutable std::mutex sessions_mutex;
    std::list<std::weak_ptr<BeastWsSession>> ws_sessions;
    std::list<std::weak_ptr<beast::tcp_stream>> http_streams;

    Impl(asio::io_context &io, const Router &r, QueryPool &p, WsAccept a,
         ListenerOptions o)
        : router(r), pool(p), ws_accept(std::move(a)), opts(std::move(o)),
          ioc(io) {}

    asio::awaitable<void> AcceptLoop(tcp::acceptor &acceptor);
    asio::awaitable<void> RunHttp(std::shared_ptr<beast::tcp_stream> stream);
};

/** One upgraded WebSocket connection. */
class BeastWsSession : public WsSession,
                       public std::enable_shared_from_this<BeastWsSession> {
public:
    using Strand = beast::tcp_stream::executor_type;
    using WsStream = websocket::stream<beast::tcp_stream>;

    BeastWsSession(std::shared_ptr<BeastListener::Impl> listener,
                   beast::tcp_stream stream, std::string peer_ip)
        : m_listener(std::move(listener)),
          m_strand(stream.get_executor()),
          m_ws(std::move(stream)), m_timer(m_strand),
          m_handler_strand(m_listener->pool.MakeStrand()),
          m_peer_ip(std::move(peer_ip)) {}

    // ---- WsSession ----
    void SendBinary(Bytes msg) override {
        asio::post(m_strand, [self = shared_from_this(),
                              msg = std::move(msg)]() mutable {
            self->Enqueue(OutMsg{OutMsg::Kind::Binary, std::move(msg)});
        });
    }
    void Close() override {
        asio::post(m_strand, [self = shared_from_this()] {
            self->Enqueue(OutMsg{OutMsg::Kind::Close, {}});
        });
    }
    const std::string &PeerIp() const override { return m_peer_ip; }
    void NotifyActivity() override {
        asio::post(m_strand,
                   [self = shared_from_this()] { self->ResetIdleTimer(); });
    }

    /** Runs on the connection's strand, with the upgrade request. */
    asio::awaitable<void>
    Run(http::request<http::vector_body<uint8_t>> req,
        std::vector<HttpHeader> extra_headers) {
        auto self = shared_from_this();
        beast::get_lowest_layer(m_ws).expires_never();
        websocket::stream_base::timeout timeout{};
        timeout.handshake_timeout = std::chrono::seconds(30);
        timeout.idle_timeout = websocket::stream_base::none();
        timeout.keep_alive_pings = false;
        m_ws.set_option(timeout);
        m_ws.set_option(websocket::stream_base::decorator(
            [extra_headers](websocket::response_type &res) {
                for (const auto &[name, value] : extra_headers) {
                    res.insert(name, value);
                }
            }));
        m_ws.read_message_max(m_listener->opts.ws_max_message_size);
        m_ws.binary(true);
        m_ws.auto_fragment(false);
        m_ws.control_callback(
            [this](websocket::frame_type, beast::string_view) {
                // Ping (auto-answered by Beast with a Pong) or Pong: both end
                // a Rust loop iteration and so re-arm the ping timer.
                ResetIdleTimer();
            });
        auto [ec] = co_await m_ws.async_accept(req, use_nothrow);
        if (ec) {
            co_return;
        }
        {
            std::lock_guard lock(m_listener->sessions_mutex);
            m_listener->ws_sessions.push_back(self);
        }
        // Create the handler on the pool strand, before any message.
        asio::post(m_handler_strand, [self] {
            if (!self->m_closed_notified.load()) {
                self->m_handler = self->m_listener->ws_accept(self);
            }
        });
        asio::co_spawn(m_strand, PingLoop(), asio::detached);
        co_await ReadLoop();
    }

    /** Thread-safe: notify the handler and close the socket (Stop()). */
    void ForceClose() {
        NotifyClosed();
        asio::post(m_strand, [self = shared_from_this()] {
            beast::error_code ec;
            beast::get_lowest_layer(self->m_ws).socket().close(ec);
            self->m_timer.cancel();
        });
    }

private:
    struct OutMsg {
        enum class Kind { Binary, Ping, Close } kind;
        Bytes data;
    };

    asio::awaitable<void> ReadLoop() {
        auto self = shared_from_this();
        while (true) {
            beast::flat_buffer buffer;
            auto [ec, n] = co_await m_ws.async_read(buffer, use_nothrow);
            if (ec) {
                break;
            }
            ResetIdleTimer();
            if (m_ws.got_text()) {
                asio::post(m_handler_strand, [self] {
                    if (self->m_handler) {
                        self->m_handler->OnText();
                    }
                });
            } else {
                const auto data = buffer.data();
                Bytes msg(static_cast<const uint8_t *>(data.data()),
                          static_cast<const uint8_t *>(data.data()) +
                              data.size());
                asio::post(m_handler_strand,
                           [self, msg = std::move(msg)] {
                               if (self->m_handler) {
                                   self->m_handler->OnBinary(msg);
                               }
                           });
            }
        }
        m_closed = true;
        m_out.clear();
        m_timer.cancel();
        NotifyClosed();
    }

    asio::awaitable<void> PingLoop() {
        auto self = shared_from_this();
        while (!m_closed) {
            m_timer.expires_after(m_listener->opts.ws_ping_interval);
            auto [ec] = co_await m_timer.async_wait(use_nothrow);
            if (m_closed) {
                break;
            }
            if (ec) {
                // Cancelled by activity: re-arm
                continue;
            }
            Enqueue(OutMsg{OutMsg::Kind::Ping,
                           Bytes(WS_PING_PAYLOAD,
                                 WS_PING_PAYLOAD +
                                     std::strlen(WS_PING_PAYLOAD))});
        }
    }

    void ResetIdleTimer() { m_timer.cancel(); }

    void Enqueue(OutMsg msg) {
        if (m_closed) {
            return;
        }
        if (msg.kind != OutMsg::Kind::Ping) {
            ResetIdleTimer();
        }
        m_out.push_back(std::move(msg));
        if (!m_writing) {
            m_writing = true;
            asio::co_spawn(m_strand, WriteLoop(), asio::detached);
        }
    }

    asio::awaitable<void> WriteLoop() {
        auto self = shared_from_this();
        while (!m_out.empty() && !m_closed) {
            OutMsg msg = std::move(m_out.front());
            m_out.pop_front();
            beast::error_code ec;
            switch (msg.kind) {
                case OutMsg::Kind::Binary: {
                    auto [wec, n] = co_await m_ws.async_write(
                        asio::buffer(msg.data), use_nothrow);
                    ec = wec;
                    break;
                }
                case OutMsg::Kind::Ping: {
                    websocket::ping_data payload(
                        reinterpret_cast<const char *>(msg.data.data()),
                        msg.data.size());
                    auto [pec] = co_await m_ws.async_ping(payload, use_nothrow);
                    ec = pec;
                    break;
                }
                case OutMsg::Kind::Close: {
                    auto [cec] = co_await m_ws.async_close(
                        websocket::close_code::normal, use_nothrow);
                    ec = cec;
                    m_closed = true;
                    break;
                }
            }
            if (ec) {
                // Rust: a failed send ends the session.
                m_closed = true;
                beast::error_code ignored;
                beast::get_lowest_layer(m_ws).socket().close(ignored);
                break;
            }
        }
        m_writing = false;
        if (m_closed) {
            m_out.clear();
            m_timer.cancel();
        }
    }

    void NotifyClosed() {
        if (m_closed_notified.exchange(true)) {
            return;
        }
        asio::post(m_handler_strand, [self = shared_from_this()] {
            if (self->m_handler) {
                self->m_handler->OnClosed();
                self->m_handler.reset();
            }
        });
    }

    std::shared_ptr<BeastListener::Impl> m_listener;
    Strand m_strand;
    WsStream m_ws;
    asio::steady_timer m_timer;
    asio::strand<QueryPool::executor_type> m_handler_strand;
    std::string m_peer_ip;
    std::unique_ptr<WsHandler> m_handler; // only touched on m_handler_strand
    std::deque<OutMsg> m_out;
    bool m_writing = false;
    bool m_closed = false;
    std::atomic<bool> m_closed_notified{false};
};

namespace {

HttpRequest ToHttpRequest(const http::request<http::vector_body<uint8_t>> &req,
                          std::string peer_ip) {
    HttpRequest out;
    out.method = std::string(req.method_string());
    std::string target(req.target());
    size_t q = target.find('?');
    if (q == std::string::npos) {
        out.path = target;
    } else {
        out.path = target.substr(0, q);
        out.query_string = target.substr(q + 1);
        out.has_query = true;
    }
    for (const auto &field : req) {
        out.headers.emplace_back(std::string(field.name_string()),
                                 std::string(field.value()));
    }
    out.peer_ip = std::move(peer_ip);
    return out;
}

http::response<http::vector_body<uint8_t>>
ToBeastResponse(HttpResponse resp, unsigned version, bool is_head) {
    http::response<http::vector_body<uint8_t>> res{
        static_cast<http::status>(resp.status), version};
    std::optional<std::string> explicit_length;
    for (auto &[name, value] : resp.headers) {
        if (beast::iequals(name, "content-length")) {
            explicit_length = value;
            continue;
        }
        res.insert(name, value);
    }
    res.body() = std::move(resp.body);
    if (is_head && explicit_length) {
        res.set(http::field::content_length, *explicit_length);
    } else {
        res.prepare_payload();
    }
    return res;
}

} // namespace

asio::awaitable<void>
BeastListener::Impl::AcceptLoop(tcp::acceptor &acceptor) {
    auto self = shared_from_this();
    while (!stopping) {
        auto [ec, socket] = co_await acceptor.async_accept(
            asio::make_strand(ioc), use_nothrow);
        if (ec) {
            if (ec == asio::error::operation_aborted || stopping) {
                co_return;
            }
            continue;
        }
        auto stream = std::make_shared<beast::tcp_stream>(std::move(socket));
        {
            std::lock_guard lock(sessions_mutex);
            http_streams.remove_if([](const auto &w) { return w.expired(); });
            ws_sessions.remove_if([](const auto &w) { return w.expired(); });
            http_streams.push_back(stream);
        }
        auto ex = stream->get_executor();
        asio::co_spawn(ex, RunHttp(std::move(stream)), asio::detached);
    }
}

asio::awaitable<void>
BeastListener::Impl::RunHttp(std::shared_ptr<beast::tcp_stream> stream) {
    auto self = shared_from_this();
    std::string peer_ip;
    {
        beast::error_code ec;
        auto ep = stream->socket().remote_endpoint(ec);
        if (!ec) {
            peer_ip = ep.address().to_string();
        }
    }
    beast::flat_buffer buffer;
    while (!stopping) {
        http::request_parser<http::vector_body<uint8_t>> parser;
        parser.header_limit(uint32_t(opts.max_header_size));
        // Content-Length is checked below; the parser would fail the header.
        parser.body_limit(boost::none);
        stream->expires_after(opts.http_idle_timeout);
        auto [hec, hn] =
            co_await http::async_read_header(*stream, buffer, parser, use_nothrow);
        if (hec) {
            break;
        }
        bool too_large = false;
        bool must_close = false;
        const auto content_length = parser.content_length();
        if (content_length && *content_length > opts.max_body_size) {
            // Don't read it: like axum's DefaultBodyLimit the protobuf
            // extractor answers 413; then the connection is closed.
            too_large = true;
            must_close = true;
        } else if (!parser.is_done()) {
            parser.body_limit(opts.max_body_size);
            const auto &hdr = parser.get();
            auto expect = hdr.find(http::field::expect);
            if (expect != hdr.end() &&
                beast::iequals(expect->value(), "100-continue")) {
                http::response<http::empty_body> cont{http::status::continue_,
                                                      hdr.version()};
                auto [cec, cn] =
                    co_await http::async_write(*stream, cont, use_nothrow);
                if (cec) {
                    break;
                }
            }
            auto [bec, bn] =
                co_await http::async_read(*stream, buffer, parser, use_nothrow);
            if (bec == http::error::body_limit) {
                too_large = true;
                must_close = true;
            } else if (bec) {
                break;
            }
        }
        auto beast_req = parser.release();
        HttpRequest req = ToHttpRequest(beast_req, peer_ip);
        if (too_large) {
            req.body.clear();
            req.body_too_large = true;
        } else {
            req.body = std::move(beast_req.body());
        }

        if (websocket::is_upgrade(beast_req) &&
            router.IsWebSocketUpgrade(req)) {
            stream->expires_never();
            auto session = std::make_shared<BeastWsSession>(
                self, std::move(*stream), peer_ip);
            co_await session->Run(std::move(beast_req),
                                  router.UpgradeResponseHeaders(req));
            co_return;
        }

        const bool is_head = beast_req.method() == http::verb::head;
        const unsigned version = beast_req.version();
        const bool keep_alive = beast_req.keep_alive() && !must_close;
        stream->expires_never();
        HttpResponse resp =
            co_await AsyncHandle(pool, router, std::move(req),
                                 asio::use_awaitable);
        auto res = ToBeastResponse(std::move(resp), version, is_head);
        // A 413 closes the connection afterwards (below), but like axum/hyper
        // its headers don't announce it: only the client's own keep-alive
        // choice is reflected.
        res.keep_alive(beast_req.keep_alive());
        stream->expires_after(opts.http_idle_timeout);
        http::response_serializer<http::vector_body<uint8_t>> sr{res};
        if (is_head) {
            sr.split(true);
            auto [wec, wn] =
                co_await http::async_write_header(*stream, sr, use_nothrow);
            if (wec) {
                break;
            }
        } else {
            auto [wec, wn] = co_await http::async_write(*stream, sr, use_nothrow);
            if (wec) {
                break;
            }
        }
        if (must_close) {
            // Lingering close: discard the unread body for a while so the
            // client can read the 413 instead of getting a reset.
            beast::error_code ec;
            stream->socket().shutdown(tcp::socket::shutdown_send, ec);
            stream->expires_after(std::chrono::seconds(2));
            std::array<char, 16384> sink;
            size_t discarded = 0;
            while (discarded < 2 * opts.max_body_size + (1 << 20)) {
                auto [rec, rn] = co_await stream->async_read_some(
                    asio::buffer(sink), use_nothrow);
                if (rec) {
                    break;
                }
                discarded += rn;
            }
            break;
        }
        if (!keep_alive) {
            break;
        }
    }
    beast::error_code ec;
    stream->socket().shutdown(tcp::socket::shutdown_send, ec);
    stream->socket().close(ec);
}

struct BeastListener::IoHolder {
    asio::io_context ioc;
};

BeastListener::BeastListener(const Router &router, QueryPool &pool,
                             WsAccept ws_accept, ListenerOptions opts)
    : m_io(std::make_unique<IoHolder>()),
      m_impl(std::make_shared<Impl>(m_io->ioc, router, pool,
                                    std::move(ws_accept), std::move(opts))) {}

BeastListener::~BeastListener() {
    Stop();
    m_impl->acceptors.clear();
    m_impl.reset();
    m_io.reset();
}

void BeastListener::Start() {
    Impl &impl = *m_impl;
    for (const ListenerBind &bind : impl.opts.binds) {
        const std::string display = FormatSocketAddr(bind.ip, bind.port);
        boost::system::error_code ec;
        const auto address = asio::ip::make_address(bind.ip, ec);
        if (ec) {
            throw ChronikError("Chronik failed binding to " + display + ": " +
                               ec.message());
        }
        const tcp::endpoint endpoint(address, bind.port);
        auto acceptor = std::make_unique<tcp::acceptor>(impl.ioc);
        acceptor->open(endpoint.protocol(), ec);
        if (!ec) {
            // Rust's std TcpListener::bind sets SO_REUSEADDR on Unix
            acceptor->set_option(asio::socket_base::reuse_address(true), ec);
            if (endpoint.address().is_v6()) {
                acceptor->set_option(asio::ip::v6_only(true), ec);
            }
            ec.clear();
            acceptor->bind(endpoint, ec);
        }
        if (!ec) {
            acceptor->listen(128, ec);
        }
        if (ec) {
            throw ChronikError("Chronik failed binding to " + display + ": " +
                               OsErrorString(ec));
        }
        impl.ports.push_back(acceptor->local_endpoint().port());
        impl.acceptors.push_back(std::move(acceptor));
    }
    for (auto &acceptor : impl.acceptors) {
        asio::co_spawn(impl.ioc, impl.AcceptLoop(*acceptor), asio::detached);
    }
    const size_t n = std::max<size_t>(1, impl.opts.io_threads);
    for (size_t i = 0; i < n; ++i) {
        impl.threads.emplace_back([impl = m_impl] { impl->ioc.run(); });
    }
}

std::vector<uint16_t> BeastListener::BoundPorts() const {
    return m_impl->ports;
}

size_t BeastListener::NumWsSessions() const {
    std::lock_guard lock(m_impl->sessions_mutex);
    size_t n = 0;
    for (const auto &weak : m_impl->ws_sessions) {
        if (!weak.expired()) {
            ++n;
        }
    }
    return n;
}

void BeastListener::Stop() {
    Impl &impl = *m_impl;
    if (impl.stopping.exchange(true)) {
        return;
    }
    asio::post(impl.ioc, [&impl] {
        for (auto &acceptor : impl.acceptors) {
            beast::error_code ec;
            acceptor->close(ec);
        }
    });
    std::vector<std::shared_ptr<BeastWsSession>> sessions;
    std::vector<std::shared_ptr<beast::tcp_stream>> streams;
    {
        std::lock_guard lock(impl.sessions_mutex);
        for (auto &weak : impl.ws_sessions) {
            if (auto s = weak.lock()) {
                sessions.push_back(std::move(s));
            }
        }
        for (auto &weak : impl.http_streams) {
            if (auto s = weak.lock()) {
                streams.push_back(std::move(s));
            }
        }
    }
    for (auto &session : sessions) {
        session->ForceClose();
    }
    for (auto &stream : streams) {
        asio::post(stream->get_executor(), [stream] {
            beast::error_code ec;
            stream->socket().close(ec);
        });
    }
    sessions.clear();
    streams.clear();
    if (impl.threads.empty()) {
        return;
    }
    // Let the close handlers run briefly, then stop the loop.
    auto stop_timer = std::make_shared<asio::steady_timer>(impl.ioc);
    stop_timer->expires_after(std::chrono::milliseconds(50));
    stop_timer->async_wait([&impl, stop_timer](const auto &) { impl.ioc.stop(); });
    for (auto &thread : impl.threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    impl.threads.clear();
}

} // namespace chronik::native
