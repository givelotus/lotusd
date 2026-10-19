// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Integration tests of the standalone Beast listener on 127.0.0.1:0, with a
// Beast client: HTTP routing/keep-alive/limits/CORS and the WebSocket
// transport (echo handler, pings, pongs, max message size).

#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/proto.h>
#include <chronik/native/transport/beast_listener.h>
#include <chronik/native/transport/query_pool.h>
#include <chronik/native/ws.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>

using namespace chronik::native;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;

namespace {

using Response = http::response<http::string_body>;

struct Client {
    asio::io_context ioc;
    tcp::socket socket{ioc};
    beast::flat_buffer buffer;

    explicit Client(uint16_t port) {
        socket.connect(
            tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
    }

    Response Request(http::verb method, const std::string &target,
                     std::string body = {},
                     std::vector<std::pair<std::string, std::string>>
                         headers = {}) {
        http::request<http::string_body> req{method, target, 11};
        req.set(http::field::host, "127.0.0.1");
        for (auto &[k, v] : headers) {
            req.set(k, v);
        }
        req.body() = std::move(body);
        req.prepare_payload();
        http::write(socket, req);
        return Read(method == http::verb::head);
    }

    Response Read(bool head = false) {
        http::response_parser<http::string_body> parser;
        parser.skip(head);
        http::read(socket, buffer, parser);
        return parser.release();
    }

    /** True if the server closed the connection. */
    bool ServerClosed() {
        beast::error_code ec;
        char c;
        socket.read_some(asio::buffer(&c, 1), ec);
        return ec == asio::error::eof || ec == asio::error::connection_reset;
    }
};

std::string ErrMsg(const Response &res) {
    proto::Error err;
    BOOST_REQUIRE(err.ParseFromString(res.body()));
    return err.msg();
}

/** Echo handler; counters shared with the test. */
struct WsCounters {
    std::atomic<int> accepted{0};
    std::atomic<int> closed{0};
    std::atomic<int> texts{0};
    std::atomic<bool> on_io_thread{false};
    std::mutex mutex;
    std::condition_variable cv;
    std::string last_peer_ip;

    void WaitClosed(int n) {
        std::unique_lock lock(mutex);
        cv.wait_for(lock, std::chrono::seconds(5),
                    [&] { return closed.load() >= n; });
    }
};

class EchoHandler : public WsHandler {
public:
    EchoHandler(std::shared_ptr<WsSession> session,
                std::shared_ptr<WsCounters> counters)
        : m_session(std::move(session)), m_counters(std::move(counters)) {}

    void OnBinary(std::span<const uint8_t> msg) override {
        const std::string text(msg.begin(), msg.end());
        if (text == "delay") {
            // Reply later, without activity in between (pings are due)
            std::thread([session = m_session] {
                std::this_thread::sleep_for(std::chrono::milliseconds(700));
                const std::string done = "done";
                session->SendBinary(Bytes(done.begin(), done.end()));
            }).detach();
            return;
        }
        if (text == "close") {
            m_session->Close();
            return;
        }
        m_session->SendBinary(Bytes(msg.begin(), msg.end()));
    }
    void OnText() override {
        ++m_counters->texts;
        const std::string reply = "Unexpected message type Text";
        m_session->SendBinary(Bytes(reply.begin(), reply.end()));
    }
    void OnClosed() override {
        m_session.reset();
        {
            std::lock_guard lock(m_counters->mutex);
            ++m_counters->closed;
        }
        m_counters->cv.notify_all();
    }

private:
    std::shared_ptr<WsSession> m_session;
    std::shared_ptr<WsCounters> m_counters;
};

Router MakeRouter() {
    Router router(RouterOptions{true, {}});
    router.Get("/info", [](const HttpRequest &req, const PathParams &) {
        return HttpResponse::Text(200, "info from " + req.peer_ip);
    });
    router.Get("/blocks/:start/:end",
               [](const HttpRequest &, const PathParams &p) {
                   return HttpResponse::Text(
                       200, std::to_string(PathI32(p, 0) + PathI32(p, 1)));
               });
    router.PostWithOptions(
        "/broadcast-tx", [](const HttpRequest &req, const PathParams &) {
            auto raw = ParseProtobufRequest<proto::BroadcastTxRequest>(req);
            proto::RawTx out;
            out.set_raw_tx(raw.raw_tx());
            return HttpResponse::Protobuf(out);
        });
    router.AddWebSocket("/ws");
    return router;
}

struct Fixture {
    Router router = MakeRouter();
    QueryPool pool{2};
    std::shared_ptr<WsCounters> counters = std::make_shared<WsCounters>();
    std::unique_ptr<BeastListener> listener;
    uint16_t port = 0;

    explicit Fixture(ListenerOptions opts = DefaultOpts()) {
        auto counters_ = counters;
        listener = std::make_unique<BeastListener>(
            router, pool,
            [counters_](std::shared_ptr<WsSession> session)
                -> std::unique_ptr<WsHandler> {
                ++counters_->accepted;
                {
                    std::lock_guard lock(counters_->mutex);
                    counters_->last_peer_ip = session->PeerIp();
                }
                return std::make_unique<EchoHandler>(std::move(session),
                                                     counters_);
            },
            std::move(opts));
        listener->Start();
        port = listener->BoundPorts().at(0);
    }

    static ListenerOptions DefaultOpts() {
        ListenerOptions opts;
        opts.binds = {{"127.0.0.1", 0}};
        opts.ws_ping_interval = std::chrono::milliseconds(300);
        return opts;
    }
};

using WsClient = websocket::stream<tcp::socket>;

std::unique_ptr<WsClient> ConnectWs(asio::io_context &ioc, uint16_t port,
                                    websocket::response_type *res = nullptr) {
    auto ws = std::make_unique<WsClient>(ioc);
    ws->next_layer().connect(
        tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
    ws->read_message_max(1 << 20);
    websocket::response_type ignored;
    ws->handshake(res ? *res : ignored, "127.0.0.1", "/ws");
    ws->binary(true);
    return ws;
}

std::string ReadMsg(WsClient &ws) {
    beast::flat_buffer buf;
    ws.read(buf);
    return beast::buffers_to_string(buf.data());
}

void WriteMsg(WsClient &ws, const std::string &msg) {
    ws.write(asio::buffer(msg));
}

} // namespace

BOOST_AUTO_TEST_SUITE(transport_tests)

BOOST_AUTO_TEST_CASE(http_routes_and_keep_alive) {
    Fixture fx;
    Client client(fx.port);

    // Several requests on one keep-alive connection
    Response res = client.Request(http::verb::get, "/info");
    BOOST_CHECK_EQUAL(res.result_int(), 200);
    BOOST_CHECK_EQUAL(res.body(), "info from 127.0.0.1");
    BOOST_CHECK_EQUAL(res[http::field::content_type],
                      "text/plain; charset=utf-8");
    BOOST_CHECK_EQUAL(res["access-control-allow-origin"], "*");
    BOOST_CHECK(res.keep_alive());

    res = client.Request(http::verb::get, "/blocks/2/40");
    BOOST_CHECK_EQUAL(res.body(), "42");

    res = client.Request(http::verb::head, "/info");
    BOOST_CHECK_EQUAL(res.result_int(), 200);
    BOOST_CHECK_EQUAL(res[http::field::content_length], "19");
    BOOST_CHECK(res.body().empty());

    res = client.Request(http::verb::get, "/nope?a=1");
    BOOST_CHECK_EQUAL(res.result_int(), 404);
    BOOST_CHECK_EQUAL(res[http::field::content_type], "application/x-protobuf");
    BOOST_CHECK_EQUAL(ErrMsg(res), "404: Not found: /nope?a=1");

    res = client.Request(http::verb::delete_, "/info");
    BOOST_CHECK_EQUAL(res.result_int(), 405);
    BOOST_CHECK_EQUAL(res[http::field::allow], "GET,HEAD");
    BOOST_CHECK(res.body().empty());

    res = client.Request(http::verb::get, "/blocks/x/1");
    BOOST_CHECK_EQUAL(res.result_int(), 400);
    BOOST_CHECK_EQUAL(res.body(), "Invalid URL: Cannot parse value at index 0 "
                                  "with value `\"x\"` to a `i32`");

    // CORS preflight
    res = client.Request(http::verb::options, "/broadcast-tx", {},
                         {{"Origin", "https://example.com"},
                          {"Access-Control-Request-Method", "POST"}});
    BOOST_CHECK_EQUAL(res.result_int(), 200);
    BOOST_CHECK_EQUAL(res["access-control-allow-origin"], "*");
    BOOST_CHECK_EQUAL(res["access-control-allow-methods"], "*");
    BOOST_CHECK_EQUAL(res[http::field::vary],
                      "origin, access-control-request-method, "
                      "access-control-request-headers");

    // POST protobuf
    proto::BroadcastTxRequest req;
    req.set_raw_tx("\x01\x02\x03");
    res = client.Request(http::verb::post, "/broadcast-tx",
                         req.SerializeAsString(),
                         {{"Content-Type", "application/x-protobuf"}});
    BOOST_CHECK_EQUAL(res.result_int(), 200);
    proto::RawTx raw;
    BOOST_REQUIRE(raw.ParseFromString(res.body()));
    BOOST_CHECK_EQUAL(raw.raw_tx(), "\x01\x02\x03");

    res = client.Request(http::verb::post, "/broadcast-tx", "\xff",
                         {{"Content-Type", "application/x-protobuf"}});
    BOOST_CHECK_EQUAL(res.result_int(), 400);
    BOOST_CHECK_EQUAL(ErrMsg(res), "400: Bad protobuf: failed to decode "
                                   "Protobuf message: invalid varint");

    res = client.Request(http::verb::post, "/broadcast-tx", "",
                         {{"Content-Type", "text/plain"}});
    BOOST_CHECK_EQUAL(ErrMsg(res), "400: Content-Type must be "
                                   "application/x-protobuf, got text/plain");

    // GET on /ws without upgrade headers: axum's WebSocketUpgrade rejection
    res = client.Request(http::verb::get, "/ws");
    BOOST_CHECK_EQUAL(res.result_int(), 400);
    BOOST_CHECK_EQUAL(res.body(),
                      "Connection header did not include 'upgrade'");

    // Connection: close is honoured
    res = client.Request(http::verb::get, "/info", {},
                         {{"Connection", "close"}});
    BOOST_CHECK_EQUAL(res.result_int(), 200);
    BOOST_CHECK(!res.keep_alive());
    BOOST_CHECK(client.ServerClosed());
}

BOOST_AUTO_TEST_CASE(http_body_limit) {
    ListenerOptions opts = Fixture::DefaultOpts();
    opts.max_body_size = 100;
    Fixture fx(opts);
    const std::string expected =
        "413: Request body exceeds maximum size of 2000000 bytes";
    {
        // Content-Length above the limit: not read, 413, connection closed.
        // Like axum/hyper the response doesn't announce the close.
        Client client(fx.port);
        Response res =
            client.Request(http::verb::post, "/broadcast-tx",
                           std::string(101, 'x'),
                           {{"Content-Type", "application/x-protobuf"}});
        BOOST_CHECK_EQUAL(res.result_int(), 413);
        BOOST_CHECK_EQUAL(ErrMsg(res), expected);
        BOOST_CHECK(res.find(http::field::connection) == res.end());
        BOOST_CHECK(client.ServerClosed());
    }
    {
        // Chunked body growing above the limit
        Client client(fx.port);
        http::request<http::string_body> req{http::verb::post,
                                             "/broadcast-tx", 11};
        req.set(http::field::host, "127.0.0.1");
        req.set(http::field::content_type, "application/x-protobuf");
        req.chunked(true);
        req.body() = std::string(150, 'y');
        http::write(client.socket, req);
        Response res = client.Read();
        BOOST_CHECK_EQUAL(res.result_int(), 413);
        BOOST_CHECK_EQUAL(ErrMsg(res), expected);
    }
    {
        // The content type is checked before the size (axum order)
        Client client(fx.port);
        Response res = client.Request(http::verb::post, "/broadcast-tx",
                                      std::string(101, 'x'),
                                      {{"Content-Type", "text/plain"}});
        BOOST_CHECK_EQUAL(res.result_int(), 400);
    }
    {
        // At the limit is fine, and Expect: 100-continue is answered
        Client client(fx.port);
        proto::BroadcastTxRequest req;
        req.set_raw_tx(std::string(90, 'z'));
        const std::string body = req.SerializeAsString();
        BOOST_REQUIRE_LE(body.size(), 100u);
        http::request<http::string_body> hreq{http::verb::post,
                                              "/broadcast-tx", 11};
        hreq.set(http::field::host, "127.0.0.1");
        hreq.set(http::field::content_type, "application/x-protobuf");
        hreq.set(http::field::expect, "100-continue");
        hreq.body() = body;
        hreq.prepare_payload();
        http::request_serializer<http::string_body> sr{hreq};
        http::write_header(client.socket, sr);
        Response cont = client.Read();
        BOOST_CHECK_EQUAL(cont.result_int(), 100);
        http::write(client.socket, sr);
        Response res = client.Read();
        BOOST_CHECK_EQUAL(res.result_int(), 200);
    }
}

BOOST_AUTO_TEST_CASE(multiple_binds_and_bind_failure) {
    ListenerOptions opts = Fixture::DefaultOpts();
    opts.binds = {{"127.0.0.1", 0}, {"127.0.0.1", 0}};
    Fixture fx(opts);
    const auto ports = fx.listener->BoundPorts();
    BOOST_REQUIRE_EQUAL(ports.size(), 2u);
    BOOST_CHECK_NE(ports[0], ports[1]);
    for (uint16_t port : ports) {
        Client client(port);
        BOOST_CHECK_EQUAL(client.Request(http::verb::get, "/info").result_int(),
                          200);
    }

    // Port already in use
    ListenerOptions taken = Fixture::DefaultOpts();
    taken.binds = {{"127.0.0.1", ports[1]}};
    BeastListener second(fx.router, fx.pool, {}, taken);
    const std::string expected = "Chronik failed binding to 127.0.0.1:" +
                                 std::to_string(ports[1]) + ": " +
                                 std::strerror(EADDRINUSE) + " (os error " +
                                 std::to_string(EADDRINUSE) + ")";
    BOOST_CHECK_EXCEPTION(second.Start(), ChronikError,
                          [&](const ChronikError &err) {
                              BOOST_CHECK_EQUAL(err.what(), expected);
                              return true;
                          });
    BOOST_CHECK_EQUAL(FormatSocketAddr("::1", 8331), "[::1]:8331");
}

BOOST_AUTO_TEST_CASE(async_handle_completion) {
    Router router = MakeRouter();
    QueryPool pool(1);
    asio::io_context ioc;
    std::optional<HttpResponse> got;
    std::thread::id handler_thread;
    HttpRequest req;
    req.method = "GET";
    req.path = "/blocks/1/2";
    AsyncHandle(pool, router, req, [&](HttpResponse resp) {
        handler_thread = std::this_thread::get_id();
        got = std::move(resp);
    });
    // Coroutine form
    std::optional<HttpResponse> got_co;
    asio::co_spawn(
        ioc,
        [&]() -> asio::awaitable<void> {
            got_co = co_await AsyncHandle(pool, router, req,
                                          asio::use_awaitable);
        },
        asio::detached);
    ioc.run();
    BOOST_REQUIRE(got_co);
    BOOST_CHECK_EQUAL(std::string(got_co->body.begin(), got_co->body.end()),
                      "3");
    pool.Join();
    // A plain callback has the system executor: it runs on the pool thread
    BOOST_REQUIRE(got);
    BOOST_CHECK_EQUAL(got->status, 200);
    BOOST_CHECK(handler_thread != std::this_thread::get_id());
}

BOOST_AUTO_TEST_CASE(websocket_echo_text_and_close) {
    Fixture fx;
    asio::io_context ioc;
    {
        websocket::response_type res;
        auto ws = ConnectWs(ioc, fx.port, &res);
        BOOST_CHECK_EQUAL(res.result_int(), 101);
        BOOST_CHECK_EQUAL(res["access-control-allow-origin"], "*");

        WriteMsg(*ws, "hello");
        BOOST_CHECK_EQUAL(ReadMsg(*ws), "hello");
        BOOST_CHECK(ws->got_binary());
        WriteMsg(*ws, std::string(20'000, 'a'));
        BOOST_CHECK_EQUAL(ReadMsg(*ws).size(), 20'000u);

        ws->text(true);
        WriteMsg(*ws, "hi");
        ws->binary(true);
        BOOST_CHECK_EQUAL(ReadMsg(*ws), "Unexpected message type Text");
        BOOST_CHECK_EQUAL(fx.counters->texts.load(), 1);
        BOOST_CHECK_EQUAL(fx.listener->NumWsSessions(), 1u);

        ws->close(websocket::close_code::normal);
    }
    fx.counters->WaitClosed(1);
    BOOST_CHECK_EQUAL(fx.counters->accepted.load(), 1);
    BOOST_CHECK_EQUAL(fx.counters->closed.load(), 1);
    {
        std::lock_guard lock(fx.counters->mutex);
        BOOST_CHECK_EQUAL(fx.counters->last_peer_ip, "127.0.0.1");
    }

    // Server-initiated close
    auto ws = ConnectWs(ioc, fx.port);
    WriteMsg(*ws, "close");
    beast::flat_buffer buf;
    beast::error_code ec;
    ws->read(buf, ec);
    BOOST_CHECK(ec == websocket::error::closed);
    BOOST_CHECK(ws->reason().code == websocket::close_code::normal);
    fx.counters->WaitClosed(2);
    BOOST_CHECK_EQUAL(fx.counters->closed.load(), 2);
}

BOOST_AUTO_TEST_CASE(websocket_ping_pong) {
    Fixture fx;
    asio::io_context ioc;
    auto ws = ConnectWs(ioc, fx.port);
    std::vector<std::pair<websocket::frame_type, std::string>> control;
    ws->control_callback(
        [&](websocket::frame_type kind, beast::string_view payload) {
            control.emplace_back(kind, std::string(payload));
        });

    // Server answers our ping with a pong
    ws->ping("abc");
    WriteMsg(*ws, "echo");
    BOOST_CHECK_EQUAL(ReadMsg(*ws), "echo");
    BOOST_REQUIRE(!control.empty());
    BOOST_CHECK(control[0].first == websocket::frame_type::pong);
    BOOST_CHECK_EQUAL(control[0].second, "abc");
    control.clear();

    // While idle (700 ms, interval 300 ms) the server pings us
    WriteMsg(*ws, "delay");
    BOOST_CHECK_EQUAL(ReadMsg(*ws), "done");
    BOOST_CHECK_GE(control.size(), 2u);
    for (const auto &[kind, payload] : control) {
        BOOST_CHECK(kind == websocket::frame_type::ping);
        BOOST_CHECK_EQUAL(payload, WS_PING_PAYLOAD);
    }
    control.clear();

    // Activity re-arms the timer: no ping while messages flow
    for (int i = 0; i < 6; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        WriteMsg(*ws, "x");
        BOOST_CHECK_EQUAL(ReadMsg(*ws), "x");
    }
    BOOST_CHECK(control.empty());
    ws->close(websocket::close_code::normal);
}

BOOST_AUTO_TEST_CASE(websocket_max_message_size) {
    Fixture fx;
    asio::io_context ioc;
    auto ws = ConnectWs(ioc, fx.port);
    // Frame and message above 20000 bytes end the session
    WriteMsg(*ws, std::string(20'001, 'b'));
    beast::flat_buffer buf;
    beast::error_code ec;
    ws->read(buf, ec);
    BOOST_CHECK(ec);
    fx.counters->WaitClosed(1);
    BOOST_CHECK_EQUAL(fx.counters->closed.load(), 1);

    // A fragmented message above the limit also ends it
    auto ws2 = ConnectWs(ioc, fx.port);
    ws2->auto_fragment(false);
    const std::string part(15'000, 'c');
    ws2->write_some(false, asio::buffer(part));
    ws2->write_some(true, asio::buffer(part));
    buf.clear();
    ws2->read(buf, ec);
    BOOST_CHECK(ec);
    fx.counters->WaitClosed(2);
    BOOST_CHECK_EQUAL(fx.counters->closed.load(), 2);
}

BOOST_AUTO_TEST_CASE(stop_closes_sessions) {
    auto fx = std::make_unique<Fixture>();
    asio::io_context ioc;
    auto ws = ConnectWs(ioc, fx->port);
    WriteMsg(*ws, "x");
    BOOST_CHECK_EQUAL(ReadMsg(*ws), "x");
    Client idle(fx->port);
    BOOST_CHECK_EQUAL(idle.Request(http::verb::get, "/info").result_int(), 200);

    fx->listener->Stop();
    fx->counters->WaitClosed(1);
    BOOST_CHECK_EQUAL(fx->counters->closed.load(), 1);
    beast::flat_buffer buf;
    beast::error_code ec;
    ws->read(buf, ec);
    BOOST_CHECK(ec);
    BOOST_CHECK(idle.ServerClosed());
    fx->listener.reset();
    // Handler calls run on the pool; it must outlive the listener's sessions
    fx->pool.Join();
    BOOST_CHECK_EQUAL(fx->counters->closed.load(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
