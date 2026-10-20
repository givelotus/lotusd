// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <http2_server.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <nghttp2/nghttp2.h>

#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace http = boost::beast::http;

namespace {

/** A real nghttp2 client, exchanging bytes with a ServerSession in memory */
class TestClient {
public:
    struct Reply {
        std::map<std::string, std::string> headers;
        std::string body;
        bool closed{false};
        uint32_t error_code{0};
        int status() const {
            const auto it{headers.find(":status")};
            return it == headers.end() ? 0 : std::stoi(it->second);
        }
    };

    explicit TestClient(bool send_preface = true) {
        nghttp2_session_callbacks *cbs;
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_on_header_callback(cbs, OnHeader);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, OnData);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, OnClose);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, OnFrame);
        nghttp2_session_client_new(&m_session, cbs, this);
        nghttp2_session_callbacks_del(cbs);
        if (send_preface) {
            nghttp2_settings_entry iv{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                                      1 << 24};
            nghttp2_submit_settings(m_session, NGHTTP2_FLAG_NONE, &iv, 1);
            nghttp2_session_set_local_window_size(m_session, NGHTTP2_FLAG_NONE,
                                                  0, 1 << 24);
        }
    }
    ~TestClient() { nghttp2_session_del(m_session); }

    nghttp2_session *Session() { return m_session; }

    int32_t Request(const std::vector<std::pair<std::string, std::string>> &h,
                    std::optional<std::string> body = std::nullopt) {
        std::vector<nghttp2_nv> nva;
        for (const auto &[n, v] : h) {
            nva.push_back({(uint8_t *)n.data(), (uint8_t *)v.data(), n.size(),
                           v.size(), NGHTTP2_NV_FLAG_NONE});
        }
        if (!body) {
            return nghttp2_submit_request2(m_session, nullptr, nva.data(),
                                           nva.size(), nullptr, nullptr);
        }
        auto src{std::make_unique<std::pair<std::string, size_t>>(*body, 0)};
        nghttp2_data_provider2 prov{};
        prov.source.ptr = src.get();
        prov.read_callback = [](nghttp2_session *, int32_t, uint8_t *buf,
                                size_t len, uint32_t *flags,
                                nghttp2_data_source *s, void *) {
            auto *p{static_cast<std::pair<std::string, size_t> *>(s->ptr)};
            const size_t n{std::min(len, p->first.size() - p->second)};
            std::memcpy(buf, p->first.data() + p->second, n);
            p->second += n;
            if (p->second == p->first.size()) {
                *flags |= NGHTTP2_DATA_FLAG_EOF;
            }
            return nghttp2_ssize(n);
        };
        m_bodies.push_back(std::move(src));
        return nghttp2_submit_request2(m_session, nullptr, nva.data(),
                                       nva.size(), &prov, nullptr);
    }

    /** Bytes the client wants to send */
    std::string Out() {
        std::string out;
        while (true) {
            const uint8_t *data;
            const nghttp2_ssize n{nghttp2_session_mem_send2(m_session, &data)};
            if (n <= 0) {
                break;
            }
            out.append(reinterpret_cast<const char *>(data), n);
        }
        return out;
    }

    bool In(const std::string &bytes) {
        return nghttp2_session_mem_recv2(
                   m_session, reinterpret_cast<const uint8_t *>(bytes.data()),
                   bytes.size()) == nghttp2_ssize(bytes.size());
    }

    std::map<int32_t, Reply> replies;
    std::optional<uint32_t> goaway_error;
    std::optional<uint32_t> remote_connect_protocol;

private:
    static TestClient &Self(void *u) { return *static_cast<TestClient *>(u); }
    static int OnHeader(nghttp2_session *, const nghttp2_frame *f,
                        const uint8_t *n, size_t nl, const uint8_t *v,
                        size_t vl, uint8_t, void *u) {
        Self(u).replies[f->hd.stream_id].headers[std::string((char *)n, nl)] =
            std::string((char *)v, vl);
        return 0;
    }
    static int OnData(nghttp2_session *, uint8_t, int32_t id, const uint8_t *d,
                      size_t len, void *u) {
        Self(u).replies[id].body.append((const char *)d, len);
        return 0;
    }
    static int OnClose(nghttp2_session *, int32_t id, uint32_t err, void *u) {
        Self(u).replies[id].closed = true;
        Self(u).replies[id].error_code = err;
        return 0;
    }
    static int OnFrame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
        if (f->hd.type == NGHTTP2_GOAWAY) {
            Self(u).goaway_error = f->goaway.error_code;
        }
        if (f->hd.type == NGHTTP2_SETTINGS &&
            !(f->hd.flags & NGHTTP2_FLAG_ACK)) {
            Self(u).remote_connect_protocol =
                nghttp2_session_get_remote_settings(
                    s, NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL);
        }
        return 0;
    }

    nghttp2_session *m_session{nullptr};
    std::vector<std::unique_ptr<std::pair<std::string, size_t>>> m_bodies;
};

/** A ServerSession recording what it is asked to serve */
struct TestServer {
    struct Received {
        int32_t id;
        http2::Request req;
    };
    std::vector<Received> requests;
    std::vector<std::pair<int32_t, std::string>> connects;
    std::map<int32_t, std::string> tunnel_in;
    std::vector<int32_t> tunnel_eofs;
    std::vector<int32_t> closed;
    http2::ServerSession session;

    explicit TestServer(http2::Limits limits = {})
        : session{limits, Handlers()} {}

    http2::ServerSession::Handlers Handlers() {
        http2::ServerSession::Handlers h;
        h.on_request = [this](int32_t id, http2::Request &&req) {
            requests.push_back({id, std::move(req)});
        };
        h.on_connect = [this](int32_t id, http2::Request &&,
                              std::string protocol) {
            connects.emplace_back(id, protocol);
        };
        h.on_tunnel_data = [this](int32_t id, std::string_view data) {
            tunnel_in[id] += data;
        };
        h.on_tunnel_eof = [this](int32_t id) { tunnel_eofs.push_back(id); };
        h.on_stream_close = [this](int32_t id, uint32_t) {
            closed.push_back(id);
        };
        return h;
    }

    std::string Out(size_t max = 1 << 30) {
        http2::Output out;
        BOOST_REQUIRE(session.Collect(out, max));
        return out.ToString();
    }
};

/** Exchange bytes until neither side has anything to say */
bool Pump(TestClient &client, TestServer &server) {
    bool ok{true};
    for (int i = 0; i < 100; ++i) {
        const std::string c2s{client.Out()};
        if (!c2s.empty()) {
            ok &= server.session.Receive(
                {reinterpret_cast<const uint8_t *>(c2s.data()), c2s.size()});
        }
        const std::string s2c{server.Out()};
        if (!s2c.empty()) {
            client.In(s2c);
        }
        if (c2s.empty() && s2c.empty()) {
            break;
        }
    }
    return ok;
}

std::vector<std::pair<std::string, std::string>> Get(const std::string &path) {
    return {{":method", "GET"},
            {":scheme", "https"},
            {":authority", "node.example:8332"},
            {":path", path}};
}

//! HPACK block of GET https://n/ (static table entries and a literal)
const std::string MINIMAL_GET{"\x82\x87\x84\x01\x01n", 6};

struct RawFrame {
    uint8_t type;
    uint8_t flags;
    int32_t stream;
    std::string payload;
};

uint32_t ReadU32(const std::string &s, size_t pos) {
    return (uint32_t(uint8_t(s[pos])) << 24) |
           (uint32_t(uint8_t(s[pos + 1])) << 16) |
           (uint32_t(uint8_t(s[pos + 2])) << 8) | uint32_t(uint8_t(s[pos + 3]));
}

/** Split server output into frames (the server never sends a preface) */
std::vector<RawFrame> ParseFrames(const std::string &bytes) {
    std::vector<RawFrame> out;
    size_t pos{0};
    while (pos + 9 <= bytes.size()) {
        const size_t len{(size_t(uint8_t(bytes[pos])) << 16) |
                         (size_t(uint8_t(bytes[pos + 1])) << 8) |
                         size_t(uint8_t(bytes[pos + 2]))};
        RawFrame f{uint8_t(bytes[pos + 3]), uint8_t(bytes[pos + 4]),
                   int32_t(ReadU32(bytes, pos + 5) & 0x7fffffff),
                   bytes.substr(pos + 9, len)};
        out.push_back(std::move(f));
        pos += 9 + len;
    }
    return out;
}

std::string Frame(uint8_t type, uint8_t flags, int32_t stream,
                  const std::string &payload) {
    std::string f;
    f.push_back(char((payload.size() >> 16) & 0xff));
    f.push_back(char((payload.size() >> 8) & 0xff));
    f.push_back(char(payload.size() & 0xff));
    f.push_back(char(type));
    f.push_back(char(flags));
    f.push_back(char((stream >> 24) & 0x7f));
    f.push_back(char((stream >> 16) & 0xff));
    f.push_back(char((stream >> 8) & 0xff));
    f.push_back(char(stream & 0xff));
    return f + payload;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(http2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(request_mapping) {
    TestServer server;
    TestClient client;
    auto headers{Get("/rest/chaininfo.json?x=1")};
    headers.emplace_back("cookie", "a=1");
    headers.emplace_back("cookie", "t=secret");
    headers.emplace_back("authorization", "Basic dTpw");
    headers.emplace_back("x-forwarded-for", "10.1.2.3");
    client.Request(headers);
    BOOST_CHECK(Pump(client, server));

    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    const auto &req{server.requests[0].req};
    BOOST_CHECK(req.method() == http::verb::get);
    BOOST_CHECK_EQUAL(req.target(), "/rest/chaininfo.json?x=1");
    // Presented as HTTP/1.1, so handlers see a keep-alive request.
    BOOST_CHECK_EQUAL(req.version(), 11U);
    BOOST_CHECK(req.keep_alive());
    // :authority becomes Host; cookie fields are joined (RFC 9113 8.2.3).
    BOOST_CHECK_EQUAL(req[http::field::host], "node.example:8332");
    BOOST_CHECK_EQUAL(req[http::field::cookie], "a=1; t=secret");
    // Lookups are case-insensitive, as on HTTP/1.1.
    BOOST_CHECK_EQUAL(req["Authorization"], "Basic dTpw");
    BOOST_CHECK_EQUAL(req["X-Forwarded-For"], "10.1.2.3");
    BOOST_CHECK(req.body().empty());
}

BOOST_AUTO_TEST_CASE(request_body_and_response) {
    TestServer server;
    TestClient client;
    // A body spanning several DATA frames.
    const std::string body(100000, 'b');
    const int32_t id{client.Request({{":method", "POST"},
                                     {":scheme", "https"},
                                     {":authority", "n"},
                                     {":path", "/"},
                                     {"content-type", "application/json"}},
                                    body)};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    BOOST_CHECK(server.requests[0].req.method() == http::verb::post);
    BOOST_CHECK_EQUAL(server.requests[0].req.body(), body);
    BOOST_CHECK_EQUAL(server.requests[0].req[http::field::host], "n");

    // A reply large enough to be framed without copying, with fields that
    // HTTP/2 forbids.
    http2::Response res{http::status::ok, 11};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::connection, "keep-alive");
    res.set("Keep-Alive", "timeout=5");
    res.set(http::field::content_encoding, "zstd");
    res.body() = std::string(300000, 'r');
    res.prepare_payload();
    BOOST_CHECK(server.session.SubmitResponse(id, std::move(res)));
    BOOST_CHECK(Pump(client, server));
    const auto &reply{client.replies[id]};
    BOOST_CHECK_EQUAL(reply.status(), 200);
    BOOST_CHECK_EQUAL(reply.body, std::string(300000, 'r'));
    BOOST_CHECK_EQUAL(reply.headers.at("content-type"), "application/json");
    BOOST_CHECK_EQUAL(reply.headers.at("content-encoding"), "zstd");
    BOOST_CHECK_EQUAL(reply.headers.at("content-length"), "300000");
    BOOST_CHECK(!reply.headers.count("connection"));
    BOOST_CHECK(!reply.headers.count("keep-alive"));
    BOOST_CHECK(reply.closed);
    BOOST_CHECK_EQUAL(reply.error_code, NGHTTP2_NO_ERROR);
    BOOST_CHECK_EQUAL(server.session.OpenStreams(), 0U);
}

BOOST_AUTO_TEST_CASE(small_and_head_responses) {
    TestServer server;
    TestClient client;
    const int32_t get{client.Request(Get("/a"))};
    const int32_t head{client.Request({{":method", "HEAD"},
                                       {":scheme", "https"},
                                       {":authority", "n"},
                                       {":path", "/b"}})};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 2U);
    BOOST_CHECK(server.requests[1].req.method() == http::verb::head);

    http2::Response small{http::status::not_found, 11};
    small.body() = "nope";
    small.prepare_payload();
    BOOST_CHECK(server.session.SubmitResponse(get, std::move(small)));
    http2::Response h{http::status::ok, 11};
    h.body() = std::string(5000, 'x');
    h.prepare_payload();
    BOOST_CHECK(
        server.session.SubmitResponse(head, std::move(h), /*head=*/true));
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(client.replies[get].status(), 404);
    BOOST_CHECK_EQUAL(client.replies[get].body, "nope");
    // HEAD: Content-Length of the GET, no body.
    BOOST_CHECK_EQUAL(client.replies[head].status(), 200);
    BOOST_CHECK_EQUAL(client.replies[head].headers.at("content-length"),
                      "5000");
    BOOST_CHECK(client.replies[head].body.empty());
    BOOST_CHECK(client.replies[head].closed);
}

BOOST_AUTO_TEST_CASE(concurrent_streams_answered_out_of_order) {
    TestServer server;
    TestClient client;
    std::vector<int32_t> ids;
    for (int i = 0; i < 10; ++i) {
        ids.push_back(client.Request(Get("/" + std::to_string(i))));
    }
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 10U);
    for (auto it = server.requests.rbegin(); it != server.requests.rend();
         ++it) {
        http2::Response res{http::status::ok, 11};
        res.body() = std::string{it->req.target()};
        res.prepare_payload();
        BOOST_CHECK(server.session.SubmitResponse(it->id, std::move(res)));
    }
    BOOST_CHECK(Pump(client, server));
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK_EQUAL(client.replies[ids[i]].body, "/" + std::to_string(i));
    }
}

BOOST_AUTO_TEST_CASE(reset_stream_drops_late_response) {
    TestServer server;
    TestClient client;
    const int32_t id{client.Request(Get("/slow"))};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    nghttp2_submit_rst_stream(client.Session(), NGHTTP2_FLAG_NONE, id,
                              NGHTTP2_CANCEL);
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(server.closed.size(), 1U);
    // The handler answers after the client gave up.
    http2::Response res{http::status::ok, 11};
    BOOST_CHECK(!server.session.SubmitResponse(id, std::move(res)));
    BOOST_CHECK_EQUAL(server.session.OpenStreams(), 0U);
}

BOOST_AUTO_TEST_CASE(oversized_header_list_gets_431) {
    http2::Limits limits;
    limits.max_header_list_size = 1000;
    TestServer server{limits};
    TestClient client;
    auto headers{Get("/")};
    headers.emplace_back("x-big", std::string(2000, 'h'));
    const int32_t id{client.Request(headers)};
    const int32_t ok{client.Request(Get("/fine"))};
    BOOST_CHECK(Pump(client, server));
    // Only the second request reaches the handlers.
    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    BOOST_CHECK_EQUAL(server.requests[0].id, ok);
    BOOST_CHECK_EQUAL(client.replies[id].status(), 431);
    BOOST_CHECK(client.replies[id].closed);
}

BOOST_AUTO_TEST_CASE(oversized_body_gets_413) {
    http2::Limits limits;
    limits.max_body_size = 10000;
    TestServer server{limits};
    TestClient client;
    const int32_t big{client.Request({{":method", "POST"},
                                      {":scheme", "https"},
                                      {":authority", "n"},
                                      {":path", "/"}},
                                     std::string(50000, 'z'))};
    const int32_t fits{client.Request({{":method", "POST"},
                                       {":scheme", "https"},
                                       {":authority", "n"},
                                       {":path", "/"}},
                                      std::string(10000, 'y'))};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    BOOST_CHECK_EQUAL(server.requests[0].id, fits);
    BOOST_CHECK_EQUAL(client.replies[big].status(), 413);
    BOOST_CHECK(client.replies[big].closed);
}

BOOST_AUTO_TEST_CASE(classic_connect_refused) {
    TestServer server;
    TestClient client;
    const int32_t id{client.Request(
        {{":method", "CONNECT"}, {":authority", "example.com:443"}})};
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK(server.requests.empty());
    BOOST_CHECK(server.connects.empty());
    BOOST_CHECK_EQUAL(client.replies[id].status(), 405);
}

BOOST_AUTO_TEST_CASE(settings_advertised) {
    http2::Limits limits;
    limits.max_concurrent_streams = 7;
    limits.max_frame_size = 32768;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    nghttp2_session *s{client.Session()};
    BOOST_CHECK_EQUAL(nghttp2_session_get_remote_settings(
                          s, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS),
                      7U);
    BOOST_CHECK_EQUAL(
        nghttp2_session_get_remote_settings(s, NGHTTP2_SETTINGS_MAX_FRAME_SIZE),
        32768U);
    BOOST_CHECK_EQUAL(nghttp2_session_get_remote_settings(
                          s, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE),
                      limits.max_header_list_size);
    BOOST_CHECK_EQUAL(
        nghttp2_session_get_remote_settings(s, NGHTTP2_SETTINGS_ENABLE_PUSH),
        0U);
    // Extended CONNECT is only advertised when enabled.
    BOOST_CHECK_EQUAL(*client.remote_connect_protocol, 0U);
    // The connection window was opened beyond the default 64 KiB.
    BOOST_CHECK_GT(nghttp2_session_get_remote_window_size(s), 65535);
}

BOOST_AUTO_TEST_CASE(too_many_streams_refused) {
    http2::Limits limits;
    limits.max_concurrent_streams = 3;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    // Ignore the advertised limit with raw HEADERS frames: six complete
    // requests that the server does not answer, so they stay open.
    std::string raw;
    for (int32_t id = 1; id <= 11; id += 2) {
        raw += Frame(NGHTTP2_HEADERS,
                     NGHTTP2_FLAG_END_HEADERS | NGHTTP2_FLAG_END_STREAM, id,
                     MINIMAL_GET);
    }
    server.session.Receive(
        {reinterpret_cast<const uint8_t *>(raw.data()), raw.size()});
    BOOST_CHECK_EQUAL(server.requests.size(), 3U);
    BOOST_CHECK_EQUAL(server.session.OpenStreams(), 3U);
    // A client that acknowledged the limit and exceeded it anyway is
    // misbehaving: nghttp2 ends the connection (GOAWAY PROTOCOL_ERROR).
    std::optional<uint32_t> goaway;
    for (const auto &f : ParseFrames(server.Out())) {
        if (f.type == NGHTTP2_GOAWAY) {
            goaway = ReadU32(f.payload, 4);
        }
    }
    BOOST_REQUIRE(goaway);
    BOOST_CHECK_EQUAL(*goaway, uint32_t{NGHTTP2_PROTOCOL_ERROR});
    BOOST_CHECK(!server.session.WantsRead());
}

BOOST_AUTO_TEST_CASE(bad_preface_closes) {
    TestServer server;
    const std::string junk{"GET / HTTP/1.1\r\nHost: x\r\n\r\n"};
    // The caller stops reading and closes when Receive() fails.
    BOOST_CHECK(!server.session.Receive(
        {reinterpret_cast<const uint8_t *>(junk.data()), junk.size()}));
    BOOST_CHECK(server.requests.empty());
}

BOOST_AUTO_TEST_CASE(continuation_flood_closes) {
    TestServer server;
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    // HEADERS without END_HEADERS, then more CONTINUATION frames than
    // allowed (CVE-2024-28182), each carrying a little header block.
    std::string raw{
        Frame(NGHTTP2_HEADERS, NGHTTP2_FLAG_END_STREAM, 1, MINIMAL_GET)};
    for (int i = 0; i < 20; ++i) {
        raw += Frame(NGHTTP2_CONTINUATION, 0, 1,
                     std::string("\x40\x01"
                                 "a\x01"
                                 "b",
                                 5));
    }
    const bool ok{server.session.Receive(
        {reinterpret_cast<const uint8_t *>(raw.data()), raw.size()})};
    client.In(server.Out());
    BOOST_CHECK(!ok || !server.session.WantsRead());
    BOOST_CHECK(server.requests.empty());
    BOOST_REQUIRE(client.goaway_error);
}

BOOST_AUTO_TEST_CASE(rapid_reset_cut_off) {
    http2::Limits limits;
    limits.reset_burst = 20;
    limits.reset_rate = 1;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    // Open streams and reset them as soon as they reached the server
    // (CVE-2023-44487). (A request reset before it is sent never leaves
    // the client.)
    int opened{0};
    for (int i = 0; i < 200 && !client.goaway_error; ++i) {
        const int32_t id{client.Request(Get("/" + std::to_string(i)))};
        const std::string headers{client.Out()};
        nghttp2_submit_rst_stream(client.Session(), NGHTTP2_FLAG_NONE, id,
                                  NGHTTP2_CANCEL);
        const std::string c2s{headers + client.Out()};
        ++opened;
        server.session.Receive(
            {reinterpret_cast<const uint8_t *>(c2s.data()), c2s.size()});
        client.In(server.Out());
    }
    // nghttp2 ends the connection with GOAWAY once the bucket is empty.
    BOOST_REQUIRE(client.goaway_error);
    BOOST_CHECK_EQUAL(*client.goaway_error, uint32_t{NGHTTP2_INTERNAL_ERROR});
    BOOST_CHECK_LE(opened, 22);
    BOOST_CHECK(!server.session.WantsRead());
    // The handlers saw at most the burst.
    BOOST_CHECK_LE(server.requests.size(), 25U);
}

BOOST_AUTO_TEST_CASE(output_batches_are_bounded) {
    TestServer server;
    TestClient client;
    const int32_t id{client.Request(Get("/big"))};
    BOOST_CHECK(Pump(client, server));
    http2::Response res{http::status::ok, 11};
    res.body() = std::string(2000000, 'q');
    res.prepare_payload();
    BOOST_CHECK(server.session.SubmitResponse(id, std::move(res)));
    // Collect in small batches: none much larger than asked for.
    std::string all;
    for (int i = 0; i < 1000; ++i) {
        http2::Output out;
        BOOST_REQUIRE(server.session.Collect(out, 50000));
        if (out.Empty()) {
            // Window exhausted: let the client acknowledge.
            client.In(all);
            all.clear();
            const std::string c2s{client.Out()};
            if (c2s.empty()) {
                break;
            }
            server.session.Receive(
                {reinterpret_cast<const uint8_t *>(c2s.data()), c2s.size()});
            continue;
        }
        BOOST_CHECK_LE(out.Size(), 50000U + 70000U);
        all += out.ToString();
    }
    client.In(all);
    BOOST_CHECK_EQUAL(client.replies[id].body.size(), 2000000U);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

std::vector<std::pair<std::string, std::string>>
ExtendedConnect(const std::string &path) {
    return {{":method", "CONNECT"},
            {":protocol", "websocket"},
            {":scheme", "https"},
            {":authority", "node.example"},
            {":path", path},
            {"sec-websocket-version", "13"},
            {"sec-websocket-protocol", "p2p-zstd-v1, p2p-zstd"}};
}

/** Stream a client sends DATA on without ending it (a tunnel) */
struct OpenDataSource {
    std::string data;
    size_t offset{0};
    bool end{false};
};

nghttp2_ssize ReadOpen(nghttp2_session *, int32_t, uint8_t *buf, size_t len,
                       uint32_t *flags, nghttp2_data_source *s, void *) {
    auto *src{static_cast<OpenDataSource *>(s->ptr)};
    const size_t n{std::min(len, src->data.size() - src->offset)};
    std::memcpy(buf, src->data.data() + src->offset, n);
    src->offset += n;
    if (src->offset == src->data.size()) {
        if (src->end) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
        } else if (n == 0) {
            return NGHTTP2_ERR_DEFERRED;
        }
    }
    return nghttp2_ssize(n);
}

int32_t OpenTunnel(TestClient &client, OpenDataSource &src,
                   const std::string &path) {
    const auto h{ExtendedConnect(path)};
    std::vector<nghttp2_nv> nva;
    for (const auto &[n, v] : h) {
        nva.push_back({(uint8_t *)n.data(), (uint8_t *)v.data(), n.size(),
                       v.size(), NGHTTP2_NV_FLAG_NONE});
    }
    nghttp2_data_provider2 prov{};
    prov.source.ptr = &src;
    prov.read_callback = ReadOpen;
    return nghttp2_submit_request2(client.Session(), nullptr, nva.data(),
                                   nva.size(), &prov, nullptr);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(http2_connect_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(extended_connect_tunnel) {
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    // RFC 8441: advertised, and only then may the client use :protocol.
    BOOST_CHECK_EQUAL(*client.remote_connect_protocol, 1U);

    OpenDataSource src;
    const int32_t id{OpenTunnel(client, src, "/p2p/ws")};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.connects.size(), 1U);
    BOOST_CHECK_EQUAL(server.connects[0].first, id);
    BOOST_CHECK_EQUAL(server.connects[0].second, "websocket");
    BOOST_CHECK(server.requests.empty());

    BOOST_CHECK(server.session.AcceptTunnel(
        id, 200, {{"sec-websocket-protocol", "p2p-zstd-v1"}}));
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(client.replies[id].status(), 200);
    BOOST_CHECK_EQUAL(client.replies[id].headers.at("sec-websocket-protocol"),
                      "p2p-zstd-v1");
    BOOST_CHECK(!client.replies[id].closed);

    // Both ways, several times.
    for (int i = 0; i < 3; ++i) {
        src.data += "client" + std::to_string(i);
        nghttp2_session_resume_data(client.Session(), id);
        server.session.TunnelSend(id, "server" + std::to_string(i));
        BOOST_CHECK(Pump(client, server));
    }
    BOOST_CHECK_EQUAL(server.tunnel_in[id], "client0client1client2");
    BOOST_CHECK_EQUAL(client.replies[id].body, "server0server1server2");
    BOOST_CHECK_EQUAL(server.session.TunnelQueued(id), 0U);
    server.session.TunnelConsumed(id, server.tunnel_in[id].size());

    // Each side ends its half: the stream closes cleanly.
    server.session.TunnelEnd(id);
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK(!client.replies[id].closed);
    src.end = true;
    nghttp2_session_resume_data(client.Session(), id);
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(server.tunnel_eofs.size(), 1U);
    BOOST_CHECK(client.replies[id].closed);
    BOOST_CHECK_EQUAL(client.replies[id].error_code, NGHTTP2_NO_ERROR);
    BOOST_CHECK_EQUAL(server.session.OpenStreams(), 0U);
}

BOOST_AUTO_TEST_CASE(tunnel_flow_control_follows_consumption) {
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    limits.stream_window = 65535;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    OpenDataSource src;
    src.data = std::string(200000, 'p');
    const int32_t id{OpenTunnel(client, src, "/p2p/ws")};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE(server.session.AcceptTunnel(id, 200, {}));
    BOOST_CHECK(Pump(client, server));
    // Without consumption, the client is held at the stream window.
    BOOST_CHECK_EQUAL(server.tunnel_in[id].size(), 65535U);
    // Delivering bytes reopens the window, bit by bit.
    size_t consumed{0};
    for (int i = 0; i < 100 && server.tunnel_in[id].size() < 200000; ++i) {
        const size_t n{server.tunnel_in[id].size() - consumed};
        server.session.TunnelConsumed(id, n);
        consumed += n;
        BOOST_CHECK(Pump(client, server));
    }
    BOOST_CHECK_EQUAL(server.tunnel_in[id], std::string(200000, 'p'));
}

BOOST_AUTO_TEST_CASE(tunnel_reset_and_closed_stream_credit) {
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    limits.stream_window = 65535;
    limits.connection_window = 65535;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    OpenDataSource src;
    src.data = std::string(65535, 'a');
    const int32_t id{OpenTunnel(client, src, "/p2p/ws")};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE(server.session.AcceptTunnel(id, 200, {}));
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(server.tunnel_in[id].size(), 65535U);
    // The application gives up on the tunnel without consuming: the
    // connection window must still be returned, or other streams starve.
    server.session.Reset(id, NGHTTP2_CANCEL);
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(client.replies[id].error_code, NGHTTP2_CANCEL);
    const int32_t next{client.Request({{":method", "POST"},
                                       {":scheme", "https"},
                                       {":authority", "n"},
                                       {":path", "/"}},
                                      std::string(30000, 'b'))};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.requests.size(), 1U);
    BOOST_CHECK_EQUAL(server.requests[0].id, next);
    BOOST_CHECK_EQUAL(server.requests[0].req.body().size(), 30000U);
}

BOOST_AUTO_TEST_CASE(connect_refused_without_tunnel) {
    http2::Limits limits;
    limits.enable_connect_protocol = true;
    TestServer server{limits};
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    OpenDataSource src;
    const int32_t id{OpenTunnel(client, src, "/nope")};
    BOOST_CHECK(Pump(client, server));
    BOOST_REQUIRE_EQUAL(server.connects.size(), 1U);
    // Answered like a request: no tunnel.
    BOOST_CHECK(server.session.SubmitResponse(
        id, http2::Response{boost::beast::http::status::not_found, 11}));
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(client.replies[id].status(), 404);
}

BOOST_AUTO_TEST_CASE(protocol_rejected_unless_enabled) {
    TestServer server; // enable_connect_protocol is off
    TestClient client;
    BOOST_CHECK(Pump(client, server));
    BOOST_CHECK_EQUAL(*client.remote_connect_protocol, 0U);
    // Send :protocol anyway with raw frames: a malformed request.
    // :method CONNECT (literal), :protocol websocket, :scheme https,
    // :path /, :authority n
    std::string block{"\x02\x07CONNECT", 9};
    block += std::string{"\x00\x09:protocol\x09websocket", 21};
    block += std::string{"\x87\x84\x01\x01n", 5};
    const std::string raw{
        Frame(NGHTTP2_HEADERS, NGHTTP2_FLAG_END_HEADERS, 1, block)};
    server.session.Receive(
        {reinterpret_cast<const uint8_t *>(raw.data()), raw.size()});
    BOOST_CHECK(server.connects.empty());
    BOOST_CHECK(server.requests.empty());
    bool reset{false};
    for (const auto &f : ParseFrames(server.Out())) {
        reset |= f.type == NGHTTP2_RST_STREAM || f.type == NGHTTP2_GOAWAY;
    }
    BOOST_CHECK(reset);
}

BOOST_AUTO_TEST_SUITE_END()
