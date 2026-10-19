// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of the Service (port of chronik-lib bridge.rs setup/handlers and
// parse_socket_addr) on a FakeHost: -chronikbind parsing, startup and
// shutdown, pause/resume, HTTP and WebSocket entry points, interrupt.

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/pause.h>
#include <chronik/native/proto.h>
#include <chronik/native/service.h>
#include <chronik/native/ws.h>

#include <core/service/bind_parse.h>
#include <core/service/service_impl.h>
#include <test/fake_host.h>
#include <test/index_test_util.h>
#include <test/test_backend.h>

#include <boost/test/unit_test.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <thread>

using namespace chronik::native;
using namespace std::chrono_literals;
namespace th = chronik::native::testhost;
namespace nt = chronik::native::test;

namespace {

struct ServiceEnv {
    th::FakeHost host;
    nt::IndexTempDir dir;

    explicit ServiceEnv(const std::string &name, int num_blocks = 3)
        : dir(name) {
        nt::RegisterTestStores();
        std::filesystem::create_directories(dir.path);
        for (int i = 0; i < num_blocks; ++i) {
            host.Extend(host.MakeBlock(host.TipHeight(), {}));
        }
    }
    ServiceParams Params(std::vector<std::string> hosts = {}) const {
        ServiceParams p;
        p.indexer.datadir_net = dir.path;
        p.indexer.backend = nt::TestBackend();
        p.indexer.token_index = false;
        p.hosts = std::move(hosts);
        p.default_port = 8331;
        p.query_workers = 2;
        return p;
    }
};

HttpRequest Get(std::string path) {
    HttpRequest req;
    req.method = "GET";
    req.path = std::move(path);
    req.peer_ip = "127.0.0.1";
    return req;
}

HttpResponse Call(Service &service, HttpRequest req) {
    std::promise<HttpResponse> promise;
    auto future = promise.get_future();
    service.HandleHttpAsync(std::move(req), [&](HttpResponse resp) {
        promise.set_value(std::move(resp));
    });
    BOOST_REQUIRE(future.wait_for(10s) == std::future_status::ready);
    return future.get();
}

std::string BodyStr(const HttpResponse &resp) {
    return std::string(resp.body.begin(), resp.body.end());
}

/** Minimal blocking HTTP/1.1 GET over TCP; returns the raw response. */
std::string RawGet(uint16_t port, const std::string &path) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    BOOST_REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return {};
    }
    const std::string req = "GET " + path +
                            " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            "Connection: close\r\n\r\n";
    ::send(fd, req.data(), req.size(), 0);
    std::string out;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        out.append(buf, size_t(n));
    }
    ::close(fd);
    return out;
}

bool CanConnect(uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const bool ok =
        ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
    ::close(fd);
    return ok;
}

class FakeSession final : public WsSession {
public:
    void SendBinary(Bytes msg) override {
        std::lock_guard lock(mutex);
        sent.push_back(std::move(msg));
        cv.notify_all();
    }
    void Close() override {}
    const std::string &PeerIp() const override { return ip; }
    void NotifyActivity() override {}
    bool WaitFor(size_t n) {
        std::unique_lock lock(mutex);
        return cv.wait_for(lock, 10s, [&] { return sent.size() >= n; });
    }
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<Bytes> sent;
    std::string ip = "127.0.0.1";
};

int32_t TipHeight(Service &service) {
    auto snap = service.Impl().indexer->Impl().Snapshot();
    auto tip = index::BlockReader(snap.Store(), snap.Txn()).Tip();
    return tip ? tip->height : -1;
}

} // namespace

BOOST_AUTO_TEST_SUITE(service_tests)

// ---------------------------------------------------------------------------
// -chronikbind parsing (bridge.rs parse_socket_addr)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(parse_chronik_host) {
    const auto check = [](const std::string &host, const std::string &ip,
                          uint16_t port) {
        const ListenerBind bind = ParseChronikHost(host, 8331);
        BOOST_CHECK_EQUAL(bind.ip, ip);
        BOOST_CHECK_EQUAL(bind.port, port);
    };
    check("127.0.0.1", "127.0.0.1", 8331);
    check("127.0.0.1:1234", "127.0.0.1", 1234);
    check("0.0.0.0:0", "0.0.0.0", 0);
    check("::1", "::1", 8331);
    check("[::1]:5", "::1", 5);
    check("0:0:0:0:0:0:0:1", "::1", 8331);
    check("2001:DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1", 8331);
    check("::ffff:1.2.3.4", "::ffff:1.2.3.4", 8331);
    check("[::]:65535", "::", 65535);
    for (const std::string bad :
         {"localhost", "1.2.3", "01.2.3.4", "1.2.3.4:", "1.2.3.4:65536",
          "256.1.1.1", "[::1]", "::1:8331:", "fe80::1%en0", " 1.2.3.4", ""}) {
        BOOST_CHECK_EQUAL(nt::ErrorMsg([&] { ParseChronikHost(bad, 1); }),
                          "Invalid Chronik host address " + RustDebugStr(bad) +
                              ": invalid IP address syntax");
    }
    BOOST_CHECK_EQUAL(
        DebugSocketAddrs({{"127.0.0.1", 8331}, {"::1", 8331}}),
        "[127.0.0.1:8331, [::1]:8331]");
    BOOST_CHECK_EQUAL(DebugSocketAddrs({}), "[]");
}

// ---------------------------------------------------------------------------
// Startup / shutdown
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(start_resyncs_and_serves) {
    ServiceEnv env("service-start");
    auto service = Service::Start(env.host, env.Params({"127.0.0.1:0"}));
    BOOST_REQUIRE(service);
    BOOST_CHECK(env.host.HasLog("Starting Chronik bound to [127.0.0.1:0]\n"));
    BOOST_CHECK(env.host.HasLog(
        "Chronik subscription limits: max_subs=10000000, "
        "max_subs_per_ip=75000, subscription_max_script_size=201, "
        "subscription_max_plugin_size=100\n"));
    BOOST_CHECK_EQUAL(TipHeight(*service), 2);

    // In-process HTTP
    HttpResponse resp = Call(*service, Get("/blockchain-info"));
    BOOST_CHECK_EQUAL(resp.status, 200);
    BOOST_CHECK_EQUAL(resp.ContentType(), "application/x-protobuf");
    proto::BlockchainInfo info;
    BOOST_REQUIRE(info.ParseFromArray(resp.body.data(), int(resp.body.size())));
    BOOST_CHECK_EQUAL(info.tip_height(), 2);
    const BlockHash tip = env.host.ActiveBlock(2).info.hash;
    BOOST_CHECK(info.tip_hash() == std::string(tip.b.begin(), tip.b.end()));
    resp = Call(*service, Get("/chronik-info"));
    proto::ChronikInfo chronik_info;
    BOOST_REQUIRE(
        chronik_info.ParseFromArray(resp.body.data(), int(resp.body.size())));
    BOOST_CHECK_EQUAL(chronik_info.version(), "v0.0.0-test");
    BOOST_CHECK_EQUAL(Call(*service, Get("/nope")).status, 404);

    // Standalone listener
    const auto ports = service->Impl().BoundPorts();
    BOOST_REQUIRE_EQUAL(ports.size(), 1u);
    BOOST_REQUIRE_NE(ports[0], 0);
    const std::string raw = RawGet(ports[0], "/blockchain-info");
    BOOST_CHECK(raw.starts_with("HTTP/1.1 200"));

    service->Stop();
    BOOST_CHECK(!CanConnect(ports[0]));
}

BOOST_AUTO_TEST_CASE(start_without_bind) {
    ServiceEnv env("service-nobind", 1);
    auto service = Service::Start(env.host, env.Params());
    BOOST_REQUIRE(service);
    BOOST_CHECK(env.host.HasLog("Starting Chronik bound to []\n"));
    BOOST_CHECK(service->Impl().BoundPorts().empty());
    BOOST_CHECK_EQUAL(Call(*service, Get("/blockchain-info")).status, 200);
}

BOOST_AUTO_TEST_CASE(start_returns_null_on_shutdown_during_resync) {
    ServiceEnv env("service-shutdown", 5);
    env.host.ShutdownAfter(2);
    auto service = Service::Start(env.host, env.Params({"127.0.0.1:0"}));
    BOOST_CHECK(!service);
    BOOST_CHECK(env.host.HasLog("Stopped re-sync adding blocks\n"));
    BOOST_CHECK(!env.host.HasLog("Chronik subscription limits"));
    // Restart continues
    env.host.SetShutdown(false);
    service = Service::Start(env.host, env.Params());
    BOOST_REQUIRE(service);
    BOOST_CHECK_EQUAL(TipHeight(*service), 4);
}

BOOST_AUTO_TEST_CASE(start_invalid_bind) {
    ServiceEnv env("service-badbind", 1);
    BOOST_CHECK_EQUAL(
        nt::ErrorMsg(
            [&] { Service::Start(env.host, env.Params({"localhost:80"})); }),
        "Invalid Chronik host address \"localhost:80\": invalid IP address "
        "syntax");
}

BOOST_AUTO_TEST_CASE(start_resync_error_propagates) {
    ServiceEnv env("service-resync-error", 2);
    {
        auto service = Service::Start(env.host, env.Params());
        BOOST_REQUIRE(service);
    }
    th::FakeHost empty;
    ServiceParams p = env.Params();
    BOOST_CHECK(nt::ErrorMsg([&] { Service::Start(empty, p); })
                    .starts_with("Cannot rewind Chronik, it contains block "));
}

// ---------------------------------------------------------------------------
// Events, OkOrAbort and logs
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(events_and_logs) {
    ServiceEnv env("service-events", 2);
    env.host.Caps().avalanche = true;
    auto service = Service::Start(env.host, env.Params());
    BOOST_REQUIRE(service);
    Block block = env.host.MakeBlock(1, {});
    env.host.Extend(block);
    service->HandleBlockConnected(block);
    BOOST_CHECK_EQUAL(TipHeight(*service), 2);
    service->HandleBlockFinalized(block.info);
    BOOST_CHECK(env.host.HasLog("Chronik: block " + HashToHex(block.info.hash) +
                                " finalized with 1 txs\n"));
    service->HandleBlockInvalidated(block);
    BOOST_CHECK(env.host.HasLog("Chronik: block " + HashToHex(block.info.hash) +
                                " invalidated with 1 txs\n"));
    const TxId cb = block.txs[0].tx->txid;
    service->HandleTxFinalized(cb);
    BOOST_CHECK(env.host.HasLog("Chronik: transaction " + HashToHex(cb) +
                                " finalized by pre-consensus\n"));
    service->HandleTxInvalidated(block.txs[0].tx);
    BOOST_CHECK(env.host.HasLog("Chronik: transaction " + HashToHex(cb) +
                                " invalidated by pre-consensus\n"));

    // A failing event: OkOrAbort reports it through Host::FatalError
    const TxId unknown = nt::TxIdNum(0x31);
    BOOST_CHECK(!OkOrAbort(env.host, "handle_tx_removed_from_mempool", [&] {
        service->HandleTxRemovedFromMempool(unknown);
    }));
    const auto fatal = env.host.FatalErrors();
    BOOST_REQUIRE_EQUAL(fatal.size(), 1u);
    BOOST_CHECK_EQUAL(fatal[0].first,
                      "ERROR Chronik in handle_tx_removed_from_mempool");
    BOOST_CHECK_EQUAL(fatal[0].second,
                      "No such mempool tx: " + HashToHex(unknown));
    // Queries now fail with 500
    BOOST_CHECK_EQUAL(Call(*service, Get("/blockchain-info")).status, 500);
}

// ---------------------------------------------------------------------------
// Pause / resume
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pause_not_allowed) {
    ServiceEnv env("service-pause-off", 1);
    auto service = Service::Start(env.host, env.Params());
    BOOST_REQUIRE(service);
    for (const char *path : {"/pause", "/resume"}) {
        HttpResponse resp = Call(*service, Get(path));
        BOOST_CHECK_EQUAL(resp.status, 403);
        proto::Error err;
        BOOST_REQUIRE(err.ParseFromArray(resp.body.data(), int(resp.body.size())));
        BOOST_CHECK_EQUAL(err.msg(), std::string(PAUSE_NOT_ALLOWED_MSG));
    }
    // Interrupt with pausing disallowed works
    service->Interrupt();
}

BOOST_AUTO_TEST_CASE(pause_blocks_events_until_resume) {
    ServiceEnv env("service-pause", 1);
    ServiceParams p = env.Params();
    p.is_pause_allowed = true;
    auto service = Service::Start(env.host, p);
    BOOST_REQUIRE(service);
    BOOST_CHECK_EQUAL(Call(*service, Get("/pause")).status, 200);
    Block block = env.host.MakeBlock(0, {});
    env.host.Extend(block);
    std::atomic<bool> done{false};
    std::thread writer([&] {
        service->HandleBlockConnected(block);
        done = true;
    });
    std::this_thread::sleep_for(200ms);
    BOOST_CHECK(!done.load());
    BOOST_CHECK_EQUAL(TipHeight(*service), 0);
    BOOST_CHECK(env.host.HasLog(std::string(PAUSE_BLOCKING_LOG_MSG)));
    // Queries still work while paused
    BOOST_CHECK_EQUAL(Call(*service, Get("/blockchain-info")).status, 200);
    BOOST_CHECK_EQUAL(Call(*service, Get("/resume")).status, 200);
    writer.join();
    BOOST_CHECK(done.load());
    BOOST_CHECK_EQUAL(TipHeight(*service), 1);
}

BOOST_AUTO_TEST_CASE(interrupt_releases_paused_writer) {
    ServiceEnv env("service-pause-interrupt", 1);
    ServiceParams p = env.Params();
    p.is_pause_allowed = true;
    auto service = Service::Start(env.host, p);
    BOOST_REQUIRE(service);
    BOOST_CHECK_EQUAL(Call(*service, Get("/pause")).status, 200);
    Block block = env.host.MakeBlock(0, {});
    env.host.Extend(block);
    std::thread writer([&] { service->HandleBlockConnected(block); });
    std::this_thread::sleep_for(100ms);
    service->Interrupt();
    writer.join();
    BOOST_CHECK_EQUAL(TipHeight(*service), 1);
}

// ---------------------------------------------------------------------------
// WebSocket entry and interrupt
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(in_process_websocket) {
    ServiceEnv env("service-ws", 1);
    auto service = Service::Start(env.host, env.Params());
    BOOST_REQUIRE(service);
    BOOST_CHECK(service->WsPingInterval() == 45s);

    HttpRequest upgrade = Get("/ws");
    upgrade.headers = {{"Connection", "Upgrade"},
                       {"Upgrade", "websocket"},
                       {"Sec-WebSocket-Version", "13"},
                       {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}};
    BOOST_CHECK(service->CheckWsUpgrade(upgrade).has_value());
    BOOST_CHECK(!service->CheckWsUpgrade(Get("/blockchain-info")).has_value());

    auto session = std::make_shared<FakeSession>();
    auto exec = service->MakeSerialExecutor();
    std::unique_ptr<WsHandler> handler;
    std::promise<void> accepted;
    exec([&] {
        handler = service->AcceptWs(session);
        proto::WsSub sub;
        sub.mutable_blocks();
        const std::string s = sub.SerializeAsString();
        handler->OnBinary(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(s.data()), s.size()));
        accepted.set_value();
    });
    accepted.get_future().wait();
    Block block = env.host.MakeBlock(0, {});
    env.host.Extend(block);
    service->HandleBlockConnected(block);
    BOOST_REQUIRE(session->WaitFor(1));
    proto::WsMsg msg;
    BOOST_REQUIRE(msg.ParseFromArray(session->sent[0].data(),
                                     int(session->sent[0].size())));
    BOOST_CHECK_EQUAL(msg.block().msg_type(), proto::BLK_CONNECTED);
    BOOST_CHECK_EQUAL(msg.block().block_height(), 1);
    std::promise<void> closed;
    exec([&] {
        handler->OnClosed();
        handler.reset();
        closed.set_value();
    });
    closed.get_future().wait();
    BOOST_CHECK_EQUAL(service->Impl().limiter->Total(), 0u);
}

BOOST_AUTO_TEST_CASE(interrupt_answers_503_and_stops_listener) {
    ServiceEnv env("service-interrupt", 1);
    auto service = Service::Start(env.host, env.Params({"127.0.0.1:0"}));
    BOOST_REQUIRE(service);
    const uint16_t port = service->Impl().BoundPorts().at(0);
    BOOST_CHECK(CanConnect(port));
    service->Interrupt();
    service->Interrupt(); // idempotent
    BOOST_CHECK(!CanConnect(port));
    HttpResponse resp = Call(*service, Get("/blockchain-info"));
    BOOST_CHECK_EQUAL(resp.status, 503);
    BOOST_CHECK_EQUAL(BodyStr(resp), "Chronik is shutting down");
    HttpRequest upgrade = Get("/ws");
    upgrade.headers = {{"Connection", "Upgrade"},
                       {"Upgrade", "websocket"},
                       {"Sec-WebSocket-Version", "13"},
                       {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="}};
    BOOST_CHECK(!service->CheckWsUpgrade(upgrade).has_value());
    // Events still reach the indexer after interrupt (until Stop)
    Block block = env.host.MakeBlock(0, {});
    env.host.Extend(block);
    service->HandleBlockConnected(block);
    BOOST_CHECK_EQUAL(TipHeight(*service), 1);
    service->Stop();
    service->Stop(); // idempotent
}

BOOST_AUTO_TEST_SUITE_END()
