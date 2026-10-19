// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-lib bridge.rs (try_setup_chronik, Chronik::handle_*,
// interrupt, stop) and of the server setup of chronik-http server.rs, without
// Electrum and plugins.

#include <chronik/native/service.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/http.h>
#include <chronik/native/indexer_impl.h>
#include <chronik/native/index/blocks.h>
#include <chronik/native/pause.h>
#include <chronik/native/proto.h>
#include <chronik/native/routes.h>
#include <chronik/native/subscription_limits.h>
#include <chronik/native/transport/beast_listener.h>
#include <chronik/native/transport/query_pool.h>
#include <chronik/native/ws.h>

#include <core/service/bind_parse.h>
#include <core/service/service_impl.h>
#include <core/ws/ws_handler.h>

#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>


namespace chronik::native {

namespace {

constexpr std::string_view SHUTTING_DOWN_MSG = "Chronik is shutting down";

HttpLogFn MakeHttpLog(const Host &host) {
    return [&host](std::string_view msg, bool debug_only) {
        host.Log(debug_only ? LogLevel::Debug : LogLevel::Info, msg);
    };
}

size_t NumQueryWorkers(size_t requested) {
    if (requested != 0) {
        return requested;
    }
    return QueryPool::DefaultThreads();
}

} // namespace

ServiceImpl::ServiceImpl(const Host &host_, ServiceParams params_)
    : host(host_), params(std::move(params_)) {}

ServiceImpl::~ServiceImpl() = default;

void ServiceImpl::BlockIfPaused() const {
    // Rust only blocks while the runtime (HTTP side) is alive.
    if (interrupted.load() || !pause) {
        return;
    }
    pause->BlockIfPaused([this](LogLevel level, std::string_view msg) {
        host.Log(level, msg);
    });
}

std::unique_ptr<Service>
Service::Start(const Host &host, ServiceParams params,
               std::vector<std::unique_ptr<Extension>> exts) {
    auto impl = std::make_unique<ServiceImpl>(host, std::move(params));
    ServiceParams &p = impl->params;

    for (const std::string &bind : p.hosts) {
        impl->binds.push_back(ParseChronikHost(bind, p.default_port));
    }
    host.Log(LogLevel::Info, "Starting Chronik bound to " +
                                 DebugSocketAddrs(impl->binds) + "\n");
    auto [pause, pause_notify] = Pause::NewPair(p.is_pause_allowed);
    impl->pause.emplace(std::move(pause));
    impl->pause_notify =
        std::make_shared<PauseNotify>(std::move(pause_notify));

    p.indexer.observe_indexed_height = p.observe_indexed_height;
    impl->indexer = Indexer::Open(host, p.indexer, std::move(exts));
    impl->indexer->Resync();
    if (host.ShutdownRequested()) {
        // Don't setup Chronik if the user requested shutdown during resync
        impl->indexer->Close();
        return nullptr;
    }

    if (p.observe_indexed_height) {
        try {
            int32_t height = -1;
            {
                auto snapshot = impl->indexer->Impl().Snapshot();
                const auto tip =
                    index::BlockReader(snapshot.Store(), snapshot.Txn()).Tip();
                if (tip) height = tip->height;
            }
            p.observe_indexed_height(height);
        } catch (...) {
            // Optional bookkeeping cannot turn a successful resync into failure.
        }
    }
    impl->limiter = SubscriptionLimiter::Create(
        p.max_subs, p.max_subs_per_ip, p.observe_ws_subscriptions);
    host.Log(LogLevel::Info,
             "Chronik subscription limits: max_subs=" +
                 std::to_string(p.max_subs) +
                 ", max_subs_per_ip=" + std::to_string(p.max_subs_per_ip) +
                 ", subscription_max_script_size=" +
                 std::to_string(p.subscription_max_script_size) +
                 ", subscription_max_plugin_size=" +
                 std::to_string(p.subscription_max_plugin_size) + "\n");

    // ---- router (server.rs make_router) ----
    RouterOptions router_opts;
    router_opts.enable_cors = p.enable_cors;
    router_opts.log = MakeHttpLog(host);
    router_opts.observe_request = p.observe_request;
    impl->router = std::make_unique<Router>(std::move(router_opts));
    const IndexerImpl &indexer = impl->indexer->Impl();
    RegisterCoreRoutes(*impl->router,
                       RouteContext{indexer, host, impl->limiter});
    impl->router->AddWebSocket("/ws");
    std::shared_ptr<PauseNotify> notify = impl->pause_notify;
    impl->router->Get("/pause",
                      [notify](const HttpRequest &, const PathParams &) {
                          notify->DoPause();
                          return HttpResponse::Protobuf(proto::Empty());
                      });
    impl->router->Get("/resume",
                      [notify](const HttpRequest &, const PathParams &) {
                          notify->Resume();
                          return HttpResponse::Protobuf(proto::Empty());
                      });
    for (const auto &ext : indexer.Extensions()) {
        // RegisterWsScriptTypes takes the undefined SubscriptionHub (see
        // extension.h); no extension implements it yet.
        ext->RegisterRoutes(*impl->router);
    }

    impl->pool =
        std::make_unique<QueryPool>(NumQueryWorkers(p.query_workers));

    // ---- standalone listener(s) on -chronikbind ----
    if (!impl->binds.empty()) {
        ListenerOptions opts;
        opts.binds = impl->binds;
        opts.ws_ping_interval =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                p.ws_ping_interval);
        opts.ws_max_message_size = MAX_WS_MESSAGE_SIZE;
        ServiceImpl *raw = impl.get();
        impl->listener = std::make_unique<BeastListener>(
            *impl->router, *impl->pool,
            [raw](std::shared_ptr<WsSession> session) {
                return raw->MakeWsHandler(std::move(session));
            },
            std::move(opts));
        impl->listener->Start();
    }
    return std::unique_ptr<Service>(new Service(std::move(impl)));
}

std::unique_ptr<WsHandler>
ServiceImpl::MakeWsHandler(std::shared_ptr<WsSession> session) {
    WsHandlerSettings settings;
    settings.subscription_max_script_size =
        params.subscription_max_script_size;
    settings.subscription_max_plugin_size =
        params.subscription_max_plugin_size;
    settings.observe_connections = params.observe_ws_connections;
    return MakeChronikWsHandler(std::move(session),
                                indexer->Impl().SubsPtr(), limiter, settings,
                                MakeSerialExecutor(), MakeHttpLog(host));
}

std::function<void(std::function<void()>)> ServiceImpl::MakeSerialExecutor() {
    auto strand = std::make_shared<
        boost::asio::strand<QueryPool::executor_type>>(pool->MakeStrand());
    return [strand](std::function<void()> fn) {
        boost::asio::post(*strand, std::move(fn));
    };
}

std::vector<uint16_t> ServiceImpl::BoundPorts() const {
    return listener ? listener->BoundPorts() : std::vector<uint16_t>{};
}

void ServiceImpl::Interrupt() {
    if (interrupted.exchange(true)) {
        return;
    }
    // Release a writer blocked by /pause (Rust: runtime shut down)
    if (pause_notify && pause_notify->IsPauseAllowed()) {
        try {
            pause_notify->Resume();
        } catch (const std::exception &) {
            // The Pause side is gone: nothing can be blocked
        }
    }
    if (listener) {
        listener->Stop();
    }
    if (pool) {
        // Let queued handlers (incl. WebSocket OnClosed) finish, then join
        pool->Join();
    }
}

void ServiceImpl::Stop() {
    Interrupt();
    if (stopped.exchange(true)) {
        return;
    }
    if (indexer) {
        indexer->Close();
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

Service::Service(std::unique_ptr<ServiceImpl> impl) : m_impl(std::move(impl)) {}

Service::~Service() {
    try {
        m_impl->Stop();
    } catch (const std::exception &e) {
        m_impl->host.Log(LogLevel::Info,
                         std::string("Error stopping Chronik: ") + e.what() +
                             "\n");
    }
    // Listener and pool before the indexer they reference
    m_impl->listener.reset();
    m_impl->pool.reset();
    m_impl->router.reset();
}

void Service::HandleTxAddedToMempool(TxRef tx, int64_t time_first_seen) {
    m_impl->BlockIfPaused();
    m_impl->indexer->OnTxAddedToMempool(std::move(tx), time_first_seen);
}

void Service::HandleTxRemovedFromMempool(const TxId &txid) {
    m_impl->BlockIfPaused();
    m_impl->indexer->OnTxRemovedFromMempool(txid);
}

void Service::HandleBlockConnected(Block block) {
    m_impl->BlockIfPaused();
    m_impl->indexer->OnBlockConnected(std::move(block));
}

void Service::HandleBlockDisconnected(Block block) {
    m_impl->BlockIfPaused();
    m_impl->indexer->OnBlockDisconnected(std::move(block));
}

void Service::HandleBlockFinalized(const BlockInfo &info) {
    m_impl->BlockIfPaused();
    // Logs "Chronik: block .. finalized with .. txs" (it loads the block)
    m_impl->indexer->OnBlockFinalized(info);
}

void Service::HandleBlockInvalidated(Block block) {
    m_impl->BlockIfPaused();
    const std::string hash = HashToHex(block.info.hash);
    const size_t num_txs = block.txs.size();
    m_impl->indexer->OnBlockInvalidated(std::move(block));
    m_impl->host.Log(LogLevel::Debug, "Chronik: block " + hash +
                                          " invalidated with " +
                                          std::to_string(num_txs) + " txs\n");
}

void Service::HandleTxFinalized(const TxId &txid) {
    m_impl->BlockIfPaused();
    m_impl->indexer->OnTxFinalized(txid);
    m_impl->host.Log(LogLevel::Debug, "Chronik: transaction " +
                                          HashToHex(txid) +
                                          " finalized by pre-consensus\n");
}

void Service::HandleTxInvalidated(TxRef tx) {
    m_impl->BlockIfPaused();
    const TxId txid = tx->txid;
    m_impl->indexer->OnTxInvalidated(std::move(tx));
    m_impl->host.Log(LogLevel::Debug, "Chronik: transaction " +
                                          HashToHex(txid) +
                                          " invalidated by pre-consensus\n");
}

void Service::HandleHttpAsync(HttpRequest req,
                              std::function<void(HttpResponse)> done) {
    if (m_impl->interrupted.load()) {
        done(HttpResponse::Text(503, SHUTTING_DOWN_MSG));
        return;
    }
    ServiceImpl *impl = m_impl.get();
    m_impl->pool->Post(
        [impl, req = std::move(req), done = std::move(done)]() mutable {
            if (impl->interrupted.load()) {
                done(HttpResponse::Text(503, SHUTTING_DOWN_MSG));
                return;
            }
            done(impl->router->Handle(req));
        });
}

std::optional<std::vector<std::pair<std::string, std::string>>>
Service::CheckWsUpgrade(const HttpRequest &req) const {
    if (m_impl->interrupted.load() || !m_impl->router->IsWebSocketUpgrade(req)) {
        return std::nullopt;
    }
    return m_impl->router->UpgradeResponseHeaders(req);
}

std::unique_ptr<WsHandler>
Service::AcceptWs(std::shared_ptr<WsSession> session) {
    return m_impl->MakeWsHandler(std::move(session));
}

std::function<void(std::function<void()>)> Service::MakeSerialExecutor() {
    return m_impl->MakeSerialExecutor();
}

std::chrono::milliseconds Service::WsPingInterval() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        m_impl->params.ws_ping_interval);
}

void Service::Interrupt() { m_impl->Interrupt(); }

void Service::Stop() { m_impl->Stop(); }

} // namespace chronik::native
