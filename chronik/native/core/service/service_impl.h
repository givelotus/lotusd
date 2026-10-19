// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_SERVICE_SERVICE_IMPL_H
#define CHRONIK_NATIVE_CORE_SERVICE_SERVICE_IMPL_H

#include <chronik/native/http.h>
#include <chronik/native/indexer.h>
#include <chronik/native/pause.h>
#include <chronik/native/service.h>
#include <chronik/native/subscription_limits.h>
#include <chronik/native/transport/beast_listener.h>
#include <chronik/native/transport/query_pool.h>
#include <chronik/native/ws.h>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace chronik::native {

/** State of a running Service (see service.h). */
class ServiceImpl {
public:
    ServiceImpl(const Host &host, ServiceParams params);
    ~ServiceImpl();

    /** Pause::block_if_paused; no-op once interrupted (runtime gone). */
    void BlockIfPaused() const;
    std::unique_ptr<WsHandler> MakeWsHandler(std::shared_ptr<WsSession> s);
    std::function<void(std::function<void()>)> MakeSerialExecutor();
    /** Ports actually bound by the standalone listener (tests, port 0). */
    std::vector<uint16_t> BoundPorts() const;
    void Interrupt();
    void Stop();

    const Host &host;
    ServiceParams params;
    std::vector<ListenerBind> binds;
    std::unique_ptr<Indexer> indexer;
    std::optional<Pause> pause;
    std::shared_ptr<PauseNotify> pause_notify;
    std::shared_ptr<SubscriptionLimiter> limiter;
    std::unique_ptr<Router> router;
    std::unique_ptr<QueryPool> pool;
    std::unique_ptr<BeastListener> listener;
    std::atomic<bool> interrupted{false};
    std::atomic<bool> stopped{false};
};

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CORE_SERVICE_SERVICE_IMPL_H
