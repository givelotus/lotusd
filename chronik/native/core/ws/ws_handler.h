// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_CORE_WS_WS_HANDLER_H
#define CHRONIK_NATIVE_CORE_WS_WS_HANDLER_H

#include <chronik/native/http.h>
#include <chronik/native/subs.h>
#include <chronik/native/subscription_limits.h>
#include <chronik/native/ws.h>

#include <cstddef>
#include <functional>
#include <memory>

/**
 * Port of chronik-http ws.rs handle_subscribe_socket (the per-session
 * subscription logic; framing/ping/pong/size limits are the transport's).
 *
 * Mapping of the Rust select loop:
 *  - client messages arrive through OnBinary/OnText/OnClosed;
 *  - subscription receivers wake the handler (BroadcastReceiver::SetWaker),
 *    which posts a drain to `post` (a serial executor). A drain handles
 *    queued subscription messages one at a time in the biased Rust order:
 *    blocks, txs, txids, scripts, token_ids, lokad_ids;
 *  - Lagged (and Closed) yields WsAction::Nothing: no message, only
 *    NotifyActivity() (Rust re-arms the ping timer on every loop);
 *  - consecutive identical block/tx messages are deduplicated (also only
 *    NotifyActivity());
 *  - errors are sent as WsMsg{error} (never deduplicated).
 * Plugins are not supported: plugin subscriptions report Rust's
 * PluginGroupTooLarge / PluginNotLoaded errors.
 *
 * All entry points (and drains) are serialized by an internal mutex, so the
 * transport may call them from any thread (one at a time per its own
 * contract).
 */
namespace chronik::native {

struct WsHandlerSettings {
    /** -chroniksubsmaxscriptsize */
    size_t subscription_max_script_size = DEFAULT_SUBSCRIPTION_MAX_SCRIPT_SIZE;
    /** -chroniksubsmaxpluginsize */
    size_t subscription_max_plugin_size = 100;
    /** Immutable atomic-only/noexcept host callback; +1 open, -1 cleanup. */
    std::function<void(int32_t)> observe_connections;
};

/** Posts a task; tasks posted by one handler must run one at a time. */
using SerialExecutor = std::function<void(std::function<void()>)>;

std::unique_ptr<WsHandler>
MakeChronikWsHandler(std::shared_ptr<WsSession> session,
                     std::shared_ptr<SubsHub> hub,
                     std::shared_ptr<SubscriptionLimiter> limiter,
                     WsHandlerSettings settings, SerialExecutor post,
                     HttpLogFn log = {});

} // namespace chronik::native

#endif // CHRONIK_NATIVE_CORE_WS_WS_HANDLER_H
