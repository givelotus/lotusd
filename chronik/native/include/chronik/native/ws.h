// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_WS_H
#define CHRONIK_NATIVE_WS_H

#include <chronik/native/types.h>

#include <functional>
#include <memory>
#include <span>
#include <string>

/**
 * Transport-neutral WebSocket session interfaces (design §6.1).
 *
 * The transport (standalone Beast listener, or the node's in-process
 * /chronik/ws) implements WsSession; the core implements one WsHandler per
 * session (port of chronik-http ws.rs handle_subscribe_socket).
 *
 * Threading: a transport calls the WsHandler methods of one session one at a
 * time, in order, never on an io thread (they run serialized on the query
 * pool, so a handler may take the indexer's shared lock). OnClosed is called
 * exactly once, last; afterwards the transport drops the handler.
 *
 * The transport itself implements the protocol-level parts of ws.rs:
 *  - binary frames are passed to OnBinary, text frames call OnText;
 *  - Ping is answered with Pong; Pong is ignored;
 *  - Close or an error ends the session (OnClosed);
 *  - messages/frames above MAX_WS_MESSAGE_SIZE (20,000 B) end the session;
 *  - after `ping_interval` without session activity, a Ping with payload
 *    "Bitcoin ABC Chronik Indexer" is sent. Rust re-arms that sleep on every
 *    loop iteration, i.e. after any client message and any subscription
 *    event; the transport resets it on every received frame and every
 *    SendBinary, and the handler calls NotifyActivity() for events it handled
 *    without sending (e.g. deduplicated messages).
 */
namespace chronik::native {

/** Payload of Chronik's keep-alive pings (ws.rs schedule_ping). */
constexpr const char *WS_PING_PAYLOAD = "Bitcoin ABC Chronik Indexer";

class WsSession {
public:
    virtual ~WsSession() = default;
    /** Non-blocking enqueue of a binary message; callable from any thread. */
    virtual void SendBinary(Bytes msg) = 0;
    /** Close the connection (normal closure); callable from any thread. */
    virtual void Close() = 0;
    /** Real client IP address, without port. */
    virtual const std::string &PeerIp() const = 0;
    /** Restart the idle-ping timer (see above). */
    virtual void NotifyActivity() = 0;
};

class WsHandler {
public:
    virtual ~WsHandler() = default;
    /** A binary message (a proto::WsSub) */
    virtual void OnBinary(std::span<const uint8_t> msg) = 0;
    /** A text message (Rust replies with an "Unexpected message type" error) */
    virtual void OnText() = 0;
    /** The session ended; release subscriptions. Called exactly once. */
    virtual void OnClosed() = 0;
};

/**
 * Creates the handler for a newly upgraded session. The handler may keep the
 * shared_ptr to its session to send messages; it must drop it in OnClosed().
 */
using WsAccept =
    std::function<std::unique_ptr<WsHandler>(std::shared_ptr<WsSession>)>;

} // namespace chronik::native

#endif // CHRONIK_NATIVE_WS_H
