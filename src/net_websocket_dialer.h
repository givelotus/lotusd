// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_DIALER_H
#define BITCOIN_NET_WEBSOCKET_DIALER_H

#include <util/fs.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <net_websocket.h>

//! What outbound P2P WebSockets offer, in order of preference
static const char *const DEFAULT_P2P_WEBSOCKET_OFFER = "p2p-v2";

/**
 * Start the outbound P2P WebSocket dialer (its own I/O thread) and register
 * it with SetWebSocketDialer(). If given, the certificate is presented to
 * wss:// peers that ask for one (see -tlsmutual). New TLS handshakes pick
 * up changed certificate/key files; invalid replacements keep the last valid
 * identity and existing sessions retain their original identity. `offer` is a
 * comma separated subset of DEFAULT_P2P_WEBSOCKET_OFFER, or "none". `pins` are
 * -p2pwebsocketpin entries "<host>=<pin>" (see DecodeSpkiPin); returns
 * false if one is invalid. With `http2` (and HTTP/2 support built in),
 * wss:// offers ALPN h2 before http/1.1 and opens the WebSocket with an
 * RFC 8441 extended CONNECT when the server selects h2; otherwise only
 * http/1.1 is offered.
 */
bool StartP2PWebSocketDialer(const std::optional<fs::path> &client_cert,
                             const std::optional<fs::path> &client_key,
                             const std::string &offer,
                             const std::vector<std::string> &pins = {},
                             bool http2 = false);

/** Unregister and stop the dialer. Call after CConnman::Stop(). */
void StopP2PWebSocketDialer();

#endif // BITCOIN_NET_WEBSOCKET_DIALER_H
