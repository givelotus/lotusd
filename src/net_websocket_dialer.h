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

/** A ws:// or wss:// P2P peer URL */
struct ParsedWebSocketURL {
    bool tls{false};
    std::string host;
    uint16_t port{0};
    //! Value of the Host header: host:port, with [] around IPv6 literals
    std::string authority;
    //! Request target, "/p2p/ws" if the URL has no path
    std::string target;
};

/** Parse ws://host[:port][/path] (default port 80) or wss:// (443) */
std::optional<ParsedWebSocketURL> ParseWebSocketURL(std::string_view url);

//! What outbound P2P WebSockets offer, in order of preference
static const char *const DEFAULT_P2P_WEBSOCKET_OFFER =
    "p2p-zstd-v1,p2p-zstd,permessage-deflate";

/**
 * Start the outbound P2P WebSocket dialer (its own I/O thread) and register
 * it with SetWebSocketDialer(). If given, the certificate is presented to
 * wss:// peers that ask for one (see -tlsmutual). `offer` is a comma
 * separated subset of DEFAULT_P2P_WEBSOCKET_OFFER, or "none".
 */
bool StartP2PWebSocketDialer(const std::optional<fs::path> &client_cert,
                             const std::optional<fs::path> &client_key,
                             const std::string &offer);

/** Unregister and stop the dialer. Call after CConnman::Stop(). */
void StopP2PWebSocketDialer();

#endif // BITCOIN_NET_WEBSOCKET_DIALER_H
