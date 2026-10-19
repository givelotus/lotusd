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
static const char *const DEFAULT_P2P_WEBSOCKET_OFFER =
    "p2p-zstd-v1,p2p-zstd";

/**
 * Start the outbound P2P WebSocket dialer (its own I/O thread) and register
 * it with SetWebSocketDialer(). If given, the certificate is presented to
 * wss:// peers that ask for one (see -tlsmutual). `offer` is a comma
 * separated subset of DEFAULT_P2P_WEBSOCKET_OFFER, or "none". `pins` are
 * -p2pwebsocketpin entries "<host>=<pin>" (see DecodeSpkiPin); returns
 * false if one is invalid.
 */
bool StartP2PWebSocketDialer(const std::optional<fs::path> &client_cert,
                             const std::optional<fs::path> &client_key,
                             const std::string &offer,
                             const std::vector<std::string> &pins = {});

/** Unregister and stop the dialer. Call after CConnman::Stop(). */
void StopP2PWebSocketDialer();

#endif // BITCOIN_NET_WEBSOCKET_DIALER_H
