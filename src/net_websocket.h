// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_H
#define BITCOIN_NET_WEBSOCKET_H

#include <netaddress.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

/**
 * P2P over WebSocket (/p2p/ws).
 *
 * The unchanged 24-byte-header P2P wire format is carried in binary WebSocket
 * messages. CConnman sees an ordinary stream socket: one end of a local
 * socketpair whose other end is pumped to/from the WebSocket by the HTTP
 * server's I/O threads. This header has no Boost/OpenSSL/zstd dependency so
 * it can be used by net.cpp in every library that compiles it.
 */

//! URI path of the P2P WebSocket endpoint on the RPC/HTTP port
static const char *const P2P_WEBSOCKET_PATH = "/p2p/ws";
static_assert(std::string_view{"/p2p/ws"} == P2P_WSS_DEFAULT_PATH);
//! Accept P2P connections over WebSocket on the RPC/HTTP port
static const bool DEFAULT_P2P_WEBSOCKET = true;
//! Sec-WebSocket-Protocol tokens, in order of preference
static const char *const P2P_WS_PROTOCOL_ZSTD_DICT = "p2p-zstd-v1";
static const char *const P2P_WS_PROTOCOL_ZSTD = "p2p-zstd";

/** How P2P bytes are compressed inside WebSocket messages */
enum class P2PWebSocketCompression : uint8_t {
    //! Plain binary messages
    NONE,
    //! RFC 7692 permessage-deflate negotiated by the WebSocket layer
    PERMESSAGE_DEFLATE,
    //! One zstd stream per direction, flushed after each message
    ZSTD,
    //! As ZSTD, primed with the prebaked P2P dictionary (P2P_ZSTD_DICT_V1)
    ZSTD_DICT,
};

std::string P2PWebSocketCompressionName(P2PWebSocketCompression c);

/** Current bounded plain WebSocket message size, including P2P framing.
 * Re-evaluated for existing peers when configured/adaptive block limits change.
 */
uint64_t GetP2PWebSocketMessageSizeLimit();

/**
 * Shared between a CNode and the WebSocket bridge feeding it. The bridge
 * updates the counters; RPC reads them.
 */
struct WebSocketTransportInfo {
    bool tls{false};
    P2PWebSocketCompression compression{P2PWebSocketCompression::NONE};
    //! Bytes of P2P data (uncompressed) carried in each direction
    std::atomic<uint64_t> payload_bytes_sent{0};
    std::atomic<uint64_t> payload_bytes_recv{0};
    //! WebSocket frame bytes (headers + possibly compressed payload), before
    //! TLS record overhead
    std::atomic<uint64_t> wire_bytes_sent{0};
    std::atomic<uint64_t> wire_bytes_recv{0};
    //! SHA-256 fingerprint of the peer's TLS certificate, if any
    std::string peer_cert_fingerprint_hex;
    //! base64url SHA-256 of the peer's public key (SPKI), if any
    std::string peer_spki;
    //! The peer's key matched a configured pin
    bool pinned{false};
};

/** Node-wide totals over all P2P WebSocket connections */
struct WebSocketTransportTotals {
    std::atomic<uint64_t> payload_bytes_sent{0};
    std::atomic<uint64_t> payload_bytes_recv{0};
    std::atomic<uint64_t> wire_bytes_sent{0};
    std::atomic<uint64_t> wire_bytes_recv{0};
};
WebSocketTransportTotals &GetWebSocketTransportTotals();

/** A ws:// or wss:// P2P peer URL */
struct ParsedWebSocketURL {
    bool tls{false};
    std::string host;
    uint16_t port{0};
    //! Value of the Host header: host:port, with [] around IPv6 literals
    std::string authority;
    //! Request target, "/p2p/ws" if the URL has no path
    std::string target;
    //! Required SHA-256 of the server's public key (from "#spki=")
    std::optional<std::vector<unsigned char>> spki_pin;
};

/**
 * Parse ws://host[:port][/path][#spki=<pin>] (default port 80) or wss://
 * (443). A pin (see DecodeSpkiPin) is only meaningful for wss://.
 */
std::optional<ParsedWebSocketURL> ParseWebSocketURL(std::string_view url);

/** Encode a public key hash as an unpadded base64url pin */
std::string EncodeSpkiPin(Span<const unsigned char> sha256);

/** Decode a pin (base64url or base64, with or without padding) */
std::optional<std::vector<unsigned char>> DecodeSpkiPin(std::string_view pin);

/** An established outbound P2P WebSocket */
struct WebSocketDialResult {
    //! A WebSocketSock on the connection, for CNode
    std::unique_ptr<Sock> sock;
    std::shared_ptr<WebSocketTransportInfo> info;
};

/**
 * Turns a connected TCP socket (direct or through a proxy) into a P2P
 * WebSocket: TLS for wss:// and the WebSocket upgrade, blocking with an
 * internal timeout. Provided by the node (net_websocket.cpp).
 */
using WebSocketDialer = std::function<std::optional<WebSocketDialResult>(
    std::unique_ptr<Sock> &&tcp, const ParsedWebSocketURL &url,
    CThreadInterrupt &interrupt)>;
void SetWebSocketDialer(WebSocketDialer dialer);
WebSocketDialer GetWebSocketDialer();

/** Whether a -addnode/-connect string is a ws:// or wss:// URL */
bool IsWebSocketURL(std::string_view str);

/** The URL dialed for a dialable NET_WSS address: wss://<name>:<port><path> */
std::string WebSocketURLForAddress(const CService &addr);

/** Size of a WebSocket frame header for a payload of this size */
constexpr uint64_t WebSocketFrameHeaderSize(uint64_t payload_size,
                                            bool masked) {
    return 2 + (payload_size > 65535 ? 8 : payload_size > 125 ? 2 : 0) +
           (masked ? 4 : 0);
}

#endif // BITCOIN_NET_WEBSOCKET_H
