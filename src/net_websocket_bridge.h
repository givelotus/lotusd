// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_BRIDGE_H
#define BITCOIN_NET_WEBSOCKET_BRIDGE_H

#include <compat/compat.h>
#include <logging.h>
#include <net_websocket.h>
#include <net_zstd_dict.h>
#include <span.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <array>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#ifdef BOOST_ASIO_HAS_LOCAL_SOCKETS
#include <boost/asio/local/stream_protocol.hpp>
#include <sys/socket.h>
#define HAVE_P2P_WEBSOCKET_BRIDGE 1
#endif

namespace p2pws {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;

//! Largest chunk of P2P bytes sent as one WebSocket message
static constexpr size_t MAX_BRIDGE_CHUNK = 256 * 1024;
//! Largest WebSocket message accepted (after permessage-deflate inflation)

//! Kernel buffer size requested for both ends of the bridge socketpair
static constexpr int BRIDGE_SOCKET_BUFFER = 1024 * 1024;

/**
 * Choose the P2P compression from a Sec-WebSocket-Protocol offer. Returns
 * the token to echo (empty if none) and the mode; `permessage_deflate` tells
 * whether the client offered that extension (used when no token matches).
 */
inline std::pair<std::string, P2PWebSocketCompression>
NegotiateP2PCompression(std::string_view offered_protocols,
                        bool permessage_deflate_offered) {
    // Lotus v2: p2p-v2 wins wherever it is in the client's list.
    for (std::string_view rest{offered_protocols}; !rest.empty();) {
        const size_t comma{rest.find(',')};
        std::string_view token{rest.substr(0, comma)};
        rest = comma == std::string_view::npos ? std::string_view{}
                                               : rest.substr(comma + 1);
        while (!token.empty() &&
               (token.front() == ' ' || token.front() == '\t')) {
            token.remove_prefix(1);
        }
        while (!token.empty() &&
               (token.back() == ' ' || token.back() == '\t')) {
            token.remove_suffix(1);
        }
        if (token == P2P_WS_PROTOCOL_V2) {
            return {P2P_WS_PROTOCOL_V2, P2PWebSocketCompression::P2P_V2};
        }
    }
    bool zstd{false};
    while (!offered_protocols.empty()) {
        const size_t comma{offered_protocols.find(',')};
        std::string_view token{offered_protocols.substr(0, comma)};
        offered_protocols = comma == std::string_view::npos
                                ? std::string_view{}
                                : offered_protocols.substr(comma + 1);
        while (!token.empty() &&
               (token.front() == ' ' || token.front() == '\t')) {
            token.remove_prefix(1);
        }
        while (!token.empty() &&
               (token.back() == ' ' || token.back() == '\t')) {
            token.remove_suffix(1);
        }
        if (token == P2P_WS_PROTOCOL_ZSTD_DICT) {
            return {P2P_WS_PROTOCOL_ZSTD_DICT,
                    P2PWebSocketCompression::ZSTD_DICT};
        }
        zstd |= token == P2P_WS_PROTOCOL_ZSTD;
    }
    if (zstd) {
        return {P2P_WS_PROTOCOL_ZSTD, P2PWebSocketCompression::ZSTD};
    }
    return {"", permessage_deflate_offered
                    ? P2PWebSocketCompression::PERMESSAGE_DEFLATE
                    : P2PWebSocketCompression::NONE};
}

/** Map the Sec-WebSocket-Protocol a server selected to a mode */
inline P2PWebSocketCompression
CompressionFromSelectedProtocol(std::string_view selected,
                                bool permessage_deflate) {
    if (selected == P2P_WS_PROTOCOL_V2) {
        return P2PWebSocketCompression::P2P_V2;
    }
    if (selected == P2P_WS_PROTOCOL_ZSTD_DICT) {
        return P2PWebSocketCompression::ZSTD_DICT;
    }
    if (selected == P2P_WS_PROTOCOL_ZSTD) {
        return P2PWebSocketCompression::ZSTD;
    }
    return permessage_deflate ? P2PWebSocketCompression::PERMESSAGE_DEFLATE
                              : P2PWebSocketCompression::NONE;
}

/** Apply the WebSocket options used by P2P bridges, before the handshake */
template <typename WS>
void ConfigureP2PWebSocket(WS &ws, beast::role_type role,
                           bool enable_permessage_deflate) {
    websocket::stream_base::timeout timeout{};
    timeout.handshake_timeout = std::chrono::seconds{30};
    // P2P has its own ping/timeout logic, which ends the bridge by closing
    // the socketpair.
    timeout.idle_timeout = websocket::stream_base::none();
    timeout.keep_alive_pings = false;
    ws.set_option(timeout);
    ws.binary(true);
    ws.auto_fragment(false);
    ws.read_message_max(P2PZstdMaxWireSize(GetP2PWebSocketMessageSizeLimit()));
    websocket::permessage_deflate pmd;
    pmd.server_enable =
        enable_permessage_deflate && role == beast::role_type::server;
    pmd.client_enable =
        enable_permessage_deflate && role == beast::role_type::client;
    ws.set_option(pmd);
}

#ifdef HAVE_P2P_WEBSOCKET_BRIDGE
using LocalSocket = asio::local::stream_protocol::socket;

/**
 * Create the socketpair joining CConnman and a bridge: returns
 * {CConnman's end, bridge's end}.
 */
inline std::optional<std::pair<int, int>> CreateBridgeSocketPair() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return std::nullopt;
    }
    for (int fd : sv) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &BRIDGE_SOCKET_BUFFER,
                   sizeof(BRIDGE_SOCKET_BUFFER));
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &BRIDGE_SOCKET_BUFFER,
                   sizeof(BRIDGE_SOCKET_BUFFER));
#ifdef SO_NOSIGPIPE
        const int on{1};
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    }
    return std::make_pair(sv[0], sv[1]);
}

inline void CountSent(WebSocketTransportInfo &info, size_t payload,
                      size_t wire) {
    auto &totals{GetWebSocketTransportTotals()};
    info.payload_bytes_sent += payload;
    info.wire_bytes_sent += wire;
    totals.payload_bytes_sent += payload;
    totals.wire_bytes_sent += wire;
}

inline void CountRecv(WebSocketTransportInfo &info, size_t payload,
                      size_t wire) {
    auto &totals{GetWebSocketTransportTotals()};
    info.payload_bytes_recv += payload;
    info.wire_bytes_recv += wire;
    totals.payload_bytes_recv += payload;
    totals.wire_bytes_recv += wire;
}

/** CConnman -> peer: read P2P bytes, (compress,) send as binary messages */
template <typename WS>
asio::awaitable<void>
PumpLocalToWebSocket(LocalSocket &local, WS &ws, P2PZstdSession *zstd,
                     WebSocketTransportInfo &info, bool masked) {
    std::vector<uint8_t> in(MAX_BRIDGE_CHUNK);
    std::vector<uint8_t> out;
    while (true) {
        auto [rec, n] = co_await local.async_read_some(
            asio::buffer(in), asio::as_tuple(asio::use_awaitable));
        if (rec || n == 0) {
            co_return;
        }
        asio::const_buffer payload{in.data(), n};
        if (zstd) {
            out.clear();
            zstd->CompressFrame(Span<const uint8_t>{in.data(), n}, out);
            payload = asio::const_buffer{out.data(), out.size()};
        }
        auto [wec, wn] = co_await ws.async_write(
            payload, asio::as_tuple(asio::use_awaitable));
        if (wec) {
            co_return;
        }
        // With permessage-deflate the frame size is not observable here.
        CountSent(info, n,
                  payload.size() +
                      WebSocketFrameHeaderSize(payload.size(), masked));
    }
}

/** peer -> CConnman: receive messages, (decompress,) write P2P bytes */
template <typename WS>
asio::awaitable<void>
PumpWebSocketToLocal(WS &ws, LocalSocket &local, P2PZstdSession *zstd,
                     WebSocketTransportInfo &info, bool masked) {
    beast::flat_buffer buffer;
    std::vector<std::vector<uint8_t>> chunks;
    while (true) {
        // Existing peers follow a changed/adaptive block limit on each read.
        const uint64_t plain_limit{GetP2PWebSocketMessageSizeLimit()};
        ws.read_message_max(P2PZstdMaxWireSize(plain_limit));
        auto [rec, n] =
            co_await ws.async_read(buffer, asio::as_tuple(asio::use_awaitable));
        if (rec) {
            co_return;
        }
        const auto data{buffer.cdata()};
        const Span<const uint8_t> message{
            static_cast<const uint8_t *>(data.data()), data.size()};
        size_t payload_size{0};
        if (zstd) {
            chunks.clear();
            try {
                zstd->DecompressFrame(message, [&](Span<const uint8_t> c) {
                    if (c.size() > plain_limit - payload_size) {
                        throw std::runtime_error("decompressed message too large");
                    }
                    payload_size += c.size();
                    chunks.emplace_back(c.begin(), c.end());
                });
            } catch (const std::exception &e) {
                LogDebug(BCLog::NET, "P2P WebSocket zstd error: %s\n",
                         e.what());
                co_return;
            }
            for (const auto &chunk : chunks) {
                auto [wec, wn] = co_await asio::async_write(
                    local, asio::buffer(chunk),
                    asio::as_tuple(asio::use_awaitable));
                if (wec) {
                    co_return;
                }
            }
        } else {
            if (data.size() > plain_limit) {
                LogDebug(BCLog::NET, "P2P WebSocket message too large\n");
                co_return;
            }
            auto [wec, wn] = co_await asio::async_write(
                local, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
            if (wec) {
                co_return;
            }
            payload_size = data.size();
        }
        CountRecv(info, payload_size,
                  message.size() +
                      WebSocketFrameHeaderSize(message.size(), masked));
        buffer.consume(buffer.size());
    }
}

/**
 * Pump bytes both ways between an established P2P WebSocket and the bridge
 * end of a socketpair, until either side closes.
 */
template <typename WS>
asio::awaitable<void>
RunP2PWebSocketBridge(WS &ws, LocalSocket local,
                      std::shared_ptr<WebSocketTransportInfo> info,
                      bool is_client) {
    using namespace boost::asio::experimental::awaitable_operators;
    std::unique_ptr<P2PZstdSession> zstd;
    if (info->compression == P2PWebSocketCompression::ZSTD ||
        info->compression == P2PWebSocketCompression::ZSTD_DICT) {
        zstd = std::make_unique<P2PZstdSession>(
            info->compression == P2PWebSocketCompression::ZSTD_DICT);
    }
    // Clients mask what they send (RFC 6455 5.3).
    co_await (PumpLocalToWebSocket(local, ws, zstd.get(), *info, is_client) ||
              PumpWebSocketToLocal(ws, local, zstd.get(), *info, !is_client));
    boost::system::error_code ignored;
    local.close(ignored);
    // Bounded by the WebSocket handshake timeout, which covers closing too.
    co_await ws.async_close(websocket::close_code::normal,
                            asio::as_tuple(asio::use_awaitable));
}
#endif // HAVE_P2P_WEBSOCKET_BRIDGE

} // namespace p2pws

#endif // BITCOIN_NET_WEBSOCKET_BRIDGE_H
