// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_dialer.h>

#include <clientversion.h>
#include <logging.h>
#include <net_websocket.h>
#include <net_websocket_bridge.h>
#include <netbase.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadnames.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <openssl/ssl.h>

#include <chrono>
#include <future>
#include <thread>

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;

//! Total time allowed for resolving, connecting and both handshakes
constexpr std::chrono::seconds DIAL_TIMEOUT{20};

std::unique_ptr<asio::io_context> g_dial_io;
std::optional<asio::executor_work_guard<asio::io_context::executor_type>>
    g_dial_work;
std::thread g_dial_thread;
std::unique_ptr<ssl::context> g_client_tls;
//! Sec-WebSocket-Protocol offered to peers ("" offers nothing)
std::string g_offered_protocols;
//! Whether to also offer permessage-deflate
bool g_offer_deflate{true};
} // namespace

std::optional<ParsedWebSocketURL> ParseWebSocketURL(std::string_view url) {
    ParsedWebSocketURL out;
    if (url.substr(0, 6) == "wss://") {
        out.tls = true;
        url.remove_prefix(6);
    } else if (url.substr(0, 5) == "ws://") {
        url.remove_prefix(5);
    } else {
        return std::nullopt;
    }
    const size_t slash{url.find('/')};
    const std::string authority{url.substr(0, slash)};
    out.target = slash == std::string_view::npos ? std::string{P2P_WEBSOCKET_PATH}
                                                 : std::string{url.substr(slash)};
    uint16_t port{static_cast<uint16_t>(out.tls ? 443 : 80)};
    std::string host;
    if (authority.empty() || !SplitHostPort(authority, port, host) ||
        host.empty()) {
        return std::nullopt;
    }
    out.host = host;
    out.port = port;
    const bool ipv6{host.find(':') != std::string::npos};
    out.authority = strprintf(ipv6 ? "[%s]:%u" : "%s:%u", host, port);
    return out;
}

// The dialer bridges through a local socketpair (not available on Windows).
#ifdef HAVE_P2P_WEBSOCKET_BRIDGE
namespace {
CService ToCService(const tcp::endpoint &endpoint) {
    return LookupNumeric(endpoint.address().to_string(), endpoint.port());
}

/** WebSocket handshake on a connected stream, then start the bridge */
template <typename WS>
asio::awaitable<std::optional<WebSocketDialResult>>
FinishDial(std::shared_ptr<WS> ws, const ParsedWebSocketURL &url, bool tls,
           CService remote, CService local) {
    // Offer permessage-deflate as a last resort for servers without zstd.
    p2pws::ConfigureP2PWebSocket(*ws, beast::role_type::client,
                                 g_offer_deflate);
    ws->set_option(websocket::stream_base::decorator(
        [protocols = g_offered_protocols](websocket::request_type &req) {
            if (!protocols.empty()) {
                req.set(http::field::sec_websocket_protocol, protocols);
            }
            req.set(http::field::user_agent, FormatFullVersion());
        }));
    websocket::response_type res;
    auto [hec] = co_await ws->async_handshake(
        res, url.authority, url.target, asio::as_tuple(asio::use_awaitable));
    if (hec) {
        LogDebug(BCLog::NET, "WebSocket handshake with %s failed: %s\n",
                 url.authority, hec.message());
        co_return std::nullopt;
    }
    const bool deflate{res[http::field::sec_websocket_extensions].find(
                           "permessage-deflate") != std::string_view::npos};

    const auto pair{p2pws::CreateBridgeSocketPair()};
    if (!pair) {
        co_return std::nullopt;
    }
    WebSocketDialResult result{
        .sock = std::make_unique<Sock>(static_cast<SOCKET>(pair->first)),
        .info = std::make_shared<WebSocketTransportInfo>(),
        .remote = remote,
        .local = local,
    };
    result.info->tls = tls;
    result.info->compression = p2pws::CompressionFromSelectedProtocol(
        res[http::field::sec_websocket_protocol], deflate);
    p2pws::LocalSocket bridge{ws->get_executor()};
    boost::system::error_code ec;
    bridge.assign(asio::local::stream_protocol{}, pair->second, ec);
    if (ec) {
        ::close(pair->second);
        co_return std::nullopt;
    }
    LogDebug(BCLog::NET, "WebSocket P2P connection to %s (%s, %s)\n",
             url.authority, tls ? "wss" : "ws",
             P2PWebSocketCompressionName(result.info->compression));
    asio::co_spawn(
        ws->get_executor(),
        [](std::shared_ptr<WS> ws, p2pws::LocalSocket bridge,
           std::shared_ptr<WebSocketTransportInfo> info)
            -> asio::awaitable<void> {
            co_await p2pws::RunP2PWebSocketBridge(*ws, std::move(bridge),
                                                  std::move(info),
                                                  /*is_client=*/true);
        }(ws, std::move(bridge), result.info),
        asio::detached);
    co_return result;
}

asio::awaitable<std::optional<WebSocketDialResult>>
Dial(ParsedWebSocketURL url) {
    try {
        auto executor{co_await asio::this_coro::executor};
        tcp::resolver resolver{executor};
        auto [rec, results] = co_await resolver.async_resolve(
            url.host, std::to_string(url.port),
            asio::as_tuple(asio::use_awaitable));
        if (rec) {
            LogDebug(BCLog::NET, "Cannot resolve %s: %s\n", url.host,
                     rec.message());
            co_return std::nullopt;
        }
        beast::tcp_stream stream{executor};
        stream.expires_after(DIAL_TIMEOUT);
        auto [cec, endpoint] = co_await stream.async_connect(
            results, asio::as_tuple(asio::use_awaitable));
        if (cec) {
            LogDebug(BCLog::NET, "WebSocket connect to %s failed: %s\n",
                     url.authority, cec.message());
            co_return std::nullopt;
        }
        boost::system::error_code ignored;
        stream.socket().set_option(tcp::no_delay(true), ignored);
        const CService remote{ToCService(endpoint)};
        const CService local{ToCService(stream.socket().local_endpoint(ignored))};

        if (!url.tls) {
            stream.expires_never();
            auto ws{std::make_shared<websocket::stream<beast::tcp_stream>>(
                std::move(stream))};
            co_return co_await FinishDial(ws, url, false, remote, local);
        }

        auto ws{std::make_shared<
            websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(
            std::move(stream), *g_client_tls)};
        auto &tls_stream{ws->next_layer()};
        // SNI lets TLS-terminating proxies route by name; not for literals.
        boost::system::error_code addr_ec;
        asio::ip::make_address(url.host, addr_ec);
        if (addr_ec &&
            !SSL_set_tlsext_host_name(tls_stream.native_handle(),
                                      url.host.c_str())) {
            co_return std::nullopt;
        }
        auto [hs_ec] = co_await tls_stream.async_handshake(
            ssl::stream_base::client, asio::as_tuple(asio::use_awaitable));
        if (hs_ec) {
            LogDebug(BCLog::NET, "TLS handshake with %s failed: %s\n",
                     url.authority, hs_ec.message());
            co_return std::nullopt;
        }
        beast::get_lowest_layer(*ws).expires_never();
        co_return co_await FinishDial(ws, url, true, remote, local);
    } catch (const std::exception &e) {
        LogDebug(BCLog::NET, "WebSocket dial to %s failed: %s\n",
                 url.authority, e.what());
        co_return std::nullopt;
    }
}

std::optional<WebSocketDialResult> DialBlocking(const std::string &url_str) {
    const auto url{ParseWebSocketURL(url_str)};
    if (!url) {
        LogPrintf("Invalid WebSocket peer URL: %s\n", url_str);
        return std::nullopt;
    }
    auto future{asio::co_spawn(asio::make_strand(*g_dial_io), Dial(*url),
                               asio::use_future)};
    if (future.wait_for(DIAL_TIMEOUT + std::chrono::seconds{5}) !=
        std::future_status::ready) {
        // The late result (if any) is dropped, closing its socketpair.
        return std::nullopt;
    }
    try {
        return future.get();
    } catch (const std::exception &) {
        return std::nullopt;
    }
}
} // namespace
#endif // HAVE_P2P_WEBSOCKET_BRIDGE

bool StartP2PWebSocketDialer(const std::optional<fs::path> &client_cert,
                             const std::optional<fs::path> &client_key,
                             const std::string &offer) {
#ifndef HAVE_P2P_WEBSOCKET_BRIDGE
    return false;
#else
    // "p2p-zstd-v1,p2p-zstd,permessage-deflate" by default; "none" offers
    // plain binary messages only.
    g_offered_protocols.clear();
    g_offer_deflate = false;
    for (const std::string &token : util::SplitString(offer, ',')) {
        const std::string t{util::TrimString(token)};
        if (t == "permessage-deflate") {
            g_offer_deflate = true;
        } else if (t == P2P_WS_PROTOCOL_ZSTD_DICT || t == P2P_WS_PROTOCOL_ZSTD) {
            g_offered_protocols += (g_offered_protocols.empty() ? "" : ", ") + t;
        } else if (t != "none") {
            LogPrintf("Ignoring unknown -p2pwebsocketoffer entry %s\n", t);
        }
    }
    auto ctx{std::make_unique<ssl::context>(ssl::context::tls_client)};
    ctx->set_options(ssl::context::default_workarounds |
                     ssl::context::no_sslv2 | ssl::context::no_sslv3 |
                     ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);
    // Peers commonly use self-signed certificates: TLS here protects against
    // passive observers and lets proxies route by SNI; peers are not
    // authenticated (as with plain TCP P2P).
    ctx->set_verify_mode(ssl::verify_none);
    if (client_cert && client_key) {
        try {
            ctx->use_certificate_chain_file(fs::PathToString(*client_cert));
            ctx->use_private_key_file(fs::PathToString(*client_key),
                                      ssl::context::pem);
        } catch (const boost::system::system_error &e) {
            LogPrintf("Not presenting a TLS client certificate to WebSocket "
                      "peers: %s\n",
                      e.what());
        }
    }
    g_client_tls = std::move(ctx);
    if (!g_dial_io) {
        g_dial_io = std::make_unique<asio::io_context>();
    } else {
        g_dial_io->restart();
    }
    g_dial_work.emplace(asio::make_work_guard(*g_dial_io));
    g_dial_thread = std::thread([] {
        util::ThreadRename("p2pws");
        g_dial_io->run();
    });
    SetWebSocketDialer(DialBlocking);
    return true;
#endif
}

void StopP2PWebSocketDialer() {
    SetWebSocketDialer(nullptr);
    if (!g_dial_io) {
        return;
    }
    g_dial_work.reset();
    // Bridges end once CConnman has closed its sockets; stop regardless.
    g_dial_io->stop();
    if (g_dial_thread.joinable()) {
        g_dial_thread.join();
    }
    // g_dial_io is kept: destroying it could run pending handlers'
    // destructors after the TLS context is gone.
}
