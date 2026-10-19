// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_dialer.h>

#include <clientversion.h>
#include <crypto/sha1.h>
#include <logging.h>
#include <net_websocket.h>
#include <net_websocket_sock.h>
#include <net_websocket_tls.h>
#include <netbase.h>
#include <random.h>
#include <sync.h>
#include <tls_util.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadinterrupt.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <map>

namespace {
using Clock = std::chrono::steady_clock;

//! Total time allowed for the TLS and WebSocket handshakes
constexpr std::chrono::seconds HANDSHAKE_TIMEOUT{20};
//! Largest HTTP response head accepted from the server
constexpr size_t MAX_RESPONSE_HEAD = 16 * 1024;
//! RFC 6455 GUID for Sec-WebSocket-Accept
constexpr const char *WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct DialerState {
    tls::SslCtxPtr client_ctx;
    //! Sec-WebSocket-Protocol value offered ("" offers none)
    std::string protocols;
    //! -p2pwebsocketpin: required public key hash per (lowercase) host
    std::map<std::string, std::vector<unsigned char>> pins;
};

GlobalMutex g_dialer_mutex;
std::shared_ptr<const DialerState> g_dialer GUARDED_BY(g_dialer_mutex);

/** Exposes the descriptor of a connected Sock during the handshake */
class HandshakeSock final : public Sock {
public:
    explicit HandshakeSock(Sock &&sock) : Sock{std::move(sock)} {}
    SOCKET Fd() const { return m_socket; }
};

/** Wait for `events` until `deadline`; false on timeout or interrupt */
bool WaitFor(const Sock &sock, Sock::Event events, Clock::time_point deadline,
             CThreadInterrupt &interrupt) {
    while (!interrupt) {
        const auto now{Clock::now()};
        if (now >= deadline) {
            return false;
        }
        const auto step{std::min<std::chrono::milliseconds>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                  now),
            std::chrono::milliseconds{100})};
        Sock::Event occurred{0};
        if (!sock.Wait(step, events, &occurred)) {
            return false;
        }
        if (occurred != 0) {
            // ERR included: the next operation reports it.
            return true;
        }
    }
    return false;
}

bool WouldBlock() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

bool WriteAll(WebSocketByteLayer &layer, const HandshakeSock &sock,
              const std::string &data, Clock::time_point deadline,
              CThreadInterrupt &interrupt) {
    size_t off{0};
    while (off < data.size()) {
        const ssize_t n{layer.Write(
            sock.Fd(), reinterpret_cast<const uint8_t *>(data.data()) + off,
            data.size() - off)};
        if (n > 0) {
            off += n;
        } else if (n < 0 && WouldBlock()) {
            if (!WaitFor(sock, layer.WriteWaitsFor(), deadline, interrupt)) {
                return false;
            }
        } else {
            return false;
        }
    }
    return true;
}

/** Read until the end of the HTTP response head: {head, leftover bytes} */
std::optional<std::pair<std::string, std::vector<uint8_t>>>
ReadResponseHead(WebSocketByteLayer &layer, const HandshakeSock &sock,
                 Clock::time_point deadline, CThreadInterrupt &interrupt) {
    std::string buf;
    uint8_t chunk[4096];
    while (true) {
        if (const size_t end{buf.find("\r\n\r\n")}; end != std::string::npos) {
            std::vector<uint8_t> rest(buf.begin() + end + 4, buf.end());
            buf.resize(end);
            return std::make_pair(std::move(buf), std::move(rest));
        }
        if (buf.size() > MAX_RESPONSE_HEAD) {
            return std::nullopt;
        }
        const ssize_t n{layer.Read(sock.Fd(), chunk, sizeof(chunk))};
        if (n > 0) {
            buf.append(reinterpret_cast<const char *>(chunk), n);
        } else if (n < 0 && WouldBlock()) {
            if (!layer.HasBuffered() &&
                !WaitFor(sock, Sock::RECV, deadline, interrupt)) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }
    }
}

std::string SecWebSocketAccept(const std::string &key) {
    const std::string input{key + WEBSOCKET_GUID};
    unsigned char digest[CSHA1::OUTPUT_SIZE];
    CSHA1()
        .Write(reinterpret_cast<const unsigned char *>(input.data()),
               input.size())
        .Finalize(digest);
    return EncodeBase64(Span<const unsigned char>{digest, sizeof(digest)});
}

P2PWebSocketCompression CompressionForProtocol(std::string_view protocol) {
    if (protocol == P2P_WS_PROTOCOL_ZSTD_DICT) {
        return P2PWebSocketCompression::ZSTD_DICT;
    }
    if (protocol == P2P_WS_PROTOCOL_ZSTD) {
        return P2PWebSocketCompression::ZSTD;
    }
    return P2PWebSocketCompression::NONE;
}

bool OfferedProtocol(const std::string &offered, const std::string &selected) {
    if (selected.empty()) {
        return true;
    }
    for (const std::string &token : util::SplitString(offered, ',')) {
        if (util::TrimString(token) == selected) {
            return true;
        }
    }
    return false;
}

std::optional<WebSocketDialResult>
Handshake(const DialerState &state, std::unique_ptr<Sock> &&tcp,
          const ParsedWebSocketURL &url, CThreadInterrupt &interrupt) {
    const auto deadline{Clock::now() + HANDSHAKE_TIMEOUT};
    // A pin in the URL wins over one configured for the host.
    std::optional<std::vector<unsigned char>> pin{url.spki_pin};
    if (!pin) {
        if (const auto it{state.pins.find(ToLower(url.host))};
            it != state.pins.end()) {
            pin = it->second;
        }
    }
    if (pin && !url.tls) {
        LogPrintf("Not connecting to %s: a key pin needs wss://\n",
                  url.authority);
        return std::nullopt;
    }
    auto sock{std::make_unique<HandshakeSock>(std::move(*tcp))};
    tcp.reset();
    if (!sock->SetNonBlocking()) {
        return std::nullopt;
    }

    std::unique_ptr<WebSocketByteLayer> layer;
    auto info{std::make_shared<WebSocketTransportInfo>()};
    if (url.tls) {
        tls::SslPtr ssl{SSL_new(state.client_ctx.get())};
        if (!ssl || SSL_set_fd(ssl.get(), int(sock->Fd())) != 1) {
            return std::nullopt;
        }
        if (!LookupHost(url.host, /*fAllowLookup=*/false)) {
            // A name, not an address literal: SNI lets TLS-terminating
            // proxies route by name, as every browser sends it.
            SSL_set_tlsext_host_name(ssl.get(), url.host.c_str());
        } else {
            LogPrintf("Dialing %s: TLS to an IP address carries no server "
                      "name, which is unusual for web traffic; prefer a host "
                      "name to blend in\n",
                      url.authority);
        }
        SSL_set_connect_state(ssl.get());
        while (true) {
            ERR_clear_error();
            const int r{SSL_do_handshake(ssl.get())};
            if (r == 1) {
                break;
            }
            const int err{SSL_get_error(ssl.get(), r)};
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                LogDebug(BCLog::NET, "TLS handshake with %s failed: %s\n",
                         url.authority, tls::ErrorString());
                return std::nullopt;
            }
            if (!WaitFor(*sock,
                         err == SSL_ERROR_WANT_READ ? Sock::RECV : Sock::SEND,
                         deadline, interrupt)) {
                LogDebug(BCLog::NET, "TLS handshake with %s timed out\n",
                         url.authority);
                return std::nullopt;
            }
        }
        X509 *peer{tls::PeerCertificate(ssl.get())};
        info->peer_cert_fingerprint_hex = tls::CertSha256Hex(peer);
        const std::vector<unsigned char> spki{tls::SpkiSha256(peer)};
        X509_free(peer);
        info->peer_spki = spki.empty() ? "" : EncodeSpkiPin(spki);
        info->alpn = tls::NegotiatedAlpn(ssl.get());
        if (pin) {
            if (spki.size() != pin->size() ||
                CRYPTO_memcmp(spki.data(), pin->data(), spki.size()) != 0) {
                LogPrintf("Not connecting to %s: its key %s does not match "
                          "the pinned key %s\n",
                          url.authority, info->peer_spki, EncodeSpkiPin(*pin));
                return std::nullopt;
            }
            info->pinned = true;
        }
        info->tls = true;
        layer = std::make_unique<TlsByteLayer>(std::move(ssl));
    } else {
        layer = std::make_unique<PlainByteLayer>();
    }

    // RFC 6455 opening handshake.
    std::vector<unsigned char> nonce(16);
    GetRandBytes(nonce);
    const std::string key{EncodeBase64(nonce)};
    std::string request{strprintf("GET %s HTTP/1.1\r\n"
                                  "Host: %s\r\n"
                                  "Upgrade: websocket\r\n"
                                  "Connection: Upgrade\r\n"
                                  "Sec-WebSocket-Key: %s\r\n"
                                  "Sec-WebSocket-Version: 13\r\n"
                                  "User-Agent: %s\r\n",
                                  url.target, url.authority, key,
                                  FormatFullVersion())};
    if (!state.protocols.empty()) {
        request += strprintf("Sec-WebSocket-Protocol: %s\r\n", state.protocols);
    }
    request += "\r\n";
    if (!WriteAll(*layer, *sock, request, deadline, interrupt)) {
        LogDebug(BCLog::NET, "WebSocket upgrade to %s: write failed\n",
                 url.authority);
        return std::nullopt;
    }
    auto response{ReadResponseHead(*layer, *sock, deadline, interrupt)};
    if (!response) {
        LogDebug(BCLog::NET, "WebSocket upgrade to %s: no response\n",
                 url.authority);
        return std::nullopt;
    }
    const auto lines{util::SplitString(response->first, '\n')};
    if (lines.empty() || !lines[0].starts_with("HTTP/1.1 101")) {
        LogDebug(BCLog::NET, "WebSocket upgrade to %s refused: %s\n",
                 url.authority,
                 lines.empty() ? std::string{} : util::TrimString(lines[0]));
        return std::nullopt;
    }
    std::map<std::string, std::string> headers;
    for (size_t i = 1; i < lines.size(); ++i) {
        const auto colon{lines[i].find(':')};
        if (colon != std::string::npos) {
            headers[ToLower(util::TrimString(lines[i].substr(0, colon)))] =
                util::TrimString(lines[i].substr(colon + 1));
        }
    }
    const auto header = [&](const std::string &name) {
        const auto it{headers.find(name)};
        return it == headers.end() ? std::string{} : it->second;
    };
    const std::string selected{header("sec-websocket-protocol")};
    if (ToLower(header("upgrade")) != "websocket" ||
        ToLower(header("connection")).find("upgrade") == std::string::npos ||
        header("sec-websocket-accept") != SecWebSocketAccept(key) ||
        !header("sec-websocket-extensions").empty() ||
        !OfferedProtocol(state.protocols, selected)) {
        LogDebug(BCLog::NET, "WebSocket upgrade to %s: invalid response\n",
                 url.authority);
        return std::nullopt;
    }
    info->compression = CompressionForProtocol(selected);
    LogDebug(BCLog::NET, "WebSocket P2P connection to %s (%s, %s)\n",
             url.authority, url.tls ? "wss" : "ws",
             P2PWebSocketCompressionName(info->compression));
    return WebSocketDialResult{
        .sock = std::make_unique<WebSocketSock>(
            std::move(*sock), WebSocketCodec::Role::CLIENT, info,
            std::move(layer), std::move(response->second)),
        .info = info,
    };
}
} // namespace

bool StartP2PWebSocketDialer(const std::optional<fs::path> &client_cert,
                             const std::optional<fs::path> &client_key,
                             const std::string &offer,
                             const std::vector<std::string> &pins) {
    auto state{std::make_shared<DialerState>()};
    for (const std::string &entry : pins) {
        // A host never contains '=', so the first one separates the pin.
        const size_t eq{entry.find('=')};
        const auto pin{eq == std::string::npos
                           ? std::nullopt
                           : DecodeSpkiPin(std::string_view{entry}.substr(eq + 1))};
        if (!pin || eq == 0) {
            LogPrintf("Error: invalid -p2pwebsocketpin=%s (expected "
                      "<host>=<base64url SHA-256 of the public key>)\n",
                      entry);
            return false;
        }
        state->pins[ToLower(entry.substr(0, eq))] = *pin;
    }
    state->client_ctx = tls::NewContext(/*server=*/false);
    if (!state->client_ctx) {
        return false;
    }
    // Peers commonly use self-signed certificates: TLS protects against
    // passive observers and lets proxies route by SNI; peers are not
    // authenticated (as with plain TCP P2P).
    SSL_CTX_set_verify(state->client_ctx.get(), SSL_VERIFY_NONE, nullptr);
    if (client_cert && client_key &&
        !tls::UseCertificateFiles(state->client_ctx.get(), *client_cert,
                                  *client_key)) {
        LogPrintf("Not presenting a TLS client certificate to WebSocket "
                  "peers: %s\n",
                  tls::ErrorString());
    }
    // "p2p-zstd-v1,p2p-zstd" by default; "none" offers plain messages.
    for (const std::string &token : util::SplitString(offer, ',')) {
        const std::string t{util::TrimString(token)};
        if (t == P2P_WS_PROTOCOL_ZSTD_DICT || t == P2P_WS_PROTOCOL_ZSTD) {
            state->protocols += (state->protocols.empty() ? "" : ", ") + t;
        } else if (t == "permessage-deflate") {
            LogPrintf("-p2pwebsocketoffer: permessage-deflate is only "
                      "accepted from inbound clients, not offered\n");
        } else if (t != "none") {
            LogPrintf("Ignoring unknown -p2pwebsocketoffer entry %s\n", t);
        }
    }
    WITH_LOCK(g_dialer_mutex, g_dialer = state);
    SetWebSocketDialer([](std::unique_ptr<Sock> &&tcp,
                          const ParsedWebSocketURL &url,
                          CThreadInterrupt &interrupt) {
        const std::shared_ptr<const DialerState> s{
            WITH_LOCK(g_dialer_mutex, return g_dialer)};
        if (!s) {
            return std::optional<WebSocketDialResult>{};
        }
        return Handshake(*s, std::move(tcp), url, interrupt);
    });
    return true;
}

void StopP2PWebSocketDialer() {
    SetWebSocketDialer(nullptr);
    WITH_LOCK(g_dialer_mutex, g_dialer.reset());
}
