// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_ENGINE_H
#define BITCOIN_NET_QUIC_QUIC_ENGINE_H

#include <net_webtransport.h>
#include <netaddress.h>
#include <util/fs.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * The QUIC engine: one thread ("quic") owning the UDP sockets, the timers
 * and every ngtcp2/OpenSSL QUIC connection, see doc/p2p-webtransport.md.
 * No ngtcp2 type appears in this header, so it can be used by init and the
 * tests without the QUIC libraries' headers.
 */

/** When the server answers a new connection with a Retry (RFC 9000 §8.1) */
enum class QuicRetryMode {
    //! Never: the 3x anti-amplification limit alone protects against
    //! reflection
    OFF,
    //! Under load: many handshakes in progress, or many token-less Initials
    //! from one address
    AUTO,
    //! Always validate the client's address first (one extra round trip)
    ALWAYS,
};

/** What the engine's connections run on top of QUIC */
enum class QuicApplication {
    //! HTTP/3 + WebTransport P2P sessions
    WEBTRANSPORT,
    //! Tests: the server echoes every client stream back on that stream
    ECHO_FOR_TEST,
};

/** Opt-in test observation of public TLS handshake messages, never secrets. */
struct QuicHandshakeObservation {
    bool outbound{false};
    bool server{false};
    uint16_t tls_version{0};
    size_t original_size{0};
    bool truncated{false};
    std::vector<uint8_t> handshake;
};
using QuicHandshakeObserver =
    std::function<void(QuicHandshakeObservation observation)>;

struct QuicEngineOptions {
    //! UDP addresses to accept connections on (none: outbound only)
    std::vector<CService> binds;
    //! A bind that fails is logged and skipped instead of failing Start()
    //! (e.g. the UDP port is taken or IPv6 is off)
    bool bind_optional{false};
    //! Server certificate chain and key (PEM); also presented to servers
    //! that ask for a client certificate. Checked for replacement once a
    //! minute.
    std::optional<fs::path> cert_file;
    std::optional<fs::path> key_file;
    QuicApplication application{QuicApplication::WEBTRANSPORT};
    QuicRetryMode retry{QuicRetryMode::AUTO};
    //! BBR instead of CUBIC
    bool bbr{false};
    std::chrono::milliseconds idle_timeout{std::chrono::seconds{30}};
    //! PING after this long without traffic (outbound connections; 0: off)
    std::chrono::milliseconds keep_alive{std::chrono::seconds{15}};
    std::chrono::milliseconds handshake_timeout{std::chrono::seconds{10}};
    //! Stateless resets sent per second at most
    uint32_t stateless_reset_rate{10};

    //! WebTransport (server): request path of the extended CONNECT,
    //! accepted Origin values (empty: any) and required access token
    //! (?t=; empty: none)
    std::string wt_path{"/p2p/wt"};
    std::vector<std::string> wt_origins;
    std::string wt_token;
    //! Tests and browser interop: echo WebTransport streams and datagrams
    //! instead of running P2P sessions
    bool wt_echo{false};
    //! Ask inbound peers for a TLS client certificate (accepting any), so
    //! -p2pwebsocketpeer keys can grant permissions
    bool request_client_cert{false};
    //! Compress P2P messages on the class streams (zstd + dictionary)
    bool compress{true};
    //! Tests only: called on the engine thread. Empty installs no TLS
    //! callback. No CLI/secret logging; bounded to 256 messages / 8 MiB
    //! per engine, at most 64 KiB per copy. Caller-owned captures must
    //! remain valid until Stop() has joined the engine thread.
    QuicHandshakeObserver handshake_observer;
};

/** Tests: an extended CONNECT made by WebTransportProbeForTest() */
struct WtProbeOptions {
    std::string path{"/p2p/wt"};
    std::string origin;
    std::string token;
    std::string protocol_token{"webtransport-h3"};
    std::vector<std::string> offer{"p2p-v1"};
    //! After a 200, send a second CONNECT on the same connection
    bool second_connect{false};
};

struct WtProbeResult {
    //! :status of the CONNECT (0: no answer / no WebTransport)
    int status{0};
    int second_status{0};
    //! wt-protocol chosen by the server
    std::string protocol;
    //! Newest WebTransport SETTINGS codepoint the server announced
    uint64_t peer_draft_setting{0};
    //! Bytes sent on each of the five class streams came back (echo server)
    bool classes_echoed{false};
};

/** Engine-wide counters (all connections, since start) */
struct QuicEngineStats {
    uint64_t connections{0};
    uint64_t inbound{0};
    uint64_t outbound{0};
    uint64_t handshaking{0};
    uint64_t handshakes_completed{0};
    uint64_t handshakes_failed{0};
    uint64_t retry_sent{0};
    uint64_t retry_token_rejected{0};
    uint64_t stateless_reset_sent{0};
    uint64_t version_negotiation_sent{0};
    uint64_t idle_closed{0};
    uint64_t packets_recv{0};
    uint64_t packets_sent{0};
    uint64_t bytes_recv{0};
    uint64_t bytes_sent{0};
    uint64_t send_errors{0};
};

class QuicEngine {
public:
    /** Bind the sockets and start the engine thread */
    static std::unique_ptr<QuicEngine> Start(const QuicEngineOptions &options,
                                             std::string &error);
    ~QuicEngine();
    QuicEngine(const QuicEngine &) = delete;
    QuicEngine &operator=(const QuicEngine &) = delete;

    /** Close every connection and join the thread (idempotent) */
    void Stop();

    /** The UDP addresses actually bound (port 0 resolved) */
    std::vector<CService> BoundAddresses() const;

    QuicEngineStats Stats() const;

    /**
     * Tests (QuicApplication::ECHO_FOR_TEST on the server): connect to
     * `target`, send `payload` on one bidirectional stream with FIN and
     * return what the server sends back before its FIN, or std::nullopt
     * on a failed handshake/timeout. `cert_sha256`, if given, must match
     * the server's certificate.
     */
    std::optional<std::vector<uint8_t>>
    EchoForTest(const CService &target, const std::vector<uint8_t> &payload,
                std::chrono::milliseconds timeout,
                const std::optional<std::vector<uint8_t>> &cert_sha256 = {});

    /**
     * Open an outbound P2P session (see WebTransportDialer): blocks until
     * the class streams are open, the dial fails, `timeout` passes or
     * `interrupt` fires.
     */
    std::optional<WebTransportDialResult>
    Dial(const CService &target, const ParsedWebTransportURL &url,
         std::chrono::milliseconds timeout, CThreadInterrupt &interrupt,
         WebTransportDialError &error);

    /**
     * Tests: QUIC + HTTP/3 + extended CONNECT to `target`; on a 200 open
     * the five class streams and send a few bytes on each.
     */
    std::optional<WtProbeResult>
    WebTransportProbeForTest(const CService &target,
                             const WtProbeOptions &options,
                             std::chrono::milliseconds timeout);

    class Impl;

private:
    explicit QuicEngine(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

#endif // BITCOIN_NET_QUIC_QUIC_ENGINE_H
