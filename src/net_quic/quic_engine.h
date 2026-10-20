// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_ENGINE_H
#define BITCOIN_NET_QUIC_QUIC_ENGINE_H

#include <netaddress.h>
#include <util/fs.h>

#include <atomic>
#include <chrono>
#include <cstdint>
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

struct QuicEngineOptions {
    //! UDP addresses to accept connections on (none: outbound only)
    std::vector<CService> binds;
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

    class Impl;

private:
    explicit QuicEngine(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

#endif // BITCOIN_NET_QUIC_QUIC_ENGINE_H
