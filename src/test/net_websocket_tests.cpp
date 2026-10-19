// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <protocol.h>
#include <net_websocket_codec.h>
#include <net_websocket_sock.h>
#include <net_websocket_tls.h>
#include <tls_util.h>

#include <random.h>
#include <util/sock.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

namespace {
using Role = WebSocketCodec::Role;
using C = P2PWebSocketCompression;

std::shared_ptr<WebSocketTransportInfo> Info(C compression) {
    auto info{std::make_shared<WebSocketTransportInfo>()};
    info->compression = compression;
    return info;
}

/** Larger socket buffers than macOS's 8 KiB socketpair default */
void BigBuffers(const int (&sv)[2]) {
    const int size{1 << 20};
    for (int fd : sv) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
}

/** A connected client/server WebSocketSock pair over a socketpair */
struct Pair {
    std::unique_ptr<WebSocketSock> client, server;
    explicit Pair(C compression) {
        int sv[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        BigBuffers(sv);
        client = std::make_unique<WebSocketSock>(
            SOCKET(sv[0]), Role::CLIENT, Info(compression),
            std::make_unique<PlainByteLayer>());
        server = std::make_unique<WebSocketSock>(
            SOCKET(sv[1]), Role::SERVER, Info(compression),
            std::make_unique<PlainByteLayer>());
    }
};

/** Receive exactly `want` bytes, pumping the sender's pending writes */
std::vector<uint8_t> ReceiveAll(const Sock &from, const Sock &to,
                                size_t want) {
    std::vector<uint8_t> got;
    uint8_t buf[0x10000];
    const auto deadline{std::chrono::steady_clock::now() +
                        std::chrono::seconds{20}};
    while (got.size() < want) {
        BOOST_REQUIRE(std::chrono::steady_clock::now() < deadline);
        if (from.PendingEvents()) {
            BOOST_REQUIRE(from.FlushPending());
        }
        const ssize_t n{to.Recv(buf, sizeof(buf), 0)};
        if (n > 0) {
            got.insert(got.end(), buf, buf + n);
        } else {
            BOOST_REQUIRE(n < 0 && errno == EAGAIN);
            Sock::Event occurred;
            (void)to.Wait(std::chrono::milliseconds{5}, Sock::RECV, &occurred);
        }
    }
    return got;
}

/** Write raw bytes to an fd (blocking) */
void WriteRaw(int fd, const std::vector<uint8_t> &data) {
    size_t off{0};
    while (off < data.size()) {
        const ssize_t n{::send(fd, data.data() + off, data.size() - off, 0)};
        BOOST_REQUIRE(n > 0);
        off += n;
    }
}

/** Unmasked (server-to-client style) or masked frame, built by hand */
std::vector<uint8_t> Frame(uint8_t first_byte, const std::vector<uint8_t> &payload,
                           bool masked) {
    std::vector<uint8_t> f{first_byte};
    const uint8_t m = masked ? 0x80 : 0;
    if (payload.size() <= 125) {
        f.push_back(m | uint8_t(payload.size()));
    } else {
        f.push_back(m | 126);
        f.push_back(payload.size() >> 8);
        f.push_back(payload.size() & 0xFF);
    }
    const uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    if (masked) {
        f.insert(f.end(), key, key + 4);
    }
    for (size_t i = 0; i < payload.size(); ++i) {
        f.push_back(masked ? payload[i] ^ key[i & 3] : payload[i]);
    }
    return f;
}

/** A server WebSocketSock on sv[0]; the test speaks raw frames on sv[1] */
struct RawPeer {
    int raw;
    std::unique_ptr<WebSocketSock> server;
    explicit RawPeer(C compression = C::NONE) {
        int sv[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        raw = sv[1];
        server = std::make_unique<WebSocketSock>(
            SOCKET(sv[0]), Role::SERVER, Info(compression),
            std::make_unique<PlainByteLayer>());
    }
    ~RawPeer() { close(raw); }
    /** Recv() until data, EOF or error; returns the result of the last call */
    ssize_t RecvUntilResult(std::vector<uint8_t> &out) {
        uint8_t buf[4096];
        for (int i = 0; i < 400; ++i) {
            const ssize_t n{server->Recv(buf, sizeof(buf), 0)};
            if (n > 0) {
                out.insert(out.end(), buf, buf + n);
                return n;
            }
            if (n == 0 || errno != EAGAIN) {
                return n;
            }
            Sock::Event occurred;
            (void)server->Wait(std::chrono::milliseconds{5}, Sock::RECV,
                               &occurred);
        }
        return -1;
    }
    std::vector<uint8_t> ReadRaw(size_t n) {
        std::vector<uint8_t> got(n);
        size_t off{0};
        while (off < n) {
            const ssize_t r{::recv(raw, got.data() + off, n - off, 0)};
            BOOST_REQUIRE(r > 0);
            off += r;
        }
        return got;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(net_websocket_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(roundtrip_all_modes_and_sizes) {
    FastRandomContext rng{/*fDeterministic=*/true};
    for (const C mode : {C::NONE, C::ZSTD, C::ZSTD_DICT}) {
        Pair p{mode};
        // Every frame length encoding, both directions, plus a payload far
        // larger than the socket buffer (exercises pending writes).
        for (const size_t size : {1, 125, 126, 65535, 65536, 3000000}) {
            std::vector<uint8_t> payload{rng.randbytes<uint8_t>(size)};
            std::fill(payload.begin(), payload.begin() + size / 2, 7);
            BOOST_CHECK_EQUAL(p.client->Send(payload.data(), size, 0),
                              ssize_t(size));
            BOOST_CHECK(ReceiveAll(*p.client, *p.server, size) == payload);
            BOOST_CHECK_EQUAL(p.server->Send(payload.data(), size, 0),
                              ssize_t(size));
            BOOST_CHECK(ReceiveAll(*p.server, *p.client, size) == payload);
        }
        const auto &ci{*p.client->Info()};
        BOOST_CHECK_EQUAL(ci.payload_bytes_sent.load(),
                          p.server->Info()->payload_bytes_recv.load());
        if (mode != C::NONE) {
            // Half of each payload is compressible.
            BOOST_CHECK_LT(ci.wire_bytes_sent.load(),
                           ci.payload_bytes_sent.load());
        }
    }
}

#ifdef MSG_MORE
BOOST_AUTO_TEST_CASE(msg_more_coalesces_into_one_frame) {
    Pair p{C::NONE};
    const std::vector<uint8_t> a(100, 1), b(200, 2);
    BOOST_CHECK_EQUAL(p.client->Send(a.data(), a.size(), MSG_MORE), 100);
    BOOST_CHECK(p.client->PendingEvents() & Sock::SEND);
    BOOST_CHECK_EQUAL(p.client->Send(b.data(), b.size(), 0), 200);
    ReceiveAll(*p.client, *p.server, 300);
    // One masked frame with a 16-bit length: 2 + 2 + 4 header bytes.
    BOOST_CHECK_EQUAL(p.client->Info()->wire_bytes_sent.load(), 300U + 8);
}
#endif

BOOST_AUTO_TEST_CASE(buffered_data_is_signalled) {
    Pair p{C::NONE};
    const std::vector<uint8_t> data(1000, 9);
    BOOST_CHECK_EQUAL(p.client->Send(data.data(), data.size(), 0), 1000);
    uint8_t buf[10];
    ssize_t n;
    while ((n = p.server->Recv(buf, sizeof(buf), 0)) < 0) {
        Sock::Event occurred;
        (void)p.server->Wait(std::chrono::milliseconds{5}, Sock::RECV,
                             &occurred);
    }
    BOOST_CHECK_EQUAL(n, 10);
    // The rest was decoded already: readable without the OS socket.
    BOOST_CHECK(p.server->HasBufferedRecv());
    std::vector<uint8_t> rest{ReceiveAll(*p.client, *p.server, 990)};
    BOOST_CHECK_EQUAL(rest.size(), 990U);
    BOOST_CHECK(!p.server->HasBufferedRecv());
}

BOOST_AUTO_TEST_CASE(fragments_ping_and_close_from_raw_peer) {
    RawPeer peer;
    const std::vector<uint8_t> part1{'a', 'b'}, part2{'c'}, ping{'p', 'i'};
    // Binary (no FIN), ping in between, continuation with FIN.
    WriteRaw(peer.raw, Frame(0x02, part1, true));
    WriteRaw(peer.raw, Frame(0x89, ping, true));
    WriteRaw(peer.raw, Frame(0x80, part2, true));
    std::vector<uint8_t> got;
    BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), 3);
    BOOST_CHECK(got == std::vector<uint8_t>({'a', 'b', 'c'}));
    // The server answered the ping with an unmasked pong.
    BOOST_CHECK(peer.ReadRaw(4) == Frame(0x8A, ping, false));

    // Close: the server replies with Close and reports EOF.
    WriteRaw(peer.raw, Frame(0x88, {0x03, 0xE8}, true));
    got.clear();
    BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), 0);
    BOOST_CHECK(peer.ReadRaw(4) == Frame(0x88, {0x03, 0xE8}, false));
    // Nothing more may be sent after Close.
    const uint8_t x{0};
    BOOST_CHECK_EQUAL(peer.server->Send(&x, 1, 0), -1);
}

BOOST_AUTO_TEST_CASE(close_from_departed_peer_is_orderly) {
    // The peer sends Close and disappears: our Close reply cannot be
    // delivered, which must still read as an orderly EOF.
    RawPeer peer;
    WriteRaw(peer.raw, Frame(0x88, {0x03, 0xE8}, true));
    close(peer.raw);
    peer.raw = -1;
    std::vector<uint8_t> got;
    BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), 0);
}

BOOST_AUTO_TEST_CASE(protocol_violations_drop_the_connection) {
    const std::vector<std::vector<uint8_t>> bad{
        Frame(0x81, {'t'}, true),          // text frame
        Frame(0x82, {'x'}, false),         // unmasked client frame
        Frame(0xC2, {'x'}, true),          // RSV1 (extension) set
        Frame(0x80, {'x'}, true),          // continuation without start
        Frame(0x09, {'x'}, true),          // fragmented control frame
        Frame(0x83, {'x'}, true),          // reserved opcode
        // 64-bit length beyond the limit, rejected before buffering
        {0x82, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
         0x11, 0x22, 0x33, 0x44},
    };
    for (const auto &frame : bad) {
        RawPeer peer;
        WriteRaw(peer.raw, frame);
        std::vector<uint8_t> got;
        BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), -1);
        BOOST_CHECK_EQUAL(errno, ECONNRESET);
        BOOST_CHECK(peer.server->HasBufferedRecv());
    }
}

BOOST_AUTO_TEST_CASE(eof_mid_frame_is_an_error) {
    RawPeer peer;
    auto frame{Frame(0x82, std::vector<uint8_t>(50, 1), true)};
    frame.resize(20);
    WriteRaw(peer.raw, frame);
    shutdown(peer.raw, SHUT_WR);
    std::vector<uint8_t> got;
    BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), -1);
}

BOOST_AUTO_TEST_CASE(corrupt_zstd_is_an_error) {
    RawPeer peer{C::ZSTD_DICT};
    WriteRaw(peer.raw, Frame(0x82, {0xde, 0xad, 0xbe, 0xef, 0x00}, true));
    std::vector<uint8_t> got;
    BOOST_CHECK_EQUAL(peer.RecvUntilResult(got), -1);
}

BOOST_AUTO_TEST_CASE(back_pressure) {
    Pair p{C::NONE};
    // Nobody reads: the socketpair buffer fills, data stays pending, and
    // Send() eventually refuses more with EAGAIN.
    const std::vector<uint8_t> chunk(256 * 1024, 5);
    size_t accepted{0};
    ssize_t n;
    while ((n = p.client->Send(chunk.data(), chunk.size(), 0)) > 0) {
        accepted += n;
        BOOST_REQUIRE(accepted < 64 * 1024 * 1024);
    }
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK(p.client->PendingEvents() & Sock::SEND);
    BOOST_CHECK_GT(accepted, WebSocketSock::MAX_PENDING_SEND);
    // Draining delivers everything that was accepted.
    BOOST_CHECK_EQUAL(ReceiveAll(*p.client, *p.server, accepted).size(),
                      accepted);
    BOOST_CHECK_EQUAL(p.client->PendingEvents(), 0);
}

BOOST_AUTO_TEST_CASE(codec_complete_frame_detection) {
    WebSocketCodec client{Role::CLIENT, C::NONE};
    std::vector<uint8_t> wire;
    const std::vector<uint8_t> payload(300, 1);
    client.EncodeMessage(payload, wire);
    BOOST_CHECK(WebSocketCodec::HasCompleteFrame(wire));
    for (size_t len : {size_t{0}, size_t{1}, size_t{3}, wire.size() - 1}) {
        BOOST_CHECK(!WebSocketCodec::HasCompleteFrame(
            Span<const uint8_t>{wire.data(), len}));
    }
}

namespace {
/** A client/server WebSocketSock pair over TLS on a socketpair */
struct TlsPair {
    std::unique_ptr<WebSocketSock> client, server;
    SSL *client_ssl{nullptr}, *server_ssl{nullptr};
    std::vector<unsigned char> server_spki;
    explicit TlsPair(C compression) {
        const auto pem{tls::GenerateSelfSigned("test", {"localhost"}, {},
                                               std::chrono::hours{1})};
        BOOST_REQUIRE(pem);
        auto server_ctx{tls::NewContext(/*server=*/true)};
        auto client_ctx{tls::NewContext(/*server=*/false)};
        BOOST_REQUIRE(server_ctx && client_ctx);
        BOOST_REQUIRE(tls::UseCertificatePem(server_ctx.get(), pem->cert_pem,
                                             pem->key_pem));
        int sv[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        BigBuffers(sv);
        for (int fd : sv) {
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        }
        tls::SslPtr c{SSL_new(client_ctx.get())}, srv{SSL_new(server_ctx.get())};
        SSL_set_fd(c.get(), sv[0]);
        SSL_set_fd(srv.get(), sv[1]);
        SSL_set_connect_state(c.get());
        SSL_set_accept_state(srv.get());
        bool c_done{false}, s_done{false};
        for (int i = 0; i < 1000 && !(c_done && s_done); ++i) {
            c_done = c_done || SSL_do_handshake(c.get()) == 1;
            s_done = s_done || SSL_do_handshake(srv.get()) == 1;
        }
        BOOST_REQUIRE(c_done && s_done);
        X509 *peer{tls::PeerCertificate(c.get())};
        server_spki = tls::SpkiSha256(peer);
        X509_free(peer);
        client_ssl = c.get();
        server_ssl = srv.get();
        client = std::make_unique<WebSocketSock>(
            SOCKET(sv[0]), Role::CLIENT, Info(compression),
            std::make_unique<TlsByteLayer>(std::move(c)));
        server = std::make_unique<WebSocketSock>(
            SOCKET(sv[1]), Role::SERVER, Info(compression),
            std::make_unique<TlsByteLayer>(std::move(srv)));
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(tls_roundtrip_all_modes_and_sizes) {
    FastRandomContext rng{/*fDeterministic=*/true};
    for (const C mode : {C::NONE, C::ZSTD_DICT}) {
        TlsPair p{mode};
        for (const size_t size : {1, 126, 65536, 3000000}) {
            std::vector<uint8_t> payload{rng.randbytes<uint8_t>(size)};
            BOOST_CHECK_EQUAL(p.client->Send(payload.data(), size, 0),
                              ssize_t(size));
            BOOST_CHECK(ReceiveAll(*p.client, *p.server, size) == payload);
            BOOST_CHECK_EQUAL(p.server->Send(payload.data(), size, 0),
                              ssize_t(size));
            BOOST_CHECK(ReceiveAll(*p.server, *p.client, size) == payload);
        }
    }
}

BOOST_AUTO_TEST_CASE(tls_key_update_mid_stream) {
    TlsPair p{C::NONE};
    const std::vector<uint8_t> a(1000, 1), b(2000, 2);
    BOOST_CHECK_EQUAL(p.client->Send(a.data(), a.size(), 0), 1000);
    BOOST_CHECK(ReceiveAll(*p.client, *p.server, a.size()) == a);
    // The client rotates its keys and asks the server to do the same; data
    // keeps flowing both ways.
    if (SSL_version(p.client_ssl) == TLS1_3_VERSION) {
        BOOST_REQUIRE_EQUAL(
            SSL_key_update(p.client_ssl, SSL_KEY_UPDATE_REQUESTED), 1);
    }
    BOOST_CHECK_EQUAL(p.client->Send(b.data(), b.size(), 0), 2000);
    BOOST_CHECK(ReceiveAll(*p.client, *p.server, b.size()) == b);
    BOOST_CHECK_EQUAL(p.server->Send(a.data(), a.size(), 0), 1000);
    BOOST_CHECK(ReceiveAll(*p.server, *p.client, a.size()) == a);
}

BOOST_AUTO_TEST_CASE(tls_orderly_close) {
    TlsPair p{C::ZSTD_DICT};
    const std::vector<uint8_t> a(500, 3);
    BOOST_CHECK_EQUAL(p.client->Send(a.data(), a.size(), 0), 500);
    BOOST_CHECK(ReceiveAll(*p.client, *p.server, a.size()) == a);
    // Destroying the client sends a WebSocket Close and TLS close_notify.
    p.client.reset();
    uint8_t buf[16];
    ssize_t n{-1};
    for (int i = 0; i < 400 && n < 0; ++i) {
        n = p.server->Recv(buf, sizeof(buf), 0);
        if (n < 0) {
            BOOST_REQUIRE_EQUAL(errno, EAGAIN);
            Sock::Event occurred;
            (void)p.server->Wait(std::chrono::milliseconds{5}, Sock::RECV,
                                 &occurred);
        }
    }
    BOOST_CHECK_EQUAL(n, 0);
}

BOOST_AUTO_TEST_CASE(tls_client_profile) {
    // Cipher suites in browser order: AES-128-GCM first (OpenSSL's default
    // puts AES-256 first), forward-secret ECDHE before static RSA.
    auto ctx{tls::NewContext(/*server=*/false)};
    BOOST_REQUIRE(ctx);
    tls::SslPtr ssl{SSL_new(ctx.get())};
    BOOST_REQUIRE(ssl);
    std::vector<std::string> names;
    STACK_OF(SSL_CIPHER) *ciphers{SSL_get_ciphers(ssl.get())};
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
        names.emplace_back(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i)));
    }
    BOOST_REQUIRE_GE(names.size(), 4U);
    BOOST_CHECK_EQUAL(names[0], "TLS_AES_128_GCM_SHA256");
    BOOST_CHECK_EQUAL(names[1], "TLS_AES_256_GCM_SHA384");
    BOOST_CHECK_EQUAL(names[2], "TLS_CHACHA20_POLY1305_SHA256");
    BOOST_CHECK_EQUAL(names[3], "ECDHE-ECDSA-AES128-GCM-SHA256");

    // ALPN agreed between our client and server.
    TlsPair p{C::NONE};
    BOOST_CHECK_EQUAL(tls::NegotiatedAlpn(p.client_ssl), "http/1.1");
    BOOST_CHECK_EQUAL(tls::NegotiatedAlpn(p.server_ssl), "http/1.1");
}

BOOST_AUTO_TEST_CASE(tls_spki_fingerprint) {
    TlsPair p{C::NONE};
    BOOST_CHECK_EQUAL(p.server_spki.size(), 32U);
    X509 *own{SSL_get_certificate(p.server_ssl)};
    BOOST_CHECK(tls::SpkiSha256(own) == p.server_spki);
    // A new certificate for a different key has a different SPKI hash.
    TlsPair other{C::NONE};
    BOOST_CHECK(other.server_spki != p.server_spki);
}

namespace {
struct RestoreBlockLimit {
    Config &config{const_cast<Config &>(GetConfig())};
    const uint64_t original{config.GetMaxBlockSize()};
    ~RestoreBlockLimit() { config.SetMaxBlockSize(original); }
};

std::vector<uint8_t> ClientFrameHeader(uint64_t bytes) {
    std::vector<uint8_t> wire{0x82, 0xff};
    for (int i = 7; i >= 0; --i) wire.push_back(uint8_t(bytes >> (8 * i)));
    wire.resize(14); // Masking key; no body is needed to reject the length.
    return wire;
}
} // namespace

BOOST_AUTO_TEST_CASE(configured_large_message_roundtrip) {
    RestoreBlockLimit restore;
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(100000000));
    // Exceeds the old64MiB cap without approaching the configured cap.
    const std::vector<uint8_t> payload(65 * 1024 * 1024, 0x5a);
    for (C compression : {C::NONE, C::ZSTD, C::ZSTD_DICT}) {
        WebSocketCodec client{Role::CLIENT, compression};
        WebSocketCodec server{Role::SERVER, compression};
        std::vector<uint8_t> wire, plain, reply;
        client.EncodeMessage(payload, wire);
        BOOST_REQUIRE(!server.Decode(wire, plain, reply).error);
        BOOST_CHECK(plain == payload);
    }
}

BOOST_AUTO_TEST_CASE(message_limit_tracks_configuration_without_body_allocation) {
    RestoreBlockLimit restore;
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(100000000));
    WebSocketCodec server{Role::SERVER, C::NONE};
    const uint64_t large{GetP2PWebSocketMessageSizeLimit()};
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(32 * 1000000));
    const uint64_t small{GetP2PWebSocketMessageSizeLimit()};
    BOOST_CHECK_LT(small, large);
    std::vector<uint8_t> plain, reply;
    auto result{server.Decode(ClientFrameHeader(small + 1), plain, reply)};
    BOOST_REQUIRE(result.error);
    BOOST_CHECK_EQUAL(*result.error, "message too large");
    BOOST_CHECK(plain.empty());
    // Restore a larger configured cap on the same already-established codec.
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(100000000));
    result = server.Decode(ClientFrameHeader(small + 1), plain, reply);
    BOOST_CHECK(!result.error);
    BOOST_CHECK_EQUAL(result.consumed, 0U); // Header accepted; no body supplied.
    BOOST_CHECK(plain.empty());
}

BOOST_AUTO_TEST_CASE(compressed_output_is_bounded_by_plain_limit) {
    RestoreBlockLimit restore;
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(32 * 1000000));
    const uint64_t limit{GetP2PWebSocketMessageSizeLimit()};
    WebSocketCodec client{Role::CLIENT, C::ZSTD_DICT};
    WebSocketCodec server{Role::SERVER, C::ZSTD_DICT};
    std::vector<uint8_t> wire, plain, reply;
    client.EncodeMessage(std::vector<uint8_t>(limit + 1, 0x00), wire);
    BOOST_CHECK_LT(wire.size(), 100000U);
    const auto result{server.Decode(wire, plain, reply)};
    BOOST_REQUIRE(result.error);
    BOOST_CHECK(result.error->find("decompressed message too large") != std::string::npos);
    BOOST_CHECK_LE(plain.size(), limit);
}

BOOST_AUTO_TEST_CASE(incompressible_stream_wire_overhead_is_allowed) {
    RestoreBlockLimit restore;
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(32 * 1000000));
    const uint64_t limit{GetP2PWebSocketMessageSizeLimit()};
    FastRandomContext rng{true};
    const auto payload{rng.randbytes(limit)};
    WebSocketCodec client{Role::CLIENT, C::ZSTD};
    WebSocketCodec server{Role::SERVER, C::ZSTD};
    std::vector<uint8_t> wire, plain, reply;
    client.EncodeMessage(payload, wire);
    BOOST_CHECK_GT(wire.size(), payload.size());
    BOOST_CHECK_LE(wire.size(), server.MaxWireMessageSize() + 14);
    BOOST_REQUIRE(!server.Decode(wire, plain, reply).error);
    BOOST_CHECK(plain == payload);
}

BOOST_AUTO_TEST_SUITE_END()
