// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <hash.h>
#include <net_websocket_codec.h>
#include <net_websocket_sock.h>
#include <net_websocket_tls.h>
#include <net_zstd_dict.h>
#include <net_zstd_independent.h>
#include <primitives/block.h>
#include <protocol.h>
#include <streams.h>
#include <tls_util.h>

#include <random.h>
#include <util/sock.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <csignal>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
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

namespace {
/**
 * OpenSSL writes to sockets with write(), which raises SIGPIPE once the peer
 * has closed. The node ignores SIGPIPE at startup (AppInitBasicSetup); do
 * the same here, where tests close one end before the other.
 */
struct WebSocketTestingSetup : BasicTestingSetup {
    WebSocketTestingSetup() {
#ifndef WIN32
        signal(SIGPIPE, SIG_IGN);
#endif
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(net_websocket_tests, WebSocketTestingSetup)

BOOST_AUTO_TEST_CASE(client_certificate_reload) {
    const auto cert{m_path_root / "client.pem"};
    const auto key{m_path_root / "client.key"};
    const auto first{tls::GenerateSelfSigned("first.example", {}, {},
                                           std::chrono::hours{24})};
    const auto second{tls::GenerateSelfSigned("second.example", {}, {},
                                            std::chrono::hours{24})};
    BOOST_REQUIRE(first && second);
    BOOST_REQUIRE(tls::WritePemFiles(*first, cert, key));
    // Zero is a valid filesystem timestamp, not an uninitialized sentinel.
    fs::last_write_time(cert, fs::file_time_type{});
    fs::last_write_time(key, fs::file_time_type{});
    tls::ReloadingClientContext contexts{cert, key};
    const auto old{contexts.Get()};
    BOOST_REQUIRE(old);
    tls::SslPtr session{SSL_new(old.get())};
    BOOST_REQUIRE(session);
    const auto original{tls::SpkiSha256(SSL_get_certificate(session.get()))};
    BOOST_REQUIRE_EQUAL(original.size(), 32);
    const auto next_check = [] {
        std::this_thread::sleep_for(std::chrono::milliseconds{1100});
    };

    // A mismatched pair cannot replace the valid published context.
    BOOST_REQUIRE(tls::ReplaceFile(cert, second->cert_pem));
    next_check();
    BOOST_CHECK(contexts.Get() == old);
    BOOST_CHECK(tls::SpkiSha256(SSL_get_certificate(session.get())) == original);
    // The corrected key completes the rotation without restarting the dialer.
    BOOST_REQUIRE(tls::ReplaceFile(key, second->key_pem));
    next_check();
    const auto rotated{contexts.Get()};
    BOOST_REQUIRE(rotated);
    BOOST_CHECK(rotated != old);
    BOOST_CHECK(tls::SpkiSha256(SSL_CTX_get0_certificate(rotated.get())) != original);
    BOOST_CHECK(tls::SpkiSha256(SSL_get_certificate(session.get())) == original);
    BOOST_CHECK(contexts.Get() == rotated);
    // Malformed and missing files also leave the last good identity intact.
    BOOST_REQUIRE(tls::ReplaceFile(key, "not a PEM key"));
    next_check();
    BOOST_CHECK(contexts.Get() == rotated);
    BOOST_REQUIRE(tls::ReplaceFile(key, second->key_pem));
    fs::remove(cert);
    next_check();
    BOOST_CHECK(contexts.Get() == rotated);
    tls::ReloadingClientContext anonymous{std::nullopt, std::nullopt};
    BOOST_REQUIRE(anonymous.Get());
    BOOST_CHECK(SSL_CTX_get0_certificate(anonymous.Get().get()) == nullptr);
}

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

namespace {
/** A byte layer whose reads wait for writability until unblocked */
class WriteBlockedReadLayer final : public WebSocketByteLayer {
public:
    std::vector<uint8_t> wire;
    bool blocked{true};
    ssize_t Read(SOCKET, uint8_t *buf, size_t len) override {
        if (blocked || wire.empty()) {
            errno = EAGAIN;
            return -1;
        }
        const size_t n{std::min(len, wire.size())};
        std::memcpy(buf, wire.data(), n);
        wire.erase(wire.begin(), wire.begin() + n);
        return n;
    }
    ssize_t Write(SOCKET, const uint8_t *, size_t len) override { return len; }
    Sock::Event ReadWaitsFor() const override {
        return blocked ? Sock::SEND : Sock::RECV;
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(read_waiting_for_send_resumes_on_flush) {
    // A read that must write first (TLS) asks to be woken when the socket
    // is writable, not readable: the data it needs may already have been
    // read from the OS socket, so readability might never come.
    int sv[2];
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    auto layer{std::make_unique<WriteBlockedReadLayer>()};
    WriteBlockedReadLayer &l{*layer};
    WebSocketSock server{SOCKET(sv[0]), Role::SERVER, Info(C::NONE),
                         std::move(layer)};
    WebSocketCodec client{Role::CLIENT, C::NONE};
    const std::vector<uint8_t> payload(100, 4);
    client.EncodeMessage(payload, l.wire);

    uint8_t buf[256];
    BOOST_CHECK_EQUAL(server.Recv(buf, sizeof(buf), 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK_EQUAL(server.PendingEvents(), Sock::SEND);
    BOOST_CHECK(!server.HasBufferedRecv());

    // Writable: FlushPending() retries the read, and the data is buffered.
    l.blocked = false;
    BOOST_CHECK(server.FlushPending());
    BOOST_CHECK(server.HasBufferedRecv());
    BOOST_CHECK_EQUAL(server.PendingEvents(), 0);
    BOOST_CHECK_EQUAL(server.Recv(buf, sizeof(buf), 0), 100);
    BOOST_CHECK(std::equal(payload.begin(), payload.end(), buf));
    close(sv[1]);
}

BOOST_AUTO_TEST_CASE(tls_key_update_while_send_blocked) {
    // A KeyUpdate asking for one back arrives while the server cannot write.
    // (OpenSSL 4.0 defers the reply to the next write; a TLS library that
    // sends it from SSL_read would block the read on writability instead,
    // the case read_waiting_for_send_resumes_on_flush covers.)
    TlsPair p{C::NONE};
    if (SSL_version(p.client_ssl) != TLS1_3_VERSION) {
        return;
    }
    // Nobody reads the server's data: its writes block.
    const std::vector<uint8_t> chunk(256 * 1024, 7);
    size_t sent{0};
    ssize_t n;
    while ((n = p.server->Send(chunk.data(), chunk.size(), 0)) > 0) {
        sent += n;
        BOOST_REQUIRE(sent < 64 * 1024 * 1024);
    }
    BOOST_REQUIRE_EQUAL(SSL_key_update(p.client_ssl, SSL_KEY_UPDATE_REQUESTED),
                        1);
    const std::vector<uint8_t> b(100, 9);
    BOOST_REQUIRE_EQUAL(p.client->Send(b.data(), b.size(), 0), 100);
    // Everything arrives both ways, and the server's keys rotate too.
    BOOST_CHECK(ReceiveAll(*p.client, *p.server, b.size()) == b);
    BOOST_CHECK_EQUAL(ReceiveAll(*p.server, *p.client, sent).size(), sent);
    BOOST_CHECK_EQUAL(p.server->Send(b.data(), b.size(), 0), 100);
    BOOST_CHECK(ReceiveAll(*p.server, *p.client, b.size()) == b);
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

    // TLS 1.3 with the post-quantum hybrid key exchange from OpenSSL 3.5
    // on, and X25519 before.
    BOOST_CHECK_EQUAL(SSL_version(p.client_ssl), TLS1_3_VERSION);
    BOOST_CHECK_EQUAL(tls::HasHybridKeyExchange(),
                      OpenSSL_version_num() >= 0x30500000L);
#if OPENSSL_VERSION_NUMBER >= 0x30200000L // SSL_get0_group_name
    BOOST_CHECK_EQUAL(ToLower(SSL_get0_group_name(p.client_ssl)),
                      tls::HasHybridKeyExchange() ? "x25519mlkem768"
                                                  : "x25519");
#endif
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

// Independent (compress-once) frames of the zstd modes.
namespace {
/** Restore g_p2p_compress_once_threshold when a test changes it */
struct RestoreThreshold {
    const size_t old{g_p2p_compress_once_threshold.load()};
    ~RestoreThreshold() { g_p2p_compress_once_threshold = old; }
};

/** A complete P2P message: 24-byte header, then the payload */
struct P2PMessage {
    std::vector<uint8_t> header, payload;
    std::vector<uint8_t> Bytes() const {
        std::vector<uint8_t> all{header};
        all.insert(all.end(), payload.begin(), payload.end());
        return all;
    }
};

P2PMessage MakeMessage(const char *type, std::vector<uint8_t> payload) {
    P2PMessage msg;
    msg.payload = std::move(payload);
    CMessageHeader hdr{CMessageHeader::MessageMagic{0xe3, 0xe1, 0xf3, 0xe8},
                       type, uint32_t(msg.payload.size())};
    const uint256 hash{Hash(msg.payload)};
    std::memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
    VectorWriter{msg.header, 0, hdr};
    BOOST_REQUIRE_EQUAL(msg.header.size(), CMessageHeader::HEADER_SIZE);
    return msg;
}

/** A block message: a block header, then `size` partly compressible bytes */
P2PMessage MakeBlockMessage(FastRandomContext &rng, size_t size) {
    std::vector<uint8_t> payload;
    CBlockHeader header;
    header.nNonce = rng.rand32();
    header.SetBlockTime(rng.rand32());
    VectorWriter{payload, 0, header};
    auto body{rng.randbytes<uint8_t>(size)};
    // Like transactions: random hashes and keys between repeated structure.
    for (size_t i = 0; i < body.size(); i += 64) {
        std::fill(body.begin() + i,
                  body.begin() + std::min(body.size(), i + 24), 0x76);
    }
    payload.insert(payload.end(), body.begin(), body.end());
    return MakeMessage(NetMsgType::BLOCK, std::move(payload));
}

/** A server and client WebSocketSock with the given compression */
struct ModePair {
    std::unique_ptr<WebSocketSock> client, server;
    explicit ModePair(C mode) {
        int sv[2];
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        BigBuffers(sv);
        client = std::make_unique<WebSocketSock>(
            SOCKET(sv[0]), Role::CLIENT, Info(mode),
            std::make_unique<PlainByteLayer>());
        server = std::make_unique<WebSocketSock>(
            SOCKET(sv[1]), Role::SERVER, Info(mode),
            std::make_unique<PlainByteLayer>());
    }
};

/** Send a P2P message as CConnman does: header with MSG_MORE, payload */
void SendLikeConnman(const Sock &sock, const P2PMessage &msg, bool more) {
    int flags{0};
#ifdef MSG_MORE
    flags = MSG_MORE;
#endif
    BOOST_REQUIRE_EQUAL(sock.Send(msg.header.data(), msg.header.size(), flags),
                        ssize_t(msg.header.size()));
    BOOST_REQUIRE_EQUAL(
        sock.Send(msg.payload.data(), msg.payload.size(), more ? flags : 0),
        ssize_t(msg.payload.size()));
}

std::vector<uint8_t> Concat(std::initializer_list<const P2PMessage *> msgs) {
    std::vector<uint8_t> all;
    for (const auto *m : msgs) {
        const auto bytes{m->Bytes()};
        all.insert(all.end(), bytes.begin(), bytes.end());
    }
    return all;
}
} // namespace

BOOST_AUTO_TEST_CASE(independent_frames_are_part_of_zstd_modes) {
    BOOST_CHECK(WebSocketCodec(Role::SERVER, C::ZSTD_DICT).IndependentFrames());
    BOOST_CHECK(WebSocketCodec(Role::SERVER, C::ZSTD).IndependentFrames());
    BOOST_CHECK(!WebSocketCodec(Role::SERVER, C::NONE).IndependentFrames());
    BOOST_CHECK(!WebSocketCodec(Role::SERVER, C::PERMESSAGE_DEFLATE)
                     .IndependentFrames());
}

BOOST_AUTO_TEST_CASE(independent_frames_keep_stream_history) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 200000)};
    const auto block_bytes{block.Bytes()};
    const std::vector<uint8_t> small(4096, 0x71);
    WebSocketCodec encoder{Role::SERVER, C::ZSTD_DICT};
    WebSocketCodec decoder{Role::CLIENT, C::ZSTD_DICT};
    std::vector<uint8_t> wire, plain, reply;
    encoder.EncodeMessage(small, wire);
    const size_t first{wire.size()};
    const auto frame{CompressP2PIndependent(block.header, block.payload)};
    encoder.EncodeIndependent(frame, wire);
    BOOST_CHECK_EQUAL(wire[first] & 0x70, 0x20);
    encoder.EncodeMessage(small, wire);
    BOOST_REQUIRE(!decoder.Decode(wire, plain, reply).error);
    std::vector<uint8_t> expected{small};
    expected.insert(expected.end(), block_bytes.begin(), block_bytes.end());
    expected.insert(expected.end(), small.begin(), small.end());
    BOOST_CHECK(plain == expected);
    BOOST_CHECK_EQUAL(decoder.IndependentFramesRecv(), 1U);
    // The frame alone decodes for a brand-new peer: no stream history.
    WebSocketCodec fresh_encoder{Role::SERVER, C::ZSTD_DICT};
    WebSocketCodec fresh{Role::CLIENT, C::ZSTD_DICT};
    wire.clear();
    plain.clear();
    fresh_encoder.EncodeIndependent(frame, wire);
    BOOST_REQUIRE(!fresh.Decode(wire, plain, reply).error);
    BOOST_CHECK(plain == block_bytes);
    // A client (masked) can send them too.
    WebSocketCodec client{Role::CLIENT, C::ZSTD_DICT};
    WebSocketCodec server{Role::SERVER, C::ZSTD_DICT};
    wire.clear();
    plain.clear();
    client.EncodeIndependent(frame, wire);
    BOOST_REQUIRE(!server.Decode(wire, plain, reply).error);
    BOOST_CHECK(plain == block_bytes);
}

BOOST_AUTO_TEST_CASE(independent_frames_rejected_without_zstd) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 70000)};
    const auto frame{CompressP2PIndependent(block.header, block.payload)};
    WebSocketCodec sender{Role::SERVER, C::ZSTD_DICT};
    std::vector<uint8_t> wire;
    sender.EncodeIndependent(frame, wire);
    // Uncompressed connections have no RSV bits at all.
    {
        WebSocketCodec decoder{Role::CLIENT, C::NONE};
        std::vector<uint8_t> plain, reply;
        const auto result{decoder.Decode(wire, plain, reply)};
        BOOST_REQUIRE(result.error);
        BOOST_CHECK(result.error->find("reserved bits") != std::string::npos);
        BOOST_CHECK(plain.empty());
    }
    // p2p-zstd (no stream dictionary) decodes them too.
    {
        WebSocketCodec decoder{Role::CLIENT, C::ZSTD};
        std::vector<uint8_t> plain, reply;
        BOOST_REQUIRE(!decoder.Decode(wire, plain, reply).error);
        BOOST_CHECK(plain == block.Bytes());
    }
    // RSV1, RSV3, RSV1|RSV2, RSV2 on a fragment,
    // continuation, text or control frame are invalid.
    for (const uint8_t first :
         {uint8_t(0xc2), uint8_t(0x92), uint8_t(0xe2), uint8_t(0x22),
          uint8_t(0xa1), uint8_t(0xa9), uint8_t(0xa8)}) {
        WebSocketCodec decoder{Role::CLIENT, C::ZSTD_DICT};
        std::vector<uint8_t> plain, reply;
        BOOST_CHECK(
            decoder.Decode(std::vector<uint8_t>{first, 1, 0}, plain, reply)
                .error);
    }
    {
        // A fragmented message cannot continue with an RSV2 frame.
        WebSocketCodec decoder{Role::CLIENT, C::ZSTD_DICT};
        std::vector<uint8_t> plain, reply;
        BOOST_CHECK(decoder
                        .Decode(std::vector<uint8_t>{0x02, 1, 0, 0xa0, 1, 0},
                                plain, reply)
                        .error);
    }
}

BOOST_AUTO_TEST_CASE(independent_frame_strict_validation) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 70000)};
    const auto bytes{block.Bytes()};
    const auto original{CompressP2PIndependent(block.header, block.payload)};
    std::vector<uint8_t> out;
    DecompressP2PIndependent(original, out, bytes.size());
    BOOST_CHECK(out == bytes);
    out.clear();
    auto expect_reject = [&](const std::vector<uint8_t> &frame,
                             size_t maximum) {
        out.assign(3, 0x55);
        BOOST_CHECK_THROW(DecompressP2PIndependent(frame, out, maximum),
                          std::runtime_error);
        // Nothing was appended.
        BOOST_CHECK(out == std::vector<uint8_t>(3, 0x55));
    };
    auto bad{original};
    bad[0] = 2; // Unknown format
    expect_reject(bad, 100000);
    bad = original;
    bad[1] ^= 1; // Unknown dictionary version
    expect_reject(bad, 100000);
    bad = original;
    bad.push_back(0); // Trailing data
    expect_reject(bad, 100000);
    bad = original;
    bad.pop_back(); // Truncated
    expect_reject(bad, 100000);
    bad = original;
    bad.insert(bad.end(), original.begin() + P2P_INDEPENDENT_ENVELOPE,
               original.end()); // Two concatenated frames
    expect_reject(bad, 1000000);
    expect_reject(original, bytes.size() - 1); // Above the message limit
    expect_reject({}, 100000);
    expect_reject({1, 1, 0, 0, 0}, 100000); // Envelope only
    // A skippable frame is not a compressed P2P message.
    bad.assign(13, 0);
    bad[0] = P2P_INDEPENDENT_FORMAT;
    WriteLE32(bad.data() + 1, P2P_INDEPENDENT_DICT_VERSION);
    WriteLE32(bad.data() + 5, 0x184d2a50);
    expect_reject(bad, 100000);
    // Without a content size.
    {
        std::vector<uint8_t> frame(P2P_INDEPENDENT_ENVELOPE +
                                   ZSTD_compressBound(bytes.size()));
        frame[0] = P2P_INDEPENDENT_FORMAT;
        WriteLE32(frame.data() + 1, P2P_INDEPENDENT_DICT_VERSION);
        std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx *)> ctx{
            ZSTD_createCCtx(), &ZSTD_freeCCtx};
        BOOST_REQUIRE(!ZSTD_isError(
            ZSTD_CCtx_setParameter(ctx.get(), ZSTD_c_contentSizeFlag, 0)));
        ZSTD_outBuffer output{frame.data(), frame.size(),
                              P2P_INDEPENDENT_ENVELOPE};
        ZSTD_inBuffer input{bytes.data(), bytes.size(), 0};
        BOOST_REQUIRE(!ZSTD_isError(
            ZSTD_compressStream2(ctx.get(), &output, &input, ZSTD_e_end)));
        frame.resize(output.pos);
        BOOST_REQUIRE_EQUAL(
            ZSTD_getFrameContentSize(frame.data() + P2P_INDEPENDENT_ENVELOPE,
                                     frame.size() - P2P_INDEPENDENT_ENVELOPE),
            ZSTD_CONTENTSIZE_UNKNOWN);
        expect_reject(frame, 1000000);
    }
    // A declared window above the decoder limit, even though the content
    // fits the message limit.
    {
        const std::vector<uint8_t> big(2 * 1024 * 1024, 0x24);
        std::vector<uint8_t> frame(P2P_INDEPENDENT_ENVELOPE +
                                   ZSTD_compressBound(big.size()));
        frame[0] = P2P_INDEPENDENT_FORMAT;
        WriteLE32(frame.data() + 1, P2P_INDEPENDENT_DICT_VERSION);
        const size_t n{ZSTD_compress(frame.data() + P2P_INDEPENDENT_ENVELOPE,
                                     frame.size() - P2P_INDEPENDENT_ENVELOPE,
                                     big.data(), big.size(), 3)};
        BOOST_REQUIRE(!ZSTD_isError(n));
        frame.resize(P2P_INDEPENDENT_ENVELOPE + n);
        expect_reject(frame, 4 * 1024 * 1024);
    }
    // Over the wire, a bad frame is a fatal decode error.
    WebSocketCodec sender{Role::SERVER, C::ZSTD_DICT};
    WebSocketCodec decoder{Role::CLIENT, C::ZSTD_DICT};
    std::vector<uint8_t> wire, plain, reply;
    bad = original;
    bad.push_back(0);
    sender.EncodeIndependent(bad, wire);
    const auto result{decoder.Decode(wire, plain, reply)};
    BOOST_REQUIRE(result.error);
    BOOST_CHECK(result.error->find("independent zstd") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(independent_frame_message_limit) {
    RestoreBlockLimit restore;
    BOOST_REQUIRE(restore.config.SetMaxBlockSize(32 * 1000000));
    const uint64_t limit{GetP2PWebSocketMessageSizeLimit()};
    WebSocketCodec sender{Role::SERVER, C::ZSTD_DICT};
    WebSocketCodec decoder{Role::CLIENT, C::ZSTD_DICT};
    // Incompressible: the frame is larger than its content, and accepted.
    FastRandomContext rng{true};
    const auto random{rng.randbytes<uint8_t>(limit - 24)};
    const std::vector<uint8_t> header(24, 0);
    std::vector<uint8_t> wire, plain, reply;
    sender.EncodeIndependent(CompressP2PIndependent(header, random), wire);
    BOOST_CHECK_GT(wire.size(), limit);
    BOOST_REQUIRE(!decoder.Decode(wire, plain, reply).error);
    BOOST_CHECK_EQUAL(plain.size(), limit);
    // One byte over the configured message limit is refused before output.
    wire.clear();
    plain.clear();
    sender.EncodeIndependent(
        CompressP2PIndependent(header, std::vector<uint8_t>(limit - 23, 0)),
        wire);
    const auto result{decoder.Decode(wire, plain, reply)};
    BOOST_REQUIRE(result.error);
    BOOST_CHECK(result.error->find("content size") != std::string::npos);
    BOOST_CHECK(plain.empty());
}

BOOST_AUTO_TEST_CASE(block_frame_cache_bounds_and_identity) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 20000)};
    P2PIndependentFrameCache cache{1 << 20, 2};
    const auto held{cache.Encode(block.header, block.payload)};
    BOOST_CHECK(cache.Encode(block.header, block.payload) == held);
    // Same block header, different body (so a different P2P checksum).
    auto changed{block.payload};
    changed.back() ^= 1;
    const auto changed_msg{MakeMessage(NetMsgType::BLOCK, changed)};
    const auto second{cache.Encode(changed_msg.header, changed_msg.payload)};
    BOOST_CHECK(second != held);
    std::vector<uint8_t> decoded;
    DecompressP2PIndependent(*second, decoded, 100000);
    BOOST_CHECK(decoded == changed_msg.Bytes());
    // A third block evicts the least recently used (the first).
    const auto third{MakeBlockMessage(rng, 20000)};
    cache.Encode(third.header, third.payload);
    auto stats{cache.GetStats()};
    BOOST_CHECK_EQUAL(stats.hits, 1U);
    BOOST_CHECK_EQUAL(stats.misses, 3U);
    BOOST_CHECK_EQUAL(stats.encodes, 3U);
    BOOST_CHECK_EQUAL(stats.entries, 2U);
    BOOST_CHECK_EQUAL(stats.evictions, 1U);
    BOOST_CHECK_LE(stats.bytes, 1U << 20);
    // The evicted frame stays valid for whoever holds it.
    decoded.clear();
    DecompressP2PIndependent(*held, decoded, 100000);
    BOOST_CHECK(decoded == block.Bytes());
    // Non-block messages and unparsable bodies are not cached.
    const auto tx{MakeMessage(NetMsgType::TX, std::vector<uint8_t>(5000, 1))};
    cache.Encode(tx.header, tx.payload);
    const auto stub{
        MakeMessage(NetMsgType::BLOCK, std::vector<uint8_t>(10, 1))};
    cache.Encode(stub.header, stub.payload);
    stats = cache.GetStats();
    BOOST_CHECK_EQUAL(stats.encodes, 5U);
    BOOST_CHECK_EQUAL(stats.misses, 3U);
    BOOST_CHECK_EQUAL(stats.entries, 2U);
    // The byte budget is of allocated capacity; shrinking it evicts.
    cache.SetMaxBytes(held->capacity());
    stats = cache.GetStats();
    BOOST_CHECK_LE(stats.bytes, held->capacity());
    BOOST_CHECK_LE(stats.entries, 1U);
    // A frame larger than the whole budget is served but not kept.
    P2PIndependentFrameCache tiny{16, 2};
    BOOST_CHECK(tiny.Encode(block.header, block.payload));
    BOOST_CHECK_EQUAL(tiny.GetStats().entries, 0U);
    BOOST_CHECK_EQUAL(tiny.GetStats().bytes, 0U);
    P2PIndependentFrameCache off{0, 2};
    off.Encode(block.header, block.payload);
    off.Encode(block.header, block.payload);
    BOOST_CHECK_EQUAL(off.GetStats().encodes, 2U);
}

BOOST_AUTO_TEST_CASE(block_frame_cache_same_header_different_payload) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 20000)};
    auto changed{block.payload};
    changed.back() ^= 1;
    P2PIndependentFrameCache cache;
    const auto first{cache.Encode(block.header, block.payload)};
    // The API does not validate the checksum. Reuse the entire P2P header,
    // including its 32-bit checksum, with different supplied body bytes.
    const auto second{cache.Encode(block.header, changed)};
    BOOST_CHECK(first != second);
    BOOST_CHECK(cache.Encode(block.header, changed) == second);
    std::vector<uint8_t> expected{block.header};
    expected.insert(expected.end(), changed.begin(), changed.end());
    std::vector<uint8_t> decoded;
    DecompressP2PIndependent(*second, decoded, expected.size());
    BOOST_CHECK(decoded == expected);
    const auto stats{cache.GetStats()};
    BOOST_CHECK_EQUAL(stats.encodes, 2U);
    BOOST_CHECK_EQUAL(stats.misses, 2U);
    BOOST_CHECK_EQUAL(stats.hits, 1U);
}

BOOST_AUTO_TEST_CASE(block_frame_cache_concurrent_single_compression) {
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 2000000)};
    P2PIndependentFrameCache cache;
    std::array<P2PIndependentFrameCache::Frame, 8> results;
    std::promise<void> start;
    const std::shared_future<void> go{start.get_future().share()};
    std::vector<std::thread> workers;
    for (size_t i = 0; i < results.size(); ++i) {
        workers.emplace_back([&, i] {
            go.wait();
            results[i] = cache.Encode(block.header, block.payload);
        });
    }
    start.set_value();
    for (auto &thread : workers) {
        thread.join();
    }
    const auto stats{cache.GetStats()};
    BOOST_CHECK_EQUAL(stats.encodes, 1U);
    BOOST_CHECK_EQUAL(stats.misses, 1U);
    BOOST_CHECK_EQUAL(stats.hits, 7U);
    for (const auto &result : results) {
        BOOST_CHECK(result == results[0]);
    }
}

BOOST_AUTO_TEST_CASE(mixed_peers_receive_identical_streams) {
    RestoreThreshold restore;
    g_p2p_compress_once_threshold = DEFAULT_P2P_COMPRESS_ONCE_THRESHOLD;
    FastRandomContext rng{true};
    const auto ping{MakeMessage("ping", rng.randbytes<uint8_t>(8))};
    const auto block{MakeBlockMessage(rng, 3000000)};
    const auto small_block{MakeBlockMessage(rng, 1000)};
    const auto inv{MakeMessage("inv", std::vector<uint8_t>(37, 2))};
    const auto expected{Concat({&ping, &block, &small_block, &inv})};
    // Three zstd peers (two modes) and two uncompressed peers.
    std::vector<std::unique_ptr<ModePair>> peers;
    for (const C mode :
         {C::ZSTD_DICT, C::NONE, C::ZSTD, C::NONE, C::ZSTD_DICT}) {
        peers.push_back(std::make_unique<ModePair>(mode));
    }
    const auto before{GetP2PIndependentFrameCache().GetStats()};
    for (const auto &p : peers) {
        SendLikeConnman(*p->server, ping, true);
        SendLikeConnman(*p->server, block, true);
        SendLikeConnman(*p->server, small_block, true);
        SendLikeConnman(*p->server, inv, false);
    }
    for (const auto &p : peers) {
        BOOST_CHECK(ReceiveAll(*p->server, *p->client, expected.size()) ==
                    expected);
        const auto &info{*p->server->Info()};
        // Only the large block goes alone, and only to zstd peers.
        const bool zstd{info.compression != C::NONE};
        BOOST_CHECK_EQUAL(info.independent_frames_sent.load(), zstd ? 1U : 0U);
        BOOST_CHECK_EQUAL(p->client->Info()->independent_frames_recv.load(),
                          zstd ? 1U : 0U);
        BOOST_CHECK_EQUAL(info.payload_bytes_sent.load(), expected.size());
    }
    // Compressed once for the three zstd peers.
    const auto after{GetP2PIndependentFrameCache().GetStats()};
    BOOST_CHECK_EQUAL(after.encodes - before.encodes, 1U);
    BOOST_CHECK_EQUAL(after.misses - before.misses, 1U);
    BOOST_CHECK_EQUAL(after.hits - before.hits, 2U);
}

BOOST_AUTO_TEST_CASE(independent_frames_follow_unusual_send_patterns) {
    RestoreThreshold restore;
    g_p2p_compress_once_threshold = DEFAULT_P2P_COMPRESS_ONCE_THRESHOLD;
    FastRandomContext rng{true};
    const auto block{MakeBlockMessage(rng, 300000)};
    const auto block2{MakeBlockMessage(rng, 300000)};
    const auto tx{MakeMessage(NetMsgType::TX, rng.randbytes<uint8_t>(200000))};
    {
        // Payload in pieces, and a header split by a flush: both still
        // deliver the same bytes; the split block goes in the stream.
        ModePair p{C::ZSTD_DICT};
        const auto bytes{block.Bytes()};
        size_t off{0};
        for (const size_t piece :
             {size_t(24), size_t(100000), bytes.size() - 100024}) {
            BOOST_REQUIRE_EQUAL(p.server->Send(bytes.data() + off, piece, 0),
                                ssize_t(piece));
            off += piece;
        }
        const auto bytes2{block2.Bytes()};
        // Header split by a flush (no MSG_MORE), then the rest at once.
        BOOST_REQUIRE_EQUAL(p.server->Send(bytes2.data(), 7, 0), 7);
        BOOST_REQUIRE_EQUAL(
            p.server->Send(bytes2.data() + 7, bytes2.size() - 7, 0),
            ssize_t(bytes2.size() - 7));
        // A large non-block message stays in the stream.
        SendLikeConnman(*p.server, tx, false);
        const auto expected{Concat({&block, &block2, &tx})};
        BOOST_CHECK(ReceiveAll(*p.server, *p.client, expected.size()) ==
                    expected);
        BOOST_CHECK_EQUAL(p.server->Info()->independent_frames_sent.load(), 1U);
    }
    {
        // Threshold 0: the streaming control, frames never sent.
        g_p2p_compress_once_threshold = 0;
        ModePair p{C::ZSTD_DICT};
        SendLikeConnman(*p.server, block, false);
        BOOST_CHECK(ReceiveAll(*p.server, *p.client, block.Bytes().size()) ==
                    block.Bytes());
        BOOST_CHECK_EQUAL(p.server->Info()->independent_frames_sent.load(), 0U);
        // Above the threshold only.
        g_p2p_compress_once_threshold = block.Bytes().size() + 1;
        SendLikeConnman(*p.server, block2, false);
        ReceiveAll(*p.server, *p.client, block2.Bytes().size());
        BOOST_CHECK_EQUAL(p.server->Info()->independent_frames_sent.load(), 0U);
        g_p2p_compress_once_threshold = block2.Bytes().size();
        SendLikeConnman(*p.server, block2, false);
        BOOST_CHECK(ReceiveAll(*p.server, *p.client, block2.Bytes().size()) ==
                    block2.Bytes());
        BOOST_CHECK_EQUAL(p.server->Info()->independent_frames_sent.load(), 1U);
    }
    {
        // Clients send them too.
        g_p2p_compress_once_threshold = DEFAULT_P2P_COMPRESS_ONCE_THRESHOLD;
        ModePair p{C::ZSTD_DICT};
        SendLikeConnman(*p.client, block, false);
        BOOST_CHECK(ReceiveAll(*p.client, *p.server, block.Bytes().size()) ==
                    block.Bytes());
        BOOST_CHECK_EQUAL(p.server->Info()->independent_frames_recv.load(), 1U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
