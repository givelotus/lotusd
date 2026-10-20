// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Built only with -DENABLE_WEBTRANSPORT=ON.

#include <net_quic/quic_engine.h>

#include <netaddress.h>
#include <random.h>
#include <tls_util.h>
#include <util/fs.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;

namespace {
CService Loopback(uint16_t port = 0) {
    in_addr a{};
    a.s_addr = htonl(INADDR_LOOPBACK);
    return CService{a, port};
}

struct QuicTestSetup : public BasicTestingSetup {
    fs::path cert;
    fs::path key;
    std::vector<uint8_t> cert_sha256;

    QuicTestSetup() {
        cert = m_path_root / "quic_cert.pem";
        key = m_path_root / "quic_key.pem";
        const auto pem{tls::GenerateSelfSigned("localhost", {"localhost"},
                                               {"127.0.0.1"}, 24h * 10)};
        BOOST_REQUIRE(pem);
        BOOST_REQUIRE(tls::WritePemFiles(*pem, cert, key));
        BIO *bio{BIO_new_mem_buf(pem->cert_pem.data(),
                                 static_cast<int>(pem->cert_pem.size()))};
        X509 *x{PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)};
        BIO_free(bio);
        BOOST_REQUIRE(x);
        unsigned char *der{nullptr};
        const int n{i2d_X509(x, &der)};
        cert_sha256.resize(SHA256_DIGEST_LENGTH);
        SHA256(der, static_cast<size_t>(n), cert_sha256.data());
        OPENSSL_free(der);
        X509_free(x);
    }

    QuicEngineOptions ServerOptions() const {
        QuicEngineOptions o;
        o.binds = {Loopback()};
        o.cert_file = cert;
        o.key_file = key;
        o.application = QuicApplication::ECHO_FOR_TEST;
        return o;
    }

    static std::unique_ptr<QuicEngine> StartEngine(const QuicEngineOptions &o) {
        std::string error;
        auto engine{QuicEngine::Start(o, error)};
        BOOST_REQUIRE_MESSAGE(engine, error);
        return engine;
    }
};

/**
 * A UDP relay between a client and a QUIC server on loopback. It can
 * corrupt address validation tokens in client Initials, or drop
 * everything.
 */
class Relay {
public:
    explicit Relay(const CService &server) {
        m_front = Bind();
        m_back = Bind();
        sockaddr_in sin{};
        socklen_t len{sizeof(sin)};
        server.GetSockAddr(reinterpret_cast<sockaddr *>(&sin), &len);
        m_server = sin;
        sockaddr_in front{};
        len = sizeof(front);
        getsockname(m_front, reinterpret_cast<sockaddr *>(&front), &len);
        m_port = ntohs(front.sin_port);
        m_thread = std::thread{[this] { Run(); }};
    }
    ~Relay() {
        m_stop = true;
        m_thread.join();
        close(m_front);
        close(m_back);
    }
    CService Address() const { return Loopback(m_port); }

    std::atomic<bool> corrupt_tokens{false};
    std::atomic<bool> drop{false};
    std::atomic<int> tokens_corrupted{0};

private:
    static int Bind() {
        const int fd{socket(AF_INET, SOCK_DGRAM, 0)};
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE(bind(fd, reinterpret_cast<sockaddr *>(&sin),
                           sizeof(sin)) == 0);
        return fd;
    }

    void Corrupt(uint8_t *p, size_t n) {
        // Long header Initial (v1): flags, version, DCID, SCID, token.
        if (n < 7 || !(p[0] & 0x80) || ((p[0] & 0x30) >> 4) != 0) {
            return;
        }
        size_t pos{5};
        for (int i = 0; i < 2; ++i) {
            if (pos >= n) {
                return;
            }
            pos += 1 + p[pos];
        }
        if (pos >= n) {
            return;
        }
        const size_t vlen{size_t{1} << (p[pos] >> 6)};
        if (pos + vlen > n) {
            return;
        }
        uint64_t tokenlen{p[pos] & 0x3fu};
        for (size_t i = 1; i < vlen; ++i) {
            tokenlen = (tokenlen << 8) | p[pos + i];
        }
        pos += vlen;
        if (tokenlen > 0 && pos + tokenlen <= n) {
            p[pos + tokenlen - 1] ^= 0x01;
            ++tokens_corrupted;
        }
    }

    void Run() {
        std::vector<uint8_t> buf(65536);
        while (!m_stop) {
            pollfd fds[2]{{m_front, POLLIN, 0}, {m_back, POLLIN, 0}};
            if (poll(fds, 2, 20) <= 0) {
                continue;
            }
            if (fds[0].revents & POLLIN) {
                sockaddr_in from{};
                socklen_t fl{sizeof(from)};
                const ssize_t r{recvfrom(m_front, buf.data(), buf.size(), 0,
                                         reinterpret_cast<sockaddr *>(&from),
                                         &fl)};
                if (r > 0) {
                    m_client = from;
                    m_have_client = true;
                    if (corrupt_tokens) {
                        Corrupt(buf.data(), static_cast<size_t>(r));
                    }
                    if (!drop) {
                        sendto(m_back, buf.data(), static_cast<size_t>(r), 0,
                               reinterpret_cast<sockaddr *>(&m_server),
                               sizeof(m_server));
                    }
                }
            }
            if (fds[1].revents & POLLIN) {
                const ssize_t r{
                    recv(m_back, buf.data(), buf.size(), MSG_DONTWAIT)};
                if (r > 0 && m_have_client && !drop) {
                    sendto(m_front, buf.data(), static_cast<size_t>(r), 0,
                           reinterpret_cast<sockaddr *>(&m_client),
                           sizeof(m_client));
                }
            }
        }
    }

    int m_front{-1}, m_back{-1};
    uint16_t m_port{0};
    sockaddr_in m_server{}, m_client{};
    bool m_have_client{false};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

std::vector<uint8_t> RandomPayload(size_t n) {
    std::vector<uint8_t> v(n);
    FastRandomContext rng;
    for (auto &b : v) {
        b = static_cast<uint8_t>(rng.randbits(8));
    }
    return v;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(net_quic_tests, QuicTestSetup)

BOOST_AUTO_TEST_CASE(handshake_and_stream_echo) {
    auto server{StartEngine(ServerOptions())};
    auto client{StartEngine(QuicEngineOptions{})};
    const auto addrs{server->BoundAddresses()};
    BOOST_REQUIRE_EQUAL(addrs.size(), 1U);
    BOOST_CHECK(addrs[0].GetPort() != 0);

    const std::vector<uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
    auto echoed{client->EchoForTest(addrs[0], hello, 10s)};
    BOOST_REQUIRE(echoed);
    BOOST_CHECK(*echoed == hello);

    // 1 MiB: several flow-control windows of the stream are exercised.
    const auto big{RandomPayload(1 << 20)};
    echoed = client->EchoForTest(addrs[0], big, 30s, cert_sha256);
    BOOST_REQUIRE(echoed);
    BOOST_CHECK(*echoed == big);

    // A certificate hash that does not match is refused.
    std::vector<uint8_t> wrong{cert_sha256};
    wrong[0] ^= 1;
    BOOST_CHECK(!client->EchoForTest(addrs[0], hello, 10s, wrong));

    const auto stats{server->Stats()};
    // The refused client may close before the server sees its Finished.
    BOOST_CHECK_GE(stats.handshakes_completed, 2U);
    BOOST_CHECK_EQUAL(stats.retry_sent, 0U);
    BOOST_CHECK_GT(stats.packets_recv, 0U);
}

BOOST_AUTO_TEST_CASE(retry_always) {
    auto options{ServerOptions()};
    options.retry = QuicRetryMode::ALWAYS;
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    const CService addr{server->BoundAddresses().at(0)};

    const std::vector<uint8_t> hello{'r', 'e', 't', 'r', 'y'};
    const auto start{std::chrono::steady_clock::now()};
    auto echoed{client->EchoForTest(addr, hello, 10s)};
    BOOST_REQUIRE(echoed);
    BOOST_CHECK(*echoed == hello);
    BOOST_TEST_MESSAGE("echo with Retry took "
                       << std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - start)
                              .count()
                       << " ms");
    // One Retry per token-less Initial datagram: a ClientHello offering
    // X25519MLKEM768 does not fit in one, so there can be two.
    BOOST_CHECK_GE(server->Stats().retry_sent, 1U);
    BOOST_CHECK_EQUAL(server->Stats().retry_token_rejected, 0U);

    // A Retry token altered on the way is rejected: no connection.
    Relay relay{addr};
    relay.corrupt_tokens = true;
    BOOST_CHECK(!client->EchoForTest(relay.Address(), hello, 3s));
    BOOST_CHECK_GE(relay.tokens_corrupted.load(), 1);
    BOOST_CHECK_GE(server->Stats().retry_token_rejected, 1U);
    BOOST_CHECK_EQUAL(server->Stats().handshakes_completed, 1U);
}

BOOST_AUTO_TEST_CASE(stateless_reset_rate_limit) {
    auto options{ServerOptions()};
    options.stateless_reset_rate = 10;
    auto server{StartEngine(options)};
    const CService addr{server->BoundAddresses().at(0)};
    sockaddr_in sin{};
    socklen_t len{sizeof(sin)};
    addr.GetSockAddr(reinterpret_cast<sockaddr *>(&sin), &len);

    const int fd{socket(AF_INET, SOCK_DGRAM, 0)};
    BOOST_REQUIRE(fd >= 0);
    // Short header packets for unknown connection IDs, 80 bytes each.
    for (int i = 0; i < 40; ++i) {
        auto pkt{RandomPayload(80)};
        pkt[0] = 0x40 | (pkt[0] & 0x3f);
        sendto(fd, pkt.data(), pkt.size(), 0,
               reinterpret_cast<sockaddr *>(&sin), sizeof(sin));
    }
    int resets{0};
    const auto deadline{std::chrono::steady_clock::now() + 500ms};
    std::vector<uint8_t> buf(2048);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, 50) > 0) {
            const ssize_t r{recv(fd, buf.data(), buf.size(), 0)};
            if (r > 0) {
                ++resets;
                // Smaller than the 80-byte trigger, at least 21 bytes.
                BOOST_CHECK_LT(r, 80);
                BOOST_CHECK_GE(r, 21);
            }
        }
    }
    close(fd);
    BOOST_CHECK_GE(resets, 1);
    BOOST_CHECK_LE(resets, 10);
    BOOST_CHECK_LE(server->Stats().stateless_reset_sent, 10U);
}

BOOST_AUTO_TEST_CASE(idle_timeout) {
    auto options{ServerOptions()};
    options.idle_timeout = 1s;
    auto server{StartEngine(options)};
    QuicEngineOptions client_options;
    client_options.idle_timeout = 1s;
    client_options.keep_alive = 0ms;
    auto client{StartEngine(client_options)};
    Relay relay{server->BoundAddresses().at(0)};

    // Black-hole the path once the handshake completes, in the middle of a
    // large transfer: both ends close after the idle timeout.
    std::atomic<bool> done{false};
    std::thread cut{[&] {
        while (!done && server->Stats().handshakes_completed == 0) {
            std::this_thread::sleep_for(1ms);
        }
        relay.drop = true;
    }};
    const auto start{std::chrono::steady_clock::now()};
    const auto echoed{
        client->EchoForTest(relay.Address(), RandomPayload(8 << 20), 10s)};
    done = true;
    cut.join();
    const auto elapsed{std::chrono::steady_clock::now() - start};
    BOOST_CHECK(!echoed);
    BOOST_CHECK(elapsed < 8s);
    // The server forgets the connection after its own idle timeout.
    const auto deadline{std::chrono::steady_clock::now() + 5s};
    while (server->Stats().connections > 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(20ms);
    }
    BOOST_CHECK_EQUAL(server->Stats().connections, 0U);
    BOOST_CHECK_GE(server->Stats().idle_closed, 1U);
    BOOST_CHECK_GE(client->Stats().idle_closed, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
