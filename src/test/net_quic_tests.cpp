// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Built only with -DENABLE_WEBTRANSPORT=ON.

#include <net_quic/quic_engine.h>
#include <crypto/common.h>
#include <net_quic/webtransport_wire.h>

#include <netaddress.h>
#include <netbase.h>
#include <random.h>
#include <tinyformat.h>
#include <tls_util.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <fstream>
#include <cstdlib>
#include <mutex>
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

BOOST_AUTO_TEST_CASE(admission_ip_groups_and_handshake_slots) {
    using D = QuicAdmission::Decision;
    const auto now{QuicAdmission::Clock::time_point{}};
    const auto a{LookupNumeric("127.0.0.1", 1000)};
    const auto same_ip{LookupNumeric("127.0.0.1", 2000)};
    const auto b{LookupNumeric("127.0.0.2", 1000)};
    const auto c{LookupNumeric("127.0.0.3", 1000)};
    QuicAdmission policy{1, 2};
    BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::OFF, now) == D::ACCEPT);
    policy.Started(a);
    BOOST_CHECK(policy.Inspect(same_ip, true, QuicRetryMode::OFF, now) ==
                D::PER_IP);
    BOOST_CHECK(policy.Inspect(b, true, QuicRetryMode::OFF, now) == D::ACCEPT);
    policy.Started(b);
    BOOST_CHECK_EQUAL(policy.Active(), 2U);
    BOOST_CHECK(policy.Inspect(c, true, QuicRetryMode::OFF, now) ==
                D::HANDSHAKING);
    policy.HandshakeDone();
    BOOST_CHECK_EQUAL(policy.Handshaking(), 1U);
    BOOST_CHECK_EQUAL(policy.Active(), 2U);
    // Completing TLS releases a handshake slot but not the address slot.
    BOOST_CHECK(policy.Inspect(a, true, QuicRetryMode::OFF, now) == D::PER_IP);
    policy.Closed(a, true);
    BOOST_CHECK(policy.Inspect(a, true, QuicRetryMode::OFF, now) == D::ACCEPT);
    policy.Closed(b, false);
    BOOST_CHECK_EQUAL(policy.Handshaking(), 0U);
    BOOST_CHECK_EQUAL(policy.Active(), 0U);

    const auto v6a{LookupNumeric("2001:db8:1:2::1", 1000)};
    const auto v6same{LookupNumeric("2001:db8:1:2::ffff", 2000)};
    const auto v6other{LookupNumeric("2001:db8:1:3::1", 1000)};
    BOOST_CHECK(policy.Inspect(v6a, true, QuicRetryMode::OFF, now) ==
                D::ACCEPT);
    policy.Started(v6a);
    BOOST_CHECK(policy.Inspect(v6same, true, QuicRetryMode::OFF, now) ==
                D::PER_IP);
    BOOST_CHECK(policy.Inspect(v6other, true, QuicRetryMode::OFF, now) ==
                D::ACCEPT);
    policy.Closed(v6a, false);
}

BOOST_AUTO_TEST_CASE(admission_retry_window_and_bounded_table) {
    using D = QuicAdmission::Decision;
    const auto t{QuicAdmission::Clock::time_point{}};
    const auto a{LookupNumeric("127.0.0.1", 1000)};
    const auto b{LookupNumeric("127.0.0.2", 1000)};
    const auto c{LookupNumeric("127.0.0.3", 1000)};
    QuicAdmission policy;
    for (unsigned i{0}; i < 8; ++i) {
        BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::AUTO, t) ==
                    D::ACCEPT);
    }
    BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::AUTO, t) == D::RETRY);
    BOOST_CHECK(policy.Inspect(a, true, QuicRetryMode::AUTO, t) == D::ACCEPT);
    BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::OFF, t) == D::ACCEPT);
    BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::AUTO,
                               t + std::chrono::seconds{10}) == D::ACCEPT);
    BOOST_CHECK(policy.Inspect(a, false, QuicRetryMode::ALWAYS, t) == D::RETRY);

    QuicAdmission bounded{16, 256, 1};
    BOOST_CHECK(bounded.Inspect(a, false, QuicRetryMode::AUTO, t) == D::ACCEPT);
    BOOST_CHECK(bounded.Inspect(b, false, QuicRetryMode::AUTO, t) == D::RETRY);
    BOOST_CHECK_EQUAL(bounded.Buckets(), 1U);
    BOOST_CHECK(bounded.Inspect(b, true, QuicRetryMode::AUTO, t) == D::ACCEPT);
    bounded.Started(b);
    BOOST_CHECK(bounded.Inspect(c, true, QuicRetryMode::AUTO, t) ==
                D::TABLE_FULL);
    bounded.Closed(b, false);
    BOOST_CHECK(bounded.Inspect(c, false, QuicRetryMode::AUTO,
                                t + std::chrono::seconds{10}) == D::ACCEPT);

    QuicAdmission loaded{100, 256};
    for (unsigned i{0}; i < 65; ++i) {
        BOOST_REQUIRE(loaded.Inspect(a, true, QuicRetryMode::AUTO, t) ==
                      D::ACCEPT);
        loaded.Started(a);
    }
    BOOST_CHECK(loaded.Inspect(b, false, QuicRetryMode::AUTO, t) == D::RETRY);
    for (unsigned i{0}; i < 65; ++i)
        loaded.Closed(a, false);
    BOOST_CHECK_EQUAL(loaded.Handshaking(), 0U);
}

BOOST_AUTO_TEST_CASE(banned_initial_is_dropped_before_tls) {
    auto observed{std::make_shared<std::atomic<size_t>>(0)};
    auto options{ServerOptions()};
    options.is_banned = [](const CNetAddr &) { return true; };
    options.handshake_observer = [observed](QuicHandshakeObservation) {
        ++*observed;
    };
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    const auto address{server->BoundAddresses().front()};
    BOOST_CHECK(!client->EchoForTest(address, {1, 2, 3},
                                     std::chrono::milliseconds{500}));
    const auto stats{server->Stats()};
    BOOST_CHECK_GT(stats.rejected[size_t(QuicRejectReason::BANNED)], 0U);
    BOOST_CHECK_EQUAL(stats.handshakes_completed, 0U);
    BOOST_CHECK_EQUAL(stats.handshaking, 0U);
    BOOST_CHECK_EQUAL(observed->load(), 0U);
    client->Stop();
    server->Stop();
}

BOOST_AUTO_TEST_CASE(inbound_capacity_is_checked_before_tls) {
    auto observed{std::make_shared<std::atomic<size_t>>(0)};
    auto options{ServerOptions()};
    options.max_inbound = 0;
    options.handshake_observer = [observed](QuicHandshakeObservation) {
        ++*observed;
    };
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    BOOST_CHECK(!client->EchoForTest(server->BoundAddresses().front(), {1},
                                     std::chrono::milliseconds{500}));
    BOOST_CHECK_GT(server->Stats().rejected[size_t(QuicRejectReason::CAPACITY)],
                   0U);
    BOOST_CHECK_EQUAL(observed->load(), 0U);
    client->Stop();
    server->Stop();
}

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

BOOST_AUTO_TEST_CASE(wt_varints_and_stream_prefixes) {
    // RFC 9000 §16 examples.
    const std::vector<std::pair<uint64_t, std::string>> vectors{
        {37, "25"},
        {15293, "7bbd"},
        {494878333, "9d7f3e7d"},
        {151288809941952652ULL, "c2197c5eff14e88c"},
    };
    for (const auto &[v, hex] : vectors) {
        std::vector<uint8_t> enc;
        wt::PutVarint(enc, v);
        BOOST_CHECK_EQUAL(HexStr(enc), hex);
        uint64_t dec{0};
        BOOST_CHECK_EQUAL(wt::GetVarint(enc, dec), enc.size());
        BOOST_CHECK_EQUAL(dec, v);
        // Truncated: incomplete, never a wrong value.
        BOOST_CHECK_EQUAL(
            wt::GetVarint(Span<const uint8_t>{enc}.first(enc.size() - 1), dec),
            0U);
    }

    using S = wt::StreamPrefix::Status;
    struct Case {
        std::string hex;
        bool uni;
        S status;
        uint64_t session;
        size_t header_len;
    };
    const std::vector<Case> cases{
        // 0x41 and 0x54 are 2-byte varints (>= 64).
        {"404100", false, S::WEBTRANSPORT, 0, 3},
        {"40410401", false, S::WEBTRANSPORT, 4, 3},       // + class byte
        {"405400", true, S::WEBTRANSPORT, 0, 3},
        {"40414004", false, S::WEBTRANSPORT, 4, 4},       // 2-byte session
        {"4041" "80000004", false, S::WEBTRANSPORT, 4, 6}, // 4-byte session
        {"4041" "c000000000000008", false, S::WEBTRANSPORT, 8, 10},
        {"80000041" "00", false, S::WEBTRANSPORT, 0, 5},  // 4-byte signal
        {"4041", false, S::INCOMPLETE, 0, 0},
        {"40", false, S::INCOMPLETE, 0, 0},
        {"4041c0", false, S::INCOMPLETE, 0, 0},
        {"", false, S::INCOMPLETE, 0, 0},
        {"00", true, S::HTTP3, 0, 0},     // control stream
        {"02", true, S::HTTP3, 0, 0},     // QPACK encoder
        {"405400", false, S::HTTP3, 0, 0}, // 0x54 on a bidi stream
        {"404100", true, S::HTTP3, 0, 0},  // 0x41 on a uni stream
        {"01", false, S::HTTP3, 0, 0},     // HEADERS frame
    };
    for (const auto &c : cases) {
        const auto bytes{ParseHex(c.hex)};
        const auto p{wt::ParseStreamPrefix(bytes, c.uni)};
        BOOST_CHECK_MESSAGE(p.status == c.status, c.hex);
        if (c.status == S::WEBTRANSPORT) {
            BOOST_CHECK_EQUAL(p.session_id, c.session);
            BOOST_CHECK_EQUAL(p.header_len, c.header_len);
        }
    }
    BOOST_CHECK_EQUAL(HexStr(wt::BidiStreamHeader(4)), "404104");
    BOOST_CHECK_EQUAL(HexStr(wt::UniStreamHeader(64)), "40544040");
}

BOOST_AUTO_TEST_CASE(wt_capsules) {
    const auto close{wt::EncodeCloseSession(7, "bye")};
    // type 0x2843 (2-byte varint 0x6843), length 7, code, reason
    BOOST_CHECK_EQUAL(HexStr(close), "68430700000007627965");
    auto parsed{wt::ParseCapsule(close)};
    BOOST_REQUIRE(parsed.status == wt::CapsuleParse::Status::OK);
    BOOST_CHECK_EQUAL(parsed.consumed, close.size());
    BOOST_CHECK_EQUAL(parsed.capsule.type, wt::CAPSULE_CLOSE_SESSION);
    const auto decoded{wt::DecodeCloseSession(parsed.capsule.value)};
    BOOST_REQUIRE(decoded);
    BOOST_CHECK_EQUAL(decoded->code, 7U);
    BOOST_CHECK_EQUAL(decoded->reason, "bye");

    // Truncated at every position: incomplete, never OK or an error.
    for (size_t n = 0; n < close.size(); ++n) {
        BOOST_CHECK(
            wt::ParseCapsule(Span<const uint8_t>{close}.first(n)).status ==
            wt::CapsuleParse::Status::INCOMPLETE);
    }
    // Two capsules back to back, an unknown one first.
    std::vector<uint8_t> two;
    wt::EncodeCapsule(two, 0x190B4D3D, std::vector<uint8_t>{1, 2, 3});
    two.insert(two.end(), close.begin(), close.end());
    parsed = wt::ParseCapsule(two);
    BOOST_REQUIRE(parsed.status == wt::CapsuleParse::Status::OK);
    BOOST_CHECK_EQUAL(parsed.capsule.type, 0x190B4D3DU);
    parsed = wt::ParseCapsule(Span<const uint8_t>{two}.subspan(parsed.consumed));
    BOOST_CHECK(parsed.status == wt::CapsuleParse::Status::OK);
    BOOST_CHECK_EQUAL(parsed.capsule.type, wt::CAPSULE_CLOSE_SESSION);

    // A reason over 1024 bytes is invalid; so is a value without a code.
    std::vector<uint8_t> long_value(4 + 1025, 'x');
    BOOST_CHECK(!wt::DecodeCloseSession(long_value));
    long_value.resize(4 + 1024);
    BOOST_CHECK(wt::DecodeCloseSession(long_value));
    BOOST_CHECK(!wt::DecodeCloseSession(std::vector<uint8_t>{0, 0, 1}));
    // Encoding truncates an over-long reason.
    const auto enc{wt::EncodeCloseSession(1, std::string(2000, 'y'))};
    parsed = wt::ParseCapsule(enc);
    BOOST_REQUIRE(parsed.status == wt::CapsuleParse::Status::OK);
    BOOST_CHECK_EQUAL(parsed.capsule.value.size(), 4U + wt::MAX_CLOSE_REASON);
    // A capsule claiming more than we buffer is an error, not a wait.
    std::vector<uint8_t> huge;
    wt::PutVarint(huge, 0x2843);
    wt::PutVarint(huge, wt::MAX_CAPSULE_SIZE + 1);
    BOOST_CHECK(wt::ParseCapsule(huge).status ==
                wt::CapsuleParse::Status::ERROR);
}

BOOST_AUTO_TEST_CASE(wt_error_code_mapping) {
    BOOST_CHECK_EQUAL(wt::WebTransportCodeToHttp(0), 0x52e4a40fa8dbULL);
    BOOST_CHECK_EQUAL(wt::WebTransportCodeToHttp(0xffffffff),
                      0x52e5ac983162ULL);
    for (uint32_t code = 0; code <= 0x1000; ++code) {
        const uint64_t h{wt::WebTransportCodeToHttp(code)};
        // Never a reserved (grease) HTTP/3 codepoint 0x1f * N + 0x21.
        BOOST_CHECK((h - 0x21) % 0x1f != 0);
        BOOST_CHECK(wt::HttpCodeToWebTransport(h) == code);
    }
    BOOST_CHECK(wt::HttpCodeToWebTransport(0xffffffff) == std::nullopt);
    BOOST_CHECK(wt::HttpCodeToWebTransport(wt::WebTransportCodeToHttp(
                    0xffffffff)) == 0xffffffffU);
    // Below/above the range and a grease codepoint inside it.
    BOOST_CHECK(!wt::HttpCodeToWebTransport(0x52e4a40fa8da));
    BOOST_CHECK(!wt::HttpCodeToWebTransport(0x52e5ac983163));
    uint64_t grease{0x52e4a40fa8db};
    while ((grease - 0x21) % 0x1f != 0) {
        ++grease;
    }
    BOOST_CHECK(!wt::HttpCodeToWebTransport(grease));
}

BOOST_AUTO_TEST_CASE(wt_protocol_lists) {
    auto l{wt::ParseProtocolList(R"("alpha", "beta")")};
    BOOST_REQUIRE(l);
    BOOST_CHECK(*l == (std::vector<std::string>{"alpha", "beta"}));
    l = wt::ParseProtocolList(R"("a";q=1,"b\"c")");
    BOOST_REQUIRE(l);
    BOOST_CHECK(*l == (std::vector<std::string>{"a", "b\"c"}));
    BOOST_CHECK(wt::ParseProtocolList("")->empty());
    for (const char *bad : {"p2p-v1", R"("p2p-v1)", R"("a" "b")", R"("a",)",
                            R"("a\x")"}) {
        BOOST_CHECK_MESSAGE(!wt::ParseProtocolList(bad), bad);
    }
    BOOST_CHECK_EQUAL(wt::SerializeProtocol("p2p-v1"), "\"p2p-v1\"");
    BOOST_CHECK_EQUAL(wt::SerializeProtocol("a\"b"), "\"a\\\"b\"");
}

BOOST_AUTO_TEST_CASE(webtransport_session_establishment) {
    auto options{ServerOptions()};
    options.application = QuicApplication::WEBTRANSPORT;
    options.wt_echo = true;
    options.wt_origins = {"https://wallet.example"};
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    const CService addr{server->BoundAddresses().at(0)};

    // A node: webtransport-h3, no Origin, p2p-v1 offered.
    WtProbeOptions probe;
    auto r{client->WebTransportProbeForTest(addr, probe, 10s)};
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 200);
    BOOST_CHECK_EQUAL(r->protocol, "p2p-v1");
    // The server announces every draft; the newest is draft-15/16's.
    BOOST_CHECK_EQUAL(r->peer_draft_setting, 0x2c7cf000U);
    BOOST_CHECK(r->classes_echoed);

    // A browser of today: :protocol webtransport, an allowed Origin, no
    // protocol list (no application protocol selected).
    probe.protocol_token = "webtransport";
    probe.origin = "https://wallet.example";
    probe.offer = {};
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 200);
    BOOST_CHECK(r->classes_echoed);

    // Refusals.
    probe = WtProbeOptions{};
    probe.second_connect = true;
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 200);
    BOOST_CHECK_EQUAL(r->second_status, 429);

    probe = WtProbeOptions{};
    probe.path = "/p2p/other";
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 404);

    probe = WtProbeOptions{};
    probe.origin = "https://evil.example";
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 403);

    probe = WtProbeOptions{};
    probe.offer = {"unsupported-test-protocol"};
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 400);
}

BOOST_AUTO_TEST_CASE(webtransport_token_and_no_acceptor) {
    auto options{ServerOptions()};
    options.application = QuicApplication::WEBTRANSPORT;
    options.wt_echo = true;
    options.wt_token = "s3cret";
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    const CService addr{server->BoundAddresses().at(0)};
    WtProbeOptions probe;
    auto r{client->WebTransportProbeForTest(addr, probe, 10s)};
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 403);
    probe.token = "wrong";
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 403);
    probe.token = "s3cret";
    r = client->WebTransportProbeForTest(addr, probe, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 200);

    // A P2P server with nobody taking sessions answers 503.
    auto p2p_options{ServerOptions()};
    p2p_options.application = QuicApplication::WEBTRANSPORT;
    auto p2p{StartEngine(p2p_options)};
    r = client->WebTransportProbeForTest(p2p->BoundAddresses().at(0),
                                         WtProbeOptions{}, 10s);
    BOOST_REQUIRE(r);
    BOOST_CHECK_EQUAL(r->status, 503);

    // An HTTP/3 server without WebTransport SETTINGS: the echo test server
    // speaks raw QUIC, so no SETTINGS ever arrive and the probe fails.
    auto raw{StartEngine(ServerOptions())};
    r = client->WebTransportProbeForTest(raw->BoundAddresses().at(0),
                                         WtProbeOptions{}, 5s);
    BOOST_CHECK(!r || r->status == 0);
}

// An application message may race ahead of the lower priority class stream
// prefixes. It must survive until the server creates its node socket.
BOOST_AUTO_TEST_CASE(webtransport_p2p_socket_roundtrip) {
    std::promise<std::unique_ptr<Sock>> accepted;
    auto inbound{accepted.get_future()};
    struct ClearAcceptor {
        ~ClearAcceptor() { SetP2PWebTransportAcceptor(nullptr); }
    } clear_acceptor;
    SetP2PWebTransportAcceptor(
        [&accepted](std::unique_ptr<Sock> &&sock, const CAddress &,
                     const CAddress &, std::shared_ptr<QuicTransportInfo>) {
            accepted.set_value(std::move(sock));
        });
    auto options{ServerOptions()};
    options.application = QuicApplication::WEBTRANSPORT;
    auto server{StartEngine(options)};
    auto client{StartEngine(QuicEngineOptions{})};
    const CService addr{server->BoundAddresses().at(0)};
    const auto url{ParseWebTransportURL("wt://" + addr.ToStringAddrPort())};
    BOOST_REQUIRE(url);
    CThreadInterrupt interrupt;
    WebTransportDialError error;
    auto dialed{client->Dial(addr, *url, 10s, interrupt, error)};
    BOOST_REQUIRE(dialed);
    std::vector<uint8_t> message(CMessageHeader::HEADER_SIZE, 0);
    std::memcpy(message.data() + CMessageHeader::MESSAGE_START_SIZE,
                "version", 7);
    WriteLE32(message.data() + CMessageHeader::MESSAGE_SIZE_OFFSET, 0);
    BOOST_REQUIRE_EQUAL(dialed->sock->Send(message.data(), message.size(), 0),
                         message.size());
    BOOST_REQUIRE(inbound.wait_for(10s) == std::future_status::ready);
    auto sock{inbound.get()};
    std::vector<uint8_t> received(message.size());
    size_t offset{0};
    const auto deadline{std::chrono::steady_clock::now() + 10s};
    while (offset < received.size() &&
           std::chrono::steady_clock::now() < deadline) {
        const auto n{sock->Recv(received.data() + offset,
                                 received.size() - offset, 0)};
        if (n > 0) {
            offset += static_cast<size_t>(n);
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    BOOST_REQUIRE_EQUAL(offset, message.size());
    BOOST_CHECK(received == message);
}

BOOST_AUTO_TEST_CASE(webtransport_handshake_observer) {
    std::mutex mutex;
    std::vector<QuicHandshakeObservation> observations;
    const auto observer{[&](QuicHandshakeObservation observation) {
        const std::lock_guard<std::mutex> lock{mutex};
        observations.push_back(std::move(observation));
    }};
    auto server_options{ServerOptions()};
    server_options.application = QuicApplication::WEBTRANSPORT;
    server_options.wt_echo = true;
    server_options.handshake_observer = observer;
    auto server{StartEngine(server_options)};
    QuicEngineOptions client_options;
    client_options.handshake_observer = observer;
    auto client{StartEngine(client_options)};
    const auto addr{server->BoundAddresses().at(0)};
    // Match the browser baseline's real localhost SNI and actual node dial
    // path, rather than comparing a no-SNI raw-QUIC echo probe to a browser.
    const auto url{ParseWebTransportURL(
        strprintf("wt://localhost:%u/p2p/wt#cert=%s", addr.GetPort(),
                  HexStr(cert_sha256)))};
    BOOST_REQUIRE(url);
    CThreadInterrupt interrupt;
    WebTransportDialError error;
    auto dialed{client->Dial(addr, *url, 10s, interrupt, error)};
    BOOST_REQUIRE(dialed);
    BOOST_CHECK(dialed->info->pinned);
    dialed->sock.reset();
    auto wrong{*url};
    (*wrong.cert_sha256)[0] ^= 1;
    BOOST_CHECK(!client->Dial(addr, wrong, 10s, interrupt, error));
    client->Stop();
    server->Stop();
    // Stop() joins both producers before inspecting their callback copies.
    BOOST_CHECK(std::any_of(observations.begin(), observations.end(),
                            [](const auto &o) {
                                return !o.server && o.outbound &&
                                       !o.handshake.empty() && o.handshake[0] == 1;
                            }));
    BOOST_CHECK(std::any_of(observations.begin(), observations.end(),
                            [](const auto &o) {
                                return o.server && o.outbound &&
                                       !o.handshake.empty() && o.handshake[0] == 2 &&
                                       o.tls_version == TLS1_3_VERSION;
                            }));
    const char *directory{std::getenv("WT_HANDSHAKE_ARTIFACT_DIR")};
    size_t index{0};
    for (const auto &o : observations) {
        BOOST_CHECK_LE(o.handshake.size(), 64 * 1024);
        BOOST_CHECK_EQUAL(o.truncated, o.original_size > o.handshake.size());
        if (directory) {
            const fs::path out{directory};
            fs::create_directories(out);
            const auto name{strprintf("%02u-%s-%s-type%u.bin", index,
                                      o.server ? "server" : "client",
                                      o.outbound ? "out" : "in", o.handshake[0])};
            BOOST_REQUIRE(!fs::exists(out / name));
            std::ofstream file(out / name, std::ios::binary);
            file.write(reinterpret_cast<const char *>(o.handshake.data()),
                        static_cast<std::streamsize>(o.handshake.size()));
            BOOST_REQUIRE(file.good());
        }
        ++index;
    }
}

// Explicit capture harness, inert during ordinary unit runs. Each browser
// uses its own invocation/directory/profile and caller-assigned UDP port.
BOOST_AUTO_TEST_CASE(webtransport_browser_capture_server) {
    const char *directory{std::getenv("WT_BROWSER_CAPTURE_DIR")};
    const char *port_text{std::getenv("WT_BROWSER_CAPTURE_PORT")};
    if (!directory || !port_text) {
        BOOST_TEST_MESSAGE("Browser capture requires explicit directory and port");
        return;
    }
    const auto port{ToIntegral<uint16_t>(port_text)};
    BOOST_REQUIRE(port && *port != 0);
    const fs::path out{directory};
    BOOST_REQUIRE(!fs::exists(out));
    fs::create_directories(out);
    std::vector<QuicHandshakeObservation> captured;
    auto options{ServerOptions()};
    options.binds = {Loopback(*port)};
    options.application = QuicApplication::WEBTRANSPORT;
    options.wt_echo = true; // Handshake capture, no CConnman/relay claim.
    options.handshake_observer = [&](QuicHandshakeObservation o) {
        // Keep test disk IO off the engine thread during the capture.
        captured.push_back(std::move(o));
    };
    auto server{StartEngine(options)};
    {
        // Readiness is communicated only after bind/TLS initialization.
        std::ofstream info(out / "server.json");
        info << "{\"url\":\"https://localhost:" << *port
             << "/p2p/wt\",\"cert_sha256\":\"" << HexStr(cert_sha256)
             << "\",\"capture_seconds\":30}\n";
        BOOST_REQUIRE(info.good());
    }
    std::this_thread::sleep_for(30s);
    server->Stop(); // Joins all callback copies before inspecting them.
    size_t index{0};
    size_t client_hellos{0};
    for (const auto &o : captured) {
        const auto name{strprintf("%02u-%s-type%u.bin", index++,
                                  o.outbound ? "out" : "in", o.handshake[0])};
        if (!o.outbound && o.handshake[0] == 1) {
            ++client_hellos;
        }
        BOOST_REQUIRE(!o.truncated);
        std::ofstream file(out / name, std::ios::binary);
        file.write(reinterpret_cast<const char *>(o.handshake.data()),
                    static_cast<std::streamsize>(o.handshake.size()));
        BOOST_REQUIRE(file.good());
    }
    BOOST_CHECK_GT(client_hellos, 0);
}

BOOST_AUTO_TEST_SUITE_END()
