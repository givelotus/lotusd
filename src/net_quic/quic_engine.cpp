// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/quic_engine.h>

#include <net_quic/quic_connection.h>
#include <net_quic/quic_peer_sock.h>
#include <net_quic/udp_socket.h>
#include <net_quic/webtransport_h3.h>
#include <net_quic/webtransport_wire.h>
#include <net_websocket.h>
#include <protocol.h>

#include <logging.h>
#include <netbase.h>
#include <node/metrics.h>
#include <random.h>
#include <sync.h>
#include <tinyformat.h>
#include <tls_util.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/threadnames.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <deque>
#include <fcntl.h>
#include <functional>
#include <future>
#include <list>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

using namespace std::chrono_literals;

namespace {
//! Expected length of the connection IDs we issue (short header parsing)
constexpr size_t QUIC_SCID_LEN = 18;
//! Datagrams read per socket per loop pass
constexpr size_t RECV_BATCH = 64;
constexpr uint64_t MAX_RECEIVE_WINDOW = 32 * 1024 * 1024;
//! Address validation tokens: Retry valid for 10 s, NEW_TOKEN for 1 h
constexpr uint64_t RETRY_TOKEN_TIMEOUT = 10 * NGTCP2_SECONDS;
constexpr uint64_t REGULAR_TOKEN_TIMEOUT = 3600 * NGTCP2_SECONDS;
//! Token secrets rotate this often (verification tries the previous one)
constexpr auto TOKEN_SECRET_ROTATION = 1h;
//! Server certificate files are checked for replacement this often
constexpr auto CERT_RELOAD_INTERVAL = 60s;
constexpr size_t SECRET_LEN = 32;

/**
 * Tests: the server echoes each client stream back on that stream; the
 * client sends one payload and collects the answer.
 */
class EchoApp final : public QuicApp {
public:
    struct Result {
        std::promise<std::optional<std::vector<uint8_t>>> promise;
        bool done{false};
        void Set(std::optional<std::vector<uint8_t>> v) {
            if (!done) {
                done = true;
                promise.set_value(std::move(v));
            }
        }
    };

    //! Server
    EchoApp() = default;
    //! Client
    EchoApp(std::vector<uint8_t> payload,
            std::optional<std::vector<uint8_t>> cert_sha256,
            std::shared_ptr<Result> result)
        : m_client{true}, m_payload{std::move(payload)},
          m_cert_sha256{std::move(cert_sha256)}, m_result{std::move(result)} {}

    int OnHandshakeCompleted(QuicConnection &conn) override {
        if (!m_client) {
            return 0;
        }
        if (m_cert_sha256) {
            X509 *cert{SSL_get0_peer_certificate(conn.Ssl())};
            unsigned char *der{nullptr};
            const int n{cert ? i2d_X509(cert, &der) : -1};
            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
            if (n > 0) {
                SHA256(der, static_cast<size_t>(n), digest.data());
                OPENSSL_free(der);
            }
            if (n <= 0 || m_cert_sha256->size() != digest.size() ||
                CRYPTO_memcmp(digest.data(), m_cert_sha256->data(),
                              digest.size()) != 0) {
                m_result->Set(std::nullopt);
                conn.CloseApp(1, "certificate mismatch");
                return 0;
            }
        }
        const int64_t id{conn.OpenStream(true, QuicStream::Kind::OWN)};
        if (id < 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        conn.QueueStreamData(conn.Stream(id), std::vector<uint8_t>{m_payload},
                             /*fin=*/true);
        return 0;
    }

    int OnStreamData(QuicConnection &conn, QuicStream &stream, uint32_t flags,
                     const uint8_t *data, size_t len) override {
        conn.ExtendCredit(stream.id, len);
        const bool fin{(flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0};
        if (m_client) {
            m_response.insert(m_response.end(), data, data + len);
            if (fin) {
                m_result->Set(std::move(m_response));
                conn.CloseApp(0);
            }
            return 0;
        }
        stream.kind = QuicStream::Kind::OWN;
        conn.QueueStreamData(stream, std::vector<uint8_t>(data, data + len),
                             fin);
        return 0;
    }

    void OnClosed(QuicConnection &) override {
        if (m_result) {
            m_result->Set(std::nullopt);
        }
    }

private:
    const bool m_client{false};
    std::vector<uint8_t> m_payload;
    std::optional<std::vector<uint8_t>> m_cert_sha256;
    std::shared_ptr<Result> m_result;
    std::vector<uint8_t> m_response;
};

/** Tests: the client side of WebTransportProbeForTest() */
class ProbeHandler final : public WtSessionHandler {
public:
    struct Result {
        std::promise<std::optional<WtProbeResult>> promise;
        WtProbeResult value;
        bool done{false};
        void Finish(bool ok) {
            if (!done) {
                done = true;
                promise.set_value(ok ? std::optional{value} : std::nullopt);
            }
        }
    };

    ProbeHandler(bool second_connect, std::shared_ptr<Result> result)
        : m_second{second_connect}, m_result{std::move(result)} {}

    void OnConnectResponse(H3Session &session, int status) override {
        if (m_first) {
            m_first = false;
            m_result->value.status = status;
            m_result->value.peer_draft_setting = session.PeerDraftSetting();
            m_result->value.protocol = session.Protocol();
            if (status != 200) {
                m_result->Finish(true);
            } else if (m_second) {
                session.SubmitExtraConnectForTest();
            }
            return;
        }
        m_result->value.second_status = status;
        m_second_done = true;
        MaybeFinish(session);
    }

    void OnSessionReady(H3Session &session) override {
        for (const StreamClass cls : ALL_STREAM_CLASSES) {
            std::string msg{strprintf("probe-%s", StreamClassName(cls))};
            m_expected[StreamClassIndex(cls)] = std::string(
                1, static_cast<char>(cls)) + msg;
            session.QueueClassData(cls,
                                   std::vector<uint8_t>(msg.begin(), msg.end()));
        }
    }

    void OnClassData(H3Session &session, StreamClass cls, const uint8_t *data,
                     size_t len, bool) override {
        session.ExtendCredit(cls, len);
        m_got[StreamClassIndex(cls)].append(reinterpret_cast<const char *>(data),
                                            len);
        if (m_got == m_expected) {
            m_result->value.classes_echoed = true;
            m_echoed = true;
            MaybeFinish(session);
        }
    }

    void OnSessionClosed(H3Session &, uint32_t, const std::string &) override {
        m_result->Finish(m_result->value.status != 0);
    }

private:
    void MaybeFinish(H3Session &session) {
        if (m_echoed && (!m_second || m_second_done)) {
            m_result->Finish(true);
            session.CloseSession(0, "probe done");
        }
    }

    const bool m_second;
    bool m_first{true};
    bool m_second_done{false};
    bool m_echoed{false};
    std::array<std::string, NUM_STREAM_CLASSES> m_expected, m_got;
    std::shared_ptr<Result> m_result;
};

/** Wakes the engine thread; outlives it (channels keep a reference) */
class EngineWaker {
public:
    explicit EngineWaker(int fd) : m_fd{fd} {}
    void Wake() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        if (pending.exchange(true)) {
            return;
        }
        LOCK(m_mutex);
        if (m_fd >= 0) {
            const uint8_t b{1};
#ifdef MSG_NOSIGNAL
            constexpr int flags{MSG_DONTWAIT | MSG_NOSIGNAL};
#else
            constexpr int flags{MSG_DONTWAIT};
#endif
            [[maybe_unused]] auto r{::send(m_fd, &b, 1, flags)};
        }
    }
    void Close() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        if (m_fd >= 0) {
            ::close(m_fd);
            m_fd = -1;
        }
    }
    std::atomic<bool> pending{false};

private:
    Mutex m_mutex;
    int m_fd GUARDED_BY(m_mutex);
};

/** Result of an outbound dial, completed on the engine thread */
struct DialState {
    std::promise<std::optional<WebTransportDialResult>> promise;
    WebTransportDialError error{WebTransportDialError::TIMEOUT};
    bool done{false};
    void Finish(std::optional<WebTransportDialResult> result,
                WebTransportDialError why) {
        if (!done) {
            done = true;
            error = result ? WebTransportDialError::NONE : why;
            promise.set_value(std::move(result));
        }
    }
};

/**
 * A P2P session: bridges the five class streams of one WebTransport
 * session to a QuicPeerSock through a QuicPeerChannel (engine thread).
 */
class P2PSessionHandler final : public WtSessionHandler {
public:
    P2PSessionHandler(std::shared_ptr<EngineWaker> waker, bool compress,
                      uint64_t receive_limit,
                      std::shared_ptr<DialState> dial = nullptr,
                      std::optional<std::vector<unsigned char>> spki_pin = {},
                      std::optional<std::vector<unsigned char>> cert_pin = {})
        : m_waker{std::move(waker)}, m_compress{compress},
          m_receive_limit{receive_limit}, m_dial{std::move(dial)},
          m_spki_pin{std::move(spki_pin)}, m_cert_pin{std::move(cert_pin)},
          m_info{std::make_shared<QuicTransportInfo>()} {}

    bool OnHandshake(H3Session &session, QuicConnection &conn) override {
        m_info->alpn = tls::NegotiatedAlpn(conn.Ssl());
        X509 *cert{tls::PeerCertificate(conn.Ssl())};
        std::vector<unsigned char> spki;
        if (cert) {
            m_info->peer_cert_fingerprint_hex = tls::CertSha256Hex(cert);
            spki = tls::SpkiSha256(cert);
            if (!spki.empty()) {
                m_info->peer_spki = EncodeSpkiPin(spki);
            }
        }
        bool ok{true};
        if (m_spki_pin) {
            ok = spki.size() == m_spki_pin->size() &&
                 CRYPTO_memcmp(spki.data(), m_spki_pin->data(),
                               spki.size()) == 0;
            if (!ok) {
                LogPrintf("WebTransport peer %s: TLS key %s does not match "
                          "the pinned key %s\n",
                          conn.Remote().ToStringAddrPort(), m_info->peer_spki,
                          EncodeSpkiPin(*m_spki_pin));
            }
            m_info->pinned = ok;
        }
        if (ok && m_cert_pin) {
            const auto digest{ParseHex(m_info->peer_cert_fingerprint_hex)};
            ok = digest.size() == m_cert_pin->size() &&
                 CRYPTO_memcmp(digest.data(), m_cert_pin->data(),
                               digest.size()) == 0;
            if (!ok) {
                LogPrintf("WebTransport peer %s: certificate %s does not "
                          "match the pinned hash\n",
                          conn.Remote().ToStringAddrPort(),
                          m_info->peer_cert_fingerprint_hex);
            }
            m_info->pinned = ok;
        }
        if (cert) {
            X509_free(cert);
        }
        if (!ok && m_dial) {
            m_dial->Finish(std::nullopt, WebTransportDialError::HANDSHAKE);
        }
        return ok;
    }

    int OnConnect(H3Session &, const WtRequest &) override {
        return GetP2PWebTransportAcceptor() ? 200 : 503;
    }

    void OnConnectResponse(H3Session &, int status) override {
        if (status != 200 && m_dial) {
            m_dial->Finish(std::nullopt, status == 0
                                             ? WebTransportDialError::UNSUPPORTED
                                             : WebTransportDialError::REFUSED);
        }
    }

    void OnSessionReady(H3Session &session) override {
        if (m_receive_closed) return;
        QuicConnection &conn{*session.Conn()};
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            session.CloseSession(0, "no socketpair");
            return;
        }
        for (int fd : sv) {
            const int fl{::fcntl(fd, F_GETFL, 0)};
            ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        m_info->protocol = session.Protocol();
        m_info->draft = session.PeerDraftSetting();
        m_info->origin = session.Request().origin;
        m_channel = std::make_shared<QuicPeerChannel>(
            sv[1], m_info, [waker = m_waker] { waker->Wake(); },
            m_receive_limit);
        // QUIC may deliver CONTROL data before the other four stream
        // prefixes. Retain it until the session has its node socket.
        for (auto &frame : m_early_rx) {
            if (!m_channel->PushRx(std::move(frame))) {
                ::close(sv[0]);
                RejectReceiveLimit(session);
                return;
            }
        }
        m_early_rx.clear();
        auto sock{std::make_unique<QuicPeerSock>(static_cast<SOCKET>(sv[0]),
                                                 m_channel, m_compress)};
        if (m_dial) {
            WebTransportDialResult result;
            result.sock = std::move(sock);
            result.info = m_info;
            result.local = conn.Local();
            m_dial->Finish(std::move(result), WebTransportDialError::NONE);
            return;
        }
        const P2PWebTransportAcceptor acceptor{GetP2PWebTransportAcceptor()};
        if (!acceptor) {
            session.CloseSession(0, "not accepting peers");
            return;
        }
        acceptor(std::move(sock), CAddress{conn.Remote(), NODE_NONE},
                 CAddress{conn.Local(), NODE_NONE}, m_info);
    }

    void OnClassData(H3Session &session, StreamClass cls, const uint8_t *data,
                     size_t len, bool) override {
        if (m_receive_closed) return;
        uint64_t buffered{m_channel ? m_channel->RxBuffered() : 0};
        for (const auto &partial : m_reassembler)
            buffered += partial.Buffered();
        for (const auto &early : m_early_rx)
            buffered += early.wire_size;
        // A large legitimate message must finish before it can be consumed.
        // Include already granted QUIC window credit, but bound aggregate
        // partial frames so five streams cannot each retain a max-size frame.
        const uint64_t limit{m_receive_limit + quic_frame::MaxFrameLength() +
                             4 + MAX_RECEIVE_WINDOW};
        if (buffered > limit || len > limit - buffered) {
            RejectReceiveLimit(session);
            return;
        }
        std::vector<FrameReassembler::Frame> frames;
        if (!m_reassembler[StreamClassIndex(cls)].Feed({data, len}, frames)) {
            LogDebug(BCLog::WEBTRANSPORT,
                     "WebTransport peer %s sent a bad frame on %s\n",
                     session.Conn()->Remote().ToStringAddrPort(),
                     StreamClassName(cls));
            session.CloseSession(wt::WT_P2P_BAD_STREAM, "bad frame");
            return;
        }
        for (auto &f : frames) {
            QuicPeerChannel::RxFrame rx;
            rx.cls = cls;
            rx.flags = f.flags;
            rx.body = std::move(f.body);
            rx.wire_size = f.wire_size;
            if (m_channel) {
                if (!m_channel->PushRx(std::move(rx))) {
                    RejectReceiveLimit(session);
                    return;
                }
            } else {
                if (m_early_rx.size() >=
                    QuicPeerChannel::MAX_PENDING_RX_FRAMES) {
                    RejectReceiveLimit(session);
                    return;
                }
                m_early_rx.push_back(std::move(rx));
            }
        }
        // Credit for received bytes, unless the node is not keeping up
        // (then the peer is back-pressured; given back as it consumes).
        if (m_channel && m_channel->RxHasRoom()) {
            session.ExtendCredit(cls, len);
        } else {
            m_deferred_credit[StreamClassIndex(cls)] += len;
        }
    }

    void BeforeWrite(H3Session &session) override {
        if (!m_channel) {
            return;
        }
        if (m_channel->SockGone()) {
            session.CloseSession(0, "disconnected");
            return;
        }
        for (const StreamClass cls : ALL_STREAM_CLASSES) {
            for (auto &frame : m_channel->TakeTx(cls)) {
                session.QueueClassData(cls, std::move(frame));
            }
            m_channel->SetEngineUnsent(cls, session.ClassUnsent(cls));
        }
        if (m_channel->send_blocked &&
            m_channel->TxPending(static_cast<StreamClass>(
                m_channel->blocked_class.load())) <=
                QuicPeerChannel::MAX_PENDING_SEND / 2) {
            m_channel->send_blocked = false;
            m_channel->Notify();
        }
        if (m_channel->RxHasRoom()) {
            m_channel->credit_wanted = false;
            for (const StreamClass cls : ALL_STREAM_CLASSES) {
                uint64_t &deferred{m_deferred_credit[StreamClassIndex(cls)]};
                if (deferred > 0) {
                    session.ExtendCredit(cls, deferred);
                    deferred = 0;
                }
            }
        }
        ngtcp2_conn_info ci;
        ngtcp2_conn_get_conn_info2(session.Conn()->Conn(), &ci);
        m_info->rtt_us = ci.smoothed_rtt / NGTCP2_MICROSECONDS;
        m_info->min_rtt_us = ci.min_rtt / NGTCP2_MICROSECONDS;
        m_info->cwnd = ci.cwnd;
        m_info->lost_pkts = ci.pkt_lost;
        m_info->udp_bytes_sent = ci.bytes_sent;
        m_info->udp_bytes_recv = ci.bytes_recv;
    }

    void OnSessionClosed(H3Session &session, uint32_t code,
                         const std::string &reason) override {
        m_receive_closed = true;
        if (m_channel) {
            LogDebug(BCLog::WEBTRANSPORT,
                     "WebTransport session with %s ended: code %u (%s)\n",
                     session.Conn() ? session.Conn()->Remote().ToStringAddrPort()
                                    : "?",
                     code, reason);
            m_channel->MarkClosed();
        }
        if (m_dial) {
            m_dial->Finish(std::nullopt, WebTransportDialError::REFUSED);
        }
    }

private:
    void RejectReceiveLimit(H3Session &session) {
        m_receive_closed = true;
        session.Conn()->Engine().OnRejected(QuicRejectReason::CAPACITY);
        session.CloseSession(wt::WT_P2P_BAD_STREAM, "receive buffer limit");
    }
    const std::shared_ptr<EngineWaker> m_waker;
    const bool m_compress;
    const uint64_t m_receive_limit;
    bool m_receive_closed{false};
    const std::shared_ptr<DialState> m_dial;
    const std::optional<std::vector<unsigned char>> m_spki_pin;
    const std::optional<std::vector<unsigned char>> m_cert_pin;
    const std::shared_ptr<QuicTransportInfo> m_info;
    std::shared_ptr<QuicPeerChannel> m_channel;
    //! Bounded by initial QUIC credit until all five stream prefixes arrive.
    std::deque<QuicPeerChannel::RxFrame> m_early_rx;
    std::array<FrameReassembler, NUM_STREAM_CLASSES> m_reassembler;
    std::array<uint64_t, NUM_STREAM_CLASSES> m_deferred_credit{};
};

std::string CidKey(const uint8_t *data, size_t len) {
    return std::string(reinterpret_cast<const char *>(data), len);
}

int SelectH3Alpn(SSL *, const unsigned char **out, unsigned char *outlen,
                 const unsigned char *in, unsigned int inlen, void *) {
    for (unsigned int i = 0; i < inlen; i += in[i] + 1) {
        if (in[i] == 2 && i + 2 < inlen && in[i + 1] == 'h' &&
            in[i + 2] == '3') {
            *out = &in[i + 1];
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
} // namespace

class QuicEngine::Impl final : public QuicEngineCore {
public:
    explicit Impl(const QuicEngineOptions &options)
        : m_opts{options},
          m_admission{options.max_per_ip, options.max_handshaking} {
        GetStrongRandBytes(m_reset_secret);
        GetStrongRandBytes(m_token_secret[0]);
        m_token_secret[1] = m_token_secret[0];
        m_next_rotation = std::chrono::steady_clock::now() +
                          TOKEN_SECRET_ROTATION;
    }

    ~Impl() override { Stop(); }

    bool Init(std::string &error) {
        if (m_opts.max_per_ip == 0 || m_opts.max_handshaking == 0 ||
            m_opts.max_handshaking > QuicAdmission::MAX_BUCKETS ||
            m_opts.receive_buffer == 0 || m_opts.receive_buffer > UINT32_MAX) {
            error = "invalid QUIC admission or receive-buffer limits";
            return false;
        }
        static std::once_flag once;
        std::call_once(once, [] { ngtcp2_crypto_ossl_init(); });
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            error = "socketpair failed";
            return false;
        }
#ifdef SO_NOSIGPIPE
        const int no_sigpipe{1};
        ::setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                     sizeof(no_sigpipe));
#endif
        m_wake_read = sv[0];
        m_waker = std::make_shared<EngineWaker>(sv[1]);
        for (int fd : sv) {
            const int fl{::fcntl(fd, F_GETFL, 0)};
            ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        if (!m_opts.binds.empty()) {
            if (!m_opts.cert_file || !m_opts.key_file) {
                error = "a QUIC listener needs a certificate and key";
                return false;
            }
            if (!LoadServerContext(error)) {
                return false;
            }
        }
        for (const CService &bind : m_opts.binds) {
            std::string why;
            auto sock{UdpSocket::Bind(bind, why)};
            if (!sock) {
                if (m_opts.bind_optional) {
                    LogPrintf("WebTransport: unable to bind UDP %s: %s "
                              "(continuing without it)\n",
                              bind.ToStringAddrPort(), why);
                    continue;
                }
                error = "unable to bind UDP " + bind.ToStringAddrPort() +
                        ": " + why;
                return false;
            }
            m_listeners.push_back(std::make_unique<UdpSocket>(std::move(*sock)));
        }
        m_client_ctx = NewClientContext();
        if (!m_client_ctx) {
            error = "unable to create the QUIC TLS client context: " +
                    tls::ErrorString();
            return false;
        }
        m_thread = std::thread{&util::TraceThread, "quic",
                               [this] { ThreadMain(); }};
        return true;
    }

    void Stop() {
        if (!m_thread.joinable()) {
            return;
        }
        m_stop = true;
        Wake();
        m_thread.join();
        if (m_wake_read >= 0) {
            ::close(m_wake_read);
            m_wake_read = -1;
        }
        m_waker->Close();
    }

    /** Run `fn` on the engine thread */
    void Post(std::function<void()> fn) EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        {
            LOCK(m_tasks_mutex);
            m_tasks.push_back(std::move(fn));
        }
        Wake();
    }

    void Wake() { m_waker->Wake(); }

    std::vector<CService> BoundAddresses() const {
        std::vector<CService> out;
        for (const auto &l : m_listeners) {
            out.push_back(l->Local());
        }
        return out;
    }

    QuicEngineStats Stats() const {
        QuicEngineStats out;
        out.connections = m_stats.connections;
        out.inbound = m_stats.inbound;
        out.outbound = m_stats.outbound;
        out.handshaking = m_stats.handshaking;
        out.handshakes_completed = m_stats.handshakes_completed;
        out.handshakes_failed = m_stats.handshakes_failed;
        out.retry_sent = m_stats.retry_sent;
        out.retry_token_rejected = m_stats.retry_token_rejected;
        out.stateless_reset_sent = m_stats.stateless_reset_sent;
        out.version_negotiation_sent = m_stats.version_negotiation_sent;
        out.idle_closed = m_stats.idle_closed;
        out.packets_recv = m_stats.packets_recv;
        out.packets_sent = m_stats.packets_sent;
        out.bytes_recv = m_stats.bytes_recv;
        out.bytes_sent = m_stats.bytes_sent;
        uint64_t errors{0};
        for (const auto &l : m_listeners) {
            errors += l->SendErrors();
        }
        out.send_errors = errors;
        for (size_t i{0}; i < out.rejected.size(); ++i)
            out.rejected[i] = m_stats.rejected[i];
        return out;
    }

    std::optional<std::vector<uint8_t>>
    EchoForTest(const CService &target, const std::vector<uint8_t> &payload,
                std::chrono::milliseconds timeout,
                const std::optional<std::vector<uint8_t>> &cert_sha256)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        auto result{std::make_shared<EchoApp::Result>()};
        auto future{result->promise.get_future()};
        auto cancel{std::make_shared<std::atomic<bool>>(false)};
        Post([this, target, payload, cert_sha256, result, cancel] {
            QuicConnection *conn{CreateClient(target, "")};
            if (!conn) {
                result->Set(std::nullopt);
                return;
            }
            conn->CancelFlag() = cancel;
            conn->SetApp(
                std::make_unique<EchoApp>(payload, cert_sha256, result));
        });
        if (future.wait_for(timeout) != std::future_status::ready) {
            *cancel = true;
            Wake();
            return std::nullopt;
        }
        return future.get();
    }

    std::optional<WebTransportDialResult>
    Dial(const CService &target, const ParsedWebTransportURL &url,
         std::chrono::milliseconds timeout, CThreadInterrupt &interrupt,
         WebTransportDialError &error) EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        auto state{std::make_shared<DialState>()};
        auto future{state->promise.get_future()};
        auto cancel{std::make_shared<std::atomic<bool>>(false)};
        const std::string sni{LookupHost(url.host, false).has_value() ||
                                      url.host.find(':') != std::string::npos
                                  ? ""
                                  : url.host};
        Post([this, target, url, sni, state, cancel] {
            QuicConnection *conn{CreateClient(target, sni)};
            if (!conn) {
                state->Finish(std::nullopt, WebTransportDialError::HANDSHAKE);
                return;
            }
            conn->CancelFlag() = cancel;
            H3Options h3;
            h3.server = false;
            h3.path = url.path;
            h3.token = url.token;
            h3.authority = url.authority;
            conn->SetApp(std::make_unique<H3Session>(
                h3, std::make_unique<P2PSessionHandler>(
                        m_waker, m_opts.compress, m_opts.receive_buffer, state,
                        url.spki_pin, url.cert_sha256)));
        });
        const auto deadline{std::chrono::steady_clock::now() + timeout};
        while (future.wait_for(std::chrono::milliseconds{50}) !=
               std::future_status::ready) {
            if (interrupt || std::chrono::steady_clock::now() >= deadline) {
                *cancel = true;
                Wake();
                error = interrupt ? WebTransportDialError::INTERRUPTED
                                  : WebTransportDialError::TIMEOUT;
                return std::nullopt;
            }
        }
        auto result{future.get()};
        error = state->error;
        return result;
    }

    std::optional<WtProbeResult>
    WebTransportProbeForTest(const CService &target,
                             const WtProbeOptions &options,
                             std::chrono::milliseconds timeout)
        EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        auto result{std::make_shared<ProbeHandler::Result>()};
        auto future{result->promise.get_future()};
        auto cancel{std::make_shared<std::atomic<bool>>(false)};
        Post([this, target, options, result, cancel] {
            QuicConnection *conn{CreateClient(target, "")};
            if (!conn) {
                result->Finish(false);
                return;
            }
            conn->CancelFlag() = cancel;
            H3Options h3;
            h3.server = false;
            h3.path = options.path;
            h3.token = options.token;
            h3.origin = options.origin;
            h3.protocol_token = options.protocol_token;
            h3.offer = options.offer;
            h3.authority = target.ToStringAddrPort();
            conn->SetApp(std::make_unique<H3Session>(
                h3, std::make_unique<ProbeHandler>(options.second_connect,
                                                   result)));
        });
        if (future.wait_for(timeout) != std::future_status::ready) {
            *cancel = true;
            Wake();
            return std::nullopt;
        }
        return future.get();
    }

    // QuicEngineCore
    void RegisterCid(QuicConnection &conn, const ngtcp2_cid &cid) override {
        const std::string key{CidKey(cid.data, cid.datalen)};
        m_by_cid[key] = &conn;
        conn.Cids().push_back(key);
    }
    void UnregisterCid(QuicConnection &conn, const ngtcp2_cid &cid) override {
        const auto it{m_by_cid.find(CidKey(cid.data, cid.datalen))};
        if (it != m_by_cid.end() && it->second == &conn) {
            m_by_cid.erase(it);
        }
    }
    const uint8_t *Secret() const override { return m_reset_secret.data(); }
    size_t SecretLen() const override { return SECRET_LEN; }
    const uint8_t *TokenSecret() const override {
        return m_token_secret[0].data();
    }
    SSL_CTX *ServerContext() override {
        MaybeReloadServerContext();
        return m_server_ctx.get();
    }
    SSL_CTX *ClientContext() override { return m_client_ctx.get(); }
    void FillSettings(ngtcp2_settings &settings,
                      ngtcp2_transport_params &params, bool server,
                      uint64_t now) override {
        ngtcp2_settings_default(&settings);
        settings.initial_ts = now;
        settings.cc_algo = m_opts.bbr ? NGTCP2_CC_ALGO_BBR : NGTCP2_CC_ALGO_CUBIC;
        settings.max_window = MAX_RECEIVE_WINDOW;
        settings.max_stream_window = 16 * 1024 * 1024;
        settings.handshake_timeout =
            static_cast<ngtcp2_duration>(m_opts.handshake_timeout.count()) *
            NGTCP2_MILLISECONDS;
        ngtcp2_transport_params_default(&params);
        params.initial_max_data = 16 * 1024 * 1024;
        params.initial_max_stream_data_bidi_local = 4 * 1024 * 1024;
        params.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
        params.initial_max_stream_data_uni = 1024 * 1024;
        params.initial_max_streams_bidi = 8;
        params.initial_max_streams_uni = 8;
        params.max_idle_timeout =
            static_cast<ngtcp2_duration>(m_opts.idle_timeout.count()) *
            NGTCP2_MILLISECONDS;
        params.max_datagram_frame_size = 65535;
        params.active_connection_id_limit = 7;
        params.grease_quic_bit = 1;
        (void)server;
    }
    void OnPacketSent(size_t bytes) override {
        ++m_stats.packets_sent;
        m_stats.bytes_sent += bytes;
    }
    void OnHandshakeDone(QuicConnection &conn) override {
        ++m_stats.handshakes_completed;
        if (conn.IsServer()) m_admission.HandshakeDone();
        if (auto *metrics{node::GetNodeMetrics()})
            metrics->webtransport_handshakes.Add(0);
        if (!conn.IsServer() && m_opts.keep_alive.count() > 0) {
            ngtcp2_conn_set_keep_alive_timeout(
                conn.Conn(),
                static_cast<ngtcp2_duration>(m_opts.keep_alive.count()) *
                    NGTCP2_MILLISECONDS);
        }
    }
    void OnIdleClose(QuicConnection &) override {
        ++m_stats.idle_closed;
    }
    void OnRejected(QuicRejectReason reason) override {
        static constexpr std::array<std::string_view, QUIC_REJECT_REASONS>
            names{"per_ip", "handshaking", "banned",  "origin",
                  "token",  "path",        "session", "capacity"};
        LogEvent(BCLog::WEBTRANSPORT, "quic_rejected",
                 "QUIC/WT request rejected: {reason}")
            .Field(BCLog::LogField::Reason, names[size_t(reason)])
            .Field(BCLog::LogField::Transport,
                   BCLog::LogStatic("webtransport"));
        ++m_stats.rejected[size_t(reason)];
        if (auto *metrics{node::GetNodeMetrics()})
            metrics->webtransport_rejected.Add(size_t(reason));
    }
    void OnStreamBlocked(uint64_t class_tag) override {
        if (class_tag >= 1 && class_tag <= NUM_STREAM_CLASSES) {
            if (auto *metrics{node::GetNodeMetrics()})
                metrics->webtransport_blocked.Add(class_tag - 1);
        }
    }

private:
    static void ObserveHandshake(int write, int, int content_type,
                                 const void *data, size_t len, SSL *ssl,
                                 void *arg) noexcept {
        auto &self{*static_cast<Impl *>(arg)};
        if (content_type != SSL3_RT_HANDSHAKE || len == 0 ||
            !self.m_opts.handshake_observer ||
            self.m_observer_records >= 256 || self.m_observer_bytes >= 8 * 1024 * 1024) {
            return;
        }
        const auto *bytes{static_cast<const uint8_t *>(data)};
        if (bytes[0] != SSL3_MT_CLIENT_HELLO && bytes[0] != SSL3_MT_SERVER_HELLO &&
            bytes[0] != SSL3_MT_CERTIFICATE && bytes[0] != SSL3_MT_ENCRYPTED_EXTENSIONS) {
            return;
        }
        const size_t copied{std::min({len, size_t{64 * 1024},
                                      size_t{8 * 1024 * 1024} - self.m_observer_bytes})};
        ++self.m_observer_records;
        self.m_observer_bytes += copied;
        try {
            QuicHandshakeObservation observed;
            observed.outbound = write != 0;
            observed.server = SSL_is_server(ssl);
            observed.tls_version = SSL_version(ssl);
            observed.original_size = len;
            observed.truncated = copied != len;
            observed.handshake.assign(bytes, bytes + copied);
            self.m_opts.handshake_observer(std::move(observed));
        } catch (...) {
            // Never unwind a C callback or affect TLS authentication.
            LogPrintf("WebTransport test handshake observer failed\n");
        }
    }

    void ConfigureHandshakeObserver(SSL_CTX *ctx) {
        if (m_opts.handshake_observer) {
            // Impl owns contexts and connections and joins the sole engine
            // thread before destruction. No global callback state or borrows
            // of callback buffers survive this call.
            SSL_CTX_set_msg_callback(ctx, ObserveHandshake);
            SSL_CTX_set_msg_callback_arg(ctx, this);
        }
    }

    bool LoadServerContext(std::string &error) {
        tls::SslCtxPtr ctx{SSL_CTX_new(TLS_server_method())};
        if (!ctx) {
            error = tls::ErrorString();
            return false;
        }
        ConfigureHandshakeObserver(ctx.get());
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_options(ctx.get(), SSL_OP_CIPHER_SERVER_PREFERENCE |
                                           SSL_OP_NO_ANTI_REPLAY);
        SSL_CTX_set_alpn_select_cb(ctx.get(), SelectH3Alpn, nullptr);
        if (m_opts.request_client_cert) {
            // Any certificate (node certificates are self-signed); its key
            // is matched against -p2pwebsocketpeer by CConnman.
            SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER,
                               [](int, X509_STORE_CTX *) { return 1; });
        }
        if (!tls::UseCertificateFiles(ctx.get(), *m_opts.cert_file,
                                      *m_opts.key_file)) {
            error = "unable to load " + fs::PathToString(*m_opts.cert_file) +
                    ": " + tls::ErrorString();
            return false;
        }
        std::error_code ec;
        m_cert_mtime = fs::last_write_time(*m_opts.cert_file, ec);
        m_key_mtime = fs::last_write_time(*m_opts.key_file, ec);
        m_server_ctx = std::move(ctx);
        m_next_cert_check = std::chrono::steady_clock::now() +
                            CERT_RELOAD_INTERVAL;
        return true;
    }

    void MaybeReloadServerContext() {
        if (m_opts.certificate_generation) {
            const auto generation{m_opts.certificate_generation()};
            if (generation != m_certificate_generation) {
                m_certificate_generation = generation;
                m_next_cert_check = {};
            }
        }
        const auto now{std::chrono::steady_clock::now()};
        if (!m_server_ctx || now < m_next_cert_check) {
            return;
        }
        m_next_cert_check = now + CERT_RELOAD_INTERVAL;
        std::error_code ec;
        if (fs::last_write_time(*m_opts.cert_file, ec) == m_cert_mtime &&
            fs::last_write_time(*m_opts.key_file, ec) == m_key_mtime) {
            return;
        }
        auto old{std::move(m_server_ctx)};
        std::string error;
        if (LoadServerContext(error)) {
            LogInfo("Reloaded the WebTransport TLS certificate %s\n",
                    fs::PathToString(*m_opts.cert_file));
        } else {
            LogPrintf("Error: keeping the previous WebTransport certificate: "
                      "%s\n",
                      error);
            m_server_ctx = std::move(old);
        }
    }

    tls::SslCtxPtr NewClientContext() {
        tls::SslCtxPtr ctx{SSL_CTX_new(TLS_client_method())};
        if (!ctx) {
            return {};
        }
        ConfigureHandshakeObserver(ctx.get());
        SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
        // Complete the handshake whatever the chain; the dialer then checks
        // a pin or certificate hash, as for wss:// peers.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER,
                           [](int, X509_STORE_CTX *) { return 1; });
        SSL_CTX_set_default_verify_paths(ctx.get());
        // Present our certificate to servers that ask (-p2pwebsocketpeer).
        if (m_opts.cert_file && m_opts.key_file &&
            !tls::UseCertificateFiles(ctx.get(), *m_opts.cert_file,
                                      *m_opts.key_file)) {
            LogPrintf("WebTransport: unable to load the client certificate "
                      "%s\n",
                      fs::PathToString(*m_opts.cert_file));
        }
        return ctx;
    }

    UdpSocket *ClientSocket(sa_family_t family) {
        auto &slot{family == AF_INET6 ? m_client6 : m_client4};
        if (!slot) {
            CService any;
            if (family == AF_INET6) {
                any = CService{in6addr_any, 0};
            } else {
                in_addr a{};
                a.s_addr = htonl(INADDR_ANY);
                any = CService{a, 0};
            }
            std::string error;
            auto sock{UdpSocket::Bind(any, error)};
            if (!sock) {
                LogPrintf("WebTransport: unable to open a UDP socket: %s\n",
                          error);
                return nullptr;
            }
            slot = std::make_unique<UdpSocket>(std::move(*sock));
        }
        return slot.get();
    }

    /** A new outbound connection (engine thread), or nullptr */
    QuicConnection *CreateClient(const CService &target,
                                 const std::string &sni) {
        sockaddr_storage remote{};
        socklen_t remote_len{sizeof(remote)};
        if (!target.GetSockAddr(reinterpret_cast<sockaddr *>(&remote),
                                &remote_len)) {
            return nullptr;
        }
        UdpSocket *sock{ClientSocket(remote.ss_family)};
        if (!sock) {
            return nullptr;
        }
        sockaddr_storage local{};
        socklen_t local_len{sizeof(local)};
        sock->Local().GetSockAddr(reinterpret_cast<sockaddr *>(&local),
                                  &local_len);
        auto conn{std::make_unique<QuicConnection>(
            *this, /*server=*/false, *sock, local, local_len, remote,
            remote_len)};
        if (!conn->InitClient(sni)) {
            LogDebug(BCLog::WEBTRANSPORT,
                     "QUIC: unable to create a connection to %s\n",
                     target.ToStringAddrPort());
            ForgetCids(*conn);
            return nullptr;
        }
        QuicConnection *raw{conn.get()};
        m_conns.push_back(std::move(conn));
        return raw;
    }

    void ForgetCids(QuicConnection &conn) {
        for (const std::string &key : conn.Cids()) {
            const auto it{m_by_cid.find(key)};
            if (it != m_by_cid.end() && it->second == &conn) {
                m_by_cid.erase(it);
            }
        }
        conn.Cids().clear();
    }

    void SendVersionNegotiation(UdpSocket &sock, const UdpDatagram &d,
                                const ngtcp2_version_cid &vc) {
        std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;
        uint8_t unused_random;
        GetStrongRandBytes(Span<unsigned char>{&unused_random, 1});
        const uint32_t versions[]{NGTCP2_PROTO_VER_V1};
        const ngtcp2_ssize n{ngtcp2_pkt_write_version_negotiation(
            buf.data(), buf.size(), unused_random, vc.scid, vc.scidlen,
            vc.dcid, vc.dcidlen, versions, 1)};
        if (n > 0 &&
            sock.SendOne(buf.data(), static_cast<size_t>(n),
                         reinterpret_cast<const sockaddr *>(&d.remote),
                         d.remote_len, &d.local, d.local_len)) {
            ++m_stats.version_negotiation_sent;
        }
    }

    void SendRetry(UdpSocket &sock, const UdpDatagram &d,
                   const ngtcp2_pkt_hd &hd) {
        ngtcp2_cid scid;
        scid.datalen = QUIC_SCID_LEN;
        GetStrongRandBytes(Span<unsigned char>{scid.data, scid.datalen});
        std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN2> token;
        const ngtcp2_ssize tokenlen{ngtcp2_crypto_generate_retry_token2(
            token.data(), m_token_secret[0].data(), SECRET_LEN, hd.version,
            reinterpret_cast<const ngtcp2_sockaddr *>(&d.remote), d.remote_len,
            &scid, &hd.dcid, QuicSystemNow())};
        if (tokenlen < 0) {
            return;
        }
        // At most 3x what the client sent (anti-amplification).
        std::vector<uint8_t> buf(
            std::min<size_t>(NGTCP2_MAX_UDP_PAYLOAD_SIZE, d.data.size() * 3));
        const ngtcp2_ssize n{ngtcp2_crypto_write_retry(
            buf.data(), buf.size(), hd.version, &hd.scid, &scid, &hd.dcid,
            token.data(), static_cast<size_t>(tokenlen))};
        if (n > 0 &&
            sock.SendOne(buf.data(), static_cast<size_t>(n),
                         reinterpret_cast<const sockaddr *>(&d.remote),
                         d.remote_len, &d.local, d.local_len)) {
            ++m_stats.retry_sent;
            if (auto *metrics{node::GetNodeMetrics()})
                metrics->webtransport_retry_sent.Inc();
        }
    }

    void SendStatelessReset(UdpSocket &sock, const UdpDatagram &d,
                            const uint8_t *dcid, size_t dcidlen) {
        RefillResetBucket();
        if (m_reset_tokens == 0) {
            return;
        }
        --m_reset_tokens;
        ngtcp2_cid cid;
        ngtcp2_cid_init(&cid, dcid, dcidlen);
        ngtcp2_stateless_reset_token token;
        if (ngtcp2_crypto_generate_stateless_reset_token(
                token.data, m_reset_secret.data(), SECRET_LEN, &cid) != 0) {
            return;
        }
        // Smaller than the packet that triggered it (RFC 9000 §10.3.3),
        // at least 21 bytes.
        constexpr size_t MAX_RAND{NGTCP2_MAX_CIDLEN + 22 -
                                  NGTCP2_STATELESS_RESET_TOKENLEN};
        const size_t randlen{
            std::min(MAX_RAND, d.data.size() - 1 -
                                   NGTCP2_STATELESS_RESET_TOKENLEN - 1)};
        std::array<uint8_t, MAX_RAND> rand;
        GetStrongRandBytes(Span<unsigned char>{rand.data(), randlen});
        std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;
        const ngtcp2_ssize n{ngtcp2_pkt_write_stateless_reset2(
            buf.data(), buf.size(), &token, rand.data(), randlen)};
        if (n > 0 &&
            sock.SendOne(buf.data(), static_cast<size_t>(n),
                         reinterpret_cast<const sockaddr *>(&d.remote),
                         d.remote_len, &d.local, d.local_len)) {
            ++m_stats.stateless_reset_sent;
            if (auto *metrics{node::GetNodeMetrics()})
                metrics->webtransport_stateless_reset_sent.Inc();
        }
    }

    void RefillResetBucket() {
        const auto now{std::chrono::steady_clock::now()};
        if (now - m_reset_refill >= 1s) {
            m_reset_refill = now;
            m_reset_tokens = m_opts.stateless_reset_rate;
        }
    }

    bool VerifyRetryToken(const ngtcp2_pkt_hd &hd, const UdpDatagram &d,
                          ngtcp2_cid &ocid) {
        for (const auto &secret : m_token_secret) {
            if (ngtcp2_crypto_verify_retry_token2(
                    &ocid, hd.token, hd.tokenlen, secret.data(), SECRET_LEN,
                    hd.version,
                    reinterpret_cast<const ngtcp2_sockaddr *>(&d.remote),
                    d.remote_len, &hd.dcid, RETRY_TOKEN_TIMEOUT,
                    QuicSystemNow()) == 0) {
                return true;
            }
        }
        return false;
    }

    bool VerifyRegularToken(const ngtcp2_pkt_hd &hd, const UdpDatagram &d) {
        for (const auto &secret : m_token_secret) {
            if (ngtcp2_crypto_verify_regular_token(
                    hd.token, hd.tokenlen, secret.data(), SECRET_LEN,
                    reinterpret_cast<const ngtcp2_sockaddr *>(&d.remote),
                    d.remote_len, REGULAR_TOKEN_TIMEOUT,
                    QuicSystemNow()) == 0) {
                return true;
            }
        }
        return false;
    }

    /** A packet for no known connection on a listener */
    void Accept(UdpSocket &sock, UdpDatagram &d,
                const ngtcp2_version_cid &vc, uint64_t now) {
        ngtcp2_pkt_hd hd;
        if (ngtcp2_accept(&hd, d.data.data(), d.data.size()) != 0) {
            // A short header packet for a connection we forgot: tell the
            // peer with a stateless reset so it stops quickly.
            if (!(d.data[0] & 0x80) &&
                d.data.size() >= 1 + QUIC_SCID_LEN + 21) {
                SendStatelessReset(sock, d, vc.dcid, vc.dcidlen);
            }
            return;
        }
        CService remote;
        if (!remote.SetSockAddr(reinterpret_cast<const sockaddr *>(&d.remote),
                                d.remote_len))
            return;
        if (m_opts.is_banned && m_opts.is_banned(remote)) {
            OnRejected(QuicRejectReason::BANNED);
            return;
        }
        if (m_admission.Active() >= m_opts.max_inbound) {
            OnRejected(QuicRejectReason::CAPACITY);
            return;
        }
        ngtcp2_cid ocid;
        const ngtcp2_cid *pocid{nullptr};
        ngtcp2_token_type token_type{NGTCP2_TOKEN_TYPE_UNKNOWN};
        if (hd.tokenlen > 0 &&
            hd.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY2) {
            if (!VerifyRetryToken(hd, d, ocid)) {
                // Forged, expired or for another address: drop (RFC 9000
                // §8.1.2 allows a CONNECTION_CLOSE; silence costs less).
                ++m_stats.retry_token_rejected;
                return;
            }
            pocid = &ocid;
            token_type = NGTCP2_TOKEN_TYPE_RETRY;
        } else if (hd.tokenlen > 0 &&
                   hd.token[0] == NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR &&
                   VerifyRegularToken(hd, d)) {
            token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
        } else {
            hd.token = nullptr;
            hd.tokenlen = 0;
        }
        const auto decision{m_admission.Inspect(
            remote, token_type != NGTCP2_TOKEN_TYPE_UNKNOWN, m_opts.retry)};
        if (decision == QuicAdmission::Decision::RETRY) {
            SendRetry(sock, d, hd);
            return;
        }
        if (decision != QuicAdmission::Decision::ACCEPT) {
            OnRejected(decision == QuicAdmission::Decision::PER_IP
                           ? QuicRejectReason::PER_IP
                       : decision == QuicAdmission::Decision::HANDSHAKING
                           ? QuicRejectReason::HANDSHAKING
                           : QuicRejectReason::CAPACITY);
            return;
        }
        sockaddr_storage local{};
        socklen_t local_len{0};
        if (d.local_len > 0) {
            local = d.local;
            local_len = d.local_len;
        } else {
            local_len = sizeof(local);
            sock.Local().GetSockAddr(reinterpret_cast<sockaddr *>(&local),
                                     &local_len);
        }
        auto conn{std::make_unique<QuicConnection>(
            *this, /*server=*/true, sock, local, local_len, d.remote,
            d.remote_len)};
        if (!conn->InitServer(hd, pocid, token_type)) {
            ForgetCids(*conn);
            return;
        }
        switch (m_opts.application) {
            case QuicApplication::ECHO_FOR_TEST:
                conn->SetApp(std::make_unique<EchoApp>());
                break;
            case QuicApplication::WEBTRANSPORT: {
                H3Options h3;
                h3.server = true;
                h3.path = m_opts.wt_path;
                h3.origins = m_opts.wt_origins;
                h3.token = m_opts.wt_token;
                h3.echo = m_opts.wt_echo;
                std::unique_ptr<WtSessionHandler> handler;
                if (!m_opts.wt_echo) {
                    handler = std::make_unique<P2PSessionHandler>(
                        m_waker, m_opts.compress, m_opts.receive_buffer);
                }
                conn->SetApp(std::make_unique<H3Session>(h3, std::move(handler)));
                break;
            }
        }
        QuicConnection &c{*conn};
        m_admission.Started(remote);
        LogDebug(BCLog::WEBTRANSPORT, "QUIC connection from %s%s\n",
                 c.Remote().ToStringAddrPort(),
                 token_type == NGTCP2_TOKEN_TYPE_RETRY ? " (after Retry)" : "");
        m_conns.push_back(std::move(conn));
        c.Read(d, now);
    }

    void HandleDatagram(UdpSocket &sock, bool listener, UdpDatagram &d,
                        uint64_t now) {
        {
            ++m_stats.packets_recv;
            m_stats.bytes_recv += d.data.size();
        }
        if (d.data.empty()) {
            return;
        }
        ngtcp2_version_cid vc;
        const int rv{ngtcp2_pkt_decode_version_cid(
            &vc, d.data.data(), d.data.size(), QUIC_SCID_LEN)};
        if (rv == NGTCP2_ERR_VERSION_NEGOTIATION) {
            if (listener) {
                SendVersionNegotiation(sock, d, vc);
            }
            return;
        }
        if (rv != 0) {
            return;
        }
        const auto it{m_by_cid.find(CidKey(vc.dcid, vc.dcidlen))};
        if (it != m_by_cid.end()) {
            it->second->Read(d, now);
            return;
        }
        if (listener) {
            Accept(sock, d, vc, now);
        }
    }

    void RunTasks() EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        std::deque<std::function<void()>> tasks;
        {
            LOCK(m_tasks_mutex);
            tasks.swap(m_tasks);
        }
        for (auto &fn : tasks) {
            fn();
        }
    }

    void RotateSecrets() {
        const auto now{std::chrono::steady_clock::now()};
        if (now >= m_next_rotation) {
            m_next_rotation = now + TOKEN_SECRET_ROTATION;
            m_token_secret[1] = m_token_secret[0];
            GetStrongRandBytes(m_token_secret[0]);
        }
    }

    void CollectGarbage(uint64_t now) {
        uint64_t inbound{0}, outbound{0}, handshaking{0};
        std::array<size_t, 6> metric_connections{};
        auto *metrics{node::GetNodeMetrics()};
        for (auto it = m_conns.begin(); it != m_conns.end();) {
            QuicConnection &c{**it};
            if (c.CancelFlag() && *c.CancelFlag() && c.IsOpen()) {
                c.CloseApp(0, "cancelled");
            }
            const bool gone{c.GetState() == QuicConnection::State::DEAD ||
                            (!c.IsOpen() && now >= c.CloseDeadline())};
            if (metrics) {
                ngtcp2_conn_info ci;
                ngtcp2_conn_get_conn_info2(c.Conn(), &ci);
                auto &[lost, next_rtt]{m_metric_state[&c]};
                if (ci.pkt_lost > lost)
                    metrics->webtransport_lost_packets.Add(0,
                                                           ci.pkt_lost - lost);
                lost = ci.pkt_lost;
                if (c.GetState() == QuicConnection::State::ESTABLISHED &&
                    now >= next_rtt && ci.smoothed_rtt > 0 &&
                    ci.smoothed_rtt != UINT64_MAX) {
                    metrics->webtransport_rtt.Record(ci.smoothed_rtt);
                    next_rtt = now + NGTCP2_SECONDS;
                }
                if (!gone) {
                    const size_t state{
                        c.GetState() == QuicConnection::State::HANDSHAKING ? 0U
                        : c.GetState() == QuicConnection::State::ESTABLISHED
                            ? 1U
                            : 2U};
                    ++metric_connections[(c.IsServer() ? 0U : 1U) * 3 + state];
                }
            }
            if (gone) {
                if (!c.HandshakeDone()) {
                    ++m_stats.handshakes_failed;
                    if (metrics) metrics->webtransport_handshakes.Add(1);
                    LogDebug(BCLog::WEBTRANSPORT,
                             "QUIC connection with %s ended before its "
                             "handshake completed\n",
                             c.Remote().ToStringAddrPort());
                }
                if (c.IsServer())
                    m_admission.Closed(c.Remote(), c.HandshakeDone());
                m_metric_state.erase(&c);
                ForgetCids(c);
                it = m_conns.erase(it);
                continue;
            }
            if (c.IsOpen()) {
                (c.IsServer() ? inbound : outbound)++;
                if (c.GetState() == QuicConnection::State::HANDSHAKING) {
                    ++handshaking;
                }
            }
            ++it;
        }
        m_stats.connections = inbound + outbound;
        m_stats.inbound = inbound;
        m_stats.outbound = outbound;
        m_stats.handshaking = handshaking;
        if (metrics) {
            for (size_t i{0}; i < metric_connections.size(); ++i)
                metrics->webtransport_connections.Set(metric_connections[i], i);
        }
    }

    void ThreadMain() EXCLUSIVE_LOCKS_REQUIRED(!m_tasks_mutex) {
        std::vector<UdpDatagram> batch;
        batch.reserve(RECV_BATCH);
        while (true) {
            uint64_t now{QuicNow()};
            uint64_t next{UINT64_MAX};
            for (const auto &c : m_conns) {
                next = std::min(next, c->NextExpiry());
            }
            int timeout_ms{1000};
            if (next != UINT64_MAX) {
                timeout_ms = next <= now
                                 ? 0
                                 : static_cast<int>(std::min<uint64_t>(
                                       1000, (next - now + 999999) / 1000000));
            }
            std::vector<pollfd> fds;
            fds.push_back({m_wake_read, POLLIN, 0});
            for (const auto &l : m_listeners) {
                fds.push_back({static_cast<int>(l->Fd()), POLLIN, 0});
            }
            for (const auto *s : {m_client4.get(), m_client6.get()}) {
                if (s) {
                    fds.push_back({static_cast<int>(s->Fd()), POLLIN, 0});
                }
            }
            ::poll(fds.data(), fds.size(), timeout_ms);
            if (fds[0].revents & POLLIN) {
                uint8_t buf[64];
                while (::recv(m_wake_read, buf, sizeof(buf), MSG_DONTWAIT) >
                       0) {
                }
            }
            m_waker->pending = false;
            if (m_stop) {
                break;
            }
            RotateSecrets();
            RunTasks();
            now = QuicNow();
            for (auto &l : m_listeners) {
                batch.clear();
                l->RecvBatch(batch, RECV_BATCH);
                for (auto &d : batch) {
                    HandleDatagram(*l, /*listener=*/true, d, now);
                }
            }
            for (auto *s : {m_client4.get(), m_client6.get()}) {
                if (!s) {
                    continue;
                }
                batch.clear();
                s->RecvBatch(batch, RECV_BATCH);
                for (auto &d : batch) {
                    HandleDatagram(*s, /*listener=*/false, d, now);
                }
            }
            now = QuicNow();
            for (auto &c : m_conns) {
                if (c->NextExpiry() <= now) {
                    c->HandleExpiry(now);
                }
            }
            for (auto &c : m_conns) {
                c->Write(now);
            }
            CollectGarbage(now);
        }
        // Shutdown: tell every peer, then forget them.
        for (auto &c : m_conns) {
            c->CloseApp(0, "shutdown");
        }
        m_conns.clear();
        m_by_cid.clear();
        m_metric_state.clear();
        if (auto *metrics{node::GetNodeMetrics()}) {
            for (size_t i{0}; i < 6; ++i)
                metrics->webtransport_connections.Set(0, i);
        }
    }

    const QuicEngineOptions m_opts;
    QuicAdmission m_admission;
    //! Only the engine thread invokes TLS callbacks, including on reload.
    size_t m_observer_records{0};
    size_t m_observer_bytes{0};
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    int m_wake_read{-1};
    std::shared_ptr<EngineWaker> m_waker;

    Mutex m_tasks_mutex;
    std::deque<std::function<void()>> m_tasks GUARDED_BY(m_tasks_mutex);

    //! Counters, written by the engine thread, read by any
    struct {
        std::atomic<uint64_t> connections{0}, inbound{0}, outbound{0},
            handshaking{0}, handshakes_completed{0}, handshakes_failed{0},
            retry_sent{0}, retry_token_rejected{0}, stateless_reset_sent{0},
            version_negotiation_sent{0}, idle_closed{0}, packets_recv{0},
            packets_sent{0}, bytes_recv{0}, bytes_sent{0};
        std::array<std::atomic<uint64_t>, QUIC_REJECT_REASONS> rejected{};
    } m_stats;

    // Engine thread only below.
    std::vector<std::unique_ptr<UdpSocket>> m_listeners;
    std::unique_ptr<UdpSocket> m_client4, m_client6;
    std::list<std::unique_ptr<QuicConnection>> m_conns;
    std::unordered_map<QuicConnection *, std::pair<uint64_t, uint64_t>>
        m_metric_state;
    std::unordered_map<std::string, QuicConnection *> m_by_cid;
    std::array<uint8_t, SECRET_LEN> m_reset_secret;
    std::array<std::array<uint8_t, SECRET_LEN>, 2> m_token_secret;
    std::chrono::steady_clock::time_point m_next_rotation;
    uint32_t m_reset_tokens{0};
    std::chrono::steady_clock::time_point m_reset_refill{};
    tls::SslCtxPtr m_server_ctx;
    uint64_t m_certificate_generation{0};
    tls::SslCtxPtr m_client_ctx;
    fs::file_time_type m_cert_mtime{}, m_key_mtime{};
    std::chrono::steady_clock::time_point m_next_cert_check{};
};

QuicEngine::QuicEngine(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}

QuicEngine::~QuicEngine() {
    Stop();
}

std::unique_ptr<QuicEngine> QuicEngine::Start(const QuicEngineOptions &options,
                                              std::string &error) {
    auto impl{std::make_unique<Impl>(options)};
    if (!impl->Init(error)) {
        return nullptr;
    }
    return std::unique_ptr<QuicEngine>{new QuicEngine{std::move(impl)}};
}

void QuicEngine::Stop() {
    if (m_impl) {
        m_impl->Stop();
    }
}

std::vector<CService> QuicEngine::BoundAddresses() const {
    return m_impl->BoundAddresses();
}

QuicEngineStats QuicEngine::Stats() const {
    return m_impl->Stats();
}

std::optional<WebTransportDialResult>
QuicEngine::Dial(const CService &target, const ParsedWebTransportURL &url,
                 std::chrono::milliseconds timeout, CThreadInterrupt &interrupt,
                 WebTransportDialError &error) {
    return m_impl->Dial(target, url, timeout, interrupt, error);
}

std::optional<WtProbeResult>
QuicEngine::WebTransportProbeForTest(const CService &target,
                                     const WtProbeOptions &options,
                                     std::chrono::milliseconds timeout) {
    return m_impl->WebTransportProbeForTest(target, options, timeout);
}

std::optional<std::vector<uint8_t>>
QuicEngine::EchoForTest(const CService &target,
                        const std::vector<uint8_t> &payload,
                        std::chrono::milliseconds timeout,
                        const std::optional<std::vector<uint8_t>> &cert_sha256) {
    return m_impl->EchoForTest(target, payload, timeout, cert_sha256);
}
