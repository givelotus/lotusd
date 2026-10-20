// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/quic_connection.h>

#include <logging.h>
#include <random.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>

uint64_t QuicNow() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

uint64_t QuicSystemNow() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

namespace {
//! Connection IDs we issue
constexpr size_t QUIC_SCID_LEN = 18;
//! Packets written per Write() pass before yielding to other connections
constexpr int MAX_PACKETS_PER_WRITE = 64;
//! iovecs offered per writev call
constexpr size_t MAX_WRITE_VECS = 16;

QuicConnection *Self(void *user_data) {
    return static_cast<QuicConnection *>(user_data);
}

ngtcp2_conn *GetConn(ngtcp2_crypto_conn_ref *ref) {
    return static_cast<QuicConnection *>(ref->user_data)->Conn();
}

void RandCb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
    GetStrongRandBytes(Span<unsigned char>{dest, destlen});
}

int GetNewConnectionId(ngtcp2_conn *, ngtcp2_cid *cid,
                       ngtcp2_stateless_reset_token *token, size_t cidlen,
                       void *user_data) {
    QuicConnection &c{*Self(user_data)};
    cid->datalen = cidlen;
    GetStrongRandBytes(Span<unsigned char>{cid->data, cidlen});
    QuicEngineCore &engine{c.Engine()};
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token->data, engine.Secret(), engine.SecretLen(), cid) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    engine.RegisterCid(c, *cid);
    return 0;
}

int RemoveConnectionId(ngtcp2_conn *, const ngtcp2_cid *cid,
                       void *user_data) {
    QuicConnection &c{*Self(user_data)};
    c.Engine().UnregisterCid(c, *cid);
    return 0;
}

int HandshakeCompleted(ngtcp2_conn *, void *user_data) {
    Self(user_data)->OnHandshakeCompletedInternal();
    return 0;
}

int StreamOpen(ngtcp2_conn *, int64_t stream_id, void *user_data) {
    QuicStream &s{Self(user_data)->Stream(stream_id)};
    s.kind = QuicStream::Kind::PENDING;
    return 0;
}

int RecvStreamData(ngtcp2_conn *, uint32_t flags, int64_t stream_id,
                   uint64_t, const uint8_t *data, size_t datalen,
                   void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    QuicStream &s{c.Stream(stream_id)};
    if (s.kind == QuicStream::Kind::IGNORED) {
        c.ExtendCredit(stream_id, datalen);
        return 0;
    }
    if (!c.App()) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return c.App()->OnStreamData(c, s, flags, data, datalen);
}

int AckedStreamDataOffset(ngtcp2_conn *, int64_t stream_id, uint64_t,
                          uint64_t datalen, void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    QuicStream *s{c.FindStream(stream_id)};
    if (!s) {
        return 0;
    }
    if (s->kind == QuicStream::Kind::LIBRARY) {
        return c.App() ? c.App()->OnLibraryAcked(c, stream_id, datalen) : 0;
    }
    c.OnAckedOwn(*s, datalen);
    return 0;
}

int StreamClose(ngtcp2_conn *, uint32_t flags, int64_t stream_id,
                uint64_t app_error_code, uint64_t, void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    if (c.App()) {
        c.App()->OnStreamClose(
            c, stream_id, flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET,
            app_error_code);
    }
    c.Streams().erase(stream_id);
    return 0;
}

int StreamReset(ngtcp2_conn *, int64_t stream_id, uint64_t, uint64_t app_error,
                void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    if (c.App()) {
        c.App()->OnStreamReset(c, stream_id, app_error);
    }
    return 0;
}

int StreamStopSending(ngtcp2_conn *, int64_t stream_id, uint64_t app_error,
                      void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    if (c.App()) {
        c.App()->OnStreamStopSending(c, stream_id, app_error);
    }
    return 0;
}

int ExtendMaxStreamData(ngtcp2_conn *, int64_t stream_id, uint64_t,
                        void *user_data, void *) {
    QuicConnection &c{*Self(user_data)};
    QuicStream *s{c.FindStream(stream_id)};
    if (!s) {
        return 0;
    }
    s->blocked = false;
    if (s->kind == QuicStream::Kind::LIBRARY && c.App()) {
        c.App()->OnLibraryUnblocked(c, stream_id);
    }
    return 0;
}

int ExtendMaxRemoteStreamsBidi(ngtcp2_conn *, uint64_t max_streams,
                               void *user_data) {
    QuicConnection &c{*Self(user_data)};
    if (c.App()) {
        c.App()->OnMaxRemoteStreamsBidi(c, max_streams);
    }
    return 0;
}

int RecvDatagram(ngtcp2_conn *, uint32_t, const uint8_t *data, size_t datalen,
                 void *user_data) {
    QuicConnection &c{*Self(user_data)};
    if (c.App()) {
        c.App()->OnDatagram(c, data, datalen);
    }
    return 0;
}

ngtcp2_callbacks MakeCallbacks(bool server) {
    ngtcp2_callbacks cb{};
    if (server) {
        cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    } else {
        cb.client_initial = ngtcp2_crypto_client_initial_cb;
        cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    }
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.handshake_completed = HandshakeCompleted;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_stream_data = RecvStreamData;
    cb.acked_stream_data_offset = AckedStreamDataOffset;
    cb.stream_open = StreamOpen;
    cb.stream_close2 = StreamClose;
    cb.rand = RandCb;
    cb.get_new_connection_id2 = GetNewConnectionId;
    cb.remove_connection_id = RemoveConnectionId;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.stream_reset = StreamReset;
    cb.extend_max_stream_data = ExtendMaxStreamData;
    cb.extend_max_remote_streams_bidi = ExtendMaxRemoteStreamsBidi;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.stream_stop_sending = StreamStopSending;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.recv_datagram = RecvDatagram;
    return cb;
}

ngtcp2_path MakePath(sockaddr_storage &local, socklen_t local_len,
                     sockaddr_storage &remote, socklen_t remote_len) {
    ngtcp2_path p;
    p.local.addr = reinterpret_cast<ngtcp2_sockaddr *>(&local);
    p.local.addrlen = local_len;
    p.remote.addr = reinterpret_cast<ngtcp2_sockaddr *>(&remote);
    p.remote.addrlen = remote_len;
    p.user_data = nullptr;
    return p;
}
} // namespace

QuicConnection::QuicConnection(QuicEngineCore &engine, bool server,
                               UdpSocket &sock, const sockaddr_storage &local,
                               socklen_t local_len,
                               const sockaddr_storage &remote,
                               socklen_t remote_len)
    : m_engine{engine}, m_server{server}, m_sock{sock}, m_local{local},
      m_local_len{local_len}, m_remote{remote}, m_remote_len{remote_len},
      m_created{QuicNow()}, m_last_ts{m_created} {
    m_local_service.SetSockAddr(reinterpret_cast<const sockaddr *>(&m_local),
                                m_local_len);
    m_remote_service.SetSockAddr(
        reinterpret_cast<const sockaddr *>(&m_remote), m_remote_len);
    m_ref.get_conn = GetConn;
    m_ref.user_data = this;
}

QuicConnection::~QuicConnection() {
    m_app.reset();
    if (m_conn) {
        ngtcp2_conn_del(m_conn);
    }
    if (m_ssl) {
        SSL_set_app_data(m_ssl, nullptr);
        SSL_free(m_ssl);
    }
    if (m_ossl) {
        ngtcp2_crypto_ossl_ctx_del(m_ossl);
    }
}

bool QuicConnection::InitTls(bool server, const std::string &sni) {
    SSL_CTX *ctx{server ? m_engine.ServerContext() : m_engine.ClientContext()};
    if (!ctx) {
        return false;
    }
    if (ngtcp2_crypto_ossl_ctx_new(&m_ossl, nullptr) != 0) {
        return false;
    }
    m_ssl = SSL_new(ctx);
    if (!m_ssl) {
        return false;
    }
    ngtcp2_crypto_ossl_ctx_set_ssl(m_ossl, m_ssl);
    if ((server ? ngtcp2_crypto_ossl_configure_server_session(m_ssl)
                : ngtcp2_crypto_ossl_configure_client_session(m_ssl)) != 0) {
        return false;
    }
    SSL_set_app_data(m_ssl, &m_ref);
    if (server) {
        SSL_set_accept_state(m_ssl);
    } else {
        SSL_set_connect_state(m_ssl);
        static const unsigned char alpn[] = {2, 'h', '3'};
        SSL_set_alpn_protos(m_ssl, alpn, sizeof(alpn));
        if (!sni.empty()) {
            SSL_set_tlsext_host_name(m_ssl, sni.c_str());
        }
    }
    ngtcp2_conn_set_tls_native_handle(m_conn, m_ossl);
    return true;
}

bool QuicConnection::InitServer(const ngtcp2_pkt_hd &hd,
                                const ngtcp2_cid *ocid,
                                ngtcp2_token_type token_type) {
    ngtcp2_cid scid;
    scid.datalen = QUIC_SCID_LEN;
    GetStrongRandBytes(Span<unsigned char>{scid.data, scid.datalen});
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    m_engine.FillSettings(settings, params, /*server=*/true, Clamp(QuicNow()));
    settings.token = hd.token;
    settings.tokenlen = hd.tokenlen;
    settings.token_type = token_type;
    params.stateless_reset_token_present = 1;
    if (ocid) {
        params.original_dcid = *ocid;
        params.retry_scid = hd.dcid;
        params.retry_scid_present = 1;
    } else {
        params.original_dcid = hd.dcid;
    }
    params.original_dcid_present = 1;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            params.stateless_reset_token, m_engine.Secret(),
            m_engine.SecretLen(), &scid) != 0) {
        return false;
    }
    const ngtcp2_callbacks cb{MakeCallbacks(/*server=*/true)};
    ngtcp2_path path{MakePath(m_local, m_local_len, m_remote, m_remote_len)};
    if (ngtcp2_conn_server_new(&m_conn, &hd.scid, &scid, &path, hd.version,
                               &cb, &settings, &params, nullptr, this) != 0) {
        m_conn = nullptr;
        return false;
    }
    if (!InitTls(/*server=*/true, "")) {
        return false;
    }
    m_engine.RegisterCid(*this, scid);
    m_engine.RegisterCid(*this, hd.dcid);
    return true;
}

bool QuicConnection::InitClient(const std::string &sni) {
    ngtcp2_cid scid, dcid;
    scid.datalen = QUIC_SCID_LEN;
    GetStrongRandBytes(Span<unsigned char>{scid.data, scid.datalen});
    dcid.datalen = QUIC_SCID_LEN;
    GetStrongRandBytes(Span<unsigned char>{dcid.data, dcid.datalen});
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    m_engine.FillSettings(settings, params, /*server=*/false, Clamp(QuicNow()));
    const ngtcp2_callbacks cb{MakeCallbacks(/*server=*/false)};
    ngtcp2_path path{MakePath(m_local, m_local_len, m_remote, m_remote_len)};
    if (ngtcp2_conn_client_new(&m_conn, &dcid, &scid, &path,
                               NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                               nullptr, this) != 0) {
        m_conn = nullptr;
        return false;
    }
    if (!InitTls(/*server=*/false, sni)) {
        return false;
    }
    m_engine.RegisterCid(*this, scid);
    return true;
}

QuicStream &QuicConnection::Stream(int64_t id) {
    auto it{m_streams.find(id)};
    if (it == m_streams.end()) {
        it = m_streams.emplace(id, QuicStream{}).first;
        it->second.id = id;
    }
    return it->second;
}

QuicStream *QuicConnection::FindStream(int64_t id) {
    const auto it{m_streams.find(id)};
    return it == m_streams.end() ? nullptr : &it->second;
}

int64_t QuicConnection::OpenStream(bool bidi, QuicStream::Kind kind,
                                   int priority) {
    int64_t id{-1};
    const int rv{bidi ? ngtcp2_conn_open_bidi_stream(m_conn, &id, nullptr)
                      : ngtcp2_conn_open_uni_stream(m_conn, &id, nullptr)};
    if (rv != 0) {
        return -1;
    }
    QuicStream &s{Stream(id)};
    s.kind = kind;
    s.priority = priority;
    return id;
}

void QuicConnection::QueueStreamData(QuicStream &stream,
                                     std::vector<uint8_t> &&data, bool fin) {
    if (!data.empty()) {
        stream.unsent += data.size();
        stream.txq.push_back(QuicTxChunk{std::move(data)});
    }
    if (fin) {
        stream.fin_queued = true;
    }
}

void QuicConnection::QueueDatagram(std::vector<uint8_t> &&payload) {
    // A small bound: datagrams are best effort.
    if (m_datagrams.size() < 64) {
        m_datagrams.push_back(std::move(payload));
    }
}

void QuicConnection::ExtendCredit(int64_t stream_id, uint64_t n) {
    if (n == 0 || !m_conn) {
        return;
    }
    ngtcp2_conn_extend_max_stream_offset(m_conn, stream_id, n);
    ngtcp2_conn_extend_max_offset(m_conn, n);
}

void QuicConnection::ShutdownStream(int64_t stream_id, uint64_t app_error) {
    if (QuicStream *s{FindStream(stream_id)}) {
        s->kind = QuicStream::Kind::IGNORED;
        s->txq.clear();
        s->unsent = 0;
        s->fin_queued = false;
    }
    if (m_conn) {
        ngtcp2_conn_shutdown_stream(m_conn, 0, stream_id, app_error);
    }
}

void QuicConnection::OnAckedOwn(QuicStream &stream, uint64_t datalen) {
    while (datalen > 0 && !stream.txq.empty()) {
        QuicTxChunk &chunk{stream.txq.front()};
        const uint64_t take{
            std::min<uint64_t>(datalen, chunk.data.size() - chunk.acked)};
        chunk.acked += take;
        datalen -= take;
        if (chunk.acked == chunk.data.size()) {
            stream.txq.pop_front();
        }
    }
}

void QuicConnection::OnHandshakeCompletedInternal() {
    m_handshake_done = true;
    if (m_state == State::HANDSHAKING) {
        m_state = State::ESTABLISHED;
    }
    if (m_server) {
        uint8_t token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN];
        const ngtcp2_path *path{ngtcp2_conn_get_path2(m_conn)};
        const auto n{ngtcp2_crypto_generate_regular_token(
            token, m_engine.TokenSecret(), m_engine.SecretLen(),
            path->remote.addr,
            path->remote.addrlen, QuicSystemNow())};
        if (n > 0) {
            ngtcp2_conn_submit_new_token(m_conn, token, static_cast<size_t>(n));
        }
    }
    m_engine.OnHandshakeDone(*this);
    if (m_app && m_app->OnHandshakeCompleted(*this) != 0) {
        CloseApp(0x0101 /* H3_INTERNAL_ERROR */, "application setup failed");
    }
}

UdpDatagram QuicConnection::Packet(const uint8_t *data, size_t len,
                                   const ngtcp2_path *path,
                                   size_t segment_size) const {
    UdpDatagram packet;
    packet.remote = m_remote;
    packet.remote_len = m_remote_len;
    packet.local = m_local;
    packet.local_len = m_local_len;
    // ngtcp2 may be writing path validation traffic or a validated new path.
    // Preserve its per-packet path instead of always using the original peer.
    if (path && path->remote.addrlen &&
        path->remote.addrlen <= sizeof(packet.remote)) {
        std::memcpy(&packet.remote, path->remote.addr, path->remote.addrlen);
        packet.remote_len = path->remote.addrlen;
    }
    if (path && path->local.addrlen &&
        path->local.addrlen <= sizeof(packet.local)) {
        std::memcpy(&packet.local, path->local.addr, path->local.addrlen);
        packet.local_len = path->local.addrlen;
    }
    packet.segment_size = segment_size;
    packet.data.assign(data, data + len);
    return packet;
}

void QuicConnection::SendPacket(const uint8_t *data, size_t len) {
    const auto packet{Packet(data, len, ngtcp2_conn_get_path2(m_conn))};
    m_sock.SendOne(packet.data.data(), packet.data.size(),
                   reinterpret_cast<const sockaddr *>(&packet.remote),
                   packet.remote_len, &packet.local, packet.local_len);
    m_engine.OnPacketSent(len);
}

uint64_t QuicConnection::Clamp(uint64_t now) {
    // ngtcp2 requires non-decreasing timestamps per connection; callers
    // pass a time taken before other connections' work.
    m_last_ts = std::max(m_last_ts, now);
    return m_last_ts;
}

void QuicConnection::Read(const UdpDatagram &dgram, uint64_t now) {
    now = Clamp(now);
    if (m_state == State::CLOSING) {
        // Closing period: repeat CONNECTION_CLOSE (RFC 9000 §10.2.1).
        if (!m_close_pkt.empty()) {
            SendPacket(m_close_pkt.data(), m_close_pkt.size());
        }
        return;
    }
    if (!IsOpen()) {
        return;
    }
    // The datagram's remote may differ from ours (NAT rebinding): ngtcp2
    // validates the new path itself.
    sockaddr_storage remote{dgram.remote};
    ngtcp2_path path{MakePath(m_local, m_local_len, remote, dgram.remote_len)};
    ngtcp2_pkt_info pi{};
    pi.ecn = dgram.ecn;
    const int rv{ngtcp2_conn_read_pkt(m_conn, &path, &pi, dgram.data.data(),
                                      dgram.data.size(), now)};
    if (rv == 0) {
        return;
    }
    switch (rv) {
        case NGTCP2_ERR_DRAINING:
            EnterDraining(now);
            return;
        case NGTCP2_ERR_DROP_CONN:
        case NGTCP2_ERR_RETRY:
            Kill();
            return;
        case NGTCP2_ERR_CRYPTO:
            LogDebug(BCLog::WEBTRANSPORT,
                     "QUIC TLS handshake with %s failed (alert %u)\n",
                     m_remote_service.ToStringAddrPort(),
                     ngtcp2_conn_get_tls_alert2(m_conn));
            break;
        default:
            LogDebug(BCLog::WEBTRANSPORT, "QUIC packet from %s: %s\n",
                     m_remote_service.ToStringAddrPort(),
                     ngtcp2_strerror(rv));
            break;
    }
    CloseLib(rv);
}

QuicStream *QuicConnection::PickOwnStream() {
    QuicStream *best{nullptr};
    // Lowest priority value wins; among equals the first stream after the
    // last one served (round-robin by stream id).
    for (auto &[id, s] : m_streams) {
        if (s.kind != QuicStream::Kind::OWN || !s.WantsWrite()) {
            continue;
        }
        if (!best || s.priority < best->priority) {
            best = &s;
            continue;
        }
        if (s.priority == best->priority) {
            const bool best_after{best->id > m_rr_last};
            const bool s_after{s.id > m_rr_last};
            if (s_after && !best_after) {
                best = &s;
            }
        }
    }
    return best;
}

void QuicConnection::AccountWritten(QuicStream &stream, size_t datalen,
                                    bool fin) {
    size_t left{datalen};
    stream.unsent -= std::min<uint64_t>(stream.unsent, datalen);
    for (QuicTxChunk &chunk : stream.txq) {
        if (left == 0) {
            break;
        }
        const size_t avail{chunk.data.size() - chunk.sent};
        const size_t take{std::min(left, avail)};
        chunk.sent += take;
        left -= take;
    }
    if (fin) {
        stream.fin_sent = true;
    }
}

void QuicConnection::Write(uint64_t now) {
    if (!IsOpen()) {
        return;
    }
    now = Clamp(now);
    if (ngtcp2_conn_get_max_data_left2(m_conn) > 0)
        m_connection_flow_blocked.fill(false);
    if (m_app) {
        m_app->BeforeWrite(*this);
    }
    if (!IsOpen()) {
        return;
    }
    const size_t max_pkt{ngtcp2_conn_get_max_tx_udp_payload_size2(m_conn)};
    if (m_txbuf.size() < max_pkt) {
        m_txbuf.resize(std::max<size_t>(max_pkt, 1500));
    }
    const size_t burst{m_sock.GsoSupported() ? 10U : 1U};
    const size_t capacity{
        std::max(max_pkt, std::min(max_pkt * burst,
                                   ngtcp2_conn_get_send_quantum2(m_conn)))};
    if (m_txbuf.size() < capacity) m_txbuf.resize(capacity);
    std::vector<UdpDatagram> packets;
    packets.reserve(MAX_PACKETS_PER_WRITE);
    const auto flush = [&] {
        // An unsent suffix is dropped, as with the previous nonblocking
        // sendmsg path; ngtcp2 retains it for ordinary loss recovery.
        m_sock.SendBatch(packets);
        for (const auto &packet : packets) {
            const size_t segment{packet.segment_size ? packet.segment_size
                                                     : packet.data.size()};
            for (size_t offset{0}; offset < packet.data.size();
                 offset += segment)
                m_engine.OnPacketSent(
                    std::min(segment, packet.data.size() - offset));
        }
        packets.clear();
    };
    for (size_t count{0}; count < MAX_PACKETS_PER_WRITE;) {
        ngtcp2_path_storage path;
        ngtcp2_path_storage_zero(&path);
        ngtcp2_pkt_info pi{};
        size_t segment{0};
        ngtcp2_ssize written;
        if (m_sock.GsoSupported()) {
            written = ngtcp2_conn_write_aggregate_pkt2(
                m_conn, &path.path, &pi, m_txbuf.data(), capacity, &segment,
                [](ngtcp2_conn *, ngtcp2_path *p, ngtcp2_pkt_info *info,
                   uint8_t *buffer, size_t len, uint64_t ts, void *user) {
                    return static_cast<QuicConnection *>(user)->WritePacket(
                        p, info, buffer, len, ts);
                },
                std::min<size_t>(10, MAX_PACKETS_PER_WRITE - count), now);
        } else {
            written =
                WritePacket(&path.path, &pi, m_txbuf.data(), max_pkt, now);
        }
        if (written < 0) {
            flush();
            CloseLib(static_cast<int>(written));
            return;
        }
        if (written == 0) break;
        const size_t bytes{static_cast<size_t>(written)};
        packets.push_back(Packet(m_txbuf.data(), bytes, &path.path, segment));
        count += segment ? (bytes + segment - 1) / segment : 1;
        if (!IsOpen()) break;
    }
    flush();
    ngtcp2_conn_update_pkt_tx_time(m_conn, now);
}

ngtcp2_ssize QuicConnection::WritePacket(ngtcp2_path *path, ngtcp2_pkt_info *pi,
                                         uint8_t *buffer, size_t capacity,
                                         uint64_t now) {
    if (!IsOpen()) return 0;
    while (true) {
        if (!m_datagrams.empty()) {
            const std::vector<uint8_t> &d{m_datagrams.front()};
            ngtcp2_vec v{const_cast<uint8_t *>(d.data()), d.size()};
            int accepted{0};
            const ngtcp2_ssize n{ngtcp2_conn_writev_datagram(
                m_conn, path, pi, buffer, capacity, &accepted,
                NGTCP2_WRITE_DATAGRAM_FLAG_MORE, m_next_datagram_id++, &v, 1,
                now)};
            if (n == NGTCP2_ERR_WRITE_MORE) {
                if (accepted) {
                    m_datagrams.pop_front();
                }
                continue;
            }
            if (n < 0) {
                if (n == NGTCP2_ERR_INVALID_STATE ||
                    n == NGTCP2_ERR_INVALID_ARGUMENT) {
                    // Not negotiated, or larger than the peer accepts.
                    m_datagrams.pop_front();
                    continue;
                }
                return static_cast<int>(n);
            }
            if (accepted) {
                m_datagrams.pop_front();
            }
            if (n == 0) {
                break;
            }
            return n;
        }
        int64_t stream_id{-1};
        int fin{0};
        ngtcp2_vec vec[MAX_WRITE_VECS];
        size_t vcnt{0};
        QuicStream *own{nullptr};
        bool library{false};
        {
            // Library (HTTP/3 control, QPACK, CONNECT) streams first: small
            // and needed for the session to progress.
            if (m_app) {
                const ngtcp2_ssize cnt{m_app->WritevLibrary(
                    *this, stream_id, fin, vec, MAX_WRITE_VECS)};
                if (cnt < 0) {
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
                vcnt = static_cast<size_t>(cnt);
                library = stream_id >= 0;
            }
            if (!library) {
                stream_id = -1;
                fin = 0;
                vcnt = 0;
                own = PickOwnStream();
                if (own) {
                    stream_id = own->id;
                    size_t covered{0};
                    for (QuicTxChunk &chunk : own->txq) {
                        if (chunk.sent < chunk.data.size()) {
                            vec[vcnt].base = chunk.data.data() + chunk.sent;
                            vec[vcnt].len = chunk.data.size() - chunk.sent;
                            covered += vec[vcnt].len;
                            if (++vcnt == MAX_WRITE_VECS) {
                                break;
                            }
                        }
                    }
                    fin = own->fin_queued && covered == own->unsent;
                }
            }
        }
        uint32_t flags{NGTCP2_WRITE_STREAM_FLAG_MORE};
        if (fin) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        ngtcp2_ssize ndatalen{-1};
        const ngtcp2_ssize n{ngtcp2_conn_writev_stream(
            m_conn, path, pi, buffer, capacity, &ndatalen, flags, stream_id,
            vec, vcnt, now)};
        if (n < 0) {
            switch (n) {
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                    if (library) {
                        m_app->OnLibraryBlocked(*this, stream_id);
                    } else if (own) {
                        own->blocked = true;
                        m_engine.OnStreamBlocked(own->app_tag);
                    }
                    continue;
                case NGTCP2_ERR_STREAM_SHUT_WR:
                    if (library) {
                        m_app->OnLibraryShutWr(*this, stream_id);
                    } else if (own) {
                        own->shut_wr = true;
                    }
                    continue;
                case NGTCP2_ERR_WRITE_MORE:
                    if (ndatalen >= 0) {
                        if (library) {
                            if (m_app->OnLibraryWritten(
                                    *this, stream_id,
                                    static_cast<size_t>(ndatalen)) != 0) {
                                return NGTCP2_ERR_CALLBACK_FAILURE;
                            }
                        } else if (own) {
                            AccountWritten(*own, static_cast<size_t>(ndatalen),
                                           fin && static_cast<size_t>(
                                                      ndatalen) == own->unsent);
                            m_rr_last = own->id;
                        }
                    }
                    continue;
                default:
                    return static_cast<int>(n);
            }
        }
        if (ndatalen >= 0) {
            if (library) {
                if (m_app->OnLibraryWritten(*this, stream_id,
                                            static_cast<size_t>(ndatalen)) !=
                    0) {
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                }
            } else if (own) {
                AccountWritten(*own, static_cast<size_t>(ndatalen),
                               fin && static_cast<size_t>(ndatalen) ==
                                          own->unsent);
                m_rr_last = own->id;
            }
        }
        if (n == 0) {
            if (own && own->unsent > 0 && own->app_tag >= 1 &&
                own->app_tag <= QuicTransportInfo::NUM_CLASSES &&
                ngtcp2_conn_get_max_data_left2(m_conn) == 0 &&
                !m_connection_flow_blocked[own->app_tag - 1]) {
                m_connection_flow_blocked[own->app_tag - 1] = true;
                m_engine.OnStreamBlocked(own->app_tag);
            }
            // Congestion, pacing or nothing left.
            break;
        }
        return n;
    }
    return 0;
}

uint64_t QuicConnection::NextExpiry() const {
    if (m_state == State::CLOSING || m_state == State::DRAINING) {
        return m_close_deadline;
    }
    if (!IsOpen() || !m_conn) {
        return UINT64_MAX;
    }
    uint64_t t{ngtcp2_conn_get_expiry2(m_conn)};
    if (m_app) {
        t = std::min(t, m_app->NextTimer());
    }
    return t;
}

void QuicConnection::HandleExpiry(uint64_t now) {
    if (!IsOpen()) {
        return;
    }
    now = Clamp(now);
    if (ngtcp2_conn_get_expiry2(m_conn) <= now) {
        const int rv{ngtcp2_conn_handle_expiry(m_conn, now)};
        if (rv == NGTCP2_ERR_IDLE_CLOSE) {
            m_engine.OnIdleClose(*this);
            Kill();
            return;
        }
        if (rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
            LogDebug(BCLog::WEBTRANSPORT, "QUIC handshake with %s timed out\n",
                     m_remote_service.ToStringAddrPort());
            Kill();
            return;
        }
        if (rv != 0) {
            CloseLib(rv);
            return;
        }
    }
    if (m_app && m_app->NextTimer() <= now) {
        m_app->OnTimer(*this, now);
    }
}

void QuicConnection::StartClosing(const ngtcp2_ccerr &err) {
    if (!IsOpen()) {
        return;
    }
    if (m_app && !m_app_closed) {
        m_app_closed = true;
        m_app->OnClosed(*this);
    }
    const uint64_t now{Clamp(QuicNow())};
    m_state = State::CLOSING;
    m_close_deadline = now + 3 * ngtcp2_conn_get_pto2(m_conn);
    if (ngtcp2_conn_in_closing_period2(m_conn) ||
        ngtcp2_conn_in_draining_period2(m_conn)) {
        return;
    }
    m_close_pkt.resize(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};
    const ngtcp2_ssize n{ngtcp2_conn_write_connection_close(
        m_conn, &ps.path, &pi, m_close_pkt.data(), m_close_pkt.size(), &err,
        now)};
    if (n > 0) {
        m_close_pkt.resize(static_cast<size_t>(n));
        SendPacket(m_close_pkt.data(), m_close_pkt.size());
    } else {
        m_close_pkt.clear();
    }
}

void QuicConnection::CloseApp(uint64_t app_error, const std::string &reason) {
    ngtcp2_ccerr err;
    ngtcp2_ccerr_default(&err);
    ngtcp2_ccerr_set_application_error(
        &err, app_error, reinterpret_cast<const uint8_t *>(reason.data()),
        reason.size());
    StartClosing(err);
}

void QuicConnection::CloseLib(int liberr) {
    ngtcp2_ccerr err;
    ngtcp2_ccerr_default(&err);
    if (liberr == NGTCP2_ERR_CRYPTO) {
        ngtcp2_ccerr_set_tls_alert(&err, ngtcp2_conn_get_tls_alert2(m_conn),
                                   nullptr, 0);
    } else {
        ngtcp2_ccerr_set_liberr(&err, liberr, nullptr, 0);
    }
    StartClosing(err);
}

void QuicConnection::EnterDraining(uint64_t now) {
    if (m_app && !m_app_closed) {
        m_app_closed = true;
        m_app->OnClosed(*this);
    }
    m_state = State::DRAINING;
    m_close_deadline = now + 3 * ngtcp2_conn_get_pto2(m_conn);
}

void QuicConnection::Kill() {
    if (m_app && !m_app_closed) {
        m_app_closed = true;
        m_app->OnClosed(*this);
    }
    m_state = State::DEAD;
    m_close_deadline = 0;
}
