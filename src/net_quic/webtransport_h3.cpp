// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/webtransport_h3.h>

#include <net_quic/webtransport_wire.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <random.h>
#include <tinyformat.h>
#include <util/string.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>

namespace {
//! H3_NO_ERROR / H3_REQUEST_REJECTED / H3_INTERNAL_ERROR (RFC 9114 §8.1)
constexpr uint64_t H3_NO_ERROR{0x100};
constexpr uint64_t H3_INTERNAL_ERROR{0x102};
//! How long a closing session waits for the peer before closing QUIC
constexpr uint64_t SESSION_CLOSE_LINGER{1000 * NGTCP2_MILLISECONDS};
//! How long after the close capsule exchange before CONNECTION_CLOSE
constexpr uint64_t SESSION_CLOSE_SHORT{50 * NGTCP2_MILLISECONDS};

H3Session *Self(void *conn_user_data) {
    return static_cast<H3Session *>(conn_user_data);
}

std::string_view View(nghttp3_rcbuf *buf) {
    const nghttp3_vec v{nghttp3_rcbuf_get_buf(buf)};
    return {reinterpret_cast<const char *>(v.base), v.len};
}

nghttp3_nv Nv(const std::string &name, const std::string &value) {
    nghttp3_nv nv;
    nv.name = reinterpret_cast<uint8_t *>(const_cast<char *>(name.data()));
    nv.namelen = name.size();
    nv.value = reinterpret_cast<uint8_t *>(const_cast<char *>(value.data()));
    nv.valuelen = value.size();
    nv.flags = NGHTTP3_NV_FLAG_NONE;
    return nv;
}

int CbAckedStreamData(nghttp3_conn *, int64_t stream_id, uint64_t datalen,
                      void *ud, void *) {
    return Self(ud)->OnConnectBodyAcked(stream_id, datalen);
}
int CbRecvData(nghttp3_conn *, int64_t stream_id, const uint8_t *data,
               size_t datalen, void *ud, void *) {
    return Self(ud)->OnRecvData(stream_id, data, datalen);
}
int CbDeferredConsume(nghttp3_conn *, int64_t stream_id, size_t consumed,
                      void *ud, void *) {
    if (QuicConnection *c{Self(ud)->Conn()}) {
        c->ExtendCredit(stream_id, consumed);
    }
    return 0;
}
int CbBeginHeaders(nghttp3_conn *, int64_t stream_id, void *ud, void *) {
    return Self(ud)->OnBeginHeaders(stream_id);
}
int CbRecvHeader(nghttp3_conn *, int64_t stream_id, int32_t,
                 nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t, void *ud,
                 void *) {
    return Self(ud)->OnHeader(stream_id, View(name), View(value));
}
int CbEndHeaders(nghttp3_conn *, int64_t stream_id, int fin, void *ud,
                 void *) {
    return Self(ud)->OnEndHeaders(stream_id, fin);
}
int CbStopSending(nghttp3_conn *, int64_t stream_id, uint64_t app_error,
                  void *ud, void *) {
    if (QuicConnection *c{Self(ud)->Conn()}) {
        ngtcp2_conn_shutdown_stream_read(c->Conn(), 0, stream_id, app_error);
    }
    return 0;
}
int CbResetStream(nghttp3_conn *, int64_t stream_id, uint64_t app_error,
                  void *ud, void *) {
    if (QuicConnection *c{Self(ud)->Conn()}) {
        ngtcp2_conn_shutdown_stream_write(c->Conn(), 0, stream_id, app_error);
    }
    return 0;
}
int CbEndStream(nghttp3_conn *, int64_t stream_id, void *ud, void *) {
    return Self(ud)->OnEndStream(stream_id);
}
void CbRand(uint8_t *dest, size_t destlen) {
    GetStrongRandBytes(Span<unsigned char>{dest, destlen});
}
int CbRecvSettings(nghttp3_conn *, const nghttp3_proto_settings *settings,
                   void *ud) {
    Self(ud)->OnPeerSettings(*settings);
    return 0;
}
int CbRecvExtraSetting(nghttp3_conn *, uint64_t id, uint64_t value,
                       void *ud) {
    Self(ud)->OnExtraSetting(id, value);
    return 0;
}
nghttp3_ssize CbReadConnectBody(nghttp3_conn *, int64_t stream_id,
                                nghttp3_vec *vec, size_t veccnt,
                                uint32_t *pflags, void *ud, void *) {
    return Self(ud)->ReadConnectBody(stream_id, vec, veccnt, pflags);
}

bool TokenMatches(std::string_view path_query, const std::string &token) {
    if (token.empty()) {
        return true;
    }
    const size_t q{path_query.find('?')};
    std::string given;
    if (q != std::string_view::npos) {
        for (const auto &param :
             util::SplitString(path_query.substr(q + 1), '&')) {
            if (param.starts_with("t=")) {
                given = param.substr(2);
            }
        }
    }
    // Compare hashes in constant time: no early exit on a matching prefix.
    uint8_t a[CSHA256::OUTPUT_SIZE], b[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(reinterpret_cast<const uint8_t *>(given.data()), given.size())
        .Finalize(a);
    CSHA256()
        .Write(reinterpret_cast<const uint8_t *>(token.data()), token.size())
        .Finalize(b);
    return CRYPTO_memcmp(a, b, sizeof(a)) == 0;
}
} // namespace

H3Session::H3Session(const H3Options &options,
                     std::unique_ptr<WtSessionHandler> handler)
    : m_opts{options}, m_handler{std::move(handler)} {
    m_class_streams.fill(-1);
}

H3Session::~H3Session() {
    if (m_h3) {
        nghttp3_conn_del(m_h3);
    }
}

bool H3Session::InitH3(QuicConnection &conn) {
    if (m_h3) {
        return true;
    }
    m_conn = &conn;
    nghttp3_callbacks cb{};
    cb.acked_stream_data = CbAckedStreamData;
    cb.recv_data = CbRecvData;
    cb.deferred_consume = CbDeferredConsume;
    cb.begin_headers = CbBeginHeaders;
    cb.recv_header = CbRecvHeader;
    cb.end_headers = CbEndHeaders;
    cb.stop_sending = CbStopSending;
    cb.end_stream = CbEndStream;
    cb.reset_stream = CbResetStream;
    cb.rand = CbRand;
    cb.recv_settings2 = CbRecvSettings;
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;
    settings.enable_connect_protocol = m_opts.server ? 1 : 0;
    settings.h3_datagram = 1;
    const int rv{m_opts.server
                     ? nghttp3_conn_server_new(&m_h3, &cb, &settings,
                                               nghttp3_mem_default(), this)
                     : nghttp3_conn_client_new(&m_h3, &cb, &settings,
                                               nghttp3_mem_default(), this)};
    if (rv != 0) {
        m_h3 = nullptr;
        return false;
    }
    nghttp3_conn_set_recv_extra_setting_cb(m_h3, CbRecvExtraSetting);
    // Every WebTransport support codepoint at once: browsers speak draft-02
    // (Chrome, Firefox) or draft-13/14 (Safari); newer peers draft-15/16.
    std::vector<nghttp3_extra_setting> extra;
    if (m_opts.server) {
        extra = {
            {wt::SETTINGS_H3_DATAGRAM_DRAFT04, 1},
            {wt::SETTINGS_ENABLE_WEBTRANSPORT_D02, 1},
            {wt::SETTINGS_WT_MAX_SESSIONS_D07, 1},
            {wt::SETTINGS_WT_MAX_SESSIONS_D13, 1},
            {wt::SETTINGS_WT_ENABLED, 1},
            {wt::SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, 8},
            {wt::SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, 8},
            {wt::SETTINGS_WT_INITIAL_MAX_DATA, 64 * 1024 * 1024},
        };
    } else {
        extra = {
            {wt::SETTINGS_ENABLE_WEBTRANSPORT_D02, 1},
            {wt::SETTINGS_WT_ENABLED, 1},
        };
    }
    if (nghttp3_conn_set_extra_settings(m_h3, extra.data(), extra.size()) !=
        0) {
        return false;
    }
    if (m_opts.server) {
        const ngtcp2_transport_params *params{
            ngtcp2_conn_get_local_transport_params2(conn.Conn())};
        nghttp3_conn_set_max_client_streams_bidi(
            m_h3, params->initial_max_streams_bidi);
    }
    const int64_t ctrl{conn.OpenStream(false, QuicStream::Kind::LIBRARY)};
    const int64_t qenc{conn.OpenStream(false, QuicStream::Kind::LIBRARY)};
    const int64_t qdec{conn.OpenStream(false, QuicStream::Kind::LIBRARY)};
    if (ctrl < 0 || qenc < 0 || qdec < 0 ||
        nghttp3_conn_bind_control_stream(m_h3, ctrl) != 0 ||
        nghttp3_conn_bind_qpack_streams(m_h3, qenc, qdec) != 0) {
        return false;
    }
    if (!m_opts.server) {
        m_settings_deadline = QuicNow() + m_opts.settings_timeout_ns;
    }
    return true;
}

int H3Session::OnHandshakeCompleted(QuicConnection &conn) {
    m_conn = &conn;
    if (m_handler && !m_handler->OnHandshake(*this, conn)) {
        SessionEnded(0, "peer refused at handshake");
        conn.CloseApp(H3_NO_ERROR, "refused");
        return 0;
    }
    return InitH3(conn) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

int H3Session::FeedH3(QuicConnection &conn, int64_t stream_id,
                      const uint8_t *data, size_t len, bool fin) {
    const nghttp3_ssize nread{nghttp3_conn_read_stream2(
        m_h3, stream_id, data, len, fin, ngtcp2_conn_get_timestamp(conn.Conn()))};
    if (nread < 0) {
        LogDebug(BCLog::WEBTRANSPORT, "HTTP/3 from %s: %s\n",
                 conn.Remote().ToStringAddrPort(),
                 nghttp3_strerror(static_cast<int>(nread)));
        conn.CloseApp(
            nghttp3_err_infer_quic_app_error_code(static_cast<int>(nread)));
        return 0;
    }
    conn.ExtendCredit(stream_id, static_cast<uint64_t>(nread));
    return 0;
}

void H3Session::RejectStream(int64_t stream_id) {
    m_conn->ShutdownStream(stream_id,
                           wt::WebTransportCodeToHttp(wt::WT_P2P_BAD_STREAM));
}

int H3Session::OnStreamData(QuicConnection &conn, QuicStream &stream,
                            uint32_t flags, const uint8_t *data, size_t len) {
    const bool fin{(flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0};
    // Peer stream data can come in the datagram that completes the
    // handshake: set up HTTP/3 on demand.
    if (!m_h3 && (!ngtcp2_conn_get_handshake_completed2(conn.Conn()) ||
                  !InitH3(conn))) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    switch (stream.kind) {
        case QuicStream::Kind::LIBRARY:
            return FeedH3(conn, stream.id, data, len, fin);
        case QuicStream::Kind::OWN:
            HandleClassBytes(conn, stream, data, len, fin);
            return 0;
        case QuicStream::Kind::IGNORED:
            conn.ExtendCredit(stream.id, len);
            return 0;
        case QuicStream::Kind::PENDING:
            break;
    }
    // WebTransport streams must be told apart before nghttp3 sees a byte:
    // nghttp3 would parse a bidirectional WebTransport stream as an HTTP/3
    // frame of type 0x41 (draft §4.3).
    stream.pending.insert(stream.pending.end(), data, data + len);
    const bool uni{(stream.id & 0x2) != 0};
    const auto prefix{wt::ParseStreamPrefix(stream.pending, uni)};
    if (prefix.status == wt::StreamPrefix::Status::INCOMPLETE) {
        if (stream.pending.size() > 16) {
            // Two varints are at most 16 bytes.
            RejectStream(stream.id);
            return 0;
        }
        if (fin) {
            conn.ExtendCredit(stream.id, stream.pending.size());
            stream.kind = QuicStream::Kind::IGNORED;
        }
        return 0;
    }
    if (prefix.status == wt::StreamPrefix::Status::HTTP3) {
        stream.kind = QuicStream::Kind::LIBRARY;
        std::vector<uint8_t> all{std::move(stream.pending)};
        stream.pending.clear();
        return FeedH3(conn, stream.id, all.data(), all.size(), fin);
    }
    return HandleWtStream(conn, stream, fin);
}

int H3Session::HandleWtStream(QuicConnection &conn, QuicStream &stream,
                              bool fin) {
    const bool uni{(stream.id & 0x2) != 0};
    const auto prefix{wt::ParseStreamPrefix(stream.pending, uni)};
    const bool peer_initiated{conn.IsServer() == ((stream.id & 0x1) == 0)};
    if (!m_accepted || m_session_closed ||
        static_cast<int64_t>(prefix.session_id) != m_session_id ||
        !peer_initiated) {
        conn.ShutdownStream(stream.id, wt::WT_BUFFERED_STREAM_REJECTED);
        return 0;
    }
    if (m_opts.echo) {
        conn.ExtendCredit(stream.id, prefix.header_len);
        std::vector<uint8_t> rest(stream.pending.begin() + prefix.header_len,
                                  stream.pending.end());
        stream.pending.clear();
        stream.app_tag = 0;
        stream.kind = QuicStream::Kind::OWN;
        if (uni && m_echo_uni < 0) {
            m_echo_uni = conn.OpenStream(false, QuicStream::Kind::OWN);
            if (m_echo_uni >= 0) {
                conn.QueueStreamData(conn.Stream(m_echo_uni),
                                     wt::UniStreamHeader(m_session_id));
            }
        }
        HandleClassBytes(conn, stream, rest.data(), rest.size(), fin);
        return 0;
    }
    if (uni) {
        // P2P uses only the five class streams.
        conn.ExtendCredit(stream.id, stream.pending.size());
        stream.pending.clear();
        RejectStream(stream.id);
        return 0;
    }
    if (stream.pending.size() < prefix.header_len + 1) {
        return 0;
    }
    const uint8_t tag{stream.pending[prefix.header_len]};
    if (!IsValidStreamClass(tag) ||
        m_class_streams[tag - 1] >= 0) {
        LogDebug(BCLog::WEBTRANSPORT,
                 "WebTransport peer %s: bad or duplicate class stream %u\n",
                 conn.Remote().ToStringAddrPort(), tag);
        RejectStream(stream.id);
        CloseSession(wt::WT_P2P_BAD_STREAM, "bad class stream");
        return 0;
    }
    const StreamClass cls{static_cast<StreamClass>(tag)};
    m_class_streams[tag - 1] = stream.id;
    stream.kind = QuicStream::Kind::OWN;
    stream.priority = StreamClassPriority(cls);
    stream.app_tag = tag;
    conn.ExtendCredit(stream.id, prefix.header_len + 1);
    std::vector<uint8_t> rest(stream.pending.begin() + prefix.header_len + 1,
                              stream.pending.end());
    stream.pending.clear();
    if (!m_ready && std::all_of(m_class_streams.begin(),
                                m_class_streams.end(),
                                [](int64_t id) { return id >= 0; })) {
        m_ready = true;
        if (m_handler) {
            m_handler->OnSessionReady(*this);
        }
    }
    if (!rest.empty() || fin) {
        HandleClassBytes(conn, stream, rest.data(), rest.size(), fin);
    }
    return 0;
}

void H3Session::HandleClassBytes(QuicConnection &conn, QuicStream &stream,
                                 const uint8_t *data, size_t len, bool fin) {
    if (m_opts.echo) {
        // Bidirectional streams echo on themselves; unidirectional ones on
        // our one unidirectional stream (without its FIN).
        conn.ExtendCredit(stream.id, len);
        if (stream.id & 0x2) {
            if (QuicStream *out{m_echo_uni >= 0 ? conn.FindStream(m_echo_uni)
                                                : nullptr};
                out && len > 0) {
                conn.QueueStreamData(*out,
                                     std::vector<uint8_t>(data, data + len));
            }
        } else if (len > 0 || fin) {
            conn.QueueStreamData(stream, std::vector<uint8_t>(data, data + len),
                                 fin);
        }
        return;
    }
    if (fin) {
        // Class streams last as long as the session.
        LogDebug(BCLog::WEBTRANSPORT,
                 "WebTransport peer %s ended class stream %u\n",
                 conn.Remote().ToStringAddrPort(), stream.app_tag);
        CloseSession(wt::WT_P2P_BAD_STREAM, "class stream ended");
        return;
    }
    if (m_handler && len > 0) {
        m_handler->OnClassData(*this, static_cast<StreamClass>(stream.app_tag),
                               data, len, fin);
    }
}

void H3Session::QueueClassData(StreamClass cls, std::vector<uint8_t> &&data) {
    const int64_t id{m_class_streams[StreamClassIndex(cls)]};
    if (!m_conn || id < 0 || m_session_closed) {
        return;
    }
    if (QuicStream *s{m_conn->FindStream(id)}) {
        m_conn->QueueStreamData(*s, std::move(data));
    }
}

uint64_t H3Session::ClassUnsent(StreamClass cls) const {
    const int64_t id{m_class_streams[StreamClassIndex(cls)]};
    if (!m_conn || id < 0) {
        return 0;
    }
    const QuicStream *s{m_conn->FindStream(id)};
    return s ? s->unsent : 0;
}

void H3Session::ExtendCredit(StreamClass cls, uint64_t n) {
    const int64_t id{m_class_streams[StreamClassIndex(cls)]};
    if (m_conn && id >= 0) {
        m_conn->ExtendCredit(id, n);
    }
}

void H3Session::OpenClassStreams() {
    for (const StreamClass cls : ALL_STREAM_CLASSES) {
        const int64_t id{m_conn->OpenStream(true, QuicStream::Kind::OWN,
                                            StreamClassPriority(cls))};
        if (id < 0) {
            CloseSession(wt::WT_P2P_BAD_STREAM, "no stream credit");
            return;
        }
        QuicStream &s{m_conn->Stream(id)};
        s.app_tag = static_cast<uint8_t>(cls);
        auto header{wt::BidiStreamHeader(static_cast<uint64_t>(m_session_id))};
        header.push_back(static_cast<uint8_t>(cls));
        m_conn->QueueStreamData(s, std::move(header));
        m_class_streams[StreamClassIndex(cls)] = id;
    }
    m_ready = true;
    if (m_handler) {
        m_handler->OnSessionReady(*this);
    }
}

void H3Session::OnStreamClose(QuicConnection &conn, int64_t stream_id,
                              bool app_error_set, uint64_t app_error) {
    QuicStream *s{conn.FindStream(stream_id)};
    if (m_h3 && s && s->kind == QuicStream::Kind::LIBRARY) {
        const uint32_t flags{
            app_error_set ? uint32_t{NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET |
                                     NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET}
                          : uint32_t{NGHTTP3_STREAM_CLOSE_FLAG_NONE}};
        const int rv{nghttp3_conn_close_stream2(m_h3, flags, stream_id,
                                                app_error, app_error)};
        if (rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
            conn.CloseApp(H3_INTERNAL_ERROR);
        }
    }
    if (stream_id == m_session_id && !m_session_closed) {
        SessionEnded(0, "CONNECT stream closed");
    }
    for (int64_t &id : m_class_streams) {
        if (id == stream_id && m_ready && !m_session_closed &&
            !m_opts.echo) {
            SessionEnded(wt::WT_P2P_BAD_STREAM, "class stream closed");
        }
    }
    m_requests.erase(stream_id);
}

void H3Session::OnStreamReset(QuicConnection &conn, int64_t stream_id,
                              uint64_t) {
    QuicStream *s{conn.FindStream(stream_id)};
    if (m_h3 && s && s->kind == QuicStream::Kind::LIBRARY) {
        nghttp3_conn_shutdown_stream_read(m_h3, stream_id);
    }
}

void H3Session::OnStreamStopSending(QuicConnection &conn, int64_t stream_id,
                                    uint64_t) {
    QuicStream *s{conn.FindStream(stream_id)};
    if (m_h3 && s && s->kind == QuicStream::Kind::LIBRARY) {
        nghttp3_conn_shutdown_stream_read(m_h3, stream_id);
    }
}

int H3Session::OnLibraryAcked(QuicConnection &, int64_t stream_id,
                              uint64_t datalen) {
    if (!m_h3) {
        return 0;
    }
    const int rv{nghttp3_conn_add_ack_offset(m_h3, stream_id, datalen)};
    return rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND
               ? NGTCP2_ERR_CALLBACK_FAILURE
               : 0;
}

void H3Session::OnLibraryUnblocked(QuicConnection &, int64_t stream_id) {
    if (m_h3) {
        nghttp3_conn_unblock_stream(m_h3, stream_id);
    }
}

void H3Session::OnMaxRemoteStreamsBidi(QuicConnection &, uint64_t max) {
    if (m_h3) {
        nghttp3_conn_set_max_client_streams_bidi(m_h3, max);
    }
}

void H3Session::OnDatagram(QuicConnection &conn, const uint8_t *data,
                           size_t len) {
    uint64_t quarter{0};
    const size_t n{wt::GetVarint(Span<const uint8_t>{data, len}, quarter)};
    if (n == 0 || m_session_id < 0 ||
        quarter * 4 != static_cast<uint64_t>(m_session_id)) {
        ++m_datagrams_dropped;
        return;
    }
    if (m_opts.echo) {
        std::vector<uint8_t> echo(data, data + len);
        conn.QueueDatagram(std::move(echo));
        return;
    }
    // P2P does not use datagrams (browsers may send them).
    ++m_datagrams_dropped;
}

ngtcp2_ssize H3Session::WritevLibrary(QuicConnection &, int64_t &stream_id,
                                      int &fin, ngtcp2_vec *vec,
                                      size_t veccnt) {
    stream_id = -1;
    fin = 0;
    if (!m_h3) {
        return 0;
    }
    static_assert(sizeof(nghttp3_vec) == sizeof(ngtcp2_vec));
    const nghttp3_ssize n{nghttp3_conn_writev_stream(
        m_h3, &stream_id, &fin, reinterpret_cast<nghttp3_vec *>(vec), veccnt)};
    if (n < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return n;
}

int H3Session::OnLibraryWritten(QuicConnection &, int64_t stream_id,
                                size_t datalen) {
    return m_h3 && nghttp3_conn_add_write_offset(m_h3, stream_id, datalen) != 0
               ? NGTCP2_ERR_CALLBACK_FAILURE
               : 0;
}

void H3Session::OnLibraryBlocked(QuicConnection &, int64_t stream_id) {
    if (m_h3) {
        nghttp3_conn_block_stream(m_h3, stream_id);
    }
}

void H3Session::OnLibraryShutWr(QuicConnection &, int64_t stream_id) {
    if (m_h3) {
        nghttp3_conn_shutdown_stream_write(m_h3, stream_id);
    }
}

void H3Session::BeforeWrite(QuicConnection &conn) {
    m_conn = &conn;
    if (m_handler && m_ready && !m_session_closed) {
        m_handler->BeforeWrite(*this);
    }
}

uint64_t H3Session::NextTimer() const {
    uint64_t t{m_close_deadline};
    if (!m_connect_sent && !m_opts.server) {
        t = std::min(t, m_settings_deadline);
    }
    return t;
}

void H3Session::OnTimer(QuicConnection &conn, uint64_t now) {
    if (now >= m_close_deadline) {
        m_close_deadline = UINT64_MAX;
        conn.CloseApp(H3_NO_ERROR);
        return;
    }
    if (!m_opts.server && !m_connect_sent && now >= m_settings_deadline) {
        m_settings_deadline = UINT64_MAX;
        LogDebug(BCLog::WEBTRANSPORT,
                 "%s sent no WebTransport SETTINGS in time\n",
                 conn.Remote().ToStringAddrPort());
        if (m_handler) {
            m_handler->OnConnectResponse(*this, 0);
        }
        SessionEnded(0, "no WebTransport SETTINGS");
        conn.CloseApp(H3_NO_ERROR);
    }
}

void H3Session::OnClosed(QuicConnection &) {
    if (!m_session_closed) {
        SessionEnded(0, "connection closed");
    }
}

void H3Session::OnPeerSettings(const nghttp3_proto_settings &settings) {
    m_peer_settings = true;
    m_peer_connect_protocol = settings.enable_connect_protocol;
    if (!m_opts.server && !m_connect_sent) {
        if (m_peer_draft_rank == 0 || !m_peer_connect_protocol) {
            LogDebug(BCLog::WEBTRANSPORT,
                     "%s speaks HTTP/3 without WebTransport\n",
                     m_conn ? m_conn->Remote().ToStringAddrPort() : "?");
            m_connect_sent = true;
            if (m_handler) {
                m_handler->OnConnectResponse(*this, 0);
            }
            SessionEnded(0, "no WebTransport");
            if (m_conn) {
                m_conn->CloseApp(H3_NO_ERROR);
            }
            return;
        }
        SubmitConnect();
    }
}

void H3Session::OnExtraSetting(uint64_t id, uint64_t value) {
    const int rank{wt::DraftRank(id)};
    if (rank > m_peer_draft_rank && value > 0) {
        m_peer_draft_rank = rank;
        m_peer_draft_setting = id;
    }
}

void H3Session::SubmitConnect() {
    if (!m_conn || !m_h3) {
        return;
    }
    const int64_t id{m_conn->OpenStream(true, QuicStream::Kind::LIBRARY)};
    if (id < 0) {
        return;
    }
    if (m_session_id < 0) {
        m_session_id = id;
    }
    m_connect_sent = true;
    std::string path{m_opts.path};
    if (!m_opts.token.empty()) {
        path += (path.find('?') == std::string::npos ? "?t=" : "&t=") +
                m_opts.token;
    }
    std::vector<std::pair<std::string, std::string>> headers{
        {":method", "CONNECT"},
        {":protocol", m_opts.protocol_token},
        {":scheme", "https"},
        {":authority", m_opts.authority},
        {":path", path},
    };
    if (!m_opts.origin.empty()) {
        headers.emplace_back("origin", m_opts.origin);
    }
    if (!m_opts.offer.empty()) {
        std::vector<std::string> items;
        for (const auto &p : m_opts.offer) {
            items.push_back(wt::SerializeProtocol(p));
        }
        headers.emplace_back("wt-available-protocols", util::Join(items, ", "));
    }
    std::vector<nghttp3_nv> nva;
    for (const auto &[name, value] : headers) {
        nva.push_back(Nv(name, value));
    }
    static const nghttp3_data_reader reader{CbReadConnectBody};
    if (nghttp3_conn_submit_request(m_h3, id, nva.data(), nva.size(), &reader,
                                    nullptr) != 0) {
        m_conn->CloseApp(H3_INTERNAL_ERROR);
    }
}

void H3Session::SubmitExtraConnectForTest() {
    const int64_t first{m_session_id};
    SubmitConnect();
    m_session_id = first;
}

int H3Session::OnBeginHeaders(int64_t stream_id) {
    m_requests[stream_id] = WtRequest{};
    return 0;
}

int H3Session::OnHeader(int64_t stream_id, std::string_view name,
                        std::string_view value) {
    WtRequest &r{m_requests[stream_id]};
    const std::string v{value};
    if (name == ":method") {
        r.method = v;
    } else if (name == ":protocol") {
        r.protocol = v;
    } else if (name == ":scheme") {
        r.scheme = v;
    } else if (name == ":authority") {
        r.authority = v;
    } else if (name == ":path") {
        r.path = v;
    } else if (name == "origin") {
        r.origin = v;
    } else if (name == "wt-available-protocols") {
        r.available_protocols = v;
    } else if (name == "sec-webtransport-http3-draft02") {
        r.draft02_header = true;
    } else if (name == ":status") {
        r.status = v;
    } else if (name == "wt-protocol") {
        r.wt_protocol = v;
    }
    return 0;
}

int H3Session::OnEndHeaders(int64_t stream_id, int fin) {
    if (m_opts.server) {
        ServerHandleRequest(stream_id, fin);
    } else {
        ClientHandleResponse(stream_id);
    }
    return 0;
}

void H3Session::Respond(
    int64_t stream_id, int status,
    const std::vector<std::pair<std::string, std::string>> &extra) {
    const std::string code{strprintf("%d", status)};
    std::vector<std::pair<std::string, std::string>> headers{
        {":status", code}};
    headers.insert(headers.end(), extra.begin(), extra.end());
    std::vector<nghttp3_nv> nva;
    for (const auto &[name, value] : headers) {
        nva.push_back(Nv(name, value));
    }
    static const nghttp3_data_reader reader{CbReadConnectBody};
    // A 200 keeps the CONNECT stream open (it carries capsules); any other
    // status ends the request.
    nghttp3_conn_submit_response(m_h3, stream_id, nva.data(), nva.size(),
                                 status == 200 ? &reader : nullptr);
}

void H3Session::ServerHandleRequest(int64_t stream_id, bool fin) {
    const WtRequest r{m_requests[stream_id]};
    const auto reject{[&](int status, const char *why) {
        LogDebug(BCLog::WEBTRANSPORT,
                 "WebTransport request from %s refused (%d %s): %s %s\n",
                 m_conn->Remote().ToStringAddrPort(), status, why, r.method,
                 r.path.substr(0, r.path.find('?')));
        Respond(stream_id, status);
    }};
    if (r.method != "CONNECT" ||
        (r.protocol != "webtransport" && r.protocol != "webtransport-h3") ||
        fin) {
        reject(404, "not a WebTransport CONNECT");
        return;
    }
    const std::string_view path{r.path};
    if (path.substr(0, path.find('?')) != m_opts.path) {
        reject(404, "path");
        return;
    }
    if (!TokenMatches(path, m_opts.token)) {
        reject(403, "token");
        return;
    }
    if (!m_opts.origins.empty() && !r.origin.empty() &&
        std::find(m_opts.origins.begin(), m_opts.origins.end(), r.origin) ==
            m_opts.origins.end()) {
        reject(403, "origin");
        return;
    }
    if (m_accepted) {
        reject(429, "one session per connection");
        return;
    }
    std::string chosen;
    if (!r.available_protocols.empty()) {
        const auto offered{wt::ParseProtocolList(r.available_protocols)};
        if (!offered) {
            reject(400, "malformed wt-available-protocols");
            return;
        }
        for (const auto &p : m_opts.supported) {
            if (std::find(offered->begin(), offered->end(), p) !=
                offered->end()) {
                chosen = p;
                break;
            }
        }
        if (chosen.empty()) {
            reject(400, "no common protocol");
            return;
        }
    }
    m_request = r;
    const int status{m_opts.echo || !m_handler ? (m_opts.echo ? 200 : 503)
                                               : m_handler->OnConnect(*this, r)};
    if (status != 200) {
        reject(status, "not accepting sessions");
        return;
    }
    m_session_id = stream_id;
    m_accepted = true;
    m_protocol = chosen;
    std::vector<std::pair<std::string, std::string>> extra;
    if (!chosen.empty() && !r.available_protocols.empty()) {
        extra.emplace_back("wt-protocol", wt::SerializeProtocol(chosen));
    }
    if (r.draft02_header) {
        extra.emplace_back("sec-webtransport-http3-draft", "draft02");
    }
    Respond(stream_id, 200, extra);
    LogDebug(BCLog::WEBTRANSPORT,
             "WebTransport session from %s (:protocol %s, draft setting "
             "0x%x, wt-protocol %s%s)\n",
             m_conn->Remote().ToStringAddrPort(), r.protocol,
             m_peer_draft_setting, chosen.empty() ? "-" : chosen,
             r.origin.empty() ? "" : ", origin " + r.origin);
}

void H3Session::ClientHandleResponse(int64_t stream_id) {
    const WtRequest r{m_requests[stream_id]};
    int status{0};
    try {
        status = r.status.empty() ? 0 : std::stoi(r.status);
    } catch (...) {
        status = 0;
    }
    if (stream_id != m_session_id) {
        // A test's extra CONNECT.
        if (m_handler) {
            m_handler->OnConnectResponse(*this, status);
        }
        return;
    }
    if (status != 200) {
        LogDebug(BCLog::WEBTRANSPORT,
                 "WebTransport CONNECT to %s refused with %s\n",
                 m_conn->Remote().ToStringAddrPort(), r.status);
        if (m_handler) {
            m_handler->OnConnectResponse(*this, status);
        }
        SessionEnded(0, "refused");
        m_conn->CloseApp(H3_NO_ERROR);
        return;
    }
    // The standard protocol header selects this endpoint's current
    // framing. Never infer an old/private version from an absent header.
    if (!r.wt_protocol.empty()) {
        const auto list{wt::ParseProtocolList(r.wt_protocol)};
        if (!list || list->size() != 1 ||
            std::find(m_opts.offer.begin(), m_opts.offer.end(), list->front()) ==
                m_opts.offer.end()) {
            SessionEnded(0, "invalid wt-protocol selection");
            m_conn->CloseApp(H3_NO_ERROR);
            return;
        }
        m_protocol = list->front();
    } else if (!m_opts.offer.empty()) {
        SessionEnded(0, "missing wt-protocol selection");
        m_conn->CloseApp(H3_NO_ERROR);
        return;
    }
    m_accepted = true;
    if (m_handler) {
        m_handler->OnConnectResponse(*this, status);
    }
    if (!m_session_closed) {
        OpenClassStreams();
    }
}

int H3Session::OnRecvData(int64_t stream_id, const uint8_t *data,
                          size_t len) {
    if (m_conn) {
        m_conn->ExtendCredit(stream_id, len);
    }
    if (stream_id != m_session_id || !m_accepted) {
        return 0;
    }
    m_capsule_rx.insert(m_capsule_rx.end(), data, data + len);
    ParseCapsules();
    return 0;
}

void H3Session::ParseCapsules() {
    size_t pos{0};
    while (pos < m_capsule_rx.size() && !m_session_closed) {
        const auto parsed{
            wt::ParseCapsule(Span<const uint8_t>{m_capsule_rx}.subspan(pos))};
        if (parsed.status == wt::CapsuleParse::Status::INCOMPLETE) {
            break;
        }
        if (parsed.status == wt::CapsuleParse::Status::ERROR) {
            SessionEnded(wt::WT_P2P_BAD_STREAM, parsed.error);
            CloseSession(wt::WT_P2P_BAD_STREAM, parsed.error);
            break;
        }
        pos += parsed.consumed;
        if (parsed.capsule.type == wt::CAPSULE_CLOSE_SESSION) {
            const auto close{wt::DecodeCloseSession(parsed.capsule.value)};
            const uint32_t code{close ? close->code : wt::WT_P2P_BAD_STREAM};
            const std::string reason{close ? close->reason
                                           : "bad WT_CLOSE_SESSION"};
            SessionEnded(code, reason);
            // Answer with our FIN and close QUIC shortly after.
            QueueConnectBody({}, /*fin=*/true);
            m_close_deadline = std::min(m_close_deadline,
                                        QuicNow() + SESSION_CLOSE_SHORT);
        } else if (parsed.capsule.type == wt::CAPSULE_DRAIN_SESSION) {
            LogDebug(BCLog::WEBTRANSPORT, "WebTransport peer %s draining\n",
                     m_conn ? m_conn->Remote().ToStringAddrPort() : "?");
        }
        // Other capsules (flow control of drafts we do not use) are ignored.
    }
    m_capsule_rx.erase(m_capsule_rx.begin(),
                       m_capsule_rx.begin() +
                           static_cast<std::ptrdiff_t>(
                               std::min(pos, m_capsule_rx.size())));
}

int H3Session::OnEndStream(int64_t stream_id) {
    if (stream_id == m_session_id && !m_session_closed) {
        SessionEnded(0, "CONNECT stream ended");
        QueueConnectBody({}, /*fin=*/true);
        m_close_deadline =
            std::min(m_close_deadline, QuicNow() + SESSION_CLOSE_SHORT);
    }
    return 0;
}

void H3Session::QueueConnectBody(std::vector<uint8_t> &&data, bool fin) {
    if (!m_h3 || m_session_id < 0 || m_connect_fin) {
        return;
    }
    if (!data.empty()) {
        m_connect_tx.push_back(BodyChunk{std::move(data)});
    }
    if (fin) {
        m_connect_fin = true;
    }
    nghttp3_conn_resume_stream(m_h3, m_session_id);
}

nghttp3_ssize H3Session::ReadConnectBody(int64_t stream_id, nghttp3_vec *vec,
                                         size_t veccnt, uint32_t *flags) {
    if (stream_id != m_session_id) {
        // A test's extra CONNECT: keep it open like a real one.
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    size_t n{0};
    for (BodyChunk &chunk : m_connect_tx) {
        if (n == veccnt) {
            break;
        }
        if (chunk.given) {
            continue;
        }
        chunk.given = true;
        vec[n].base = chunk.data.data();
        vec[n].len = chunk.data.size();
        ++n;
    }
    const bool all_given{std::all_of(m_connect_tx.begin(), m_connect_tx.end(),
                                     [](const BodyChunk &c) {
                                         return c.given;
                                     })};
    if (m_connect_fin && all_given) {
        *flags |= NGHTTP3_DATA_FLAG_EOF;
        m_connect_fin_given = true;
        return static_cast<nghttp3_ssize>(n);
    }
    if (n == 0) {
        return NGHTTP3_ERR_WOULDBLOCK;
    }
    return static_cast<nghttp3_ssize>(n);
}

int H3Session::OnConnectBodyAcked(int64_t stream_id, uint64_t datalen) {
    if (stream_id != m_session_id) {
        return 0;
    }
    while (datalen > 0 && !m_connect_tx.empty() &&
           m_connect_tx.front().given) {
        BodyChunk &front{m_connect_tx.front()};
        if (datalen < front.data.size()) {
            front.data.erase(front.data.begin(),
                             front.data.begin() +
                                 static_cast<std::ptrdiff_t>(datalen));
            break;
        }
        datalen -= front.data.size();
        m_connect_tx.pop_front();
    }
    return 0;
}

void H3Session::SessionEnded(uint32_t code, const std::string &reason) {
    if (m_session_closed) {
        return;
    }
    m_session_closed = true;
    if (m_handler) {
        m_handler->OnSessionClosed(*this, code, reason);
    }
}

void H3Session::CloseSession(uint32_t code, const std::string &reason) {
    if (!m_conn) {
        return;
    }
    const bool was_open{!m_session_closed};
    SessionEnded(code, reason);
    if (was_open && m_accepted && m_session_id >= 0 && !m_connect_fin) {
        LogDebug(BCLog::WEBTRANSPORT,
                 "Closing WebTransport session with %s: WT_CLOSE_SESSION "
                 "code %u (%s)\n",
                 m_conn->Remote().ToStringAddrPort(), code, reason);
        QueueConnectBody(wt::EncodeCloseSession(code, reason), /*fin=*/true);
        m_close_deadline =
            std::min(m_close_deadline, QuicNow() + SESSION_CLOSE_LINGER);
    } else if (m_close_deadline == UINT64_MAX) {
        m_close_deadline = QuicNow();
    }
}
