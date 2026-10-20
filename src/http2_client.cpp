// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <http2_client.h>

#include <logging.h>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>

namespace {
bool WouldBlock(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}
//! Most decoded bytes a write may buffer while it reads for a window update
constexpr size_t MAX_PLAIN_WHILE_WRITING = 1024 * 1024;
} // namespace

struct Http2ClientLayer::Callbacks {
    static Http2ClientLayer &Self(void *u) {
        return *static_cast<Http2ClientLayer *>(u);
    }

    static int Header(nghttp2_session *, const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen, const uint8_t *value,
                      size_t valuelen, uint8_t, void *u) {
        Http2ClientLayer &self{Self(u)};
        if (frame->hd.stream_id != self.m_stream_id ||
            frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
            return 0;
        }
        const std::string n(reinterpret_cast<const char *>(name), namelen);
        const std::string v(reinterpret_cast<const char *>(value), valuelen);
        if (n == ":status") {
            self.m_status = std::atoi(v.c_str());
        } else {
            self.m_response_headers[n] = v;
        }
        return 0;
    }

    static int FrameRecv(nghttp2_session *, const nghttp2_frame *frame,
                         void *u) {
        Http2ClientLayer &self{Self(u)};
        if (frame->hd.type == NGHTTP2_SETTINGS &&
            !(frame->hd.flags & NGHTTP2_FLAG_ACK)) {
            self.m_settings_received = true;
        }
        if (frame->hd.stream_id == self.m_stream_id &&
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
            (frame->hd.type == NGHTTP2_DATA ||
             frame->hd.type == NGHTTP2_HEADERS)) {
            // The server ended its side: EOF once the data is read.
            self.m_remote_ended = true;
        }
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            // Our stream is closed by on_stream_close if it was refused.
            LogDebug(BCLog::NET, "HTTP/2 GOAWAY from WebSocket peer (%u)\n",
                     frame->goaway.error_code);
        }
        return 0;
    }

    static int Data(nghttp2_session *, uint8_t, int32_t stream_id,
                    const uint8_t *data, size_t len, void *u) {
        Http2ClientLayer &self{Self(u)};
        if (stream_id == self.m_stream_id) {
            self.m_plain.append(reinterpret_cast<const char *>(data), len);
        }
        return 0;
    }

    static int StreamClose(nghttp2_session *, int32_t stream_id,
                           uint32_t error_code, void *u) {
        Http2ClientLayer &self{Self(u)};
        if (stream_id == self.m_stream_id) {
            self.m_stream_closed = true;
            self.m_stream_error = error_code;
        }
        return 0;
    }

    static nghttp2_ssize ReadTx(nghttp2_session *, int32_t, uint8_t *buf,
                                size_t length, uint32_t *,
                                nghttp2_data_source *, void *u) {
        Http2ClientLayer &self{Self(u)};
        const size_t n{std::min(length, self.TxUnframed())};
        if (n == 0) {
            self.m_tx_deferred = true;
            return NGHTTP2_ERR_DEFERRED;
        }
        std::memcpy(buf, self.m_tx.data() + self.m_tx_offset, n);
        self.m_tx_offset += n;
        if (self.m_tx_offset == self.m_tx.size()) {
            self.m_tx.clear();
            self.m_tx_offset = 0;
        } else if (self.m_tx_offset > TX_LIMIT) {
            self.m_tx.erase(0, self.m_tx_offset);
            self.m_tx_offset = 0;
        }
        return nghttp2_ssize(n);
    }

    static nghttp2_ssize ReadLength(nghttp2_session *, uint8_t, int32_t,
                                    int32_t session_window,
                                    int32_t stream_window,
                                    uint32_t remote_max_frame_size, void *) {
        int64_t n{std::min<int64_t>(session_window, stream_window)};
        n = std::min<int64_t>(n, remote_max_frame_size);
        return nghttp2_ssize(std::max<int64_t>(n, 1));
    }
};

Http2ClientLayer::Http2ClientLayer(std::unique_ptr<WebSocketByteLayer> inner)
    : m_inner{std::move(inner)} {
    nghttp2_session_callbacks *cbs{nullptr};
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_header_callback(cbs, Callbacks::Header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
                                                         Callbacks::FrameRecv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
                                                              Callbacks::Data);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs, Callbacks::StreamClose);
    nghttp2_session_callbacks_set_data_source_read_length_callback2(
        cbs, Callbacks::ReadLength);
    nghttp2_option *opt{nullptr};
    nghttp2_option_new(&opt);
    // Servers do not push to us.
    nghttp2_option_set_max_reserved_remote_streams(opt, 0);
    const int rv{
        nghttp2_session_client_new3(&m_session, cbs, this, opt, nullptr)};
    nghttp2_option_del(opt);
    nghttp2_session_callbacks_del(cbs);
    assert(rv == 0);
    (void)rv;
    const nghttp2_settings_entry settings[]{
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, uint32_t(STREAM_WINDOW)},
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1},
    };
    nghttp2_submit_settings(m_session, NGHTTP2_FLAG_NONE, settings,
                            std::size(settings));
    nghttp2_session_set_local_window_size(m_session, NGHTTP2_FLAG_NONE, 0,
                                          CONNECTION_WINDOW);
    Serialize();
}

Http2ClientLayer::~Http2ClientLayer() {
    nghttp2_session_del(m_session);
}

bool Http2ClientLayer::ConnectProtocolAllowed() const {
    return nghttp2_session_get_remote_settings(
               m_session, NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) == 1;
}

bool Http2ClientLayer::SubmitConnect(
    const std::string &authority, const std::string &path,
    const std::vector<std::pair<std::string, std::string>> &headers) {
    std::vector<std::pair<std::string, std::string>> fields{
        {":method", "CONNECT"}, {":protocol", "websocket"},
        {":scheme", "https"},   {":authority", authority},
        {":path", path},
    };
    fields.insert(fields.end(), headers.begin(), headers.end());
    std::vector<nghttp2_nv> nva;
    for (auto &[name, value] : fields) {
        nva.push_back({reinterpret_cast<uint8_t *>(name.data()),
                       reinterpret_cast<uint8_t *>(value.data()), name.size(),
                       value.size(), NGHTTP2_NV_FLAG_NONE});
    }
    nghttp2_data_provider2 provider{};
    provider.read_callback = Callbacks::ReadTx;
    m_stream_id = nghttp2_submit_request2(m_session, nullptr, nva.data(),
                                          nva.size(), &provider, nullptr);
    return m_stream_id > 0 && Serialize();
}

std::string Http2ClientLayer::ResponseHeader(const std::string &name) const {
    const auto it{m_response_headers.find(name)};
    return it == m_response_headers.end() ? std::string{} : it->second;
}

bool Http2ClientLayer::Serialize() {
    while (true) {
        const uint8_t *data{nullptr};
        const nghttp2_ssize n{nghttp2_session_mem_send2(m_session, &data)};
        if (n < 0) {
            m_failed = true;
            return false;
        }
        if (n == 0) {
            return true;
        }
        if (m_out_offset == m_out.size()) {
            m_out.clear();
            m_out_offset = 0;
        }
        m_out.append(reinterpret_cast<const char *>(data), size_t(n));
    }
}

bool Http2ClientLayer::FlushOut(SOCKET fd) {
    while (m_out_offset < m_out.size()) {
        const ssize_t n{m_inner->Write(
            fd, reinterpret_cast<const uint8_t *>(m_out.data()) + m_out_offset,
            m_out.size() - m_out_offset)};
        if (n > 0) {
            m_out_offset += size_t(n);
            continue;
        }
        if (n < 0 && WouldBlock(errno)) {
            return true;
        }
        m_failed = true;
        return false;
    }
    m_out.clear();
    m_out_offset = 0;
    return true;
}

ssize_t Http2ClientLayer::ReadOnce(SOCKET fd) {
    uint8_t buf[64 * 1024];
    const ssize_t n{m_inner->Read(fd, buf, sizeof(buf))};
    if (n > 0) {
        if (nghttp2_session_mem_recv2(m_session, buf, size_t(n)) != n) {
            m_failed = true;
            errno = ECONNRESET;
            return -1;
        }
        // Acknowledgements, window updates, pings.
        if (!Serialize()) {
            errno = ECONNRESET;
            return -1;
        }
        return n;
    }
    if (n == 0) {
        m_eof = true;
        return 0;
    }
    if (WouldBlock(errno)) {
        m_read_waits_for = m_inner->ReadWaitsFor();
    } else {
        m_failed = true;
    }
    return -1;
}

bool Http2ClientLayer::Pump(SOCKET fd) {
    if (!FlushOut(fd)) {
        return false;
    }
    while (!m_eof && !m_failed) {
        const ssize_t n{ReadOnce(fd)};
        if (n <= 0) {
            break;
        }
    }
    return !m_failed && !m_eof && FlushOut(fd) &&
           (m_stream_id < 0 || !m_stream_closed || m_status);
}

Sock::Event Http2ClientLayer::WaitEvents() const {
    Sock::Event events{m_read_waits_for};
    if (m_out_offset < m_out.size()) {
        events |= m_inner->WriteWaitsFor();
    }
    return events;
}

ssize_t Http2ClientLayer::Read(SOCKET fd, uint8_t *buf, size_t len) {
    if (!FlushOut(fd)) {
        errno = ECONNRESET;
        return -1;
    }
    while (m_plain_offset == m_plain.size()) {
        m_plain.clear();
        m_plain_offset = 0;
        if (m_stream_closed || m_eof || m_remote_ended) {
            if (m_stream_error != NGHTTP2_NO_ERROR || m_failed) {
                errno = ECONNRESET;
                return -1;
            }
            // The server ended the stream (or the connection): EOF.
            return 0;
        }
        if (m_failed) {
            errno = ECONNRESET;
            return -1;
        }
        const ssize_t n{ReadOnce(fd)};
        if (n < 0) {
            return -1;
        }
        if (!FlushOut(fd)) {
            errno = ECONNRESET;
            return -1;
        }
    }
    const size_t n{std::min(len, m_plain.size() - m_plain_offset)};
    std::memcpy(buf, m_plain.data() + m_plain_offset, n);
    m_plain_offset += n;
    return ssize_t(n);
}

ssize_t Http2ClientLayer::Write(SOCKET fd, const uint8_t *buf, size_t len) {
    if (m_failed || m_stream_closed || m_stream_id < 0) {
        errno = EPIPE;
        return -1;
    }
    if (TxUnframed() >= TX_LIMIT && !FlushBuffered(fd)) {
        errno = ECONNRESET;
        return -1;
    }
    const size_t n{std::min(len, TX_LIMIT - std::min(TX_LIMIT, TxUnframed()))};
    if (n == 0) {
        // The server's window is closed: retried by FlushBuffered() once
        // the socket is readable (a WINDOW_UPDATE).
        errno = EAGAIN;
        return -1;
    }
    m_tx.append(reinterpret_cast<const char *>(buf), n);
    if (m_tx_deferred) {
        m_tx_deferred = false;
        nghttp2_session_resume_data(m_session, m_stream_id);
    }
    if (!Serialize() || !FlushOut(fd)) {
        errno = ECONNRESET;
        return -1;
    }
    return ssize_t(n);
}

bool Http2ClientLayer::HasBuffered() const {
    return m_plain_offset < m_plain.size() || m_inner->HasBuffered() ||
           m_stream_closed || m_remote_ended || m_failed || m_eof;
}

Sock::Event Http2ClientLayer::WriteWaitsFor() const {
    if (m_out_offset < m_out.size()) {
        return m_inner->WriteWaitsFor();
    }
    // Bytes waiting for the server's window: a WINDOW_UPDATE arrives by
    // reading.
    return Sock::RECV;
}

Sock::Event Http2ClientLayer::ReadWaitsFor() const {
    return m_read_waits_for;
}

bool Http2ClientLayer::HasPendingWrite() const {
    return m_out_offset < m_out.size() ||
           (TxUnframed() > 0 && !m_stream_closed && !m_failed);
}

bool Http2ClientLayer::FlushBuffered(SOCKET fd) {
    if (m_failed) {
        return false;
    }
    if (!FlushOut(fd)) {
        return false;
    }
    // Read what is there (window updates, pings), within reason.
    while (TxUnframed() > 0 &&
           m_plain.size() - m_plain_offset < MAX_PLAIN_WHILE_WRITING &&
           !m_eof && !m_stream_closed) {
        if (ReadOnce(fd) <= 0) {
            break;
        }
    }
    if (m_failed) {
        return false;
    }
    if (m_tx_deferred && TxUnframed() > 0) {
        m_tx_deferred = false;
        nghttp2_session_resume_data(m_session, m_stream_id);
    }
    return Serialize() && FlushOut(fd);
}

void Http2ClientLayer::Shutdown(SOCKET fd) {
    // Best effort, non-blocking: GOAWAY, then TLS close_notify.
    nghttp2_session_terminate_session(m_session, NGHTTP2_NO_ERROR);
    Serialize();
    (void)FlushOut(fd);
    m_inner->Shutdown(fd);
}
