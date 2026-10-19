// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_sock.h>

#include <compat/compat.h>
#include <logging.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

ssize_t PlainByteLayer::Read(SOCKET fd, uint8_t *buf, size_t len) {
    return ::recv(fd, reinterpret_cast<char *>(buf), len, MSG_DONTWAIT);
}

ssize_t PlainByteLayer::Write(SOCKET fd, const uint8_t *buf, size_t len) {
    return ::send(fd, reinterpret_cast<const char *>(buf), len,
                  MSG_NOSIGNAL | MSG_DONTWAIT);
}

namespace {
bool WouldBlock(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

void AddCounters(WebSocketTransportInfo &info, uint64_t payload_sent,
                 uint64_t payload_recv, uint64_t wire_sent,
                 uint64_t wire_recv) {
    auto &totals{GetWebSocketTransportTotals()};
    info.payload_bytes_sent += payload_sent;
    info.payload_bytes_recv += payload_recv;
    info.wire_bytes_sent += wire_sent;
    info.wire_bytes_recv += wire_recv;
    totals.payload_bytes_sent += payload_sent;
    totals.payload_bytes_recv += payload_recv;
    totals.wire_bytes_sent += wire_sent;
    totals.wire_bytes_recv += wire_recv;
}
} // namespace

WebSocketSock::WebSocketSock(SOCKET fd, WebSocketCodec::Role role,
                             std::shared_ptr<WebSocketTransportInfo> info,
                             std::unique_ptr<WebSocketByteLayer> layer,
                             std::vector<uint8_t> initial_wire_bytes)
    : WebSocketSock(Sock{fd}, role, std::move(info), std::move(layer),
                    std::move(initial_wire_bytes)) {}

WebSocketSock::WebSocketSock(Sock &&sock, WebSocketCodec::Role role,
                             std::shared_ptr<WebSocketTransportInfo> info,
                             std::unique_ptr<WebSocketByteLayer> layer,
                             std::vector<uint8_t> initial_wire_bytes)
    : Sock{std::move(sock)}, m_info{std::move(info)},
      m_layer{std::move(layer)}, m_codec{role, m_info->compression},
      m_rx_wire{std::move(initial_wire_bytes)} {
    // Never block a CConnman thread: MSG_DONTWAIT may be unavailable (it is
    // then defined as 0 by compat.h), so make the socket itself
    // non-blocking. Likewise avoid SIGPIPE where MSG_NOSIGNAL is missing.
    if (!SetNonBlocking()) {
        LogPrintf("WebSocket: unable to make socket non-blocking\n");
    }
#ifdef SO_NOSIGPIPE
    const int on{1};
    (void)SetSockOpt(SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    LOCK(m_mutex);
    UpdateFlagsLocked();
}

WebSocketSock::~WebSocketSock() {
    LOCK(m_mutex);
    if (!m_failed && m_socket != INVALID_SOCKET) {
        // Best effort: say goodbye without blocking.
        m_codec.EncodeClose(1000, m_tx);
        (void)FlushLocked();
        m_layer->Shutdown(m_socket);
    }
}

void WebSocketSock::UpdateFlagsLocked() const {
    m_has_buffered = m_rx_offset < m_rx_plain.size() || m_layer->HasBuffered() ||
                     WebSocketCodec::HasCompleteFrame(m_rx_wire) ||
                     m_eof || m_failed;
    const bool pending{!m_coalesce.empty() || m_tx_offset < m_tx.size()};
    // A read blocked on writability resumes from FlushPending().
    m_pending_events = (pending ? m_layer->WriteWaitsFor() : Event{0}) |
                       (m_read_waits_send ? Sock::SEND : Event{0});
}

bool WebSocketSock::FlushLocked() const {
    if (!m_coalesce.empty()) {
        m_codec.EncodeMessage(m_coalesce, m_tx);
        AddCounters(*m_info, m_coalesce.size(), 0, 0, 0);
        m_coalesce.clear();
    }
    while (m_tx_offset < m_tx.size()) {
        const ssize_t n{m_layer->Write(m_socket, m_tx.data() + m_tx_offset,
                                       m_tx.size() - m_tx_offset)};
        if (n <= 0) {
            if (n < 0 && WouldBlock(errno)) {
                break;
            }
            // After the peer's Close, failing to deliver our reply (it may
            // already have gone) still ends the connection in an orderly way.
            if (!m_codec.PeerClosed()) {
                m_failed = true;
            }
            m_tx.clear();
            m_tx_offset = 0;
            return false;
        }
        m_tx_offset += n;
    }
    if (m_tx_offset == m_tx.size()) {
        m_tx.clear();
        m_tx_offset = 0;
    } else if (m_tx_offset > (1 << 20)) {
        m_tx.erase(m_tx.begin(), m_tx.begin() + m_tx_offset);
        m_tx_offset = 0;
    }
    const uint64_t wire{m_codec.WireBytesSent()};
    AddCounters(*m_info, 0, 0, wire - m_wire_sent_reported, 0);
    m_wire_sent_reported = wire;
    return true;
}

ssize_t WebSocketSock::Send(const void *data, size_t len, int flags) const {
    LOCK(m_mutex);
    if (m_failed || m_codec.CloseSent()) {
        errno = EPIPE;
        return -1;
    }
    if (m_tx.size() - m_tx_offset + m_coalesce.size() > MAX_PENDING_SEND) {
        // Back-pressure: try to drain first.
        if (!FlushLocked()) {
            errno = ECONNRESET;
            UpdateFlagsLocked();
            return -1;
        }
        if (m_tx.size() - m_tx_offset > MAX_PENDING_SEND) {
            UpdateFlagsLocked();
            errno = EAGAIN;
            return -1;
        }
    }
    const auto *bytes{static_cast<const uint8_t *>(data)};
    m_coalesce.insert(m_coalesce.end(), bytes, bytes + len);
    bool more{false};
#ifdef MSG_MORE
    more = flags & MSG_MORE;
#endif
    if (!more || m_coalesce.size() >= MAX_COALESCE) {
        if (!FlushLocked()) {
            errno = ECONNRESET;
            UpdateFlagsLocked();
            return -1;
        }
    }
    UpdateFlagsLocked();
    return len;
}

bool WebSocketSock::FillLocked() const {
    // Read what the OS socket (or TLS layer) has, then decode.
    uint8_t buf[64 * 1024];
    m_read_waits_send = false;
    while (!m_eof) {
        const ssize_t n{m_layer->Read(m_socket, buf, sizeof(buf))};
        if (n > 0) {
            m_rx_wire.insert(m_rx_wire.end(), buf, buf + n);
            if (m_rx_wire.size() > m_codec.MaxWireMessageSize() + 16) {
                break; // Decode before reading more.
            }
            continue;
        }
        if (n == 0) {
            m_eof = true;
            break;
        }
        if (WouldBlock(errno)) {
            m_read_waits_send = m_layer->ReadWaitsFor() == Sock::SEND;
            break;
        }
        m_failed = true;
        return false;
    }

    std::vector<uint8_t> reply;
    const size_t plain_before{m_rx_plain.size()};
    const auto result{m_codec.Decode(m_rx_wire, m_rx_plain, reply)};
    m_rx_wire.erase(m_rx_wire.begin(), m_rx_wire.begin() + result.consumed);
    AddCounters(*m_info, 0, m_rx_plain.size() - plain_before, 0,
                m_codec.WireBytesRecv() - m_wire_recv_reported);
    m_wire_recv_reported = m_codec.WireBytesRecv();
    if (result.error) {
        LogDebug(BCLog::NET, "WebSocket peer error: %s\n", *result.error);
        m_failed = true;
        return false;
    }
    if (m_codec.PeerClosed()) {
        m_eof = true;
    }
    if (!reply.empty()) {
        m_tx.insert(m_tx.end(), reply.begin(), reply.end());
        if (!FlushLocked() && !m_codec.PeerClosed()) {
            return false;
        }
    }
    return true;
}

ssize_t WebSocketSock::Recv(void *buf, size_t len, int flags) const {
    LOCK(m_mutex);
    if (m_rx_offset == m_rx_plain.size()) {
        m_rx_plain.clear();
        m_rx_offset = 0;
        if (!m_failed && !FillLocked()) {
            UpdateFlagsLocked();
            errno = ECONNRESET;
            return -1;
        }
    }
    if (m_rx_offset < m_rx_plain.size()) {
        const size_t n{std::min(len, m_rx_plain.size() - m_rx_offset)};
        std::memcpy(buf, m_rx_plain.data() + m_rx_offset, n);
        m_rx_offset += n;
        UpdateFlagsLocked();
        return n;
    }
    UpdateFlagsLocked();
    if (m_failed) {
        errno = ECONNRESET;
        return -1;
    }
    if (m_eof) {
        // An EOF in the middle of a frame is not an orderly close.
        if (!m_rx_wire.empty() && !m_codec.PeerClosed()) {
            errno = ECONNRESET;
            return -1;
        }
        return 0;
    }
    errno = EAGAIN;
    return -1;
}

bool WebSocketSock::HasBufferedRecv() const {
    return m_has_buffered.load();
}

Sock::Event WebSocketSock::PendingEvents() const {
    return m_pending_events.load();
}

bool WebSocketSock::FlushPending() const {
    LOCK(m_mutex);
    bool ok{!m_failed && FlushLocked()};
    // Retry a read that was waiting for the socket to become writable; what
    // it decodes is then reported by HasBufferedRecv().
    if (ok && m_read_waits_send) {
        ok = FillLocked();
    }
    UpdateFlagsLocked();
    return ok;
}
