// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_websocket_sock.h>

#include <compat/compat.h>
#include <crypto/common.h>
#include <logging.h>
#include <net_zstd_independent.h>
#include <node/metrics.h>
#include <protocol.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <utility>

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
    : Sock{std::move(sock)}, m_info{std::move(info)}, m_layer{std::move(layer)},
      m_codec{role, m_info->compression},
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
    const bool pending{!m_coalesce.empty() || m_tx_offset < m_tx.size() ||
                       m_layer->HasPendingWrite()};
    // A read blocked on writability resumes from FlushPending().
    m_pending_events = (pending ? m_layer->WriteWaitsFor() : Event{0}) |
                       (m_read_waits_send ? Sock::SEND : Event{0});
}

void WebSocketSock::EncodeCoalescedLocked() const {
    if (m_coalesce.empty()) {
        return;
    }
    m_codec.EncodeMessage(m_coalesce, m_tx);
    AddCounters(*m_info, m_coalesce.size(), 0, 0, 0);
    m_coalesce.clear();
    if (m_out_header_have > 0) {
        // The start of the current header went into the zstd stream.
        m_out_header_split = true;
    }
}

void WebSocketSock::EncodeIndependentLocked(Span<const uint8_t> payload) const {
    const auto frame{
        GetP2PIndependentFrameCache().Encode(m_out_header, payload)};
    m_codec.EncodeIndependent(*frame, m_tx);
    m_out_independent = false;
    AddCounters(*m_info, m_out_header.size() + payload.size(), 0, 0, 0);
    ++m_info->independent_frames_sent;
    if (auto *metrics{node::GetNodeMetrics()}) {
        metrics->websocket_independent_frames.Add(0);
    }
}

void WebSocketSock::QueueLocked(Span<const uint8_t> bytes) const {
    if (!m_codec.IndependentFrames()) {
        m_coalesce.insert(m_coalesce.end(), bytes.begin(), bytes.end());
        return;
    }
    // CConnman sends whole P2P messages (header, then payload) in order, so
    // the stream can be followed message by message. Following it wrongly
    // would only change how bytes are framed, never the bytes themselves.
    static constexpr size_t HEADER{CMessageHeader::HEADER_SIZE};
    static_assert(std::tuple_size_v<decltype(m_out_header)> == HEADER);
    static constexpr char BLOCK_COMMAND[CMessageHeader::MESSAGE_TYPE_SIZE]{
        "block"};
    while (!bytes.empty()) {
        if (m_out_body_left == 0 && !m_out_independent) {
            const size_t take{
                std::min(HEADER - m_out_header_have, bytes.size())};
            std::copy(bytes.begin(), bytes.begin() + take,
                      m_out_header.begin() + m_out_header_have);
            m_coalesce.insert(m_coalesce.end(), bytes.begin(),
                              bytes.begin() + take);
            m_out_header_have += take;
            bytes = bytes.subspan(take);
            if (m_out_header_have < HEADER) {
                break;
            }
            m_out_header_have = 0;
            const bool split{std::exchange(m_out_header_split, false)};
            m_out_body_left = ReadLE32(m_out_header.data() +
                                       CMessageHeader::MESSAGE_SIZE_OFFSET);
            const uint64_t total{HEADER + m_out_body_left};
            const size_t threshold{g_p2p_compress_once_threshold.load()};
            if (!split && threshold != 0 && total >= threshold &&
                total <= GetP2PWebSocketMessageSizeLimit() &&
                std::memcmp(m_out_header.data() +
                                CMessageHeader::MESSAGE_START_SIZE,
                            BLOCK_COMMAND, sizeof(BLOCK_COMMAND)) == 0) {
                // Frame what precedes the block, then the block on its own.
                m_coalesce.resize(m_coalesce.size() - HEADER);
                EncodeCoalescedLocked();
                m_out_independent = true;
            }
            continue;
        }
        const size_t take{
            size_t(std::min<uint64_t>(m_out_body_left, bytes.size()))};
        if (!m_out_independent) {
            m_coalesce.insert(m_coalesce.end(), bytes.begin(),
                              bytes.begin() + take);
            m_out_body_left -= take;
        } else if (m_out_block.empty() && take == m_out_body_left) {
            // The whole payload in one call (as CConnman sends it): no copy.
            m_out_body_left = 0;
            EncodeIndependentLocked(bytes.first(take));
        } else {
            m_out_block.insert(m_out_block.end(), bytes.begin(),
                               bytes.begin() + take);
            m_out_body_left -= take;
            if (m_out_body_left == 0) {
                EncodeIndependentLocked(m_out_block);
                std::vector<uint8_t>().swap(m_out_block);
            }
        }
        bytes = bytes.subspan(take);
    }
}

bool WebSocketSock::FlushLocked() const {
    EncodeCoalescedLocked();
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
    if (m_tx_offset == m_tx.size() && m_layer->HasPendingWrite() &&
        !m_layer->FlushBuffered(m_socket)) {
        m_failed = true;
        m_tx.clear();
        m_tx_offset = 0;
        return false;
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
    if (m_tx.size() - m_tx_offset + m_coalesce.size() + m_out_block.size() >
        MAX_PENDING_SEND) {
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
    try {
        QueueLocked(Span<const uint8_t>{bytes, len});
    } catch (const std::exception &e) {
        LogPrintf("WebSocket: cannot encode an independent frame: %s\n",
                  e.what());
        m_failed = true;
        UpdateFlagsLocked();
        errno = ECONNRESET;
        return -1;
    }
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
    if (const uint64_t independent{m_codec.IndependentFramesRecv() -
                                   m_independent_recv_reported}) {
        m_independent_recv_reported = m_codec.IndependentFramesRecv();
        m_info->independent_frames_recv += independent;
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->websocket_independent_frames.Add(1, independent);
        }
    }
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
