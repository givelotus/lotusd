// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/quic_peer_sock.h>

#include <crypto/common.h>
#include <hash.h>
#include <net_websocket.h>
#include <node/metrics.h>
#include <protocol.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <sys/socket.h>
#include <unistd.h>

uint64_t quic_frame::MaxFrameLength() {
    return std::min<uint64_t>(
        P2PZstdMaxWireSize(GetP2PWebSocketMessageSizeLimit()) + 1,
        std::numeric_limits<uint32_t>::max());
}

namespace {
struct CCtxDeleter {
    void operator()(ZSTD_CCtx *p) const { ZSTD_freeCCtx(p); }
};
struct DCtxDeleter {
    void operator()(ZSTD_DCtx *p) const { ZSTD_freeDCtx(p); }
};

/** One-shot compression with the P2P dictionary (independent frames) */
void CompressIndependent(Span<const uint8_t> in, std::vector<uint8_t> &out) {
    thread_local std::unique_ptr<ZSTD_CCtx, CCtxDeleter> cctx{
        ZSTD_createCCtx()};
    const size_t start{out.size()};
    out.resize(start + ZSTD_compressBound(in.size()));
    const size_t n{ZSTD_compress_usingCDict(cctx.get(), out.data() + start,
                                            out.size() - start, in.data(),
                                            in.size(), GetP2PZstdCDict())};
    if (ZSTD_isError(n)) {
        throw std::runtime_error(ZSTD_getErrorName(n));
    }
    out.resize(start + n);
}

std::string MessageType(Span<const uint8_t> msg) {
    if (msg.size() < CMessageHeader::HEADER_SIZE) {
        return {};
    }
    const char *p{reinterpret_cast<const char *>(msg.data()) +
                  CMessageHeader::MESSAGE_START_SIZE};
    return std::string(p, strnlen(p, CMessageHeader::MESSAGE_TYPE_SIZE));
}

/** A tier message with this header's magic and type, for `payload` */
std::vector<uint8_t> RebuildMessage(Span<const uint8_t> original_header,
                                    Span<const uint8_t> payload) {
    std::vector<uint8_t> msg(original_header.begin(),
                             original_header.begin() +
                                 CMessageHeader::HEADER_SIZE);
    WriteLE32(msg.data() + CMessageHeader::MESSAGE_SIZE_OFFSET,
              static_cast<uint32_t>(payload.size()));
    const uint256 hash{Hash(payload)};
    std::memcpy(msg.data() + CMessageHeader::CHECKSUM_OFFSET, hash.begin(),
                CMessageHeader::CHECKSUM_SIZE);
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}
} // namespace

P2PZstdSession &StreamFramer::Session(
    std::array<std::unique_ptr<P2PZstdSession>, NUM_STREAM_CLASSES> &set,
    StreamClass cls) {
    auto &slot{set[StreamClassIndex(cls)]};
    if (!slot) {
        slot = std::make_unique<P2PZstdSession>(/*use_dict=*/true);
    }
    return *slot;
}

std::vector<uint8_t> StreamFramer::Encode(StreamClass cls,
                                          Span<const uint8_t> msg) {
    if (msg.size() > GetP2PWebSocketMessageSizeLimit()) {
        throw std::length_error("P2P message exceeds frame size limit");
    }
    std::vector<uint8_t> frame(quic_frame::HEADER_SIZE);
    uint8_t flags{quic_frame::FLAG_RAW};
    if (!m_compress || msg.size() < quic_frame::COMPRESS_MIN) {
        frame.insert(frame.end(), msg.begin(), msg.end());
    } else if (msg.size() >= quic_frame::INDEPENDENT_MIN) {
        // Blocks: no state shared with the stream's small messages.
        flags = quic_frame::FLAG_INDEPENDENT;
        CompressIndependent(msg, frame);
    } else {
        flags = quic_frame::FLAG_STREAM;
        Session(m_tx, cls).CompressFrame(msg, frame);
    }
    if (frame.size() - 4 > quic_frame::MaxFrameLength()) {
        throw std::length_error("P2P frame length is not representable");
    }
    WriteLE32(frame.data(), static_cast<uint32_t>(frame.size() - 4));
    frame[4] = flags;
    return frame;
}

bool StreamFramer::Decode(StreamClass cls, uint8_t flags,
                          Span<const uint8_t> body, std::vector<uint8_t> &out,
                          std::string &error) {
    const uint64_t limit{GetP2PWebSocketMessageSizeLimit()};
    out.clear();
    switch (flags) {
        case quic_frame::FLAG_RAW:
            if (body.size() > limit) {
                error = "message over the size limit";
                return false;
            }
            out.assign(body.begin(), body.end());
            return true;
        case quic_frame::FLAG_STREAM:
            try {
                bool over{false};
                Session(m_rx, cls).DecompressFrame(
                    body, [&](Span<const uint8_t> chunk) {
                        if (over || out.size() + chunk.size() > limit) {
                            over = true;
                            return;
                        }
                        out.insert(out.end(), chunk.begin(), chunk.end());
                    });
                if (over) {
                    error = "decompressed message over the size limit";
                    return false;
                }
            } catch (const std::exception &e) {
                error = std::string{"zstd: "} + e.what();
                return false;
            }
            return true;
        case quic_frame::FLAG_INDEPENDENT: {
            const unsigned long long size{
                ZSTD_getFrameContentSize(body.data(), body.size())};
            if (size == ZSTD_CONTENTSIZE_ERROR ||
                size == ZSTD_CONTENTSIZE_UNKNOWN || size > limit) {
                error = "independent frame without a valid size";
                return false;
            }
            thread_local std::unique_ptr<ZSTD_DCtx, DCtxDeleter> dctx{
                ZSTD_createDCtx()};
            out.resize(static_cast<size_t>(size));
            const size_t n{ZSTD_decompress_usingDDict(
                dctx.get(), out.data(), out.size(), body.data(), body.size(),
                GetP2PZstdDDict())};
            if (ZSTD_isError(n) || n != out.size()) {
                error = "independent frame does not decode";
                out.clear();
                return false;
            }
            return true;
        }
        default:
            error = "reserved frame flags";
            return false;
    }
}

bool FrameReassembler::Feed(Span<const uint8_t> data, std::vector<Frame> &out) {
    m_buf.insert(m_buf.end(), data.begin(), data.end());
    size_t pos{0};
    bool ok{true};
    while (m_buf.size() - pos >= 4) {
        const uint32_t len{ReadLE32(m_buf.data() + pos)};
        if (len == 0 || len > quic_frame::MaxFrameLength()) {
            ok = false;
            break;
        }
        if (m_buf.size() - pos - 4 < len) {
            break;
        }
        Frame f;
        f.flags = m_buf[pos + 4];
        if (pos == 0 && m_buf.size() == 4 + size_t{len}) {
            // Transfer a completed large frame instead of keeping a second
            // full-sized buffer in each of the five reassemblers.
            m_buf.erase(m_buf.begin(), m_buf.begin() + 5);
            f.body = std::move(m_buf);
            f.wire_size = 4 + size_t{len};
            out.push_back(std::move(f));
            return true;
        }
        f.body.assign(m_buf.begin() + pos + 5, m_buf.begin() + pos + 4 + len);
        f.wire_size = 4 + size_t{len};
        out.push_back(std::move(f));
        pos += 4 + size_t{len};
    }
    if (pos > 0 && m_buf.capacity() > 64 * 1024 &&
        m_buf.size() - pos < 64 * 1024) {
        std::vector<uint8_t> tail(m_buf.begin() + pos, m_buf.end());
        m_buf.swap(tail);
    } else {
        m_buf.erase(m_buf.begin(),
                    m_buf.begin() + static_cast<std::ptrdiff_t>(pos));
    }
    return ok;
}

QuicPeerChannel::QuicPeerChannel(int notify_fd,
                                 std::shared_ptr<QuicTransportInfo> info,
                                 std::function<void()> wake_engine,
                                 uint64_t receive_limit)
    : m_notify_fd{notify_fd}, m_info{std::move(info)},
      m_wake_engine{std::move(wake_engine)},
      m_receive_limit{std::max<uint64_t>(1, receive_limit)} {
#ifdef SO_NOSIGPIPE
    const int no_sigpipe{1};
    ::setsockopt(m_notify_fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe,
                 sizeof(no_sigpipe));
#endif
}

QuicPeerChannel::~QuicPeerChannel() {
    if (m_notify_fd >= 0) {
        ::close(m_notify_fd);
    }
}

void QuicPeerChannel::Notify() const {
    const uint8_t b{1};
    // A full socketpair already holds a pending notification. Never raise
    // SIGPIPE if the net thread has already destroyed its end.
#ifdef MSG_NOSIGNAL
    constexpr int flags{MSG_DONTWAIT | MSG_NOSIGNAL};
#else
    constexpr int flags{MSG_DONTWAIT};
#endif
    [[maybe_unused]] auto r{::send(m_notify_fd, &b, 1, flags)};
}

void QuicPeerChannel::WakeEngine() const {
    if (m_wake_engine) {
        m_wake_engine();
    }
}

void QuicPeerChannel::EnqueueTx(StreamClass cls, std::vector<uint8_t> &&frame) {
    m_tx_queued[StreamClassIndex(cls)] += frame.size();
    {
        LOCK(m_mutex);
        m_tx[StreamClassIndex(cls)].push_back(std::move(frame));
    }
}

uint64_t QuicPeerChannel::TxPending(StreamClass cls) const {
    return m_tx_queued[StreamClassIndex(cls)] +
           m_tx_engine[StreamClassIndex(cls)];
}

std::deque<std::vector<uint8_t>> QuicPeerChannel::TakeTx(StreamClass cls) {
    std::deque<std::vector<uint8_t>> out;
    {
        LOCK(m_mutex);
        out.swap(m_tx[StreamClassIndex(cls)]);
    }
    uint64_t bytes{0};
    for (const auto &f : out) {
        bytes += f.size();
    }
    // Moved to the engine: counted there until handed to QUIC.
    m_tx_engine[StreamClassIndex(cls)] += bytes;
    m_tx_queued[StreamClassIndex(cls)] -= bytes;
    return out;
}

void QuicPeerChannel::SetEngineUnsent(StreamClass cls, uint64_t bytes) {
    m_tx_engine[StreamClassIndex(cls)] = bytes;
}

bool QuicPeerChannel::PushRx(RxFrame &&frame) {
    bool was_empty;
    {
        LOCK(m_mutex);
        if (m_rx.size() >= MAX_PENDING_RX_FRAMES) return false;
        m_rx_bytes += frame.wire_size;
        was_empty = m_rx.empty();
        m_rx.push_back(std::move(frame));
    }
    if (was_empty) {
        Notify();
    }
    return true;
}

bool QuicPeerChannel::RxHasRoom() const {
    return m_rx_bytes < m_receive_limit;
}

std::optional<QuicPeerChannel::RxFrame>
QuicPeerChannel::PopRx(bool after_verack) {
    std::optional<RxFrame> out;
    {
        LOCK(m_mutex);
        auto it{m_rx.begin()};
        if (!after_verack) {
            it = std::find_if(m_rx.begin(), m_rx.end(), [](const RxFrame &f) {
                return f.cls == StreamClass::CONTROL;
            });
        }
        if (it == m_rx.end()) {
            return std::nullopt;
        }
        out = std::move(*it);
        m_rx.erase(it);
    }
    const uint64_t before{m_rx_bytes.fetch_sub(out->wire_size)};
    if (before >= m_receive_limit &&
        before - out->wire_size < m_receive_limit) {
        // Credit was being held back: let the engine give it now.
        credit_wanted = true;
        WakeEngine();
    }
    return out;
}

bool QuicPeerChannel::HasDeliverable(bool after_verack) const {
    LOCK(m_mutex);
    if (after_verack) {
        return !m_rx.empty();
    }
    return std::any_of(m_rx.begin(), m_rx.end(), [](const RxFrame &f) {
        return f.cls == StreamClass::CONTROL;
    });
}

void QuicPeerChannel::SockClosed() {
    m_sock_gone = true;
    WakeEngine();
}

void QuicPeerChannel::MarkClosed() {
    m_closed = true;
    Notify();
}

QuicPeerSock::QuicPeerSock(SOCKET fd, std::shared_ptr<QuicPeerChannel> channel,
                           bool compress)
    : Sock{fd}, m_channel{std::move(channel)}, m_framer{compress} {}

QuicPeerSock::~QuicPeerSock() {
    m_channel->SockClosed();
}

void QuicPeerSock::DrainNotifications() const {
    uint8_t buf[256];
    while (::recv(m_socket, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }
}

void QuicPeerSock::SendMessage(Span<const uint8_t> msg) const {
    QuicTransportInfo &info{*m_channel->Info()};
    const std::string type{MessageType(msg)};
    const auto payload{msg.subspan(CMessageHeader::HEADER_SIZE)};
    const StreamClass cls{ClassifyMessage(type, payload)};
    if (cls != StreamClass::MIXED) {
        info.msg_bytes_sent[StreamClassIndex(cls)] += msg.size();
        auto frame{m_framer.Encode(cls, msg)};
        info.stream_bytes_sent[StreamClassIndex(cls)] += frame.size();
        if (auto *metrics{node::GetNodeMetrics()})
            metrics->webtransport_bytes.Add(
                NUM_STREAM_CLASSES + StreamClassIndex(cls), frame.size());
        m_channel->EnqueueTx(cls, std::move(frame));
        return;
    }
    ++info.splits;
    if (auto *metrics{node::GetNodeMetrics()})
        metrics->webtransport_split.Add(type == NetMsgType::INV       ? 0
                                        : type == NetMsgType::GETDATA ? 1
                                                                      : 2);
    for (const auto &[part_cls, part] : SplitByClass(type, payload)) {
        const auto rebuilt{RebuildMessage(msg, part)};
        info.msg_bytes_sent[StreamClassIndex(part_cls)] += rebuilt.size();
        auto frame{m_framer.Encode(part_cls, rebuilt)};
        info.stream_bytes_sent[StreamClassIndex(part_cls)] += frame.size();
        if (auto *metrics{node::GetNodeMetrics()})
            metrics->webtransport_bytes.Add(
                NUM_STREAM_CLASSES + StreamClassIndex(part_cls), frame.size());
        m_channel->EnqueueTx(part_cls, std::move(frame));
    }
}

ssize_t QuicPeerSock::Send(const void *data, size_t len, int) const {
    if (m_channel->Closed()) {
        errno = EPIPE;
        return -1;
    }
    const auto *bytes{static_cast<const uint8_t *>(data)};
    LOCK(m_mutex);
    if (m_failed) {
        errno = EPIPE;
        return -1;
    }
    // Back-pressure is decided when a new message starts: by the class its
    // type alone gives (inventories are refined after the payload).
    if (m_assembling.empty() && len >= CMessageHeader::HEADER_SIZE) {
        const StreamClass cls{
            ClassifyMessage(MessageType(Span<const uint8_t>{bytes, len}), {})};
        if (m_channel->TxPending(cls) > QuicPeerChannel::MAX_PENDING_SEND) {
            m_channel->blocked_class = static_cast<uint8_t>(cls);
            m_channel->send_blocked = true;
            // The engine may have drained meanwhile: check again so the
            // unblock notification cannot be missed.
            if (m_channel->TxPending(cls) > QuicPeerChannel::MAX_PENDING_SEND) {
                errno = EAGAIN;
                return -1;
            }
            m_channel->send_blocked = false;
        }
    }
    m_assembling.insert(m_assembling.end(), bytes, bytes + len);
    bool queued{false};
    try {
        while (m_assembling.size() >= CMessageHeader::HEADER_SIZE) {
            const uint32_t payload_len{ReadLE32(
                m_assembling.data() + CMessageHeader::MESSAGE_SIZE_OFFSET)};
            const size_t total{CMessageHeader::HEADER_SIZE +
                               size_t{payload_len}};
            if (total > GetP2PWebSocketMessageSizeLimit()) {
                m_failed = true;
                errno = EMSGSIZE;
                return -1;
            }
            if (m_assembling.size() < total) {
                break;
            }
            SendMessage(Span<const uint8_t>{m_assembling.data(), total});
            m_assembling.erase(m_assembling.begin(),
                               m_assembling.begin() +
                                   static_cast<std::ptrdiff_t>(total));
            queued = true;
        }
    } catch (const std::exception &) {
        m_failed = true;
        errno = EPIPE;
        return -1;
    }
    if (queued) {
        m_channel->WakeEngine();
    }
    return static_cast<ssize_t>(len);
}

bool QuicPeerSock::FillLocked() const {
    while (m_out_offset >= m_out.size()) {
        auto frame{m_channel->PopRx(m_after_verack)};
        if (!frame) {
            return true;
        }
        std::string error;
        std::vector<uint8_t> msg;
        if (!m_framer.Decode(frame->cls, frame->flags, frame->body, msg,
                             error) ||
            msg.size() < CMessageHeader::HEADER_SIZE ||
            ReadLE32(msg.data() + CMessageHeader::MESSAGE_SIZE_OFFSET) !=
                msg.size() - CMessageHeader::HEADER_SIZE) {
            m_failed = true;
            return false;
        }
        QuicTransportInfo &info{*m_channel->Info()};
        info.msg_bytes_recv[StreamClassIndex(frame->cls)] += msg.size();
        info.stream_bytes_recv[StreamClassIndex(frame->cls)] +=
            frame->wire_size;
        if (auto *metrics{node::GetNodeMetrics()})
            metrics->webtransport_bytes.Add(StreamClassIndex(frame->cls),
                                            frame->wire_size);
        if (!m_after_verack && frame->cls == StreamClass::CONTROL &&
            MessageType(msg) == NetMsgType::VERACK) {
            m_after_verack = true;
        }
        m_out = std::move(msg);
        m_out_offset = 0;
    }
    return true;
}

ssize_t QuicPeerSock::Recv(void *buf, size_t len, int) const {
    DrainNotifications();
    LOCK(m_mutex);
    if (m_failed) {
        errno = ECONNRESET;
        return -1;
    }
    if (!FillLocked()) {
        errno = ECONNRESET;
        return -1;
    }
    if (m_out_offset < m_out.size()) {
        const size_t n{std::min(len, m_out.size() - m_out_offset)};
        std::memcpy(buf, m_out.data() + m_out_offset, n);
        m_out_offset += n;
        if (m_out_offset == m_out.size()) {
            m_out.clear();
            m_out_offset = 0;
        }
        m_has_out = !m_out.empty() || m_channel->HasDeliverable(m_after_verack);
        return static_cast<ssize_t>(n);
    }
    m_has_out = false;
    if (m_channel->Closed() && !m_channel->HasDeliverable(m_after_verack)) {
        // The session ended: orderly EOF.
        return 0;
    }
    errno = EAGAIN;
    return -1;
}

bool QuicPeerSock::HasBufferedRecv() const {
    return m_has_out || m_channel->HasDeliverable(m_after_verack) ||
           m_channel->Closed();
}

Sock::Event QuicPeerSock::PendingEvents() const {
    return m_channel->send_blocked ? Sock::RECV : 0;
}

bool QuicPeerSock::FlushPending() const {
    DrainNotifications();
    return true;
}

bool QuicPeerSock::SendBlockedByTransport() const {
    return m_channel->send_blocked;
}
