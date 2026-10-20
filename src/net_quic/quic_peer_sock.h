// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_PEER_SOCK_H
#define BITCOIN_NET_QUIC_QUIC_PEER_SOCK_H

// A P2P peer carried by a WebTransport session, as a Sock for CConnman.
// No QUIC library header: the engine side talks to it through
// QuicPeerChannel.

#include <net_quic/quic_transport_info.h>
#include <net_webtransport.h>
#include <net_zstd_dict.h>
#include <span.h>
#include <sync.h>
#include <util/sock.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * Framing of P2P messages on a class stream:
 *   u32 LE length of (flags + body), u8 flags, body
 * flags: 0 raw, 1 zstd (the stream's own compression context, primed with
 * the P2P dictionary, flushed per message), 2 zstd independent (dictionary
 * only, one frame per message); 3-255 reserved (the peer is dropped).
 * body (p2p-v1, this tier): the 24-byte message header and the payload.
 */
namespace quic_frame {
constexpr uint8_t FLAG_RAW{0};
constexpr uint8_t FLAG_STREAM{1};
constexpr uint8_t FLAG_INDEPENDENT{2};
constexpr size_t HEADER_SIZE{5};
//! Messages below this are sent raw (compression costs more than it saves)
constexpr size_t COMPRESS_MIN{64};
//! Messages from this size are compressed independently (blocks)
constexpr size_t INDEPENDENT_MIN{64 * 1024};
//! Largest frame length field accepted (plain P2P message limit, or its
//! zstd bound, plus the flags byte)
uint64_t MaxFrameLength();
} // namespace quic_frame

/** Per-peer compression state of the five class streams */
class StreamFramer {
public:
    explicit StreamFramer(bool compress = true) : m_compress{compress} {}

    /** One complete frame for a tier message (header + payload) */
    std::vector<uint8_t> Encode(StreamClass cls, Span<const uint8_t> msg);

    /**
     * Decode a frame's body (as received on `cls`) into the message bytes.
     * False on corrupt data, a reserved flag or a message over the size
     * limit; the peer must then be dropped.
     */
    bool Decode(StreamClass cls, uint8_t flags, Span<const uint8_t> body,
                std::vector<uint8_t> &out, std::string &error);

private:
    P2PZstdSession &Session(
        std::array<std::unique_ptr<P2PZstdSession>, NUM_STREAM_CLASSES> &set,
        StreamClass cls);

    const bool m_compress;
    //! Created on first use: most classes carry few messages.
    std::array<std::unique_ptr<P2PZstdSession>, NUM_STREAM_CLASSES> m_tx;
    std::array<std::unique_ptr<P2PZstdSession>, NUM_STREAM_CLASSES> m_rx;
};

/** Splits a class stream's bytes into frames (engine side) */
class FrameReassembler {
public:
    struct Frame {
        uint8_t flags{0};
        std::vector<uint8_t> body;
        //! Stream bytes the frame took (header included)
        size_t wire_size{0};
    };
    /** Append stream bytes; complete frames are appended to `out`. False on
     * a length over quic_frame::MaxFrameLength() or a zero length. */
    bool Feed(Span<const uint8_t> data, std::vector<Frame> &out);
    //! Bytes of the frame being received
    size_t Buffered() const { return m_buf.size(); }

private:
    std::vector<uint8_t> m_buf;
};

/**
 * Shared between a QuicPeerSock (net threads) and the QUIC engine's
 * session for that peer (engine thread). The engine writes one byte to the
 * notification descriptor (the other end of the socketpair the Sock
 * polls) when received frames become available, when sending can resume
 * and when the session ends.
 */
class QuicPeerChannel {
public:
    //! A frame received on a class stream, not yet decoded
    struct RxFrame {
        StreamClass cls{StreamClass::CONTROL};
        uint8_t flags{0};
        std::vector<uint8_t> body;
        size_t wire_size{0};
    };

    //! Per-class queued bytes above which Send() refuses new messages
    static constexpr uint64_t MAX_PENDING_SEND{4 * 1024 * 1024};
    //! Received complete frames above which flow control credit is held
    //! back (the peer is back-pressured instead of buffered)
    static constexpr uint64_t RX_QUEUE_LIMIT{8 * 1024 * 1024};

    QuicPeerChannel(int notify_fd, std::shared_ptr<QuicTransportInfo> info,
                    std::function<void()> wake_engine);
    ~QuicPeerChannel();
    QuicPeerChannel(const QuicPeerChannel &) = delete;
    QuicPeerChannel &operator=(const QuicPeerChannel &) = delete;

    const std::shared_ptr<QuicTransportInfo> &Info() const { return m_info; }

    // --- net side
    /** Queue an encoded frame on a class stream */
    void EnqueueTx(StreamClass cls, std::vector<uint8_t> &&frame)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Bytes of a class waiting: queued here or not yet sent by QUIC */
    uint64_t TxPending(StreamClass cls) const;
    /**
     * The next frame to deliver: the oldest one, except that before the
     * peer's verack only CONTROL frames are delivered (later frames are
     * held back in order), so a block request racing ahead of the
     * handshake on another stream is not dropped as "before verack".
     */
    std::optional<RxFrame> PopRx(bool after_verack)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool HasDeliverable(bool after_verack) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** The Sock is gone (CNode destroyed): end the session */
    void SockClosed();
    /** Wake the engine (new data to send, credit to give) */
    void WakeEngine() const;

    // --- engine side
    std::deque<std::vector<uint8_t>> TakeTx(StreamClass cls)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void SetEngineUnsent(StreamClass cls, uint64_t bytes);
    /** Queue a received frame and notify the Sock */
    void PushRx(RxFrame &&frame) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Whether credit for newly received bytes may be given now */
    bool RxHasRoom() const;
    /** The session ended: Recv() reports EOF once the queue is empty */
    void MarkClosed();
    bool Closed() const { return m_closed; }
    bool SockGone() const { return m_sock_gone; }
    /** Write a notification byte (engine side) */
    void Notify() const;

    //! Send() hit MAX_PENDING_SEND on `blocked_class`; the engine notifies
    //! when that class has drained to half of it
    std::atomic<bool> send_blocked{false};
    std::atomic<uint8_t> blocked_class{0};
    //! The net side consumed frames while credit was held back
    std::atomic<bool> credit_wanted{false};

private:
    const int m_notify_fd;
    const std::shared_ptr<QuicTransportInfo> m_info;
    const std::function<void()> m_wake_engine;

    mutable Mutex m_mutex;
    std::array<std::deque<std::vector<uint8_t>>, NUM_STREAM_CLASSES>
        m_tx GUARDED_BY(m_mutex);
    std::deque<RxFrame> m_rx GUARDED_BY(m_mutex);

    std::array<std::atomic<uint64_t>, NUM_STREAM_CLASSES> m_tx_queued{};
    std::array<std::atomic<uint64_t>, NUM_STREAM_CLASSES> m_tx_engine{};
    std::atomic<uint64_t> m_rx_bytes{0};
    std::atomic<bool> m_closed{false};
    std::atomic<bool> m_sock_gone{false};
};

/**
 * The Sock CConnman uses for a WebTransport peer: one end of a socketpair
 * (polled like any socket; the engine writes notification bytes to the
 * other end) plus the channel. Send() coalesces bytes into whole P2P
 * messages, classifies them (splitting mixed inventories), frames and
 * compresses them on the calling thread and queues them per class; it
 * fails with EAGAIN while the message's class has more than
 * MAX_PENDING_SEND bytes waiting. Recv() returns decoded messages in the
 * order their frames completed.
 */
class QuicPeerSock final : public Sock {
public:
    QuicPeerSock(SOCKET fd, std::shared_ptr<QuicPeerChannel> channel,
                 bool compress = true);
    ~QuicPeerSock() override;

    ssize_t Send(const void *data, size_t len, int flags) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ssize_t Recv(void *buf, size_t len, int flags) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool HasBufferedRecv() const override;
    Event PendingEvents() const override;
    bool FlushPending() const override;
    bool SendBlockedByTransport() const override;

    const std::shared_ptr<QuicPeerChannel> &Channel() const {
        return m_channel;
    }

private:
    void DrainNotifications() const;
    //! Classify, split, frame and queue one complete tier message
    void SendMessage(Span<const uint8_t> msg) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    //! Decode frames until there is output; false on a fatal error
    bool FillLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const std::shared_ptr<QuicPeerChannel> m_channel;

    mutable Mutex m_mutex;
    mutable StreamFramer m_framer GUARDED_BY(m_mutex);
    //! Bytes of the message being assembled by Send()
    mutable std::vector<uint8_t> m_assembling GUARDED_BY(m_mutex);
    //! Decoded message bytes not yet returned by Recv()
    mutable std::vector<uint8_t> m_out GUARDED_BY(m_mutex);
    mutable size_t m_out_offset GUARDED_BY(m_mutex){0};
    mutable bool m_failed GUARDED_BY(m_mutex){false};
    //! The peer's verack has been delivered
    mutable std::atomic<bool> m_after_verack{false};
    mutable std::atomic<bool> m_has_out{false};
};

#endif // BITCOIN_NET_QUIC_QUIC_PEER_SOCK_H
