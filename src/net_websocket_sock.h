// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_SOCK_H
#define BITCOIN_NET_WEBSOCKET_SOCK_H

#include <net_websocket.h>
#include <net_websocket_codec.h>
#include <sync.h>
#include <util/sock.h>

#include <array>
#include <atomic>
#include <memory>
#include <vector>

/**
 * Raw byte I/O beneath WebSocket framing: the plain socket, or TLS (see
 * net_websocket_tls.h). Called with WebSocketSock's lock held.
 * Read/Write follow recv(2)/send(2) on a non-blocking socket: >0 bytes, 0 on
 * orderly EOF (Read only), -1 with errno set (EAGAIN when it would block).
 */
class WebSocketByteLayer {
public:
    virtual ~WebSocketByteLayer() = default;
    virtual ssize_t Read(SOCKET fd, uint8_t *buf, size_t len) = 0;
    virtual ssize_t Write(SOCKET fd, const uint8_t *buf, size_t len) = 0;
    //! Bytes already read from the OS socket but not yet returned
    virtual bool HasBuffered() const { return false; }
    //! OS socket events a blocked Write() is waiting for
    virtual Sock::Event WriteWaitsFor() const { return Sock::SEND; }
    //! OS socket events the last blocked Read() is waiting for (TLS: a read
    //! can need to write first, e.g. to answer a KeyUpdate)
    virtual Sock::Event ReadWaitsFor() const { return Sock::RECV; }
    //! Best-effort non-blocking shutdown before the socket is closed
    virtual void Shutdown(SOCKET fd) {}
    //! Whether the layer is TLS
    virtual bool IsTLS() const { return false; }
    //! The layer holds bytes Write() accepted but could not send yet
    //! (e.g. HTTP/2 framing waiting for a flow control window)
    virtual bool HasPendingWrite() const { return false; }
    //! Make progress on those bytes; false on a fatal error
    virtual bool FlushBuffered(SOCKET fd) { return true; }
};

class PlainByteLayer final : public WebSocketByteLayer {
public:
    ssize_t Read(SOCKET fd, uint8_t *buf, size_t len) override;
    ssize_t Write(SOCKET fd, const uint8_t *buf, size_t len) override;
};

/**
 * A P2P socket carrying the P2P byte stream in WebSocket messages, used by
 * CConnman like any other Sock (polled on the real TCP socket). Send()
 * frames and (if negotiated) compresses on the calling thread; Recv()
 * deframes and decompresses. No extra thread or socketpair is involved.
 *
 * With zstd compression, Send() follows the P2P
 * message framing of the outgoing stream. A block message of at least
 * g_p2p_compress_once_threshold bytes is sent as one independent frame from
 * the shared cache (GetP2PIndependentFrameCache()) instead of through the
 * connection's zstd stream; bytes before it are framed first, so the P2P
 * byte stream is unchanged.
 *
 * Send() coalesces chunks passed with MSG_MORE into one message. It accepts
 * everything it is given (returning `len`) unless more than
 * MAX_PENDING_SEND bytes are already waiting to be written, in which case
 * it fails with EAGAIN; the unwritten tail is flushed via the Sock
 * PendingEvents()/FlushPending() hooks.
 */
class WebSocketSock final : public Sock {
public:
    //! Back-pressure threshold for data accepted but not yet written
    static constexpr size_t MAX_PENDING_SEND = 4 * 1024 * 1024;
    //! Coalesced chunks are framed once they reach this size
    static constexpr size_t MAX_COALESCE = 1024 * 1024;

    WebSocketSock(SOCKET fd, WebSocketCodec::Role role,
                  std::shared_ptr<WebSocketTransportInfo> info,
                  std::unique_ptr<WebSocketByteLayer> layer,
                  std::vector<uint8_t> initial_wire_bytes = {});
    /** Take over the descriptor of `sock` */
    WebSocketSock(Sock &&sock, WebSocketCodec::Role role,
                  std::shared_ptr<WebSocketTransportInfo> info,
                  std::unique_ptr<WebSocketByteLayer> layer,
                  std::vector<uint8_t> initial_wire_bytes = {});
    ~WebSocketSock() override;

    ssize_t Send(const void *data, size_t len, int flags) const override;
    ssize_t Recv(void *buf, size_t len, int flags) const override;
    bool HasBufferedRecv() const override;
    Event PendingEvents() const override;
    bool FlushPending() const override;

    const std::shared_ptr<WebSocketTransportInfo> &Info() const {
        return m_info;
    }

private:
    /** Queue P2P bytes, routing large block messages to independent frames */
    void QueueLocked(Span<const uint8_t> bytes) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** Frame m_coalesce (if any) as a stream message into m_tx */
    void EncodeCoalescedLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    /** Queue the current block message as an independent frame */
    void EncodeIndependentLocked(Span<const uint8_t> payload) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    //! Frame coalesced data; write as much as possible. False on error.
    bool FlushLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    //! Read and decode what is available. False on fatal error.
    bool FillLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void UpdateFlagsLocked() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const std::shared_ptr<WebSocketTransportInfo> m_info;

    mutable Mutex m_mutex;
    const std::unique_ptr<WebSocketByteLayer> m_layer GUARDED_BY(m_mutex);
    mutable WebSocketCodec m_codec GUARDED_BY(m_mutex);
    //! P2P bytes passed with MSG_MORE, not yet framed
    mutable std::vector<uint8_t> m_coalesce GUARDED_BY(m_mutex);
    //! Encoded frames not yet written
    mutable std::vector<uint8_t> m_tx GUARDED_BY(m_mutex);
    mutable size_t m_tx_offset GUARDED_BY(m_mutex){0};
    //! Wire bytes not yet decoded
    mutable std::vector<uint8_t> m_rx_wire GUARDED_BY(m_mutex);
    //! Decoded P2P bytes not yet returned by Recv()
    mutable std::vector<uint8_t> m_rx_plain GUARDED_BY(m_mutex);
    mutable size_t m_rx_offset GUARDED_BY(m_mutex){0};
    //! The last read blocked until the OS socket is writable
    mutable bool m_read_waits_send GUARDED_BY(m_mutex){false};
    mutable bool m_eof GUARDED_BY(m_mutex){false};
    mutable bool m_failed GUARDED_BY(m_mutex){false};
    mutable uint64_t m_payload_recv_reported GUARDED_BY(m_mutex){0};
    mutable uint64_t m_wire_recv_reported GUARDED_BY(m_mutex){0};
    mutable uint64_t m_wire_sent_reported GUARDED_BY(m_mutex){0};
    mutable uint64_t m_independent_recv_reported GUARDED_BY(m_mutex){0};

    //! Outgoing P2P message framing, tracked with independent frames only.
    //! Header of the current message, bytes of it seen so far.
    mutable std::array<uint8_t, 24> m_out_header GUARDED_BY(m_mutex){};
    mutable size_t m_out_header_have GUARDED_BY(m_mutex){0};
    //! Part of the current header was already framed, so the message
    //! cannot be moved to an independent frame
    mutable bool m_out_header_split GUARDED_BY(m_mutex){false};
    //! Payload bytes of the current message not yet passed to Send()
    mutable uint64_t m_out_body_left GUARDED_BY(m_mutex){0};
    //! The current message is sent as an independent frame
    mutable bool m_out_independent GUARDED_BY(m_mutex){false};
    //! Its payload so far, when it arrives over several Send() calls
    mutable std::vector<uint8_t> m_out_block GUARDED_BY(m_mutex);

    //! Lock-free views for the Sock hooks (see util/sock.h). A failed or
    //! closed socket reports buffered data so CConnman calls Recv() and
    //! sees the error/EOF without waiting for the OS socket.
    mutable std::atomic<bool> m_has_buffered{false};
    mutable std::atomic<Event> m_pending_events{0};
};

#endif // BITCOIN_NET_WEBSOCKET_SOCK_H
