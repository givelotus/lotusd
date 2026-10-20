// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBSOCKET_CODEC_H
#define BITCOIN_NET_WEBSOCKET_CODEC_H

#include <net_websocket.h>
#include <net_zstd_dict.h>
#include <random.h>
#include <span.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * RFC 6455 framing for P2P over WebSocket, without any I/O.
 *
 * One P2P chunk handed to EncodeMessage() becomes one binary message (one
 * frame), optionally zstd-compressed as negotiated (see P2PZstdSession).
 * Decode() turns received wire bytes back into P2P bytes, answering pings
 * and closes. Extensions (permessage-deflate) are not supported: connections
 * that negotiated them use the HTTP server's bridge instead. The only RSV
 * bit used is RSV2, for independent frames, part of the zstd modes (see
 * net_zstd_independent.h).
 */
class WebSocketCodec {
public:
    enum class Role { CLIENT, SERVER };

    //! Bound wire bytes without reserving them; follows current P2P config.
    uint64_t MaxWireMessageSize() const;

    WebSocketCodec(Role role, P2PWebSocketCompression compression);

    bool IndependentFrames() const { return m_independent; }

    /**
     * Append an independent frame (see CompressP2PIndependent) as one RSV2
     * binary message. It neither uses nor changes the zstd stream's state.
     * Only with IndependentFrames() (the zstd modes).
     */
    void EncodeIndependent(Span<const uint8_t> frame,
                           std::vector<uint8_t> &out);

    /** Append `payload` (P2P bytes) to `out` as one binary message */
    void EncodeMessage(Span<const uint8_t> payload, std::vector<uint8_t> &out);

    /** Append a Close frame (once) */
    void EncodeClose(uint16_t code, std::vector<uint8_t> &out);

    struct DecodeResult {
        //! Wire bytes consumed from the input
        size_t consumed{0};
        //! Set if the stream is invalid; the connection must be dropped
        std::optional<std::string> error;
    };

    /**
     * Decode complete frames from `in`. P2P bytes are appended to `plain`,
     * frames to send back (pong, close reply) to `reply`.
     */
    DecodeResult Decode(Span<const uint8_t> in, std::vector<uint8_t> &plain,
                        std::vector<uint8_t> &reply);

    /** Whether `in` starts with at least one complete frame */
    static bool HasCompleteFrame(Span<const uint8_t> in);

    bool PeerClosed() const { return m_peer_closed; }
    bool CloseSent() const { return m_close_sent; }

    //! Bytes of wire frames produced / consumed (headers included)
    uint64_t WireBytesSent() const { return m_wire_sent; }
    uint64_t WireBytesRecv() const { return m_wire_recv; }
    //! Independent frames decoded
    uint64_t IndependentFramesRecv() const { return m_independent_recv; }

private:
    void AppendFrame(uint8_t opcode, Span<const uint8_t> payload,
                     std::vector<uint8_t> &out, uint8_t rsv = 0);
    std::optional<std::string> FinishMessage(std::vector<uint8_t> &plain);

    const Role m_role;
    const P2PWebSocketCompression m_compression;
    const bool m_independent;
    std::unique_ptr<P2PZstdSession> m_zstd;
    FastRandomContext m_rng;

    //! Fragments of the message being received
    std::vector<uint8_t> m_message;
    bool m_in_message{false};
    //! The message being received is an independent (RSV2) frame
    bool m_message_independent{false};
    bool m_peer_closed{false};
    bool m_close_sent{false};
    uint64_t m_wire_sent{0};
    uint64_t m_wire_recv{0};
    uint64_t m_independent_recv{0};
    std::vector<uint8_t> m_scratch;
};

#endif // BITCOIN_NET_WEBSOCKET_CODEC_H
