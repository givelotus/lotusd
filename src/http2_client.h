// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTP2_CLIENT_H
#define BITCOIN_HTTP2_CLIENT_H

#include <net_websocket_sock.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

struct nghttp2_session;

/**
 * The client side of a WebSocket over HTTP/2 (RFC 8441), as the byte layer
 * beneath WebSocketSock: WebSocketSock frames P2P messages exactly as over
 * HTTP/1.1, and this layer carries those bytes in DATA frames of one
 * extended CONNECT stream, over the TLS layer it wraps. nghttp2 does the
 * HTTP/2 framing, HPACK and flow control; I/O stays non-blocking and on the
 * caller's thread, like the other byte layers.
 *
 * Writes are accepted up to TX_LIMIT bytes ahead of the server's flow
 * control window; what the window or the socket cannot take yet is reported
 * by HasPendingWrite() and sent by FlushBuffered(), which also reads (a
 * window update or a ping may be waiting). Reads only fetch more from the
 * socket once what was decoded has been returned, so the server's window
 * cannot outgrow what the reader consumes by more than one read.
 */
class Http2ClientLayer final : public WebSocketByteLayer {
public:
    //! Bytes accepted by Write() but not framed yet (window exhausted)
    static constexpr size_t TX_LIMIT = 1024 * 1024;
    //! Our receive windows (stream and connection)
    static constexpr int32_t STREAM_WINDOW = 4 * 1024 * 1024;
    static constexpr int32_t CONNECTION_WINDOW = 16 * 1024 * 1024;

    /** `inner`: the TLS layer, after a handshake that selected ALPN h2 */
    explicit Http2ClientLayer(std::unique_ptr<WebSocketByteLayer> inner);
    ~Http2ClientLayer() override;

    // Handshake (driven by the dialer)
    //! The server's SETTINGS arrived
    bool SettingsReceived() const { return m_settings_received; }
    //! It allows extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL)
    bool ConnectProtocolAllowed() const;
    /** Send CONNECT :protocol websocket for `path`, with extra headers */
    bool SubmitConnect(
        const std::string &authority, const std::string &path,
        const std::vector<std::pair<std::string, std::string>> &headers);
    //! The response status, once its headers arrived
    std::optional<int> Status() const { return m_status; }
    //! Response header (lower case name), "" if absent
    std::string ResponseHeader(const std::string &name) const;
    /** Do the I/O that is possible now. False if the connection failed */
    bool Pump(SOCKET fd);
    //! Socket events the next Pump() waits for
    Sock::Event WaitEvents() const;

    // WebSocketByteLayer
    ssize_t Read(SOCKET fd, uint8_t *buf, size_t len) override;
    ssize_t Write(SOCKET fd, const uint8_t *buf, size_t len) override;
    bool HasBuffered() const override;
    Sock::Event WriteWaitsFor() const override;
    Sock::Event ReadWaitsFor() const override;
    bool HasPendingWrite() const override;
    bool FlushBuffered(SOCKET fd) override;
    void Shutdown(SOCKET fd) override;
    bool IsTLS() const override { return m_inner->IsTLS(); }

    //! Implementation detail, public for the nghttp2 callbacks
    struct Callbacks;

private:
    //! Frame what nghttp2 wants to send into m_out
    bool Serialize();
    //! Write m_out; false on a fatal error
    bool FlushOut(SOCKET fd);
    //! Read and process one chunk from the socket: >0, 0 on EOF, -1
    ssize_t ReadOnce(SOCKET fd);
    size_t TxUnframed() const { return m_tx.size() - m_tx_offset; }

    const std::unique_ptr<WebSocketByteLayer> m_inner;
    nghttp2_session *m_session{nullptr};
    int32_t m_stream_id{-1};

    std::string m_out;
    size_t m_out_offset{0};
    //! Bytes from Write() not framed yet
    std::string m_tx;
    size_t m_tx_offset{0};
    bool m_tx_deferred{false};
    //! Decoded stream DATA not yet returned by Read()
    std::string m_plain;
    size_t m_plain_offset{0};

    bool m_settings_received{false};
    std::optional<int> m_status;
    std::map<std::string, std::string> m_response_headers;
    bool m_stream_closed{false};
    //! The server sent END_STREAM on our stream
    bool m_remote_ended{false};
    uint32_t m_stream_error{0};
    bool m_failed{false};
    bool m_eof{false};
    Sock::Event m_read_waits_for{Sock::RECV};
};

#endif // BITCOIN_HTTP2_CLIENT_H
