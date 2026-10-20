// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTP2_SERVER_H
#define BITCOIN_HTTP2_SERVER_H

#include <boost/asio/buffer.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct nghttp2_session;

/**
 * HTTP/2 server side of one connection, on top of nghttp2 (framing, HPACK,
 * flow control and protocol state). There is no I/O here: the caller feeds
 * received bytes to Receive() and writes what Collect() produces, so this can
 * be unit tested and fuzzed without sockets.
 *
 * Requests and responses are Boost.Beast messages, so that the HTTP server's
 * existing handlers serve HTTP/2 streams exactly like HTTP/1.1 requests.
 * Requests are presented as HTTP/1.1 (version 11) with the :authority as the
 * Host header and repeated cookie fields joined, as RFC 9113 8.2.3 requires.
 *
 * Not thread-safe: use one session from one strand.
 */
namespace http2 {

using Request = boost::beast::http::request<boost::beast::http::string_body>;
using Response = boost::beast::http::response<boost::beast::http::string_body>;
using Headers = std::vector<std::pair<std::string, std::string>>;

//! ALPN protocol identifier of HTTP/2 over TLS
inline constexpr std::string_view ALPN_PROTOCOL{"h2"};

/** Per-connection resource limits (see doc/http2.md) */
struct Limits {
    //! SETTINGS_MAX_CONCURRENT_STREAMS
    uint32_t max_concurrent_streams{100};
    //! Largest decoded header list (RFC 9113: name + value + 32 per field)
    //! of a request; larger ones are answered with 431
    uint32_t max_header_list_size{16384};
    //! SETTINGS_MAX_FRAME_SIZE: largest frame payload accepted
    uint32_t max_frame_size{16384};
    //! SETTINGS_INITIAL_WINDOW_SIZE: bytes a client may send on one stream
    //! before it is consumed
    uint32_t stream_window{1 << 20};
    //! Receive window of the whole connection
    uint32_t connection_window{8 << 20};
    //! RST_STREAM token bucket (Rapid Reset, CVE-2023-44487): initial and
    //! maximum tokens, and tokens regained per second
    uint64_t reset_burst{200};
    uint64_t reset_rate{33};
    //! CONTINUATION frames allowed after one HEADERS frame (CVE-2024-28182)
    size_t max_continuations{8};
    //! Largest request body
    uint64_t max_body_size{32 << 20};
    //! Advertise and accept extended CONNECT (RFC 8441)
    bool enable_connect_protocol{false};
};

/**
 * Bytes ready to be written: a sequence of pieces, either copied here or
 * borrowed from response bodies that `keep` holds until the write is done.
 */
class Output {
public:
    void AppendCopy(const uint8_t *data, size_t len);
    void AppendBorrowed(const char *data, size_t len);
    void Keep(std::unique_ptr<std::string> body) {
        m_keep.push_back(std::move(body));
    }

    size_t Size() const { return m_size; }
    bool Empty() const { return m_size == 0; }
    //! Buffers to write, valid until the Output is cleared or changed
    std::vector<boost::asio::const_buffer> Buffers() const;
    //! Everything, contiguously (tests)
    std::string ToString() const;
    void Clear();

private:
    struct Piece {
        //! Copied bytes (when ptr is null)
        std::string owned;
        const char *ptr{nullptr};
        size_t len{0};
    };
    std::vector<Piece> m_pieces;
    std::vector<std::unique_ptr<std::string>> m_keep;
    size_t m_size{0};
};

class ServerSession {
public:
    struct Handlers {
        //! A complete request (its END_STREAM was received)
        std::function<void(int32_t stream_id, Request &&req)> on_request;
        //! The headers of an extended CONNECT (RFC 8441) with :protocol;
        //! answer with AcceptTunnel() or SubmitResponse()
        std::function<void(int32_t stream_id, Request &&req,
                           std::string protocol)>
            on_connect;
        //! Tunnel bytes from the client; report them with TunnelConsumed()
        //! once delivered, which reopens the client's flow control window
        std::function<void(int32_t stream_id, std::string_view data)>
            on_tunnel_data;
        //! The client ended its side of a tunnel (END_STREAM)
        std::function<void(int32_t stream_id)> on_tunnel_eof;
        //! A stream was closed, for any reason. The id is unknown afterwards.
        std::function<void(int32_t stream_id, uint32_t error_code)>
            on_stream_close;
    };

    ServerSession(const Limits &limits, Handlers handlers);
    ~ServerSession();
    ServerSession(const ServerSession &) = delete;
    ServerSession &operator=(const ServerSession &) = delete;

    /**
     * Process bytes from the client. Returns false if the connection must
     * be closed (protocol error, flood, bad preface): Collect() may still
     * produce a GOAWAY to send first, but nothing more must be received.
     */
    bool Receive(std::span<const uint8_t> data);

    /**
     * Append pending frames to `out`, stopping once it holds about
     * `max_bytes`. Returns false on a fatal error.
     */
    bool Collect(Output &out, size_t max_bytes);

    bool WantsRead() const;
    bool WantsWrite() const;

    /**
     * Answer a stream. Hop-by-hop fields (Connection, Keep-Alive,
     * Transfer-Encoding, ...) are dropped, as HTTP/2 forbids them. With
     * `head`, no body is sent but Content-Length is kept. Returns false if
     * the stream no longer exists (e.g. the client reset it).
     */
    bool SubmitResponse(int32_t stream_id, Response &&res, bool head = false);

    /** Accept an extended CONNECT: 2xx headers, the stream stays open */
    bool AcceptTunnel(int32_t stream_id, unsigned status,
                      const Headers &headers);
    //! Queue tunnel bytes for the client
    void TunnelSend(int32_t stream_id, std::string_view data);
    //! Tunnel bytes queued but not yet framed
    size_t TunnelQueued(int32_t stream_id) const;
    //! End our side of a tunnel after the queued bytes (END_STREAM)
    void TunnelEnd(int32_t stream_id);
    //! `n` bytes passed to on_tunnel_data were delivered
    void TunnelConsumed(int32_t stream_id, size_t n);

    //! Reset a stream (RST_STREAM)
    void Reset(int32_t stream_id, uint32_t error_code);

    //! Graceful shutdown: GOAWAY, finish the open streams, accept no more
    void Shutdown();
    //! Immediate GOAWAY with an error code; open streams are abandoned
    void Terminate(uint32_t error_code);

    //! Streams open (any state)
    size_t OpenStreams() const { return m_streams.size(); }
    //! Streams whose request has not been received completely yet
    size_t IncompleteRequests() const;
    //! Stream ids whose request started arriving before `cutoff` and is
    //! still incomplete (for a read deadline)
    std::vector<int32_t>
    IncompleteRequestsSince(std::chrono::steady_clock::time_point cutoff) const;

    //! Whether an error reported by Receive() was a flood/limit violation
    bool Flooded() const { return m_flooded; }

    //! Implementation detail, public for the nghttp2 callbacks
    struct Stream;

private:
    friend struct Callbacks;

    Stream *Find(int32_t stream_id);
    const Stream *Find(int32_t stream_id) const;
    void CompleteRequest(int32_t stream_id, Stream &s);
    void ApplyDeferredConsumption();

    const Limits m_limits;
    const Handlers m_handlers;
    nghttp2_session *m_session{nullptr};
    std::map<int32_t, std::unique_ptr<Stream>> m_streams;
    //! Bodies of closed streams that a pending Output may still borrow
    std::vector<std::unique_ptr<std::string>> m_retired;
    //! Bytes of closed tunnels the client never got window credit for
    size_t m_deferred_consume{0};
    //! The current Collect() target
    Output *m_out{nullptr};
    size_t m_out_limit{0};
    bool m_flooded{false};
};

} // namespace http2

#endif // BITCOIN_HTTP2_SERVER_H
