// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <http2_server.h>

#include <boost/beast/core/string.hpp>
#include <boost/beast/http/field.hpp>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <deque>
#include <optional>

namespace http = boost::beast::http;

namespace http2 {

//! Response bodies at least this large are framed without copying
static constexpr size_t NO_COPY_MIN_SIZE{4096};

void Output::AppendCopy(const uint8_t *data, size_t len) {
    if (len == 0) {
        return;
    }
    if (m_pieces.empty() || m_pieces.back().ptr) {
        m_pieces.emplace_back();
    }
    m_pieces.back().owned.append(reinterpret_cast<const char *>(data), len);
    m_size += len;
}

void Output::AppendBorrowed(const char *data, size_t len) {
    if (len == 0) {
        return;
    }
    m_pieces.push_back(Piece{{}, data, len});
    m_size += len;
}

std::vector<boost::asio::const_buffer> Output::Buffers() const {
    std::vector<boost::asio::const_buffer> out;
    out.reserve(m_pieces.size());
    for (const Piece &p : m_pieces) {
        if (p.ptr) {
            out.emplace_back(p.ptr, p.len);
        } else {
            out.emplace_back(p.owned.data(), p.owned.size());
        }
    }
    return out;
}

std::string Output::ToString() const {
    std::string out;
    out.reserve(m_size);
    for (const Piece &p : m_pieces) {
        if (p.ptr) {
            out.append(p.ptr, p.len);
        } else {
            out.append(p.owned);
        }
    }
    return out;
}

void Output::Clear() {
    m_pieces.clear();
    m_keep.clear();
    m_size = 0;
}

struct ServerSession::Stream {
    enum class Kind {
        //! An ordinary request; its body is buffered
        REQUEST,
        //! An accepted or pending extended CONNECT: bytes both ways
        TUNNEL,
        //! Answered early (431, 413, 405): the rest of the request is
        //! discarded
        DISCARD,
    };
    Kind kind{Kind::REQUEST};
    std::chrono::steady_clock::time_point started{
        std::chrono::steady_clock::now()};
    //! The request has been received completely (or the tunnel opened)
    bool complete{false};
    //! The client ended its side (END_STREAM)
    bool remote_closed{false};

    // Request being received
    std::string method, path, authority, scheme, protocol;
    std::string cookie;
    Request req;
    size_t header_list_size{0};
    bool headers_too_large{false};
    bool body_too_large{false};

    // Response (or tunnel output) being sent
    std::unique_ptr<std::string> body;
    size_t body_offset{0};
    //! The tunnel's output, not yet framed
    std::deque<std::string> tunnel_tx;
    size_t tunnel_tx_size{0};
    size_t tunnel_tx_front_offset{0};
    bool tunnel_end{false};
    bool data_deferred{false};
    bool tunnel_accepted{false};
    //! Reset the stream once our response has been sent (the client is
    //! still sending a request we refused)
    bool reset_after_response{false};
    //! Tunnel bytes handed to on_tunnel_data and not consumed yet
    size_t unconsumed{0};
};

/** nghttp2 callbacks, with access to the session's internals */
struct Callbacks {
    static ServerSession &Self(void *user_data) {
        return *static_cast<ServerSession *>(user_data);
    }

    static nghttp2_ssize Send(nghttp2_session *, const uint8_t *data,
                              size_t length, int, void *user_data) {
        ServerSession &self{Self(user_data)};
        if (!self.m_out || self.m_out->Size() >= self.m_out_limit) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        self.m_out->AppendCopy(data, length);
        return nghttp2_ssize(length);
    }

    static int SendData(nghttp2_session *, nghttp2_frame *frame,
                        const uint8_t *framehd, size_t length,
                        nghttp2_data_source *source, void *user_data) {
        ServerSession &self{Self(user_data)};
        if (!self.m_out || self.m_out->Size() >= self.m_out_limit) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        auto *s{static_cast<ServerSession::Stream *>(source->ptr)};
        self.m_out->AppendCopy(framehd, 9);
        const size_t padlen{frame->data.padlen};
        if (padlen > 0) {
            const uint8_t pad_length(padlen - 1);
            self.m_out->AppendCopy(&pad_length, 1);
        }
        assert(s->body && s->body_offset + length <= s->body->size());
        self.m_out->AppendBorrowed(s->body->data() + s->body_offset, length);
        s->body_offset += length;
        if (padlen > 1) {
            const std::string zeros(padlen - 1, '\0');
            self.m_out->AppendCopy(
                reinterpret_cast<const uint8_t *>(zeros.data()), zeros.size());
        }
        return 0;
    }

    static nghttp2_ssize ReadBody(nghttp2_session *, int32_t, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source, void *) {
        auto *s{static_cast<ServerSession::Stream *>(source->ptr)};
        const size_t left{s->body->size() - s->body_offset};
        const size_t n{std::min(length, left)};
        if (n == left) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        if (s->body->size() >= NO_COPY_MIN_SIZE) {
            // SendData() frames the bytes in place.
            *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
        } else {
            std::memcpy(buf, s->body->data() + s->body_offset, n);
            s->body_offset += n;
        }
        return nghttp2_ssize(n);
    }

    static nghttp2_ssize ReadTunnel(nghttp2_session *, int32_t, uint8_t *buf,
                                    size_t length, uint32_t *data_flags,
                                    nghttp2_data_source *source, void *) {
        auto *s{static_cast<ServerSession::Stream *>(source->ptr)};
        size_t n{0};
        while (n < length && !s->tunnel_tx.empty()) {
            const std::string &front{s->tunnel_tx.front()};
            const size_t take{
                std::min(length - n, front.size() - s->tunnel_tx_front_offset)};
            std::memcpy(buf + n, front.data() + s->tunnel_tx_front_offset,
                        take);
            n += take;
            s->tunnel_tx_front_offset += take;
            if (s->tunnel_tx_front_offset == front.size()) {
                s->tunnel_tx.pop_front();
                s->tunnel_tx_front_offset = 0;
            }
        }
        s->tunnel_tx_size -= n;
        if (s->tunnel_tx.empty()) {
            if (s->tunnel_end) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            } else if (n == 0) {
                s->data_deferred = true;
                return NGHTTP2_ERR_DEFERRED;
            }
        }
        return nghttp2_ssize(n);
    }

    static nghttp2_ssize ReadLength(nghttp2_session *, uint8_t, int32_t,
                                    int32_t session_window,
                                    int32_t stream_window,
                                    uint32_t remote_max_frame_size, void *) {
        // As large as the peer allows, so big replies need fewer frames.
        int64_t n{std::min<int64_t>(session_window, stream_window)};
        n = std::min<int64_t>(n, remote_max_frame_size);
        return nghttp2_ssize(std::max<int64_t>(n, 1));
    }

    static int BeginHeaders(nghttp2_session *, const nghttp2_frame *frame,
                            void *user_data) {
        ServerSession &self{Self(user_data)};
        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            return 0;
        }
        self.m_streams[frame->hd.stream_id] =
            std::make_unique<ServerSession::Stream>();
        return 0;
    }

    static int Header(nghttp2_session *, const nghttp2_frame *frame,
                      const uint8_t *name_data, size_t namelen,
                      const uint8_t *value_data, size_t valuelen, uint8_t,
                      void *user_data) {
        ServerSession &self{Self(user_data)};
        ServerSession::Stream *s{self.Find(frame->hd.stream_id)};
        if (!s || frame->hd.type != NGHTTP2_HEADERS) {
            return 0;
        }
        // RFC 9113 6.5.2 accounting, over every header block of the stream
        // (trailers included).
        s->header_list_size += namelen + valuelen + 32;
        if (s->header_list_size > self.m_limits.max_header_list_size) {
            s->headers_too_large = true;
        }
        if (s->headers_too_large ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            // Trailers are not passed on; nor is anything past the limit.
            return 0;
        }
        const std::string_view name{reinterpret_cast<const char *>(name_data),
                                    namelen};
        const std::string_view value{reinterpret_cast<const char *>(value_data),
                                     valuelen};
        // nghttp2 has validated pseudo-headers and field names (lower case,
        // no connection-specific fields) already.
        if (name == ":method") {
            s->method = value;
        } else if (name == ":path") {
            s->path = value;
        } else if (name == ":authority") {
            s->authority = value;
        } else if (name == ":scheme") {
            s->scheme = value;
        } else if (name == ":protocol") {
            s->protocol = value;
        } else if (name == "cookie") {
            if (!s->cookie.empty()) {
                s->cookie += "; ";
            }
            s->cookie += value;
        } else {
            s->req.insert(name, value);
        }
        return 0;
    }

    static int FrameRecv(nghttp2_session *, const nghttp2_frame *frame,
                         void *user_data) {
        ServerSession &self{Self(user_data)};
        ServerSession::Stream *s{self.Find(frame->hd.stream_id)};
        if (!s) {
            return 0;
        }
        const bool end_stream{(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0};
        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            using K = ServerSession::Stream::Kind;
            if (s->headers_too_large) {
                Response res{http::status::request_header_fields_too_large, 11};
                s->kind = K::DISCARD;
                s->complete = true;
                s->reset_after_response = !end_stream;
                self.SubmitResponse(frame->hd.stream_id, std::move(res));
                return 0;
            }
            if (s->method == "CONNECT") {
                if (s->protocol.empty() || !self.m_handlers.on_connect) {
                    // Classic CONNECT (a proxy tunnel) is not served, as
                    // over HTTP/1.1.
                    s->kind = K::DISCARD;
                    s->complete = true;
                    s->reset_after_response = !end_stream;
                    self.SubmitResponse(
                        frame->hd.stream_id,
                        Response{http::status::method_not_allowed, 11});
                    return 0;
                }
                s->kind = K::TUNNEL;
                s->complete = true;
                s->remote_closed = end_stream;
                Request req{std::move(s->req)};
                req.method_string(s->method);
                req.target(s->path);
                req.version(11);
                if (req.find(http::field::host) == req.end()) {
                    req.set(http::field::host, s->authority);
                }
                if (!s->cookie.empty()) {
                    req.set(http::field::cookie, s->cookie);
                }
                self.m_handlers.on_connect(frame->hd.stream_id, std::move(req),
                                           s->protocol);
                if (end_stream && self.m_handlers.on_tunnel_eof &&
                    self.Find(frame->hd.stream_id)) {
                    self.m_handlers.on_tunnel_eof(frame->hd.stream_id);
                }
                return 0;
            }
        }
        if (!end_stream || (frame->hd.type != NGHTTP2_HEADERS &&
                            frame->hd.type != NGHTTP2_DATA)) {
            return 0;
        }
        s->remote_closed = true;
        switch (s->kind) {
            case ServerSession::Stream::Kind::REQUEST:
                if (s->complete) {
                    break;
                }
                if (s->headers_too_large) {
                    // The trailers took the header list over the limit.
                    s->kind = ServerSession::Stream::Kind::DISCARD;
                    s->complete = true;
                    self.SubmitResponse(
                        frame->hd.stream_id,
                        Response{http::status::request_header_fields_too_large,
                                 11});
                    break;
                }
                self.CompleteRequest(frame->hd.stream_id, *s);
                break;
            case ServerSession::Stream::Kind::TUNNEL:
                if (self.m_handlers.on_tunnel_eof) {
                    self.m_handlers.on_tunnel_eof(frame->hd.stream_id);
                }
                break;
            case ServerSession::Stream::Kind::DISCARD:
                break;
        }
        return 0;
    }

    static int FrameSend(nghttp2_session *, const nghttp2_frame *frame,
                         void *user_data) {
        ServerSession &self{Self(user_data)};
        if ((frame->hd.type != NGHTTP2_HEADERS &&
             frame->hd.type != NGHTTP2_DATA) ||
            !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            return 0;
        }
        ServerSession::Stream *s{self.Find(frame->hd.stream_id)};
        if (s && s->reset_after_response && !s->remote_closed) {
            // RFC 9113 8.1: a complete response, then RST_STREAM(NO_ERROR)
            // so that the client stops sending the rest of its request.
            // (Submitted earlier, the reset would cancel the response.)
            s->reset_after_response = false;
            nghttp2_submit_rst_stream(self.m_session, NGHTTP2_FLAG_NONE,
                                      frame->hd.stream_id, NGHTTP2_NO_ERROR);
        }
        return 0;
    }

    static int DataChunk(nghttp2_session *, uint8_t, int32_t stream_id,
                         const uint8_t *data, size_t len, void *user_data) {
        ServerSession &self{Self(user_data)};
        ServerSession::Stream *s{self.Find(stream_id)};
        if (!s) {
            nghttp2_session_consume(self.m_session, stream_id, len);
            return 0;
        }
        using K = ServerSession::Stream::Kind;
        if (s->kind == K::TUNNEL) {
            s->unconsumed += len;
            if (self.m_handlers.on_tunnel_data) {
                self.m_handlers.on_tunnel_data(
                    stream_id, std::string_view{
                                   reinterpret_cast<const char *>(data), len});
            }
            return 0;
        }
        // Request bodies are buffered, bounded by max_body_size: the window
        // is reopened at once.
        nghttp2_session_consume(self.m_session, stream_id, len);
        if (s->kind == K::DISCARD || s->body_too_large) {
            return 0;
        }
        if (s->req.body().size() + len > self.m_limits.max_body_size) {
            s->body_too_large = true;
            s->kind = K::DISCARD;
            s->complete = true;
            s->req.body().clear();
            s->req.body().shrink_to_fit();
            s->reset_after_response = !s->remote_closed;
            self.SubmitResponse(stream_id,
                                Response{http::status::payload_too_large, 11});
            return 0;
        }
        s->req.body().append(reinterpret_cast<const char *>(data), len);
        return 0;
    }

    static int StreamClose(nghttp2_session *, int32_t stream_id,
                           uint32_t error_code, void *user_data) {
        ServerSession &self{Self(user_data)};
        auto it{self.m_streams.find(stream_id)};
        if (it == self.m_streams.end()) {
            return 0;
        }
        std::unique_ptr<ServerSession::Stream> s{std::move(it->second)};
        self.m_streams.erase(it);
        // Window credit the client never got back for tunnel bytes.
        self.m_deferred_consume += s->unconsumed;
        if (s->body) {
            // A pending Output may borrow from it.
            self.m_retired.push_back(std::move(s->body));
        }
        if (self.m_handlers.on_stream_close) {
            self.m_handlers.on_stream_close(stream_id, error_code);
        }
        return 0;
    }
};

ServerSession::ServerSession(const Limits &limits, Handlers handlers)
    : m_limits{limits}, m_handlers{std::move(handlers)} {
    nghttp2_session_callbacks *cbs{nullptr};
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback2(cbs, Callbacks::Send);
    nghttp2_session_callbacks_set_send_data_callback(cbs, Callbacks::SendData);
    nghttp2_session_callbacks_set_on_begin_headers_callback(
        cbs, Callbacks::BeginHeaders);
    nghttp2_session_callbacks_set_on_header_callback(cbs, Callbacks::Header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
                                                         Callbacks::FrameRecv);
    nghttp2_session_callbacks_set_on_frame_send_callback(cbs,
                                                         Callbacks::FrameSend);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs, Callbacks::DataChunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs, Callbacks::StreamClose);
    nghttp2_session_callbacks_set_data_source_read_length_callback2(
        cbs, Callbacks::ReadLength);

    nghttp2_option *opt{nullptr};
    nghttp2_option_new(&opt);
    // Window updates follow what is delivered (tunnels), not just received.
    nghttp2_option_set_no_auto_window_update(opt, 1);
    nghttp2_option_set_max_continuations(opt, m_limits.max_continuations);
    nghttp2_option_set_stream_reset_rate_limit(opt, m_limits.reset_burst,
                                               m_limits.reset_rate);
    // A server never accepts pushes; keep closed-stream state small.
    nghttp2_option_set_max_reserved_remote_streams(opt, 0);
    nghttp2_option_set_no_closed_streams(opt, 1);
    const int rv{
        nghttp2_session_server_new3(&m_session, cbs, this, opt, nullptr)};
    nghttp2_option_del(opt);
    nghttp2_session_callbacks_del(cbs);
    assert(rv == 0);
    (void)rv;

    std::vector<nghttp2_settings_entry> settings{
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
         m_limits.max_concurrent_streams},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, m_limits.stream_window},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, m_limits.max_frame_size},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, m_limits.max_header_list_size},
        // A server never pushes, and clients must not push to it.
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    };
    if (m_limits.enable_connect_protocol) {
        settings.push_back({NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1});
    }
    nghttp2_submit_settings(m_session, NGHTTP2_FLAG_NONE, settings.data(),
                            settings.size());
    if (m_limits.connection_window > NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE) {
        nghttp2_session_set_local_window_size(
            m_session, NGHTTP2_FLAG_NONE, 0,
            int32_t(m_limits.connection_window));
    }
}

ServerSession::~ServerSession() {
    nghttp2_session_del(m_session);
}

ServerSession::Stream *ServerSession::Find(int32_t stream_id) {
    const auto it{m_streams.find(stream_id)};
    return it == m_streams.end() ? nullptr : it->second.get();
}

const ServerSession::Stream *ServerSession::Find(int32_t stream_id) const {
    const auto it{m_streams.find(stream_id)};
    return it == m_streams.end() ? nullptr : it->second.get();
}

void ServerSession::CompleteRequest(int32_t stream_id, Stream &s) {
    s.complete = true;
    Request req{std::move(s.req)};
    req.method_string(s.method);
    req.target(s.path);
    req.version(11);
    if (req.find(http::field::host) == req.end() && !s.authority.empty()) {
        req.set(http::field::host, s.authority);
    }
    if (!s.cookie.empty()) {
        req.set(http::field::cookie, s.cookie);
    }
    if (m_handlers.on_request) {
        m_handlers.on_request(stream_id, std::move(req));
    }
}

void ServerSession::ApplyDeferredConsumption() {
    if (m_deferred_consume > 0) {
        nghttp2_session_consume_connection(m_session, m_deferred_consume);
        m_deferred_consume = 0;
    }
}

bool ServerSession::Receive(std::span<const uint8_t> data) {
    if (!nghttp2_session_want_read(m_session)) {
        return false;
    }
    const nghttp2_ssize rv{
        nghttp2_session_mem_recv2(m_session, data.data(), data.size())};
    ApplyDeferredConsumption();
    if (rv < 0) {
        m_flooded = rv == NGHTTP2_ERR_FLOODED;
        if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC) {
            // Tell the client why, if the library did not already.
            nghttp2_session_terminate_session(
                m_session,
                m_flooded ? NGHTTP2_ENHANCE_YOUR_CALM : NGHTTP2_PROTOCOL_ERROR);
        }
        return false;
    }
    return true;
}

bool ServerSession::Collect(Output &out, size_t max_bytes) {
    for (auto &body : m_retired) {
        out.Keep(std::move(body));
    }
    m_retired.clear();
    m_out = &out;
    m_out_limit = out.Size() + max_bytes;
    const int rv{nghttp2_session_send(m_session)};
    m_out = nullptr;
    ApplyDeferredConsumption();
    // Bodies retired while framing may be borrowed by `out`.
    for (auto &body : m_retired) {
        out.Keep(std::move(body));
    }
    m_retired.clear();
    return rv == 0;
}

bool ServerSession::WantsRead() const {
    return nghttp2_session_want_read(m_session) != 0;
}

bool ServerSession::WantsWrite() const {
    return nghttp2_session_want_write(m_session) != 0;
}

/** Whether a response field must not be sent over HTTP/2 (RFC 9113 8.2.2) */
static bool IsConnectionSpecific(std::string_view name) {
    namespace beast = boost::beast;
    return beast::iequals(name, "connection") ||
           beast::iequals(name, "keep-alive") ||
           beast::iequals(name, "proxy-connection") ||
           beast::iequals(name, "transfer-encoding") ||
           beast::iequals(name, "upgrade");
}

static std::string Lower(std::string_view in) {
    std::string out{in};
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? char(c - 'A' + 'a') : char(c);
    });
    return out;
}

/** Name/value storage for a HEADERS frame, kept until it is submitted */
struct HeaderBlock {
    std::vector<std::pair<std::string, std::string>> fields;
    std::vector<nghttp2_nv> nva;

    void Add(std::string name, std::string value) {
        fields.emplace_back(std::move(name), std::move(value));
    }
    const std::vector<nghttp2_nv> &Build() {
        nva.clear();
        for (auto &[name, value] : fields) {
            nva.push_back({reinterpret_cast<uint8_t *>(name.data()),
                           reinterpret_cast<uint8_t *>(value.data()),
                           name.size(), value.size(), NGHTTP2_NV_FLAG_NONE});
        }
        return nva;
    }
};

bool ServerSession::SubmitResponse(int32_t stream_id, Response &&res,
                                   bool head) {
    Stream *s{Find(stream_id)};
    if (!s) {
        return false;
    }
    HeaderBlock block;
    block.Add(":status", std::to_string(res.result_int()));
    for (const auto &f : res) {
        if (IsConnectionSpecific(f.name_string())) {
            continue;
        }
        block.Add(Lower(f.name_string()), std::string{f.value()});
    }
    const auto &nva{block.Build()};
    if (head || res.body().empty()) {
        return nghttp2_submit_response2(m_session, stream_id, nva.data(),
                                        nva.size(), nullptr) == 0;
    }
    s->body = std::make_unique<std::string>(std::move(res.body()));
    s->body_offset = 0;
    nghttp2_data_provider2 provider{};
    provider.source.ptr = s;
    provider.read_callback = Callbacks::ReadBody;
    return nghttp2_submit_response2(m_session, stream_id, nva.data(),
                                    nva.size(), &provider) == 0;
}

bool ServerSession::AcceptTunnel(int32_t stream_id, unsigned status,
                                 const Headers &headers) {
    Stream *s{Find(stream_id)};
    if (!s || s->kind != Stream::Kind::TUNNEL || s->tunnel_accepted) {
        return false;
    }
    HeaderBlock block;
    block.Add(":status", std::to_string(status));
    for (const auto &[name, value] : headers) {
        if (!IsConnectionSpecific(name)) {
            block.Add(Lower(name), value);
        }
    }
    const auto &nva{block.Build()};
    nghttp2_data_provider2 provider{};
    provider.source.ptr = s;
    provider.read_callback = Callbacks::ReadTunnel;
    s->tunnel_accepted = true;
    return nghttp2_submit_response2(m_session, stream_id, nva.data(),
                                    nva.size(), &provider) == 0;
}

void ServerSession::TunnelSend(int32_t stream_id, std::string_view data) {
    Stream *s{Find(stream_id)};
    if (!s || s->kind != Stream::Kind::TUNNEL || s->tunnel_end ||
        data.empty()) {
        return;
    }
    s->tunnel_tx.emplace_back(data);
    s->tunnel_tx_size += data.size();
    if (s->data_deferred) {
        s->data_deferred = false;
        nghttp2_session_resume_data(m_session, stream_id);
    }
}

size_t ServerSession::TunnelQueued(int32_t stream_id) const {
    const Stream *s{Find(stream_id)};
    return s ? s->tunnel_tx_size : 0;
}

void ServerSession::TunnelEnd(int32_t stream_id) {
    Stream *s{Find(stream_id)};
    if (!s || s->kind != Stream::Kind::TUNNEL || s->tunnel_end) {
        return;
    }
    s->tunnel_end = true;
    if (s->data_deferred) {
        s->data_deferred = false;
        nghttp2_session_resume_data(m_session, stream_id);
    }
}

void ServerSession::TunnelConsumed(int32_t stream_id, size_t n) {
    Stream *s{Find(stream_id)};
    if (!s) {
        return;
    }
    n = std::min(n, s->unconsumed);
    s->unconsumed -= n;
    nghttp2_session_consume(m_session, stream_id, n);
}

void ServerSession::Reset(int32_t stream_id, uint32_t error_code) {
    if (Find(stream_id)) {
        nghttp2_submit_rst_stream(m_session, NGHTTP2_FLAG_NONE, stream_id,
                                  error_code);
    }
}

void ServerSession::Shutdown() {
    nghttp2_submit_goaway(m_session, NGHTTP2_FLAG_NONE,
                          nghttp2_session_get_last_proc_stream_id(m_session),
                          NGHTTP2_NO_ERROR, nullptr, 0);
}

void ServerSession::Terminate(uint32_t error_code) {
    nghttp2_session_terminate_session(m_session, error_code);
}

size_t ServerSession::IncompleteRequests() const {
    return size_t(std::count_if(
        m_streams.begin(), m_streams.end(), [](const auto &entry) {
            return !entry.second->complete && !entry.second->remote_closed;
        }));
}

std::vector<int32_t> ServerSession::IncompleteRequestsSince(
    std::chrono::steady_clock::time_point cutoff) const {
    std::vector<int32_t> out;
    for (const auto &[id, s] : m_streams) {
        if (!s->complete && !s->remote_closed && s->started < cutoff) {
            out.push_back(id);
        }
    }
    return out;
}

} // namespace http2
