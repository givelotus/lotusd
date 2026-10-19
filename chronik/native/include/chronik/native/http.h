// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_HTTP_H
#define CHRONIK_NATIVE_HTTP_H

#include <chronik/native/types.h>

#include <array>
#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace google::protobuf {
class Message;
class MessageLite;
} // namespace google::protobuf

/**
 * Transport-neutral HTTP framework of the native Chronik, reproducing the
 * observable behaviour of the Rust axum 0.7 server (chronik-http/src/
 * server.rs): routing, 404 fallback, 405 + Allow, HEAD for GET routes, the
 * tower-http CORS layer, error-to-response mapping (error.rs), the protobuf
 * extractor/responder (protobuf.rs, validation.rs) and axum's path rejections.
 *
 * Transports (the standalone Beast listener, the node's in-process /chronik
 * handler) build an HttpRequest, call Router::Handle on the query pool (it may
 * block) and write the HttpResponse back.
 */
namespace chronik::native {

/** Consensus maximum transaction size in bytes (C++ MAX_TX_SIZE). */
constexpr size_t MAX_TX_SIZE = 1'000'000;
/** Maximum HTTP request body size for Chronik protobuf POSTs. */
constexpr size_t MAX_REQUEST_BODY_SIZE = 2 * MAX_TX_SIZE;
/** 'Content-Type' header for protobuf requests/responses */
constexpr std::string_view CONTENT_TYPE_PROTOBUF = "application/x-protobuf";
/** Content type axum uses for String/&str responses (rejections). */
constexpr std::string_view CONTENT_TYPE_TEXT = "text/plain; charset=utf-8";

/** Header name/value pair. Names are compared case-insensitively. */
using HttpHeader = std::pair<std::string, std::string>;

struct HttpRequest {
    /** "GET", "POST", "OPTIONS", "HEAD", ... (case-sensitive, as on wire) */
    std::string method;
    /**
     * Raw path as received (still percent-encoded), without the query and,
     * for the in-process transport, without the "/chronik" prefix.
     */
    std::string path;
    /** Raw query string (without '?'); empty if none. */
    std::string query_string;
    /** Whether the request target contained a '?' */
    bool has_query = false;
    /** Header fields as received, in order. */
    std::vector<HttpHeader> headers;
    Bytes body;
    /**
     * Set by the transport when the body exceeds its limit
     * (MAX_REQUEST_BODY_SIZE); `body` is then empty/partial. Reported as 413
     * by the protobuf extractor only (as axum's DefaultBodyLimit does).
     */
    bool body_too_large = false;
    /** Real client address (in-process) or socket peer, without port. */
    std::string peer_ip;

    /** First header with this name (case-insensitive). */
    const std::string *Header(std::string_view name) const;
    /** Path and query, as axum's Uri Display prints an origin-form URI. */
    std::string Target() const;
    /**
     * Query params decoded like axum's Query<HashMap<String, String>>
     * (application/x-www-form-urlencoded, '+' as space, lossy UTF-8, last
     * value of a repeated key wins).
     */
    std::map<std::string, std::string> QueryParams() const;
};

struct HttpResponse {
    int status = 200;
    /** Header fields in order (content-type included, if any). */
    std::vector<HttpHeader> headers;
    Bytes body;

    const std::string *Header(std::string_view name) const;
    void SetHeader(std::string name, std::string value);
    /** Content-Type, or empty if not set. */
    std::string ContentType() const;

    /** 200 application/x-protobuf with the serialized message. */
    static HttpResponse Protobuf(const google::protobuf::MessageLite &msg,
                                 int status = 200);
    /** text/plain; charset=utf-8 body, like an axum String response. */
    static HttpResponse Text(int status, std::string_view text);
    /** Empty body, no content type (e.g. 405). */
    static HttpResponse Empty(int status);
};

/**
 * Logging hook: (message, debug_category_only). debug_category_only=true
 * corresponds to Rust's log_chronik! (logged in the "chronik" debug
 * category), false to log! (always logged).
 */
using HttpLogFn = std::function<void(std::string_view, bool)>;

/**
 * An axum extractor rejection: plain text body with a status, sent as-is
 * (not as a protobuf error). Thrown by the path-parameter helpers.
 */
class HttpRejection : public std::exception {
public:
    HttpRejection(int status, std::string body)
        : m_status(status), m_body(std::move(body)) {}
    int Status() const { return m_status; }
    const std::string &Body() const { return m_body; }
    const char *what() const noexcept override { return m_body.c_str(); }

private:
    int m_status;
    std::string m_body;
};

/**
 * Port of chronik-http error.rs `report_status_error`: maps an error message
 * to (status, proto Error msg). Messages with a "NNN: " prefix keep it; 5xx
 * are logged. Unprefixed messages become 500 "Unknown error, contact admins"
 * and are logged.
 */
struct StatusError {
    int status;
    std::string msg;
};
StatusError ReportStatusError(std::string_view error_msg,
                              const HttpLogFn &log = {});
/** Same, as a protobuf HTTP response (proto::Error{msg}). */
HttpResponse ErrorResponse(std::string_view error_msg,
                           const HttpLogFn &log = {});
/** Maps any exception: ChronikError/std::exception what(), HttpRejection. */
HttpResponse ExceptionResponse(const std::exception &err,
                               const HttpLogFn &log = {});

/**
 * Port of validation.rs check_content_type: throws ChronikError
 * "400: No Content-Type set" / "400: Content-Type bad encoding: ..." /
 * "400: Content-Type must be <expected>, got <actual>".
 */
void CheckContentType(const HttpRequest &req, std::string_view expected);

/**
 * Port of the protobuf.rs extractor: check Content-Type, then the body limit
 * ("413: Request body exceeds maximum size of 2000000 bytes"), then decode
 * (errors "400: Bad protobuf: <prost DecodeError Display>").
 */
void ParseProtobufRequest(const HttpRequest &req,
                          google::protobuf::Message &out);
template <typename P> P ParseProtobufRequest(const HttpRequest &req) {
    P msg;
    ParseProtobufRequest(req, msg);
    return msg;
}

/**
 * Validate `data` against `msg`'s descriptor exactly like prost 0.11's
 * Message::decode, and return its DecodeError Display text
 * ("failed to decode Protobuf message: [Msg.field: ...]<description>"), or
 * nullopt if prost would accept it. Used to reproduce the Rust error strings
 * on the wire; parsing itself is done by libprotobuf.
 */
std::optional<std::string>
ProstDecodeError(const google::protobuf::Message &msg, ByteView data);

/**
 * Decode `data` into `out` (Message::decode semantics), throwing a
 * ChronikError with the prost DecodeError Display text (no status prefix).
 */
void DecodeProtobuf(ByteView data, google::protobuf::Message &out);

/** Percent-decoded path parameters, in pattern order. */
struct PathParams {
    std::vector<std::string> names;
    std::vector<std::string> values;
    size_t size() const { return values.size(); }
    const std::string &operator[](size_t i) const { return values[i]; }
};

/**
 * Typed path parameter extraction with axum's Path<T> rejections (400,
 * text/plain, "Invalid URL: Cannot parse ..."):
 *  - PathI32(params, i) for Path<(i32, i32, ...)> (tuple):
 *    "Invalid URL: Cannot parse value at index {i} with value `{v:?}` to a
 *    `i32`"
 *  - PathSingleI32(params) for Path<i32>:
 *    "Invalid URL: Cannot parse `{v:?}` to a `i32`"
 */
int32_t PathI32(const PathParams &params, size_t index);
int32_t PathSingleI32(const PathParams &params);
uint32_t PathU32(const PathParams &params, size_t index);

/** Rust `{:?}` formatting of a str (quoted, escape_debug). */
std::string RustDebugStr(std::string_view s);

using HttpHandler =
    std::function<HttpResponse(const HttpRequest &, const PathParams &)>;

struct RouterOptions {
    /** -chronikcors: tower-http CorsLayer allow_origin(any) allow_methods(any) */
    bool enable_cors = false;
    HttpLogFn log;
    /** Optional host observer. Bound before publication; must be noexcept,
     * non-blocking and never re-enter the router/indexer. Duration is nanoseconds. */
    std::function<void(std::string_view, uint16_t, uint64_t)> observe_request;
};

/**
 * Method + path router with axum 0.7 (matchit) semantics:
 *  - patterns like "/script/:type/:payload/utxos"; a ":param" matches one
 *    segment, which may be empty except as the last segment of the path;
 *    static segments take priority over params;
 *  - no matching path -> fallback (default: protobuf 404
 *    "404: Not found: <path?query>", port of handlers::handle_not_found);
 *  - matching path, unregistered method -> 405, empty body, Allow header
 *    listing the registered methods in registration order (GET adds
 *    "GET,HEAD"), HEAD served by the GET handler with the body stripped;
 *  - handler exceptions -> ExceptionResponse;
 *  - CORS (if enabled) as tower-http 0.5 CorsLayer: every OPTIONS request is
 *    answered as a preflight; other responses get Access-Control-Allow-Origin
 *    and Vary.
 * Handle() is thread-safe once all routes are added, and may block (it runs
 * handlers): transports must call it on the query pool, never on io threads.
 */
class Router {
public:
    explicit Router(RouterOptions opts = {});
    ~Router();
    Router(Router &&) noexcept;
    Router &operator=(Router &&) noexcept;

    void Add(std::string_view method, std::string_view pattern,
             HttpHandler handler);
    void Get(std::string_view pattern, HttpHandler h) {
        Add("GET", pattern, std::move(h));
    }
    void Post(std::string_view pattern, HttpHandler h) {
        Add("POST", pattern, std::move(h));
    }
    /**
     * POST route with an explicit OPTIONS handler answering 200
     * "Allow: OPTIONS, HEAD, POST" (server.rs handle_post_options).
     */
    void PostWithOptions(std::string_view pattern, HttpHandler h);
    /**
     * WebSocket route (GET). Transports upgrade a request when
     * IsWebSocketUpgrade() is true; otherwise Handle() returns axum's
     * WebSocketUpgrade rejection for it.
     */
    void AddWebSocket(std::string_view pattern);
    void SetFallback(HttpHandler handler);

    HttpResponse Handle(const HttpRequest &req) const;

    /**
     * Whether `req` is a valid WebSocket upgrade for a WebSocket route (all
     * axum WebSocketUpgrade checks pass).
     */
    bool IsWebSocketUpgrade(const HttpRequest &req) const;
    /** Extra headers for the 101 response (CORS), as tower-http adds. */
    std::vector<HttpHeader> UpgradeResponseHeaders(const HttpRequest &req) const;

    const RouterOptions &Options() const { return m_opts; }

private:
    struct Route;
    struct Segment;
    const Route *Match(std::string_view path,
                       std::vector<std::string_view> &raw_params) const;
    HttpResponse Dispatch(const HttpRequest &req) const;
    void ApplyCors(HttpResponse &resp) const;

    RouterOptions m_opts;
    std::vector<std::unique_ptr<Route>> m_routes;
    HttpHandler m_fallback;
};

/** Port of parse.rs: hex and LOKAD ID parsing with Rust error strings. */
/** "400: Invalid hex: <hex::FromHexError>" */
Bytes ParseHex(std::string_view payload);
/** hex 0.4 FromHexError Display, or nullopt if valid */
std::optional<std::string> HexDecodeError(std::string_view payload);
/** "400: Invalid LOKAD ID length: expected 4 but got N" */
std::array<uint8_t, 4> ParseLokadId(ByteView lokad_id);
std::array<uint8_t, 4> ParseLokadIdHex(std::string_view lokad_id_hex);

} // namespace chronik::native

#endif // CHRONIK_NATIVE_HTTP_H
