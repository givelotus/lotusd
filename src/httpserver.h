// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HTTPSERVER_H
#define BITCOIN_HTTPSERVER_H

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

static const int DEFAULT_HTTP_THREADS = 4;
static const int DEFAULT_HTTP_WORKQUEUE = 16;
static const int DEFAULT_HTTP_SERVER_TIMEOUT = 30;
//! Threads doing socket I/O, TLS and WebSocket framing for the HTTP server.
static const int DEFAULT_HTTP_IO_THREADS = 2;
static const bool DEFAULT_HTTP_TLS_EPHEMERAL = true;
static const bool DEFAULT_HTTP_TLS_MUTUAL = false;
static const char *const HTTP_TLS_CERT_FILENAME = "node_tls_cert.pem";
static const char *const HTTP_TLS_KEY_FILENAME = "node_tls_key.pem";
//! Replies at least this large are zstd-compressed if the client accepts it.
static const size_t HTTP_ZSTD_MIN_REPLY_SIZE = 512;
//! Serve /chronik/* (incl. /chronik/ws) on the RPC port when Chronik is on.
static const bool DEFAULT_CHRONIK_PUBLIC_ON_RPC_PORT = true;

/**
 * Opaque token kept for source compatibility with code that used to queue
 * libevent timers. It now identifies the HTTP server's Boost.Asio I/O context.
 */
struct event_base;
struct HTTPRequestImpl;

class Config;
class CService;
class HTTPRequest;

/**
 * Initialize HTTP server.
 * Call this before RegisterHTTPHandler or EventBase().
 */
bool InitHTTPServer(Config &config);

/**
 * Start HTTP server.
 * This is separate from InitHTTPServer to give users race-condition-free time
 * to register their handlers between InitHTTPServer and StartHTTPServer.
 */
void StartHTTPServer();

/** Interrupt HTTP server threads */
void InterruptHTTPServer();

/** Stop HTTP server */
void StopHTTPServer();

/** Change logging level for libevent (still used by torcontrol). */
void UpdateHTTPServerLogging(bool enable);

/** Handler for requests to a certain HTTP path */
typedef std::function<bool(Config &config, HTTPRequest *req,
                           const std::string &)>
    HTTPRequestHandler;

/** Coroutine handler for requests to a certain HTTP path */
using HTTPAsyncRequestHandler = std::function<boost::asio::awaitable<bool>(
    Config &config, HTTPRequest *req, const std::string &,
    boost::asio::any_io_executor)>;

/**
 * Register handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */
void RegisterHTTPHandler(const std::string &prefix, bool exactMatch,
                         const HTTPRequestHandler &handler);

/**
 * Register coroutine handler for prefix.
 * If multiple handlers match a prefix, the first-registered one will
 * be invoked.
 */
void RegisterHTTPAsyncHandler(const std::string &prefix, bool exactMatch,
                              const HTTPAsyncRequestHandler &handler);

/**
 * Exempt requests whose URI is `prefix`, or continues it with '/' or '?', from
 * the -rpcallowip address check. Handlers for such paths must not rely on the
 * ACL. Call before StartHTTPServer.
 */
void RegisterPublicHTTPPrefix(const std::string &prefix);

/** Unregister handler for prefix */
void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch);

/** Release/reacquire an HTTP workqueue slot while a coroutine is suspended. */
void HTTPReleaseWorkQueueSlot() noexcept;
void HTTPAcquireWorkQueueSlot() noexcept;

class HTTPScopedWaitSuspension {
public:
    HTTPScopedWaitSuspension() noexcept { HTTPReleaseWorkQueueSlot(); }
    ~HTTPScopedWaitSuspension() noexcept { HTTPAcquireWorkQueueSlot(); }
    HTTPScopedWaitSuspension(const HTTPScopedWaitSuspension &) = delete;
    HTTPScopedWaitSuspension &
    operator=(const HTTPScopedWaitSuspension &) = delete;
};

/** Return the HTTP coroutine thread pool executor if running. */
boost::asio::any_io_executor GetHTTPThreadPoolExecutor();

/**
 * Return an opaque, non-null token for the HTTP server's I/O context once the
 * server is initialized. This can be passed to HTTPEvent to queue timers or
 * cross-thread triggers.
 */
struct event_base *EventBase();

/**
 * Parse a raw HTTP/1.1 request (request line, headers and body). Returns
 * nullptr if it is not a complete, valid request. The returned request is not
 * connected to any client: replies are discarded. Used by tests and fuzzers.
 */
std::unique_ptr<HTTPRequest> ParseHTTPRequestForTesting(const std::string &raw);

/**
 * In-flight HTTP request.
 * Thin C++ wrapper around a Boost.Beast request and its pending response.
 */
class HTTPRequest {
private:
    std::unique_ptr<HTTPRequestImpl> m_impl;
    bool replySent;

public:
    explicit HTTPRequest(std::unique_ptr<HTTPRequestImpl> impl,
                         bool replySent = false);
    ~HTTPRequest();

    enum RequestMethod { UNKNOWN, GET, POST, HEAD, PUT, OPTIONS };

    /** Get requested URI */
    std::string GetURI() const;

    /** Get CService (address:ip) for the origin of the http request */
    CService GetPeer() const;

    /** Get request method */
    RequestMethod GetRequestMethod() const;

    /** Whether the request arrived over TLS (https:// or wss://) */
    bool IsTLS() const;

    /**
     * Hex SHA-256 fingerprint of the TLS client certificate, or an empty
     * string if none was presented (see -tlsmutual).
     */
    std::string GetClientCertFingerprint() const;

    /**
     * Get the query parameter value from request uri for a specified key, or
     * std::nullopt if the key is not found.
     *
     * If the query string contains duplicate keys, the first value is
     * returned. Many web frameworks would instead parse this as an array of
     * values, but this is not (yet) implemented as it is currently not needed
     * in any of the endpoints.
     *
     * @param[in] key represents the query parameter of which the value is
     *                returned
     */
    std::optional<std::string> GetQueryParameter(const std::string &key) const;

    /**
     * Get the request header specified by hdr, or an empty string.
     * Return a pair (isPresent,string).
     */
    std::pair<bool, std::string> GetHeader(const std::string &hdr) const;

    /**
     * Read request body. A "Content-Encoding: zstd" body is decompressed.
     *
     * @note As this consumes the underlying buffer, call this only once.
     * Repeated calls will return an empty string.
     */
    std::string ReadBody();

    /**
     * Write output header.
     *
     * @note call this before calling WriteErrorReply or Reply.
     */
    void WriteHeader(const std::string &hdr, const std::string &value);

    /**
     * Write HTTP reply.
     * nStatus is the HTTP status code to send.
     * strReply is the body of the reply. Keep it empty to send a standard
     * message. Replies of at least HTTP_ZSTD_MIN_REPLY_SIZE bytes are sent
     * with "Content-Encoding: zstd" when the client's Accept-Encoding allows
     * it and no Content-Encoding header was written.
     * Pass an rvalue (e.g. std::move) to hand the body over without copying.
     *
     * @note Can be called only once. As this will give the request back to the
     * main thread, do not call any other HTTPRequest methods after calling
     * this.
     */
    void WriteReply(int nStatus, std::string strReply = "");
};

/**
 * Get the query parameter value from request uri for a specified key, or
 * std::nullopt if the key is not found.
 *
 * If the query string contains duplicate keys, the first value is returned.
 * Many web frameworks would instead parse this as an array of values, but
 * this is not (yet) implemented as it is currently not needed in any of the
 * endpoints.
 *
 * Helper function for HTTPRequest::GetQueryParameter.
 *
 * @param[in] uri is the entire request uri
 * @param[in] key represents the query parameter of which the value is returned
 */
std::optional<std::string> GetQueryParameterFromUri(const char *uri,
                                                    const std::string &key);

/** Event handler closure */


/**
 * Event class. This can be used either as a cross-thread trigger or as a
 * timer.
 */
class HTTPEvent {
public:
    /**
     * Create a new event.
     * deleteWhenTriggered deletes this event object after the event is
     * triggered (and the handler called)
     * handler is the handler to call when the event is triggered.
     */
    HTTPEvent(struct event_base *base, bool deleteWhenTriggered,
              const std::function<void()> &handler);
    ~HTTPEvent();

    /**
     * Trigger the event. If tv is 0, trigger it immediately. Otherwise trigger
     * it after the given time has elapsed.
     */
    void trigger(struct timeval *tv);

    bool deleteWhenTriggered;
    std::function<void()> handler;

private:
    struct State;
    std::shared_ptr<State> m_state;
};

/**
 * Chronik on the HTTP server (-chronikpubliconrpcport).
 *
 * The running Chronik implementation registers handlers that serve /chronik
 * requests and /chronik/ws WebSocket sessions in process, with the client
 * address seen on the HTTP server's socket. Public-prefix rules, TLS, zstd
 * compression, response framing and WebSocket pings stay the HTTP server's.
 * Without handlers, /chronik answers 503. The types carry no Chronik
 * dependency.
 */
struct InProcessHTTPRequest {
    std::string method;
    //! Target with the /chronik prefix stripped (starts with '/')
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    //! Real client address, without port
    std::string peer_ip;
};

struct InProcessHTTPResponse {
    int status{200};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

/** Server side of an in-process WebSocket session; thread-safe. */
class InProcessWebSocket {
public:
    virtual ~InProcessWebSocket() = default;
    //! Queue a binary message (non-blocking)
    virtual void SendBinary(std::string msg) = 0;
    //! Close with a normal closure
    virtual void Close() = 0;
    //! Restart the idle-ping timer
    virtual void NotifyActivity() = 0;
};

/**
 * Receiver of one in-process WebSocket session. Called on HTTP server I/O
 * threads, one call at a time and in order, so it must not block. OnClosed is
 * called exactly once, last.
 */
class InProcessWebSocketHandler {
public:
    virtual ~InProcessWebSocketHandler() = default;
    virtual void OnBinary(std::string msg) = 0;
    virtual void OnText() = 0;
    virtual void OnClosed() = 0;
};

struct ChronikInProcessHandlers {
    /**
     * Handle a request; `done` is called exactly once, from any thread. Must
     * not block.
     */
    std::function<void(InProcessHTTPRequest,
                       std::function<void(InProcessHTTPResponse)>)>
        http;
    /**
     * For an upgrade request to /chronik/ws...: the extra headers of the 101
     * response if it is a valid WebSocket upgrade, nullopt to serve it as an
     * HTTP request instead.
     */
    std::function<std::optional<std::vector<std::pair<std::string, std::string>>>(
        const InProcessHTTPRequest &)>
        ws_check;
    //! Create the handler of an accepted session
    std::function<std::unique_ptr<InProcessWebSocketHandler>(
        std::shared_ptr<InProcessWebSocket>, const std::string &peer_ip)>
        ws_open;
    std::chrono::milliseconds ws_ping_interval{std::chrono::seconds{45}};
    std::string ws_ping_payload;
    size_t ws_max_message_size{20000};
};

/**
 * Serve /chronik with `handlers` (nullptr: answer 503 again). Clearing also
 * closes the open /chronik/ws sessions.
 */
void SetChronikInProcessHandlers(
    std::shared_ptr<const ChronikInProcessHandlers> handlers);

#endif // BITCOIN_HTTPSERVER_H
