// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <compat/compat.h>
#include <config.h>
#include <logging.h>
#include <net_websocket.h>
#include <net_websocket_bridge.h>
#include <net_websocket_sock.h>
#include <net_websocket_tls.h>
#include <netbase.h>
#include <protocol.h>
#include <node/ui_interface.h>
#include <random.h>
#include <rpc/protocol.h> // For HTTP status codes
#include <shutdown.h>
#include <sync.h>
#include <http_tls_stream.h>
#include <tls_util.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/translation.h>

// libevent is no longer used by the HTTP server, but torcontrol still uses it
// and its logging is configured from here.
#include <event2/event.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <zstd.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <rpc/async_waiter.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <deque>
#include <map>
#include <unordered_map>
#include <memory>
#include <thread>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/stat.h>
#endif

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;
using namespace boost::asio::experimental::awaitable_operators;

/** Maximum size of http request (request line + headers) */
static const size_t MAX_HEADERS_SIZE = 8192;

/**
 * Maximum HTTP post body size. Twice the maximum block size is added to this
 * value in practice.
 */
static const size_t MIN_SUPPORTED_BODY_SIZE = 0x02000000;

using BeastRequest = http::request<http::string_body>;
using BeastResponse = http::response<http::string_body>;

/** Backing store of an HTTPRequest (see httpserver.h). */
struct HTTPRequestImpl {
    BeastRequest beast_req;
    BeastResponse beast_res;
    CService peer_address;
    bool is_tls{false};
    std::string client_cert_fingerprint_hex;
    uint64_t max_body_size{0};
    //! Delivers the finished response to the connection that owns the
    //! request. May be called from any thread. Empty for detached requests.
    std::function<void(BeastResponse &&)> send_reply_fn;
};

/** HTTP request work item */
class HTTPWorkItem final {
public:
    HTTPWorkItem(Config &_config, std::unique_ptr<HTTPRequest> _req,
                 const std::string &_path, const HTTPAsyncRequestHandler &_func)
        : req(std::move(_req)), path(_path), func(_func), config(&_config) {}

    boost::asio::awaitable<void>
    ExecuteAsync(boost::asio::any_io_executor executor) {
        co_await func(*config, req.get(), path, std::move(executor));
        co_return;
    }

    std::unique_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPAsyncRequestHandler func;
    Config *config;
};

/**
 * Non-blocking Boost.Asio coroutine dispatcher pool for HTTP requests.
 * Suspended long-polls yield workers, but still count toward the bounded
 * request capacity: configured workqueue depth plus worker count, matching
 * the maximum queued/running request count of the upstream dispatcher.
 */
class HTTPCoroutinePool {
private:
    Mutex m_mutex;
    std::condition_variable m_cv GUARDED_BY(m_mutex);
    bool m_running GUARDED_BY(m_mutex){true};
    size_t m_queued_requests GUARDED_BY(m_mutex){0};
    size_t m_total_in_flight GUARDED_BY(m_mutex){0};
    const size_t m_max_depth;
    size_t m_max_in_flight{0};
    std::unique_ptr<boost::asio::thread_pool> m_pool;
    std::atomic<size_t> m_suspended_coroutines{0};
    std::unordered_map<
        uint64_t,
        std::weak_ptr<boost::asio::strand<boost::asio::any_io_executor>>>
        m_conn_strands GUARDED_BY(m_mutex);

public:
    explicit HTTPCoroutinePool(size_t max_depth) : m_max_depth(max_depth) {}
    ~HTTPCoroutinePool() { WaitExit(); }

    void Start(int num_threads) {
        const size_t threads = static_cast<size_t>(std::max(1, num_threads));
        m_max_in_flight = m_max_depth + threads;
        m_pool = std::make_unique<boost::asio::thread_pool>(threads);
        for (size_t i = 0; i < threads; ++i) {
            boost::asio::post(*m_pool, [i]() {
                util::ThreadRename(strprintf("httpworker.%zu", i));
            });
        }
    }

    boost::asio::any_io_executor GetExecutor() const {
        if (!m_pool) {
            return {};
        }
        return m_pool->get_executor();
    }

    bool Enqueue(uint64_t conn,
                 std::unique_ptr<HTTPWorkItem> &item)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        std::shared_ptr<boost::asio::strand<boost::asio::any_io_executor>>
            strand;
        {
            LOCK(m_mutex);
            if (!m_running || !m_pool || m_queued_requests >= m_max_depth ||
                m_total_in_flight >= m_max_in_flight) {
                return false;
            }
            ++m_queued_requests;
            ++m_total_in_flight;

            if (conn != 0) {
                auto &weak_strand = m_conn_strands[conn];
                strand = weak_strand.lock();
                if (!strand) {
                    strand = std::make_shared<
                        boost::asio::strand<boost::asio::any_io_executor>>(
                        m_pool->get_executor());
                    weak_strand = strand;
                }
                if (m_conn_strands.size() > 256) {
                    for (auto it = m_conn_strands.begin();
                         it != m_conn_strands.end();) {
                        if (it->second.expired()) {
                            it = m_conn_strands.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
            } else {
                strand = std::make_shared<
                    boost::asio::strand<boost::asio::any_io_executor>>(
                    m_pool->get_executor());
            }
        }

        HTTPWorkItem *raw_item = item.release();
        boost::asio::any_io_executor pool_exec = m_pool->get_executor();
        boost::asio::co_spawn(
            *strand,
            [this, strand, raw_item,
             pool_exec]() -> boost::asio::awaitable<void> {
                std::unique_ptr<HTTPWorkItem> owned_item(raw_item);
                {
                    LOCK(m_mutex);
                    if (m_queued_requests > 0) {
                        --m_queued_requests;
                    }
                }
                struct InFlightGuard {
                    HTTPCoroutinePool *pool;
                    ~InFlightGuard() {
                        LOCK(pool->m_mutex);
                        if (--pool->m_total_in_flight == 0) {
                            pool->m_cv.notify_all();
                        }
                    }
                } guard{this};

                co_await owned_item->ExecuteAsync(pool_exec);
                co_return;
            },
            boost::asio::detached);
        return true;
    }

    void OnSuspend() noexcept {
        m_suspended_coroutines.fetch_add(1, std::memory_order_relaxed);
    }

    void OnResume() noexcept {
        m_suspended_coroutines.fetch_sub(1, std::memory_order_relaxed);
    }

    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        {
            LOCK(m_mutex);
            m_running = false;
        }
        GetRPCBlockChangeWaiter().NotifyAll();
    }

    void WaitExit() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        Interrupt();
        {
            WAIT_LOCK(m_mutex, lock);
            m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_total_in_flight == 0;
            });
            m_conn_strands.clear();
        }
        if (m_pool) {
            m_pool->join();
            m_pool.reset();
        }
    }
};

struct HTTPPathHandler {
    HTTPPathHandler(std::string _prefix, bool _exactMatch,
                    HTTPAsyncRequestHandler _handler)
        : prefix(std::move(_prefix)), exactMatch(_exactMatch),
          handler(std::move(_handler)) {}
    std::string prefix;
    bool exactMatch;
    HTTPAsyncRequestHandler handler;
};

/** HTTP module state */

//! I/O context running accept loops, connections and HTTPEvent timers. It is
//! never destroyed once created so that late HTTPEvent destructors are safe.
static std::unique_ptr<asio::io_context> g_io;
//! Listening sockets, each bound to its own strand
struct HTTPListener {
    std::unique_ptr<tcp::acceptor> acceptor;
    //! A -publicbind listener: serves only public paths, to anyone
    bool public_only{false};
};
static std::vector<HTTPListener> g_acceptors;
//! TLS context for connections detected as TLS, if TLS is enabled
static tls::SslCtxPtr g_ssl_ctx;
//! The configuration handlers are invoked with
static Config *g_config{nullptr};
//! Maximum accepted request body size
static uint64_t g_max_body_size{MIN_SUPPORTED_BODY_SIZE};
//! Idle/read/write timeout
static std::chrono::seconds g_server_timeout{DEFAULT_HTTP_SERVER_TIMEOUT};
//! Set by InterruptHTTPServer: reject new requests with 503
static std::atomic<bool> g_reject_requests{false};
//! List of subnets to allow RPC connections from
static std::vector<CSubNet> rpc_allow_subnets;
//! Coroutine pool for handling requests off the event loop thread
static std::unique_ptr<HTTPCoroutinePool> g_work_queue{nullptr};
//! Handlers for (sub)paths
static std::vector<HTTPPathHandler> pathHandlers;
//! URI prefixes served on -publicbind listeners (P2P WebSocket, Chronik).
//! Everything else is only served on the RPC listeners, to -rpcallowip.
static std::vector<std::string> g_public_prefixes;

//! Whether /chronik is served (-chronik and -chronikpubliconrpcport)
static bool g_chronik_enabled{false};

//! Whether /p2p/ws is served
static bool g_p2p_websocket_enabled{false};
//! Use X-Forwarded-For of /p2p/ws upgrades coming from loopback
static bool g_p2p_websocket_trust_forwarded_for{false};
//! Debug: bridge every /p2p/ws peer through a socketpair (-p2pwebsocketbridge)
static bool g_p2p_websocket_force_bridge{false};
static Mutex g_p2p_websocket_mutex;
//! Receiver of /p2p/ws peers (CConnman), set once the node is ready
static P2PWebSocketAcceptor
    g_p2p_websocket_acceptor GUARDED_BY(g_p2p_websocket_mutex);
static const std::string CHRONIK_PREFIX{"/chronik"};
//! Maximum size of a Chronik response
static const uint64_t MAX_CHRONIK_RESPONSE_SIZE = 256 * 1024 * 1024;

/**
 * Tracks live connections (so they can be closed on shutdown) and requests
 * whose reply has not been written yet (so shutdown can wait for them).
 */
class HTTPConnectionTracker {
private:
    mutable Mutex m_mutex;
    mutable std::condition_variable m_cv;
    uint64_t m_next_id GUARDED_BY(m_mutex){0};
    //! Native socket handle of each open connection
    std::map<uint64_t, SOCKET> m_connections GUARDED_BY(m_mutex);
    size_t m_active_requests GUARDED_BY(m_mutex){0};

public:
    uint64_t AddConnection(SOCKET fd) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        const uint64_t id{m_next_id++};
        m_connections.emplace(id, fd);
        return id;
    }
    void RemoveConnection(uint64_t id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        m_connections.erase(id);
    }
    void AddRequest() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        WITH_LOCK(m_mutex, ++m_active_requests);
    }
    void RemoveRequest() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        if (m_active_requests > 0 && --m_active_requests == 0) {
            m_cv.notify_all();
        }
    }
    size_t CountActiveRequests() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        return WITH_LOCK(m_mutex, return m_active_requests);
    }
    //! Wait until every dispatched request has had its reply written
    void WaitUntilNoActiveRequests() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        WAIT_LOCK(m_mutex, lock);
        m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_active_requests == 0;
        });
    }
    //! Shut down every open connection. Pending reads and writes on them
    //! complete with an error, which ends their coroutines. Only the OS
    //! socket is touched, so this is safe from any thread.
    void ShutdownAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        LOCK(m_mutex);
        for (const auto &[id, fd] : m_connections) {
#ifdef WIN32
            ::shutdown(fd, SD_BOTH);
#else
            ::shutdown(fd, SHUT_RDWR);
#endif
        }
    }
};
static HTTPConnectionTracker g_connections;

/** Whether uri is prefix itself or continues it with '/' or '?' */
static bool URIHasPathPrefix(std::string_view uri, std::string_view prefix) {
    if (uri.substr(0, prefix.size()) != prefix) {
        return false;
    }
    return uri.size() == prefix.size() || uri[prefix.size()] == '/' ||
           uri[prefix.size()] == '?';
}

static bool IsPublicPath(std::string_view uri) {
    return std::any_of(g_public_prefixes.begin(), g_public_prefixes.end(),
                       [&](const std::string &prefix) {
                           return URIHasPathPrefix(uri, prefix);
                       });
}

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed(const CNetAddr &netaddr) {
    if (!netaddr.IsValid()) {
        return false;
    }
    for (const CSubNet &subnet : rpc_allow_subnets) {
        if (subnet.Match(netaddr)) {
            return true;
        }
    }
    return false;
}

/** Initialize ACL list for HTTP server */
static bool InitHTTPAllowList() {
    rpc_allow_subnets.clear();
    // always allow IPv4 local subnet
    rpc_allow_subnets.push_back(
        CSubNet{LookupHost("127.0.0.1", false).value(), 8});
    // always allow IPv6 localhost
    rpc_allow_subnets.push_back(CSubNet{LookupHost("::1", false).value()});
    for (const std::string &strAllow : gArgs.GetArgs("-rpcallowip")) {
        CSubNet subnet;
        LookupSubNet(strAllow, subnet);
        if (!subnet.IsValid()) {
            uiInterface.ThreadSafeMessageBox(
                strprintf(
                    Untranslated("Invalid -rpcallowip subnet specification: "
                                 "%s. Valid are a single IP (e.g. 1.2.3.4), a "
                                 "network/netmask (e.g. 1.2.3.4/255.255.255.0) "
                                 "or a network/CIDR (e.g. 1.2.3.4/24)."),
                    strAllow),
                "", CClientUIInterface::MSG_ERROR);
            return false;
        }
        rpc_allow_subnets.push_back(subnet);
    }
    std::string strAllowed;
    for (const CSubNet &subnet : rpc_allow_subnets) {
        strAllowed += subnet.ToString() + " ";
    }
    LogDebug(BCLog::HTTP, "Allowing HTTP connections from: %s\n", strAllowed);
    return true;
}

/** HTTP request method as string - use for logging only */
std::string RequestMethodString(HTTPRequest::RequestMethod m) {
    switch (m) {
        case HTTPRequest::GET:
            return "GET";
        case HTTPRequest::POST:
            return "POST";
        case HTTPRequest::HEAD:
            return "HEAD";
        case HTTPRequest::PUT:
            return "PUT";
        case HTTPRequest::OPTIONS:
            return "OPTIONS";
        default:
            return "unknown";
    }
}

/** Whether a comma-separated header value lists `token` (q=0 excluded) */
static bool HeaderListsToken(std::string_view value, std::string_view token) {
    while (!value.empty()) {
        const size_t comma{value.find(',')};
        std::string_view item{value.substr(0, comma)};
        value = comma == std::string_view::npos ? std::string_view{}
                                                : value.substr(comma + 1);
        std::string_view params;
        if (const size_t semi{item.find(';')}; semi != std::string_view::npos) {
            params = item.substr(semi + 1);
            item = item.substr(0, semi);
        }
        item = util::TrimStringView(item);
        if (!beast::iequals(item, token)) {
            continue;
        }
        // Reject an explicit "q=0" / "q=0.0" weight.
        params = util::TrimStringView(params);
        if (params.size() >= 3 && (params[0] == 'q' || params[0] == 'Q') &&
            params[1] == '=' &&
            params.substr(2).find_first_not_of("0.") ==
                std::string_view::npos) {
            return false;
        }
        return true;
    }
    return false;
}

/**
 * Replace the response body by its zstd compression if the request accepts
 * it, the body is large enough and no other encoding is set.
 */
static void MaybeCompressZstd(const BeastRequest &req, BeastResponse &res) {
    if (res.body().size() < HTTP_ZSTD_MIN_REPLY_SIZE ||
        res.find(http::field::content_encoding) != res.end()) {
        return;
    }
    auto ae = req.find(http::field::accept_encoding);
    if (ae == req.end() || !HeaderListsToken(ae->value(), "zstd")) {
        return;
    }
    const std::string &in = res.body();
    std::string out(ZSTD_compressBound(in.size()), '\0');
    const size_t n{ZSTD_compress(out.data(), out.size(), in.data(), in.size(),
                                 /*compressionLevel=*/1)};
    if (ZSTD_isError(n)) {
        return;
    }
    out.resize(n);
    res.body() = std::move(out);
    res.set(http::field::content_encoding, "zstd");
    res.set(http::field::vary, "Accept-Encoding");
}

/** Fill in fields of a response that libevent used to add by default */
static void FinalizeResponse(BeastResponse &res, unsigned version) {
    res.version(version);
    if (res.find(http::field::content_type) == res.end()) {
        res.set(http::field::content_type, "text/html; charset=ISO-8859-1");
    }
    res.prepare_payload();
}

static BeastResponse MakeSimpleResponse(int status, unsigned version,
                                        std::string body = {}) {
    BeastResponse res{static_cast<http::status>(status), version};
    res.body() = std::move(body);
    FinalizeResponse(res, version);
    return res;
}

/**
 * One-shot rendezvous between a worker thread producing a reply and the
 * connection coroutine waiting for it. Only touched on the connection's
 * strand.
 */
struct ReplySlot {
    asio::steady_timer timer;
    std::optional<BeastResponse> response;
    explicit ReplySlot(const asio::any_io_executor &exec)
        : timer(exec, asio::steady_timer::time_point::max()) {}
};

/** Per-connection facts shared by every request on it */
struct HTTPConnectionInfo {
    uint64_t connection_id{0};
    bool public_only{false};
    CService peer;
    CService local;
    bool is_tls{false};
    std::string client_cert_fingerprint_hex;
};

/**
 * Route a parsed request (the logic of the former libevent http_request_cb)
 * and wait for its reply.
 */
static asio::awaitable<BeastResponse>
DispatchRequest(BeastRequest &&beast_req, const HTTPConnectionInfo &conn) {
    const unsigned version{beast_req.version()};
    auto executor{co_await asio::this_coro::executor};

    g_connections.AddRequest();
    if (g_reject_requests.load()) {
        LogDebug(BCLog::HTTP, "Rejecting request while shutting down\n");
        co_return MakeSimpleResponse(HTTP_SERVICE_UNAVAILABLE, version);
    }

    auto slot{std::make_shared<ReplySlot>(executor)};
    auto impl{std::make_unique<HTTPRequestImpl>()};
    impl->beast_req = std::move(beast_req);
    impl->peer_address = conn.peer;
    impl->is_tls = conn.is_tls;
    impl->client_cert_fingerprint_hex = conn.client_cert_fingerprint_hex;
    impl->max_body_size = g_max_body_size;
    impl->send_reply_fn = [slot, executor](BeastResponse &&res) {
        asio::post(executor, [slot, res = std::move(res)]() mutable {
            slot->response = std::move(res);
            slot->timer.cancel();
        });
    };
    auto hreq{std::make_unique<HTTPRequest>(std::move(impl))};

    if (conn.public_only) {
        // Public listeners only serve the WebSocket and Chronik endpoints,
        // which are handled before dispatch: never RPC, wallet or REST.
        LogDebug(BCLog::HTTP,
                 "Request for %s on a public listener from %s rejected\n",
                 SanitizeString(hreq->GetURI(), SAFE_CHARS_URI).substr(0, 100),
                 hreq->GetPeer().ToStringAddrPort());
        hreq->WriteReply(HTTP_NOT_FOUND);
    } else if (!ClientAllowed(hreq->GetPeer())) {
        // Early address-based allow check
        LogDebug(BCLog::HTTP,
                 "HTTP request from %s rejected: Client network is not allowed "
                 "RPC access\n",
                 hreq->GetPeer().ToStringAddrPort());
        hreq->WriteReply(HTTP_FORBIDDEN);
    } else if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) {
        // Early reject unknown HTTP methods
        LogDebug(BCLog::HTTP,
                 "HTTP request from %s rejected: Unknown HTTP request method\n",
                 hreq->GetPeer().ToStringAddrPort());
        hreq->WriteReply(HTTP_BAD_METHOD);
    } else {
        LogDebug(BCLog::HTTP, "Received a %s request for %s from %s\n",
                 RequestMethodString(hreq->GetRequestMethod()),
                 SanitizeString(hreq->GetURI(), SAFE_CHARS_URI).substr(0, 100),
                 hreq->GetPeer().ToStringAddrPort());

        // Find registered handler for prefix
        std::string strURI = hreq->GetURI();
        std::string path;
        std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
        std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
        for (; i != iend; ++i) {
            bool match = false;
            if (i->exactMatch) {
                match = (strURI == i->prefix);
            } else {
                match = (strURI.substr(0, i->prefix.size()) == i->prefix);
            }
            if (match) {
                path = strURI.substr(i->prefix.size());
                break;
            }
        }

        // Dispatch to worker thread.
        if (i != iend) {
            std::unique_ptr<HTTPWorkItem> item(
                new HTTPWorkItem(*g_config, std::move(hreq), path, i->handler));
            assert(g_work_queue);
            if (!g_work_queue->Enqueue(conn.connection_id, item)) {
                LogPrintf("WARNING: request rejected because http work queue "
                          "depth exceeded, it can be increased with the "
                          "-rpcworkqueue= setting\n");
                item->req->WriteReply(HTTP_SERVICE_UNAVAILABLE,
                                      "Work queue depth exceeded");
            }
        } else {
            hreq->WriteReply(HTTP_NOT_FOUND);
        }
    }

    // The reply is posted to this strand, so it cannot be delivered before
    // this coroutine suspends here.
    if (!slot->response) {
        co_await slot->timer.async_wait(asio::as_tuple(asio::use_awaitable));
    }
    if (!slot->response) {
        // Only possible if the reply sink was dropped without a reply.
        slot->response =
            MakeSimpleResponse(HTTP_INTERNAL_SERVER_ERROR, version);
    }
    co_return std::move(*slot->response);
}

/**
 * Write a response. On plain TCP and TLS, first write directly while the
 * socket accepts data: a reply that fits in the socket buffer (most of them) then
 * costs one writev and no trip through the I/O scheduler. Whatever does not
 * fit is written asynchronously, continuing the same serializer.
 */
template <typename Stream>
static asio::awaitable<boost::system::error_code>
WriteResponse(Stream &stream, BeastResponse &res) {
    http::serializer<false, http::string_body> sr{res};
    if constexpr (std::is_same_v<Stream, beast::tcp_stream> ||
                  std::is_same_v<Stream, OsslStream>) {
        boost::system::error_code ec;
        const auto try_write = [&](auto &sync_stream) {
            while (!ec && !sr.is_done()) {
                http::write_some(sync_stream, sr, ec);
            }
        };
        if constexpr (std::is_same_v<Stream, beast::tcp_stream>) {
            stream.socket().non_blocking(true, ec);
            try_write(stream.socket());
        } else {
            try_write(stream);
        }
        if (ec != asio::error::would_block) {
            co_return ec;
        }
    }
    auto [ec, n] = co_await http::async_write(
        stream, sr, asio::as_tuple(asio::use_awaitable));
    co_return ec;
}

/**
 * Per-connection -rpcservertimeout enforcement. Instead of re-arming a timer
 * around every read and write, one timer wakes up about once per timeout and
 * shuts the socket down if the connection made no progress for that long
 * while no handler was running. Only used on the connection's strand.
 */
struct IdleState {
    explicit IdleState(const asio::any_io_executor &exec) : timer(exec) {}
    asio::steady_timer timer;
    std::chrono::steady_clock::time_point last_activity{
        std::chrono::steady_clock::now()};
    //! A handler (or a WebSocket session) is running: never time out
    bool busy{false};
    //! The connection is finished: the socket may be gone
    bool done{false};

    void Touch() { last_activity = std::chrono::steady_clock::now(); }
};

static asio::awaitable<void> WatchIdle(std::shared_ptr<IdleState> state,
                                       tcp::socket *socket) {
    while (!state->done) {
        if (state->busy) {
            state->timer.expires_after(g_server_timeout);
        } else {
            state->timer.expires_at(state->last_activity + g_server_timeout);
        }
        co_await state->timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (state->done) {
            co_return;
        }
        if (!state->busy && std::chrono::steady_clock::now() >=
                                state->last_activity + g_server_timeout) {
            boost::system::error_code ec;
            socket->shutdown(tcp::socket::shutdown_both, ec);
            socket->cancel(ec);
            co_return;
        }
    }
}

/** Map "/chronik/x?y" to "/x?y" */
static std::string StripChronikPrefix(std::string_view target) {
    std::string rest{target.substr(CHRONIK_PREFIX.size())};
    if (rest.empty() || rest[0] != '/') {
        rest.insert(rest.begin(), '/');
    }
    return rest;
}

/** In-process /chronik handlers, see httpserver.h */
static GlobalMutex g_chronik_inprocess_mutex;
static std::shared_ptr<const ChronikInProcessHandlers>
    g_chronik_inprocess GUARDED_BY(g_chronik_inprocess_mutex);
//! Open in-process WebSocket sessions, closed when the handlers are cleared
static std::list<std::weak_ptr<InProcessWebSocket>>
    g_chronik_inprocess_sessions GUARDED_BY(g_chronik_inprocess_mutex);

static std::shared_ptr<const ChronikInProcessHandlers> GetChronikInProcess() {
    LOCK(g_chronik_inprocess_mutex);
    return g_chronik_inprocess;
}

void SetChronikInProcessHandlers(
    std::shared_ptr<const ChronikInProcessHandlers> handlers) {
    std::list<std::weak_ptr<InProcessWebSocket>> sessions;
    {
        LOCK(g_chronik_inprocess_mutex);
        g_chronik_inprocess = std::move(handlers);
        if (!g_chronik_inprocess) {
            sessions.swap(g_chronik_inprocess_sessions);
        }
    }
    for (const auto &weak : sessions) {
        if (auto session = weak.lock()) {
            session->Close();
        }
    }
}

static InProcessHTTPRequest ToInProcessRequest(const BeastRequest &req,
                                               const HTTPConnectionInfo &conn) {
    InProcessHTTPRequest out;
    out.method = std::string{req.method_string()};
    out.target = StripChronikPrefix(req.target());
    for (const auto &f : req) {
        out.headers.emplace_back(std::string{f.name_string()},
                                 std::string{f.value()});
    }
    out.body = req.body();
    out.peer_ip = conn.peer.ToStringAddr();
    return out;
}

/** Serve a /chronik request with the in-process handler */
static asio::awaitable<BeastResponse>
InProcessChronikHTTP(std::shared_ptr<const ChronikInProcessHandlers> handlers,
                     const BeastRequest &req, const HTTPConnectionInfo &conn) {
    const unsigned version{req.version()};
    InProcessHTTPResponse in = co_await asio::async_initiate<
        decltype(asio::use_awaitable), void(InProcessHTTPResponse)>(
        [&](auto handler) {
            using Handler = decltype(handler);
            struct State {
                Handler handler;
                asio::executor_work_guard<asio::associated_executor_t<Handler>>
                    work;
            };
            // Take the work guard before moving the handler.
            auto work =
                asio::make_work_guard(asio::get_associated_executor(handler));
            auto state = std::make_shared<State>(
                State{std::move(handler), std::move(work)});
            handlers->http(ToInProcessRequest(req, conn),
                           [state](InProcessHTTPResponse resp) mutable {
                               auto ex = state->work.get_executor();
                               asio::dispatch(ex, [state, resp = std::move(
                                                              resp)]() mutable {
                                   std::move(state->handler)(std::move(resp));
                                   state->work.reset();
                               });
                           });
        },
        asio::use_awaitable);

    BeastResponse res{static_cast<http::status>(in.status), version};
    std::optional<std::string> explicit_length;
    for (auto &[name, value] : in.headers) {
        if (beast::iequals(name, "content-length")) {
            explicit_length = value;
            continue;
        }
        if (beast::iequals(name, "transfer-encoding")) {
            continue;
        }
        res.insert(name, value);
    }
    res.body() = std::move(in.body);
    if (res.body().size() > MAX_CHRONIK_RESPONSE_SIZE) {
        co_return MakeSimpleResponse(500, version,
                                     "Chronik response too large");
    }
    MaybeCompressZstd(req, res);
    FinalizeResponse(res, version);
    if (req.method() == http::verb::head && explicit_length &&
        res.body().empty()) {
        res.set(http::field::content_length, *explicit_length);
    }
    co_return res;
}

/**
 * One in-process /chronik/ws session on the connection's strand. Handler
 * calls happen on that strand, in order; the session object outlives the
 * stream only as an inert shell (all operations check m_closed).
 */
template <typename Stream>
class InProcessWsSession final
    : public InProcessWebSocket,
      public std::enable_shared_from_this<InProcessWsSession<Stream>> {
public:
    InProcessWsSession(Stream &stream, asio::any_io_executor ex,
                       std::shared_ptr<const ChronikInProcessHandlers> handlers)
        : m_ex(ex), m_ws(stream), m_timer(ex), m_wait(ex),
          m_handlers(std::move(handlers)) {}

    void SendBinary(std::string msg) override {
        asio::post(m_ex, [self = this->shared_from_this(),
                          msg = std::move(msg)]() mutable {
            self->Enqueue(Out{Out::Kind::Binary, std::move(msg)});
        });
    }
    void Close() override {
        asio::post(m_ex, [self = this->shared_from_this()] {
            self->Enqueue(Out{Out::Kind::Close, {}});
        });
    }
    void NotifyActivity() override {
        asio::post(m_ex, [self = this->shared_from_this()] {
            self->m_timer.cancel();
        });
    }

    asio::awaitable<void>
    Run(const BeastRequest &req,
        std::vector<std::pair<std::string, std::string>> extra_headers,
        const HTTPConnectionInfo &conn) {
        auto self = this->shared_from_this();
        beast::get_lowest_layer(m_ws.next_layer()).expires_never();
        websocket::stream_base::timeout timeout{};
        timeout.handshake_timeout = std::chrono::seconds(30);
        timeout.idle_timeout = websocket::stream_base::none();
        timeout.keep_alive_pings = false;
        m_ws.set_option(timeout);
        m_ws.set_option(websocket::stream_base::decorator(
            [extra_headers](websocket::response_type &res) {
                for (const auto &[name, value] : extra_headers) {
                    res.insert(name, value);
                }
            }));
        m_ws.read_message_max(m_handlers->ws_max_message_size);
        m_ws.binary(true);
        m_ws.auto_fragment(false);
        m_ws.control_callback([this](websocket::frame_type,
                                     beast::string_view) { m_timer.cancel(); });
        auto [aec] =
            co_await m_ws.async_accept(req, asio::as_tuple(asio::use_awaitable));
        if (aec) {
            co_return;
        }
        {
            LOCK(g_chronik_inprocess_mutex);
            if (g_chronik_inprocess != m_handlers) {
                // Unregistered meanwhile: don't start a session.
                co_return;
            }
            g_chronik_inprocess_sessions.remove_if(
                [](const auto &w) { return w.expired(); });
            g_chronik_inprocess_sessions.push_back(self);
        }
        m_handler = m_handlers->ws_open(self, conn.peer.ToStringAddr());
        m_pinging = true;
        asio::co_spawn(m_ex, PingLoop(), asio::detached);
        co_await ReadLoop();
        // Wait for the writer and pinger: they use the stream.
        while (m_writing || m_pinging) {
            m_wait.expires_at(asio::steady_timer::time_point::max());
            co_await m_wait.async_wait(asio::as_tuple(asio::use_awaitable));
        }
        if (m_handler) {
            m_handler->OnClosed();
            m_handler.reset();
        }
    }

private:
    struct Out {
        enum class Kind { Binary, Ping, Close } kind;
        std::string data;
    };

    asio::awaitable<void> ReadLoop() {
        while (true) {
            beast::flat_buffer buffer;
            auto [ec, n] = co_await m_ws.async_read(
                buffer, asio::as_tuple(asio::use_awaitable));
            if (ec) {
                break;
            }
            m_timer.cancel();
            if (!m_handler) {
                continue;
            }
            if (m_ws.got_text()) {
                m_handler->OnText();
            } else {
                m_handler->OnBinary(beast::buffers_to_string(buffer.data()));
            }
        }
        m_closed = true;
        m_out.clear();
        m_timer.cancel();
        boost::system::error_code ignored;
        beast::get_lowest_layer(m_ws.next_layer()).socket().close(ignored);
    }

    asio::awaitable<void> PingLoop() {
        auto self = this->shared_from_this();
        while (!m_closed) {
            m_timer.expires_after(m_handlers->ws_ping_interval);
            auto [ec] =
                co_await m_timer.async_wait(asio::as_tuple(asio::use_awaitable));
            if (m_closed) {
                break;
            }
            if (ec) {
                // Cancelled by activity: re-arm
                continue;
            }
            Enqueue(Out{Out::Kind::Ping, m_handlers->ws_ping_payload});
        }
        m_pinging = false;
        m_wait.cancel();
    }

    void Enqueue(Out msg) {
        if (m_closed) {
            return;
        }
        if (msg.kind != Out::Kind::Ping) {
            m_timer.cancel();
        }
        m_out.push_back(std::move(msg));
        if (!m_writing) {
            m_writing = true;
            asio::co_spawn(m_ex, WriteLoop(), asio::detached);
        }
    }

    asio::awaitable<void> WriteLoop() {
        auto self = this->shared_from_this();
        while (!m_out.empty() && !m_closed) {
            Out msg = std::move(m_out.front());
            m_out.pop_front();
            boost::system::error_code ec;
            switch (msg.kind) {
                case Out::Kind::Binary: {
                    auto [wec, n] = co_await m_ws.async_write(
                        asio::buffer(msg.data),
                        asio::as_tuple(asio::use_awaitable));
                    ec = wec;
                    break;
                }
                case Out::Kind::Ping: {
                    websocket::ping_data payload(msg.data);
                    auto [pec] = co_await m_ws.async_ping(
                        payload, asio::as_tuple(asio::use_awaitable));
                    ec = pec;
                    break;
                }
                case Out::Kind::Close: {
                    auto [cec] = co_await m_ws.async_close(
                        websocket::close_code::normal,
                        asio::as_tuple(asio::use_awaitable));
                    ec = cec;
                    m_closed = true;
                    break;
                }
            }
            if (ec) {
                m_closed = true;
                break;
            }
        }
        if (m_closed) {
            m_out.clear();
            m_timer.cancel();
            boost::system::error_code ignored;
            beast::get_lowest_layer(m_ws.next_layer()).socket().close(ignored);
        }
        m_writing = false;
        m_wait.cancel();
    }

    asio::any_io_executor m_ex;
    websocket::stream<Stream &> m_ws;
    asio::steady_timer m_timer;
    //! Wakes Run when the writer or pinger finishes
    asio::steady_timer m_wait;
    std::shared_ptr<const ChronikInProcessHandlers> m_handlers;
    std::unique_ptr<InProcessWebSocketHandler> m_handler;
    std::deque<Out> m_out;
    bool m_writing{false};
    bool m_pinging{false};
    bool m_closed{false};
};

/**
 * Serve a /chronik/ws upgrade in process. Returns false (without touching the
 * stream) if the handlers don't accept it as a WebSocket upgrade.
 */
template <typename Stream>
static asio::awaitable<bool> InProcessChronikWebSocket(
    std::shared_ptr<const ChronikInProcessHandlers> handlers, Stream &stream,
    const BeastRequest &req, const HTTPConnectionInfo &conn) {
    auto extra{handlers->ws_check(ToInProcessRequest(req, conn))};
    if (!extra) {
        co_return false;
    }
    auto session{std::make_shared<InProcessWsSession<Stream>>(
        stream, co_await asio::this_coro::executor, handlers)};
    co_await session->Run(req, std::move(*extra), conn);
    co_return true;
}

/**
 * Address the P2P layer should see for a /p2p/ws peer: the TCP peer, or the
 * last X-Forwarded-For hop if trusted and the TCP peer is a local proxy.
 */
static CService P2PWebSocketPeerAddress(const BeastRequest &req,
                                        const HTTPConnectionInfo &conn) {
    if (!g_p2p_websocket_trust_forwarded_for || !conn.peer.IsLocal()) {
        return conn.peer;
    }
    auto xff = req.find("X-Forwarded-For");
    if (xff == req.end()) {
        return conn.peer;
    }
    std::string_view hops{xff->value()};
    std::string_view last{hops.substr(hops.rfind(',') + 1)};
    const CService forwarded{
        LookupNumeric(std::string{util::TrimStringView(last)}, 0)};
    return forwarded.IsValid() ? forwarded : conn.peer;
}

/** Accept a /p2p/ws upgrade and bridge it into CConnman */
template <typename Stream>
static asio::awaitable<void> AcceptP2PWebSocket(Stream &stream,
                                                beast::flat_buffer &buffer,
                                                const BeastRequest &req,
                                                const HTTPConnectionInfo &conn) {
    P2PWebSocketAcceptor acceptor{
        WITH_LOCK(g_p2p_websocket_mutex, return g_p2p_websocket_acceptor)};
    if (!acceptor) {
        BeastResponse res{MakeSimpleResponse(HTTP_SERVICE_UNAVAILABLE,
                                             req.version(),
                                             "P2P is not ready")};
        res.keep_alive(false);
        co_await WriteResponse(stream, res);
        co_return;
    }

    const auto offered_protocols{req[http::field::sec_websocket_protocol]};
    const bool deflate_offered{
        req[http::field::sec_websocket_extensions].find("permessage-deflate") !=
        std::string_view::npos};
    auto [selected, compression] =
        p2pws::NegotiateP2PCompression(offered_protocols, deflate_offered);
#ifndef HAVE_P2P_WEBSOCKET_BRIDGE
    // permessage-deflate needs the socketpair bridge: decline it here.
    if (compression == P2PWebSocketCompression::PERMESSAGE_DEFLATE) {
        compression = P2PWebSocketCompression::NONE;
    }
#endif
    const bool use_bridge{
        compression == P2PWebSocketCompression::PERMESSAGE_DEFLATE ||
        g_p2p_websocket_force_bridge};

    beast::get_lowest_layer(stream).expires_never();
    websocket::stream<Stream &> ws{stream};
    // Only fall back to permessage-deflate when no zstd protocol matched, so
    // payloads are never compressed twice.
    p2pws::ConfigureP2PWebSocket(
        ws, beast::role_type::server,
        compression == P2PWebSocketCompression::PERMESSAGE_DEFLATE);
    ws.set_option(websocket::stream_base::decorator(
        [selected = selected](websocket::response_type &res) {
            if (!selected.empty()) {
                res.set(http::field::sec_websocket_protocol, selected);
            }
        }));
    auto [aec] =
        co_await ws.async_accept(req, asio::as_tuple(asio::use_awaitable));
    if (aec) {
        LogDebug(BCLog::NET, "P2P WebSocket handshake with %s failed: %s\n",
                 conn.peer.ToStringAddrPort(), aec.message());
        co_return;
    }
    auto info{std::make_shared<WebSocketTransportInfo>()};
    info->tls = conn.is_tls;
    info->compression = compression;
    info->peer_cert_fingerprint_hex = conn.client_cert_fingerprint_hex;
    const CService peer{P2PWebSocketPeerAddress(req, conn)};

    if (!use_bridge) {
        // Hand the connection to CConnman: the TCP socket (and our TLS
        // session), plus any bytes the client already sent after the
        // upgrade request. From here on P2P data never touches the HTTP
        // server's threads.
        const auto leftover{buffer.cdata()};
        std::vector<uint8_t> initial(
            static_cast<const uint8_t *>(leftover.data()),
            static_cast<const uint8_t *>(leftover.data()) + leftover.size());
        buffer.consume(buffer.size());
        std::unique_ptr<WebSocketByteLayer> layer;
        if constexpr (std::is_same_v<Stream, OsslStream>) {
            layer = std::make_unique<TlsByteLayer>(stream.ReleaseSsl());
        } else {
            layer = std::make_unique<PlainByteLayer>();
        }
        boost::system::error_code ec;
        tcp::socket socket{
            beast::get_lowest_layer(stream).release_socket()};
        const auto fd{socket.release(ec)};
        if (ec) {
            co_return;
        }
        // CConnman owns the socket now: don't shut it down with the server.
        g_connections.RemoveConnection(conn.connection_id);
        LogDebug(BCLog::NET, "P2P WebSocket peer %s connected (%s, %s)\n",
                 peer.ToStringAddrPort(), conn.is_tls ? "wss" : "ws",
                 P2PWebSocketCompressionName(compression));
        acceptor(std::make_unique<WebSocketSock>(
                     SOCKET(fd), WebSocketCodec::Role::SERVER, info,
                     std::move(layer), std::move(initial)),
                 CAddress{peer, NODE_NONE}, CAddress{conn.local, NODE_NONE},
                 info);
        co_return;
    }

#ifdef HAVE_P2P_WEBSOCKET_BRIDGE
    // permessage-deflate (generic clients) or -p2pwebsocketbridge: bridge
    // through a socketpair, with Beast doing the WebSocket framing.
    const auto pair{p2pws::CreateBridgeSocketPair()};
    if (!pair) {
        LogPrintf("P2P WebSocket: socketpair failed: %s\n",
                  NetworkErrorString(WSAGetLastError()));
        co_return;
    }
    p2pws::LocalSocket local{co_await asio::this_coro::executor};
    boost::system::error_code ec;
    local.assign(asio::local::stream_protocol{}, pair->second, ec);
    if (ec) {
        // Closes CConnman's end.
        Sock unused{static_cast<SOCKET>(pair->first)};
        ::close(pair->second);
        co_return;
    }
    LogDebug(BCLog::NET, "P2P WebSocket peer %s connected (%s, %s, bridged)\n",
             peer.ToStringAddrPort(), conn.is_tls ? "wss" : "ws",
             P2PWebSocketCompressionName(compression));
    acceptor(std::make_unique<Sock>(static_cast<SOCKET>(pair->first)),
             CAddress{peer, NODE_NONE},
             CAddress{conn.local, NODE_NONE}, info);
    co_await p2pws::RunP2PWebSocketBridge(ws, std::move(local), info,
                                          /*is_client=*/false);
#endif
}

/**
 * Handle a WebSocket upgrade request if a WebSocket endpoint matches its
 * target. Returns true if the connection was taken over.
 */
template <typename Stream>
static asio::awaitable<bool>
TryHandleWebSocketUpgrade(Stream &stream, beast::flat_buffer &buffer,
                          const BeastRequest &req,
                          const HTTPConnectionInfo &conn) {
    const std::string_view target{req.target()};
    if (g_p2p_websocket_enabled && URIHasPathPrefix(target, P2P_WEBSOCKET_PATH)) {
        co_await AcceptP2PWebSocket(stream, buffer, req, conn);
        co_return true;
    }
    if (g_chronik_enabled &&
        URIHasPathPrefix(target, CHRONIK_PREFIX + "/ws")) {
        // Not a valid upgrade, or Chronik not running: answered by the HTTP
        // handler.
        if (auto handlers{GetChronikInProcess()}) {
            co_return co_await InProcessChronikWebSocket(std::move(handlers),
                                                         stream, req, conn);
        }
    }
    co_return false;
}

/** Serve HTTP/1.1 keep-alive requests on an established (TLS or plain) stream */
template <typename Stream>
static asio::awaitable<void> ServeHTTP(Stream &stream,
                                       beast::flat_buffer &buffer,
                                       const HTTPConnectionInfo &conn) {
    // Idle timeout (see IdleState) replaces per-operation stream timeouts.
    auto &lowest{beast::get_lowest_layer(stream)};
    lowest.expires_never();
    auto idle{std::make_shared<IdleState>(co_await asio::this_coro::executor)};
    asio::co_spawn(idle->timer.get_executor(),
                   WatchIdle(idle, &lowest.socket()), asio::detached);
    struct StopWatch {
        std::shared_ptr<IdleState> state;
        ~StopWatch() {
            state->done = true;
            state->timer.cancel();
        }
    } stop_watch{idle};

    while (true) {
        http::request_parser<http::string_body> parser;
        parser.header_limit(MAX_HEADERS_SIZE);
        parser.body_limit(g_max_body_size);

        idle->Touch();
        auto [hdr_ec, hdr_n] = co_await http::async_read_header(
            stream, buffer, parser, asio::as_tuple(asio::use_awaitable));
        if (hdr_ec) {
            if (hdr_ec == http::error::end_of_stream ||
                hdr_ec == asio::error::eof || hdr_ec == beast::error::timeout ||
                hdr_ec == asio::error::operation_aborted ||
                hdr_ec == asio::error::connection_reset) {
                co_return;
            }
            // Malformed or oversized request line/headers (libevent also
            // answered these with 400).
            LogDebug(BCLog::HTTP, "Bad HTTP request from %s: %s\n",
                     conn.peer.ToStringAddrPort(), hdr_ec.message());
            BeastResponse res{MakeSimpleResponse(HTTP_BAD_REQUEST, 11)};
            res.keep_alive(false);
            co_await WriteResponse(stream, res);
            co_return;
        }

        idle->Touch();
        const auto &header{parser.get()};
        if (auto expect{header.find(http::field::expect)};
            expect != header.end() &&
            beast::iequals(expect->value(), "100-continue")) {
            http::response<http::empty_body> cont{http::status::continue_,
                                                  header.version()};
            auto [ec, n] = co_await http::async_write(
                stream, cont, asio::as_tuple(asio::use_awaitable));
            if (ec) {
                co_return;
            }
        }

        if (!parser.is_done()) {
            // Beast otherwise reuses its initial 512-byte capacity as the
            // parser consumes each chunk. Grow lazily for bodies, with bounded
            // read-ahead rather than one receive operation per tiny chunk.
            constexpr uint64_t body_read_chunk = 16 * 1024;
            buffer.reserve(std::min<uint64_t>(
                body_read_chunk, parser.content_length().value_or(body_read_chunk)));
            auto [body_ec, body_n] = co_await http::async_read(
                stream, buffer, parser, asio::as_tuple(asio::use_awaitable));
            if (body_ec) {
                if (body_ec == http::error::body_limit) {
                    BeastResponse res{MakeSimpleResponse(
                        413 /* Payload Too Large */, header.version())};
                    res.keep_alive(false);
                    co_await WriteResponse(stream, res);
                }
                co_return;
            }
        }

        BeastRequest req{parser.release()};
        const bool keep_alive{req.keep_alive()};
        const unsigned version{req.version()};
        const bool is_head{req.method() == http::verb::head};

        // WebSocket and Chronik endpoints: on public listeners for anyone,
        // on RPC listeners only for -rpcallowip clients. Other requests go
        // to DispatchRequest, which applies the same rules.
        const bool endpoint_allowed{conn.public_only
                                        ? IsPublicPath(req.target())
                                        : ClientAllowed(conn.peer)};

        // Handlers may take arbitrarily long (e.g. long polling), as may
        // WebSocket sessions.
        idle->busy = true;
        if (endpoint_allowed && websocket::is_upgrade(req) &&
            !g_reject_requests.load() &&
            co_await TryHandleWebSocketUpgrade(stream, buffer, req, conn)) {
            co_return;
        }

        BeastResponse res;
        if (endpoint_allowed && g_chronik_enabled &&
            !g_reject_requests.load() &&
            URIHasPathPrefix(req.target(), CHRONIK_PREFIX)) {
            g_connections.AddRequest();
            if (auto handlers{GetChronikInProcess()}) {
                res = co_await InProcessChronikHTTP(std::move(handlers), req,
                                                    conn);
            } else {
                // Before Chronik started or after it was interrupted
                res = MakeSimpleResponse(503, version,
                                         "Chronik is not running");
            }
        } else {
            res = co_await DispatchRequest(std::move(req), conn);
        }

        bool close{!keep_alive || g_reject_requests.load()};
        if (auto c{res.find(http::field::connection)};
            c != res.end() && beast::iequals(c->value(), "close")) {
            close = true;
        }
        res.version(version);
        res.keep_alive(!close);
        if (is_head) {
            // Keep Content-Length, send no body.
            res.body().clear();
        }
        idle->busy = false;
        idle->Touch();
        const auto ec{co_await WriteResponse(stream, res)};
        g_connections.RemoveRequest();
        if (ec || close) {
            co_return;
        }
    }
}

static std::string ClientCertFingerprint(SSL *ssl) {
    X509 *cert{tls::PeerCertificate(ssl)};
    std::string hex{tls::CertSha256Hex(cert)};
    X509_free(cert);
    return hex;
}

/** Connection coroutine: detect TLS, then serve HTTP on the resulting stream */
static asio::awaitable<void> HandleConnection(tcp::socket socket,
                                              bool public_only) {
    HTTPConnectionInfo conn;
    conn.public_only = public_only;
    {
        boost::system::error_code ec;
        const auto remote{socket.remote_endpoint(ec)};
        if (!ec) {
            conn.peer = LookupNumeric(remote.address().to_string(),
                                      remote.port());
        }
        const auto local{socket.local_endpoint(ec)};
        if (!ec) {
            conn.local =
                LookupNumeric(local.address().to_string(), local.port());
        }
        socket.set_option(tcp::no_delay(true), ec);
    }
    const uint64_t conn_id{g_connections.AddConnection(socket.native_handle())};
    conn.connection_id = conn_id;

    try {
        beast::tcp_stream stream{std::move(socket)};
        beast::flat_buffer buffer;
        auto &sock{stream.socket()};
        boost::system::error_code ec;
        sock.non_blocking(true, ec);

        // Until the TLS handshake (if any) is done, a deadline shuts the
        // socket down, which completes any pending wait with an error.
        asio::steady_timer deadline{sock.get_executor(), g_server_timeout};
        deadline.async_wait([fd = sock.native_handle()](
                                const boost::system::error_code &wec) {
            if (!wec) {
                ::shutdown(fd, SHUT_RDWR);
            }
        });

        // Classify the connection by its first byte, without consuming it:
        // 0x16 starts a TLS handshake record.
        auto [wait_ec] = co_await sock.async_wait(
            tcp::socket::wait_read, asio::as_tuple(asio::use_awaitable));
        uint8_t first{0};
        const ssize_t peeked{
            wait_ec ? -1
                    : ::recv(sock.native_handle(),
                             reinterpret_cast<char *>(&first), 1, MSG_PEEK)};
        if (peeked <= 0) {
            // Client went away (or timed out) before sending anything.
        } else if (first != 0x16) {
            deadline.cancel();
            co_await ServeHTTP(stream, buffer, conn);
            sock.shutdown(tcp::socket::shutdown_send, ec);
        } else if (!g_ssl_ctx) {
            LogDebug(BCLog::HTTP,
                     "TLS connection from %s rejected: TLS is disabled\n",
                     conn.peer.ToStringAddrPort());
        } else {
            tls::SslPtr ssl{SSL_new(g_ssl_ctx.get())};
            if (ssl && SSL_set_fd(ssl.get(), int(sock.native_handle())) == 1) {
                OsslStream tls_stream{stream, std::move(ssl)};
                auto [hs_ec, hs] = co_await tls_stream.async_handshake(
                    asio::as_tuple(asio::use_awaitable));
                deadline.cancel();
                if (hs_ec) {
                    LogDebug(BCLog::HTTP,
                             "TLS handshake with %s failed: %s\n",
                             conn.peer.ToStringAddrPort(), tls::ErrorString());
                } else {
                    conn.is_tls = true;
                    conn.client_cert_fingerprint_hex =
                        ClientCertFingerprint(tls_stream.native_handle());
                    co_await ServeHTTP(tls_stream, buffer, conn);
                    tls_stream.shutdown(ec);
                    sock.shutdown(tcp::socket::shutdown_send, ec);
                }
            }
        }
    } catch (const std::exception &e) {
        LogDebug(BCLog::HTTP, "HTTP connection from %s ended: %s\n",
                 conn.peer.ToStringAddrPort(), e.what());
    }
    g_connections.RemoveConnection(conn_id);
}

static asio::awaitable<void> AcceptLoop(tcp::acceptor &acceptor,
                                        bool public_only) {
    while (acceptor.is_open()) {
        auto [ec, socket] = co_await acceptor.async_accept(
            asio::make_strand(*g_io), asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec == asio::error::operation_aborted || !acceptor.is_open()) {
                break;
            }
            LogDebug(BCLog::HTTP, "HTTP accept failed: %s\n", ec.message());
            // Back off on resource exhaustion (e.g. EMFILE).
            asio::steady_timer t{acceptor.get_executor(),
                                 std::chrono::milliseconds{50}};
            co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
            continue;
        }
        auto executor{socket.get_executor()};
        asio::co_spawn(executor,
                       HandleConnection(std::move(socket), public_only),
                       asio::detached);
    }
}

/** Bind one listening socket. Returns false on failure. */
static bool BindEndpoint(const std::string &host, uint16_t port,
                         bool public_only) {
    std::vector<tcp::endpoint> candidates;
    boost::system::error_code ec;
    if (host.empty()) {
        candidates.emplace_back(asio::ip::address_v6::any(), port);
        candidates.emplace_back(asio::ip::address_v4::any(), port);
    } else if (auto addr{asio::ip::make_address(host, ec)}; !ec) {
        candidates.emplace_back(addr, port);
    } else {
        tcp::resolver resolver{*g_io};
        auto results{resolver.resolve(host, std::to_string(port),
                                      tcp::resolver::passive, ec)};
        if (!ec) {
            for (const auto &r : results) {
                candidates.push_back(r.endpoint());
            }
        }
    }
    for (const auto &endpoint : candidates) {
        auto acceptor{
            std::make_unique<tcp::acceptor>(asio::make_strand(*g_io))};
        acceptor->open(endpoint.protocol(), ec);
        if (ec) {
            continue;
        }
        acceptor->set_option(asio::socket_base::reuse_address(true), ec);
        if (endpoint.address().is_v6() &&
            endpoint.address().to_v6().is_unspecified()) {
            // Dual-stack "any", like getaddrinfo(NULL) did for libevent.
            acceptor->set_option(asio::ip::v6_only(false), ec);
        }
        acceptor->bind(endpoint, ec);
        if (ec) {
            continue;
        }
        acceptor->listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            continue;
        }
        g_acceptors.push_back({std::move(acceptor), public_only});
        return true;
    }
    return false;
}

/** Bind HTTP server to specified addresses */
static bool HTTPBindAddresses() {
    uint16_t http_port{static_cast<uint16_t>(
        gArgs.GetIntArg("-rpcport", BaseParams().RPCPort()))};
    std::vector<std::pair<std::string, uint16_t>> endpoints;

    // Determine what addresses to bind to
    if (!(gArgs.IsArgSet("-rpcallowip") && gArgs.IsArgSet("-rpcbind"))) {
        // Default to loopback if not allowing external IPs.
        endpoints.push_back(std::make_pair("::1", http_port));
        endpoints.push_back(std::make_pair("127.0.0.1", http_port));
        if (gArgs.IsArgSet("-rpcallowip")) {
            LogPrintf("WARNING: option -rpcallowip was specified without "
                      "-rpcbind; this doesn't usually make sense\n");
        }
        if (gArgs.IsArgSet("-rpcbind")) {
            LogPrintf("WARNING: option -rpcbind was ignored because "
                      "-rpcallowip was not specified, refusing to allow "
                      "everyone to connect\n");
        }
    } else if (gArgs.IsArgSet("-rpcbind")) {
        // Specific bind address.
        for (const std::string &strRPCBind : gArgs.GetArgs("-rpcbind")) {
            uint16_t port{http_port};
            std::string host;
            SplitHostPort(strRPCBind, port, host);
            endpoints.push_back(std::make_pair(host, port));
        }
    }

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t>>::iterator i =
             endpoints.begin();
         i != endpoints.end(); ++i) {
        LogDebug(BCLog::HTTP, "Binding RPC on address %s port %i\n", i->first,
                 i->second);
        if (BindEndpoint(i->first, i->second, /*public_only=*/false)) {
            const std::optional<CNetAddr> addr{LookupHost(i->first, false)};
            if (i->first.empty() || (addr.has_value() && addr->IsBindAny())) {
                LogPrintf("WARNING: the RPC server is not safe to expose to "
                          "untrusted networks such as the public internet\n");
            }
        } else {
            LogPrintf("Binding RPC on address %s port %i failed.\n", i->first,
                      i->second);
        }
    }
    if (g_acceptors.empty()) {
        return false;
    }

    // Public listeners: only /p2p/ws and /chronik, for anyone.
    for (const std::string &strBind : gArgs.GetArgs("-publicbind")) {
        uint16_t port{0};
        std::string host;
        if (!SplitHostPort(strBind, port, host) || port == 0) {
            LogPrintf("Error: -publicbind=%s needs an explicit port\n",
                      strBind);
            return false;
        }
        if (!BindEndpoint(host, port, /*public_only=*/true)) {
            LogPrintf("Binding public HTTP endpoints on %s failed.\n",
                      strBind);
            return false;
        }
        LogPrintf("Serving %s on public listener %s (RPC, wallet and REST "
                  "are not served there)\n",
                  util::Join(g_public_prefixes, ", "), strBind);
    }
    return true;
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg) {
    BCLog::Level level;
    switch (severity) {
        case EVENT_LOG_DEBUG:
            level = BCLog::Level::Debug;
            break;
        case EVENT_LOG_MSG:
            level = BCLog::Level::Info;
            break;
        case EVENT_LOG_WARN:
            level = BCLog::Level::Warning;
            break;
        default: // EVENT_LOG_ERR and others are mapped to error
            level = BCLog::Level::Error;
            break;
    }
    LogPrintLevel(BCLog::LIBEVENT, level, "%s\n", msg);
}

/**
 * Generate a self-signed EC P-256 certificate valid for 10 years and write it
 * and its key (mode 0600) as PEM files.
 */
static bool GenerateSelfSignedCertificate(const fs::path &cert_path,
                                          const fs::path &key_path) {
    const auto pem{tls::GenerateSelfSigned(
        "bitcoind node", {"localhost"}, {"127.0.0.1", "::1"},
        std::chrono::hours{24 * 365 * 10})};
    return pem && tls::WritePemFiles(*pem, cert_path, key_path);
}

/** Set up g_ssl_ctx from -tlscert/-tlskey or the datadir certificate */
static bool InitTLS() {
    g_ssl_ctx.reset();
    fs::path cert_path, key_path;
    if (gArgs.IsArgSet("-tlscert") || gArgs.IsArgSet("-tlskey")) {
        if (!gArgs.IsArgSet("-tlscert") || !gArgs.IsArgSet("-tlskey")) {
            LogPrintf("Error: -tlscert and -tlskey must be used together\n");
            return false;
        }
        cert_path = gArgs.GetPathArg("-tlscert");
        key_path = gArgs.GetPathArg("-tlskey");
    } else if (gArgs.GetBoolArg("-tlsephemeral", DEFAULT_HTTP_TLS_EPHEMERAL)) {
        cert_path = gArgs.GetDataDirNet() / HTTP_TLS_CERT_FILENAME;
        key_path = gArgs.GetDataDirNet() / HTTP_TLS_KEY_FILENAME;
        if (!fs::exists(cert_path) || !fs::exists(key_path)) {
            LogPrintf("Generating self-signed TLS certificate %s\n",
                      fs::PathToString(cert_path));
            if (!GenerateSelfSignedCertificate(cert_path, key_path)) {
                LogPrintf("Error: failed to generate a TLS certificate\n");
                return false;
            }
        }
    } else {
        LogPrintf("TLS disabled on the RPC port\n");
        return true;
    }

    auto ctx{tls::NewContext(/*server=*/true)};
    if (!ctx || !tls::UseCertificateFiles(ctx.get(), cert_path, key_path)) {
        LogPrintf("Error: unable to load TLS certificate %s / key %s: %s\n",
                  fs::PathToString(cert_path), fs::PathToString(key_path),
                  tls::ErrorString());
        return false;
    }
    if (gArgs.GetBoolArg("-tlsmutual", DEFAULT_HTTP_TLS_MUTUAL)) {
        // Ask for a client certificate, accept any (including self-signed
        // node certificates); the fingerprint is exposed per request.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER,
                           [](int, X509_STORE_CTX *) { return 1; });
    }
    g_ssl_ctx = std::move(ctx);
    LogPrintf("TLS enabled on the RPC port using %s\n",
              fs::PathToString(cert_path));
    return true;
}

bool InitHTTPServer(Config &config) {
    if (!InitHTTPAllowList()) {
        return false;
    }

    // Redirect libevent's logging to our own log
    event_set_log_callback(&libevent_log_cb);
    // Update libevent's log handling.
    UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT));

    if (!InitTLS()) {
        return false;
    }

    g_public_prefixes.clear();
    g_chronik_enabled =
        gArgs.GetBoolArg("-chronik", false) &&
        gArgs.GetBoolArg("-chronikpubliconrpcport",
                         DEFAULT_CHRONIK_PUBLIC_ON_RPC_PORT);
    if (g_chronik_enabled) {
        RegisterPublicHTTPPrefix(CHRONIK_PREFIX);
        LogPrintf("Serving Chronik on the RPC port at %s\n", CHRONIK_PREFIX);
    }

    g_p2p_websocket_enabled =
        gArgs.GetBoolArg("-p2pwebsocket", DEFAULT_P2P_WEBSOCKET);
    g_p2p_websocket_trust_forwarded_for =
        gArgs.GetBoolArg("-p2pwebsockettrustforwardedfor", false);
    g_p2p_websocket_force_bridge =
        gArgs.GetBoolArg("-p2pwebsocketbridge", false);
    if (g_p2p_websocket_enabled) {
        RegisterPublicHTTPPrefix(P2P_WEBSOCKET_PATH);
    }

    g_config = &config;
    g_server_timeout = std::chrono::seconds{std::max<int64_t>(
        gArgs.GetIntArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT), 1)};
    g_max_body_size = MIN_SUPPORTED_BODY_SIZE + 2 * config.GetMaxBlockSize();
    g_reject_requests = false;

    if (!g_io) {
        g_io = std::make_unique<asio::io_context>();
    } else {
        g_io->restart();
    }

    if (!HTTPBindAddresses()) {
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        return false;
    }

    LogDebug(BCLog::HTTP, "Initialized HTTP server\n");
    int workQueueDepth = std::max(
        (long)gArgs.GetIntArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L);
    LogDebug(BCLog::HTTP, "creating work queue of depth %d\n", workQueueDepth);

    g_work_queue = std::make_unique<HTTPCoroutinePool>(workQueueDepth);
    return true;
}

void UpdateHTTPServerLogging(bool enable) {
    if (enable) {
        event_enable_debug_logging(EVENT_DBG_ALL);
    } else {
        event_enable_debug_logging(EVENT_DBG_NONE);
    }
}

static std::vector<std::thread> g_thread_http_io;
static std::optional<asio::executor_work_guard<asio::io_context::executor_type>>
    g_io_work;

void StartHTTPServer() {
    const int rpcThreads = std::max(
        (long)gArgs.GetIntArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L);
    const int ioThreads = std::max(
        (long)gArgs.GetIntArg("-rpciothreads", DEFAULT_HTTP_IO_THREADS), 1L);
    LogInfo("Starting HTTP server with %d coroutine worker threads and %d I/O threads\n",
            rpcThreads, ioThreads);
    if (g_work_queue) g_work_queue->Start(rpcThreads);
    g_io_work.emplace(asio::make_work_guard(*g_io));
    for (auto &listener : g_acceptors) {
        asio::co_spawn(listener.acceptor->get_executor(),
                       AcceptLoop(*listener.acceptor, listener.public_only),
                       asio::detached);
    }
    for (int i = 0; i < ioThreads; ++i) {
        g_thread_http_io.emplace_back([i] {
            util::ThreadRename(i == 0 ? std::string{"http"} : strprintf("http.%i", i));
            g_io->run();
        });
    }
}

void InterruptHTTPServer() {
    LogDebug(BCLog::HTTP, "Interrupting HTTP server\n");
    // Reject requests on current connections
    g_reject_requests = true;
    if (g_work_queue) {
        g_work_queue->Interrupt();
    }
}

void StopHTTPServer() {
    LogDebug(BCLog::HTTP, "Stopping HTTP server\n");
    SetP2PWebSocketAcceptor(nullptr);
    if (g_work_queue) {
        LogDebug(BCLog::HTTP, "Waiting for HTTP worker threads to exit\n");
        g_work_queue->WaitExit();
    }
    // Stop accepting connections.
    for (auto &listener : g_acceptors) {
        asio::post(listener.acceptor->get_executor(), [&listener] {
            boost::system::error_code ec;
            listener.acceptor->close(ec);
        });
    }
    if (!g_thread_http_io.empty()) {
        // Let the I/O threads flush replies of requests already handled.
        if (const auto n{g_connections.CountActiveRequests()}; n != 0) {
            LogDebug(BCLog::HTTP,
                     "Waiting for %d requests to stop HTTP server\n", n);
        }
        g_connections.WaitUntilNoActiveRequests();
    }
    g_connections.ShutdownAll();
    if (g_io) {
        LogDebug(BCLog::HTTP, "Waiting for HTTP I/O threads to exit\n");
        g_io_work.reset();
        g_io->stop();
        for (auto &thread : g_thread_http_io) {
            thread.join();
        }
        g_thread_http_io.clear();
    }
    g_acceptors.clear();
    g_work_queue.reset();
    g_ssl_ctx.reset();
    LogDebug(BCLog::HTTP, "Stopped HTTP server\n");
}

struct event_base *EventBase() {
    return reinterpret_cast<struct event_base *>(g_io.get());
}

struct HTTPEvent::State {
    // A strand: the timer may be touched from several I/O threads.
    explicit State(asio::io_context &io) : timer(asio::make_strand(io)) {}
    Mutex mutex;
    bool cancelled GUARDED_BY(mutex){false};
    asio::steady_timer timer;
};

HTTPEvent::HTTPEvent(struct event_base *base, bool _deleteWhenTriggered,
                     const std::function<void()> &_handler)
    : deleteWhenTriggered(_deleteWhenTriggered), handler(_handler) {
    auto *io = reinterpret_cast<asio::io_context *>(base);
    assert(io);
    m_state = std::make_shared<State>(*io);
}
HTTPEvent::~HTTPEvent() {
    {
        LOCK(m_state->mutex);
        m_state->cancelled = true;
    }
    asio::post(m_state->timer.get_executor(),
               [state = m_state] { state->timer.cancel(); });
}
void HTTPEvent::trigger(struct timeval *tv) {
    auto run = [this, state = m_state](const boost::system::error_code &ec) {
        if (ec == asio::error::operation_aborted) {
            return;
        }
        if (deleteWhenTriggered) {
            // Nobody else owns a self-deleting event.
            handler();
            delete this;
            return;
        }
        LOCK(state->mutex);
        if (!state->cancelled) {
            handler();
        }
    };
    if (tv == nullptr) {
        // Immediately trigger event in the I/O thread.
        asio::post(m_state->timer.get_executor(),
                   [run] { run(boost::system::error_code{}); });
    } else {
        // Trigger after timeval passed. The timer is only touched on the I/O
        // context.
        const auto delay{std::chrono::seconds{tv->tv_sec} +
                         std::chrono::microseconds{tv->tv_usec}};
        asio::post(m_state->timer.get_executor(),
                   [state = m_state, delay, run] {
                       state->timer.expires_after(delay);
                       state->timer.async_wait(run);
                   });
    }
}

HTTPRequest::HTTPRequest(std::unique_ptr<HTTPRequestImpl> impl,
                         bool _replySent)
    : m_impl(std::move(impl)), replySent(_replySent) {}
HTTPRequest::~HTTPRequest() {
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        LogPrintf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL_SERVER_ERROR, "Unhandled request");
    }
}

std::pair<bool, std::string>
HTTPRequest::GetHeader(const std::string &hdr) const {
    assert(m_impl);
    auto it = m_impl->beast_req.find(hdr);
    if (it != m_impl->beast_req.end()) {
        return std::make_pair(true, std::string{it->value()});
    } else {
        return std::make_pair(false, "");
    }
}

/** Decompress a zstd body, refusing output larger than max_size */
static std::optional<std::string> ZstdDecompressBounded(const std::string &in,
                                                        uint64_t max_size) {
    std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> dctx{
        ZSTD_createDCtx(), &ZSTD_freeDCtx};
    if (!dctx) {
        return std::nullopt;
    }
    std::string out;
    const unsigned long long frame_size{
        ZSTD_getFrameContentSize(in.data(), in.size())};
    if (frame_size != ZSTD_CONTENTSIZE_UNKNOWN &&
        frame_size != ZSTD_CONTENTSIZE_ERROR) {
        if (frame_size > max_size) {
            return std::nullopt;
        }
        out.reserve(frame_size);
    }
    ZSTD_inBuffer input{in.data(), in.size(), 0};
    std::vector<char> chunk(ZSTD_DStreamOutSize());
    size_t ret{1};
    while (input.pos < input.size || ret != 0) {
        ZSTD_outBuffer output{chunk.data(), chunk.size(), 0};
        ret = ZSTD_decompressStream(dctx.get(), &output, &input);
        if (ZSTD_isError(ret)) {
            return std::nullopt;
        }
        out.append(chunk.data(), output.pos);
        if (out.size() > max_size) {
            return std::nullopt;
        }
        if (input.pos == input.size && output.pos < output.size && ret != 0) {
            // Truncated frame.
            return std::nullopt;
        }
    }
    return out;
}

std::string HTTPRequest::ReadBody() {
    if (!m_impl) {
        return "";
    }
    std::string body = std::move(m_impl->beast_req.body());
    m_impl->beast_req.body().clear();
    if (body.empty()) {
        return "";
    }
    auto ce = m_impl->beast_req.find(http::field::content_encoding);
    if (ce != m_impl->beast_req.end() && beast::iequals(ce->value(), "zstd")) {
        auto decoded = ZstdDecompressBounded(body, m_impl->max_body_size);
        if (!decoded) {
            LogDebug(BCLog::HTTP, "Invalid zstd request body from %s\n",
                     m_impl->peer_address.ToStringAddrPort());
            return "";
        }
        return std::move(*decoded);
    }
    return body;
}

void HTTPRequest::WriteHeader(const std::string &hdr,
                              const std::string &value) {
    assert(m_impl);
    m_impl->beast_res.insert(hdr, value);
}

void HTTPRequest::WriteReply(int nStatus, std::string strReply) {
    assert(!replySent && m_impl);
    if (ShutdownRequested()) {
        WriteHeader("Connection", "close");
    }
    BeastResponse &res = m_impl->beast_res;
    res.result(static_cast<unsigned>(nStatus));
    // The body is moved through to the socket write: no copies.
    res.body() = std::move(strReply);
    MaybeCompressZstd(m_impl->beast_req, res);
    FinalizeResponse(res, m_impl->beast_req.version());

    if (m_impl->send_reply_fn) {
        m_impl->send_reply_fn(std::move(res));
    }
    replySent = true;
    // transferred back to the connection.
    m_impl.reset();
}

CService HTTPRequest::GetPeer() const {
    return m_impl ? m_impl->peer_address : CService{};
}

std::string HTTPRequest::GetURI() const {
    return std::string{m_impl->beast_req.target()};
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod() const {
    switch (m_impl->beast_req.method()) {
        case http::verb::get:
            return GET;
        case http::verb::post:
            return POST;
        case http::verb::head:
            return HEAD;
        case http::verb::put:
            return PUT;
        case http::verb::options:
            return OPTIONS;
        default:
            return UNKNOWN;
    }
}

bool HTTPRequest::IsTLS() const {
    return m_impl && m_impl->is_tls;
}

std::string HTTPRequest::GetClientCertFingerprint() const {
    return m_impl ? m_impl->client_cert_fingerprint_hex : std::string{};
}

std::optional<std::string>
HTTPRequest::GetQueryParameter(const std::string &key) const {
    const std::string uri{GetURI()};
    return GetQueryParameterFromUri(uri.c_str(), key);
}

std::unique_ptr<HTTPRequest> ParseHTTPRequestForTesting(const std::string &raw) {
    http::request_parser<http::string_body> parser;
    parser.header_limit(MAX_HEADERS_SIZE);
    parser.body_limit(MIN_SUPPORTED_BODY_SIZE);
    parser.eager(true);
    boost::system::error_code ec;
    parser.put(asio::buffer(raw), ec);
    if (ec || !parser.is_done()) {
        return nullptr;
    }
    auto impl{std::make_unique<HTTPRequestImpl>()};
    impl->beast_req = parser.release();
    impl->max_body_size = MIN_SUPPORTED_BODY_SIZE;
    return std::make_unique<HTTPRequest>(std::move(impl), /*replySent=*/true);
}

namespace {
int HexValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}
bool IsHexChar(char c) {
    return HexValue(c) >= 0;
}
bool IsUnreserved(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || IsDigit(c) ||
           c == '-' || c == '.' || c == '_' || c == '~';
}
bool IsSubDelim(char c) {
    return std::strchr("!$&'()*+,;=", c) != nullptr && c != '\0';
}

/**
 * Validate the RFC 3986 characters of a URI or relative reference, as
 * libevent's evhttp_uri_parse did: every character is unreserved, a
 * sub-delimiter, one of ":@/?#[]" or a complete "%XX" escape.
 */
bool IsValidURIChars(std::string_view uri) {
    for (size_t i = 0; i < uri.size(); ++i) {
        const char c{uri[i]};
        if (c == '%') {
            if (i + 2 >= uri.size() || !IsHexChar(uri[i + 1]) ||
                !IsHexChar(uri[i + 2])) {
                return false;
            }
            i += 2;
        } else if (!IsUnreserved(c) && !IsSubDelim(c) &&
                   std::strchr(":@/?#[]", c) == nullptr) {
            return false;
        }
    }
    return true;
}

/** Percent-decode, also mapping '+' to ' ' (as evhttp did for values) */
std::string DecodeQueryValue(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        const char c{in[i]};
        if (c == '+') {
            out.push_back(' ');
        } else if (c == '%' && i + 2 < in.size() && IsHexChar(in[i + 1]) &&
                   IsHexChar(in[i + 2])) {
            out.push_back(
                static_cast<char>(HexValue(in[i + 1]) * 16 + HexValue(in[i + 2])));
            i += 2;
        } else {
            out.push_back(c);
        }
    }
    return out;
}
} // namespace

std::optional<std::string> GetQueryParameterFromUri(const char *uri,
                                                    const std::string &key) {
    const std::string_view uri_view{uri};
    if (!IsValidURIChars(uri_view)) {
        throw std::runtime_error("URI parsing failed, it likely contained RFC "
                                 "3986 invalid characters");
    }
    const size_t qpos{uri_view.find('?')};
    if (qpos == std::string_view::npos) {
        return std::nullopt;
    }
    std::string_view query{uri_view.substr(qpos + 1)};
    query = query.substr(0, query.find('#'));

    // Like evhttp_parse_query_str: a malformed pair (no '=' or an empty key)
    // invalidates the whole query string.
    std::optional<std::string> result;
    while (!query.empty()) {
        const size_t amp{query.find('&')};
        const std::string_view pair{query.substr(0, amp)};
        query = amp == std::string_view::npos ? std::string_view{}
                                              : query.substr(amp + 1);
        const size_t eq{pair.find('=')};
        if (eq == std::string_view::npos || eq == 0) {
            return std::nullopt;
        }
        if (!result && pair.substr(0, eq) == key) {
            result = DecodeQueryValue(pair.substr(eq + 1));
        }
    }
    return result;
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch,
                         const HTTPRequestHandler &handler) {
    RegisterHTTPAsyncHandler(
        prefix, exactMatch,
        [handler](Config &config, HTTPRequest *req, const std::string &path,
                  boost::asio::any_io_executor) -> boost::asio::awaitable<bool> {
            co_return handler(config, req, path);
        });
}

void RegisterHTTPAsyncHandler(const std::string &prefix, bool exactMatch,
                              const HTTPAsyncRequestHandler &handler) {
    LogDebug(BCLog::HTTP, "Registering HTTP handler for %s (exactmatch %d)\n",
             prefix, exactMatch);
    pathHandlers.push_back(HTTPPathHandler(prefix, exactMatch, handler));
}

void SetP2PWebSocketAcceptor(P2PWebSocketAcceptor acceptor) {
    LOCK(g_p2p_websocket_mutex);
    g_p2p_websocket_acceptor = std::move(acceptor);
}

void RegisterPublicHTTPPrefix(const std::string &prefix) {
    LogDebug(BCLog::HTTP, "Registering public HTTP prefix %s\n", prefix);
    g_public_prefixes.push_back(prefix);
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch) {
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i) {
        if (i->prefix == prefix && i->exactMatch == exactMatch) {
            break;
        }
    }
    if (i != iend) {
        LogDebug(BCLog::HTTP,
                 "Unregistering HTTP handler for %s (exactmatch %d)\n", prefix,
                 exactMatch);
        pathHandlers.erase(i);
    }
}

void HTTPReleaseWorkQueueSlot() noexcept {
    if (g_work_queue) {
        g_work_queue->OnSuspend();
    }
}

void HTTPAcquireWorkQueueSlot() noexcept {
    if (g_work_queue) {
        g_work_queue->OnResume();
    }
}

boost::asio::any_io_executor GetHTTPThreadPoolExecutor() {
    if (g_work_queue) {
        return g_work_queue->GetExecutor();
    }
    return {};
}
