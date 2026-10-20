// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>

#include <chainparams.h>
#include <config/bitcoin-config.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <compat/compat.h>
#include <config.h>
#include <crypto/sha256.h>
#include <http_tls_stream.h>
#ifdef ENABLE_HTTP2
#include <http2_server.h>
#endif
#include <logging.h>
#include <net.h>
#include <net_websocket.h>
#include <net_websocket_bridge.h>
#include <net_websocket_sock.h>
#include <net_websocket_tls.h>
#include <netbase.h>
#include <node/metrics.h>
#include <node/ui_interface.h>
#include <protocol.h>
#include <proxy_protocol.h>
#include <random.h>
#include <rpc/protocol.h> // For HTTP status codes
#include <shutdown.h>
#include <sync.h>
#include <tls_util.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <univalue.h>

#include <openssl/crypto.h>

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
#include <boost/asio/read.hpp>
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

#ifdef ENABLE_HTTP2
#include <nghttp2/nghttp2.h>
#endif

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
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
#include <memory>
#include <set>
#include <thread>
#include <unordered_map>

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
    //! Whether the TCP peer is a -trustedproxy (X-Forwarded-Proto believed)
    bool tcp_peer_trusted{false};
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
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->rpc_work_queue_capacity.Set(double(m_max_depth));
        }
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
            SetWorkMetrics();

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
                    SetWorkMetrics();
                }
                struct InFlightGuard {
                    HTTPCoroutinePool *pool;
                    ~InFlightGuard() {
                        LOCK(pool->m_mutex);
                        if (--pool->m_total_in_flight == 0) {
                            pool->m_cv.notify_all();
                        }
                        pool->SetWorkMetrics();
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
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->rpc_work_suspended.Add(1);
        }
    }

    void OnResume() noexcept {
        m_suspended_coroutines.fetch_sub(1, std::memory_order_relaxed);
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->rpc_work_suspended.Add(-1);
        }
    }

    /** Mirror the queue's counts in the metrics (with m_mutex held) */
    void SetWorkMetrics() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        if (auto *metrics{node::GetNodeMetrics()}) {
            metrics->rpc_work_queue_depth.Set(double(m_queued_requests));
            metrics->rpc_work_in_flight.Set(double(m_total_in_flight));
        }
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
//! Where the TLS certificate comes from
struct TlsFiles {
    fs::path cert, key;
    //! Generated in the datadir (renewed by us) rather than -tlscert/-tlskey
    bool generated{false};
    fs::file_time_type cert_mtime{}, key_mtime{};
};
static GlobalMutex g_tls_mutex;
//! TLS context for connections detected as TLS, if TLS is enabled
static tls::SslCtxPtr g_ssl_ctx GUARDED_BY(g_tls_mutex);
static std::optional<TlsFiles> g_tls_files GUARDED_BY(g_tls_mutex);
static std::chrono::steady_clock::time_point
    g_tls_next_check GUARDED_BY(g_tls_mutex);
static std::chrono::steady_clock::time_point
    g_tls_next_renewal_check GUARDED_BY(g_tls_mutex);
//! Validity of generated certificates, and how early they are renewed
static constexpr std::chrono::hours GENERATED_CERT_VALIDITY{24 * 90};
static constexpr std::chrono::hours GENERATED_CERT_RENEW_BEFORE{24 * 30};
//! How often the certificate files are checked for replacement
static constexpr std::chrono::seconds TLS_RELOAD_CHECK_INTERVAL{1};
static constexpr std::chrono::hours TLS_RENEWAL_CHECK_INTERVAL{1};
static tls::SslPtr NewServerSsl();
//! The configuration handlers are invoked with
static Config *g_config{nullptr};
//! Maximum accepted request body size
static uint64_t g_max_body_size{MIN_SUPPORTED_BODY_SIZE};
//! Idle/read/write timeout
static std::chrono::seconds g_server_timeout{DEFAULT_HTTP_SERVER_TIMEOUT};
//! How long a TLS connection may take to accept our close_notify
static constexpr std::chrono::seconds CLOSE_NOTIFY_TIMEOUT{5};
//! Set by InterruptHTTPServer: reject new requests with 503
static std::atomic<bool> g_reject_requests{false};
//! -p2prequiretls: P2P WebSocket peers must have used TLS
static bool g_p2p_require_tls{false};
//! How long a P2P port connection has to finish its WebSocket upgrade
static std::chrono::seconds g_p2p_port_handshake_timeout{
    DEFAULT_P2P_PORT_HANDSHAKE_TIMEOUT};
//! P2P port connections handed to us and not yet upgraded (or closed)
static GlobalMutex g_p2p_port_mutex;
static std::map<CNetAddr, size_t>
    g_p2p_port_pending_by_addr GUARDED_BY(g_p2p_port_mutex);
static size_t g_p2p_port_pending GUARDED_BY(g_p2p_port_mutex){0};
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

/** A web server requests are relayed to */
struct ForwardTarget {
    bool enabled{false};
    std::string host;
    uint16_t port{0};
};
//! Web server that gets every other request on -publicbind (-publicfallback)
static ForwardTarget g_public_fallback;

//! Whether /p2p/ws is served
static bool g_p2p_websocket_enabled{false};
//! Path P2P WebSocket upgrades are served at (-p2pwebsocketpath)
static std::string g_p2p_websocket_path{P2P_WEBSOCKET_PATH};
//! SHA-256 of the accepted upgrade tokens; none: no token needed
static std::vector<uint256> g_p2p_websocket_token_hashes;
//! Proxies whose PROXY headers and X-Forwarded-For are believed
static std::vector<CSubNet> g_trusted_proxies;

//! Whether TLS listeners offer HTTP/2 (-http2; needs ENABLE_HTTP2)
static bool g_http2_enabled{false};
#ifdef ENABLE_HTTP2
//! Per-connection HTTP/2 limits (see doc/http2.md)
static http2::Limits g_http2_limits;
#endif

/**
 * Whether a TLS connection on this listener may select ALPN h2. Not where
 * -publicfallback relays unserved requests: that relay passes the client's
 * HTTP/1.1 bytes through unchanged, which HTTP/2 cannot do.
 */
static bool HTTP2Allowed(bool public_only) {
    return g_http2_enabled && !(public_only && g_public_fallback.enabled);
}

//! Whether /livez, /readyz and /healthz are served (-httphealth)
static bool g_health_enabled{true};
static GlobalMutex g_readiness_mutex;
static HTTPReadinessCheck g_readiness_check GUARDED_BY(g_readiness_mutex);

static bool IsTrustedProxy(const CNetAddr &addr) {
    return std::any_of(g_trusted_proxies.begin(), g_trusted_proxies.end(),
                       [&](const CSubNet &s) { return s.Match(addr); });
}
//! Debug: bridge every /p2p/ws peer through a socketpair (-p2pwebsocketbridge)
static bool g_p2p_websocket_force_bridge{false};
static GlobalMutex g_p2p_websocket_mutex;
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
    //! Reached through the P2P port (implies public_only): only the P2P
    //! WebSocket endpoint is served, and the connection must get there
    //! before the handshake deadline.
    bool p2p_port{false};
    //! Stop the connection's handshake deadline (once it is a WebSocket, or
    //! handed to the fallback site). Safe to call more than once.
    std::function<void()> disarm_deadline;
    CService peer;
    CService local;
    bool is_tls{false};
    //! Whether the original TCP peer is a -trustedproxy
    bool tcp_peer_trusted{false};
    //! A trusted proxy's PROXY v2 header said the client used TLS
    bool proxy_tls{false};
    //! HTTP comes from a trusted proxy (after any PROXY header): its
    //! X-Forwarded-* headers are believed
    bool from_trusted_proxy{false};
    std::string client_cert_fingerprint_hex;
    //! base64url SHA-256 of the client certificate's public key, if any
    std::string client_cert_spki;
    //! ALPN protocol agreed in the TLS handshake, if any
    std::string alpn;
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
        LogEvent(BCLog::HTTP, "http_shutdown_request_rejected",
                 "Rejecting request while shutting down");
        co_return MakeSimpleResponse(HTTP_SERVICE_UNAVAILABLE, version);
    }

    auto slot{std::make_shared<ReplySlot>(executor)};
    auto impl{std::make_unique<HTTPRequestImpl>()};
    impl->beast_req = std::move(beast_req);
    impl->peer_address = conn.peer;
    impl->is_tls = conn.is_tls;
    impl->tcp_peer_trusted = conn.tcp_peer_trusted;
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
                if (auto *metrics{node::GetNodeMetrics()}) {
                    metrics->rpc_work_queue_rejected.Inc();
                }
                LogInfoEvent(BCLog::ALL, "http_work_queue_full",
                             "WARNING: request rejected because http work "
                             "queue depth exceeded, it can be increased with "
                             "the -rpcworkqueue= setting");
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
 * Address the P2P layer should see for a /p2p/ws peer: the client, already
 * resolved through trusted proxies (PROXY header, X-Forwarded-For).
 */
static CService P2PWebSocketPeerAddress(const BeastRequest &,
                                        const HTTPConnectionInfo &conn) {
    return conn.peer;
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
    if (conn.disarm_deadline) {
        // A WebSocket peer now, possibly handed to CConnman with its socket.
        conn.disarm_deadline();
    }
    auto info{std::make_shared<WebSocketTransportInfo>()};
    info->tls = conn.is_tls;
    info->compression = compression;
    info->peer_cert_fingerprint_hex = conn.client_cert_fingerprint_hex;
    info->peer_spki = conn.client_cert_spki;
    info->alpn = conn.alpn;
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
        const auto socketpair_error{NetworkErrorString(WSAGetLastError())};
        LogInfoEvent(BCLog::ALL, "p2p_websocket_socketpair_failed",
                     "P2P WebSocket: socketpair failed: {error}")
            .Field(BCLog::LogField::Error, socketpair_error);
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

static uint256 HashToken(std::string_view token) {
    uint256 out;
    CSHA256()
        .Write(reinterpret_cast<const uint8_t *>(token.data()), token.size())
        .Finalize(out.begin());
    return out;
}

/**
 * Whether a request carries an accepted upgrade token, as
 * "Authorization: Bearer <t>" or a "t=<t>" cookie. Compared as SHA-256
 * digests in constant time, so neither content nor length leaks by timing.
 */
static bool HasP2PWebSocketToken(const BeastRequest &req) {
    std::vector<std::string> candidates;
    const std::string_view auth{req[http::field::authorization]};
    if (auth.substr(0, 7) == "Bearer ") {
        candidates.emplace_back(auth.substr(7));
    }
    for (const std::string &cookie :
         util::SplitString(req[http::field::cookie], ';')) {
        const std::string_view trimmed{util::TrimStringView(cookie)};
        if (trimmed.substr(0, 2) == "t=") {
            candidates.emplace_back(trimmed.substr(2));
        }
    }
    bool found{false};
    for (const std::string &candidate : candidates) {
        const uint256 hash{HashToken(candidate)};
        for (const uint256 &accepted : g_p2p_websocket_token_hashes) {
            found |= CRYPTO_memcmp(hash.begin(), accepted.begin(),
                                   uint256::size()) == 0;
        }
    }
    return found;
}

/**
 * Whether a request is a P2P WebSocket upgrade for us. With tokens
 * configured, one without a valid token is not: it is handled as a request
 * for any other path would be, so the endpoint cannot be probed for.
 */
/**
 * Whether the client used TLS: to us, or to a trusted proxy that says so
 * (a PROXY v2 SSL TLV, or "X-Forwarded-Proto: https" as set by the nearest
 * proxy, i.e. the last value, from a connection by a trusted proxy).
 * Nothing an untrusted client sends is believed.
 */
static bool ClientUsedTLS(const BeastRequest &req,
                          const HTTPConnectionInfo &conn) {
    if (conn.is_tls || conn.proxy_tls) {
        return true;
    }
    if (!conn.from_trusted_proxy) {
        return false;
    }
    std::string last;
    const auto [first, end] = req.equal_range("X-Forwarded-Proto");
    for (auto f = first; f != end; ++f) {
        for (const std::string &proto : util::SplitString(f->value(), ',')) {
            last = util::TrimString(proto);
        }
    }
    return beast::iequals(last, "https");
}

static bool IsP2PWebSocketRequest(const BeastRequest &req,
                                  const HTTPConnectionInfo &conn) {
    return g_p2p_websocket_enabled &&
           URIHasPathPrefix(req.target(), g_p2p_websocket_path) &&
           (g_p2p_websocket_token_hashes.empty() ||
            (websocket::is_upgrade(req) && HasP2PWebSocketToken(req))) &&
           // Without TLS (-p2prequiretls), the endpoint answers like any
           // unserved path, so a probe cannot tell it exists.
           (!g_p2p_require_tls || ClientUsedTLS(req, conn));
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
    if (IsP2PWebSocketRequest(req, conn)) {
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

//! Health endpoints, for load balancer and orchestrator checks
static constexpr std::string_view LIVEZ_PATH{"/livez"};
static constexpr std::string_view READYZ_PATH{"/readyz"};
static constexpr std::string_view HEALTHZ_PATH{"/healthz"};

static std::string_view TargetPath(std::string_view target) {
    return target.substr(0, target.find('?'));
}

/** Whether a request (header) is a health check this server answers */
static bool IsHealthRequest(const BeastRequest &header, bool body_done) {
    if (!g_health_enabled || !body_done ||
        (header.method() != http::verb::get &&
         header.method() != http::verb::head)) {
        return false;
    }
    const std::string_view path{TargetPath(header.target())};
    return path == LIVEZ_PATH || path == READYZ_PATH || path == HEALTHZ_PATH;
}

/**
 * /livez: the server is running. /readyz (and /healthz, its alias for
 * tools expecting that name): the node is ready for traffic, i.e. out of
 * initial block download with peers; else 503 and the reason.
 */
static BeastResponse HealthResponse(const BeastRequest &header) {
    std::string reason;
    if (TargetPath(header.target()) != LIVEZ_PATH) {
        LOCK(g_readiness_mutex);
        reason = g_readiness_check ? g_readiness_check() : "starting";
    }
    UniValue body{UniValue::VOBJ};
    body.pushKV("status", reason.empty() ? "ok" : "unavailable");
    if (!reason.empty()) {
        body.pushKV("reason", reason);
    }
    BeastResponse res{reason.empty() ? http::status::ok
                                     : http::status::service_unavailable,
                      header.version()};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::cache_control, "no-store");
    res.body() = body.write() + "\n";
    res.prepare_payload();
    if (header.method() == http::verb::head) {
        res.body().clear();
    }
    return res;
}

/** Copy bytes from `from` to `to` until either side fails or closes */
template <typename From, typename To>
static asio::awaitable<void> PumpBytes(From &from, To &to) {
    std::array<char, 16384> data;
    while (true) {
        auto [rec, n] = co_await from.async_read_some(
            asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (rec) {
            co_return;
        }
        auto [wec, wn] =
            co_await asio::async_write(to, asio::buffer(data.data(), n),
                                       asio::as_tuple(asio::use_awaitable));
        if (wec) {
            co_return;
        }
    }
}

/**
 * Whether a public listener serves this request itself: a P2P WebSocket
 * upgrade we accept, or a Chronik path. Decided from the header alone.
 */
static bool ServedPublicly(const BeastRequest &req,
                           const HTTPConnectionInfo &conn) {
    const std::string_view target{req.target()};
    if (websocket::is_upgrade(req) && IsP2PWebSocketRequest(req, conn)) {
        return true;
    }
    return IsPublicPath(target) &&
           !URIHasPathPrefix(target, g_p2p_websocket_path);
}

/** Whether the P2P port serves this request itself (from the header alone) */
static bool ServedOnP2PPort(const BeastRequest &req,
                            const HTTPConnectionInfo &conn) {
    return websocket::is_upgrade(req) && IsP2PWebSocketRequest(req, conn);
}

/**
 * Hand the rest of a public connection to -publicfallback: the request
 * header as received (field names and order kept), whatever followed it in
 * `buffer` (the start of a body, pipelined requests), then raw bytes both
 * ways. The client sees the fallback's responses unchanged, as from an
 * ordinary site behind this TLS endpoint.
 */
template <typename Stream>
static asio::awaitable<void>
RelayToPublicFallback(Stream &stream, beast::flat_buffer &buffer,
                      const BeastRequest &header,
                      const HTTPConnectionInfo &conn) {
    beast::tcp_stream upstream{co_await asio::this_coro::executor};
    tcp::resolver resolver{co_await asio::this_coro::executor};
    auto [rec, results] = co_await resolver.async_resolve(
        g_public_fallback.host, std::to_string(g_public_fallback.port),
        asio::as_tuple(asio::use_awaitable));
    boost::system::error_code cec{rec};
    if (!rec) {
        upstream.expires_after(std::chrono::seconds{10});
        auto [ec, endpoint] = co_await upstream.async_connect(
            results, asio::as_tuple(asio::use_awaitable));
        cec = ec;
    }
    if (cec) {
        LogDebug(BCLog::HTTP, "-publicfallback %s:%u unreachable: %s\n",
                 g_public_fallback.host, g_public_fallback.port, cec.message());
        BeastResponse res{MakeSimpleResponse(502, header.version())};
        res.keep_alive(false);
        co_await WriteResponse(stream, res);
        co_return;
    }
    upstream.expires_never();
    boost::system::error_code ignored;
    upstream.socket().set_option(tcp::no_delay(true), ignored);

    std::string head{strprintf("%s %s HTTP/%u.%u\r\n",
                               std::string_view{header.method_string()},
                               std::string_view{header.target()},
                               header.version() / 10, header.version() % 10)};
    for (const auto &f : header) {
        head += strprintf("%s: %s\r\n", std::string_view{f.name_string()},
                          std::string_view{f.value()});
    }
    // Where the request really came from, for the fallback's own logs.
    head += strprintf("X-Forwarded-For: %s\r\nX-Forwarded-Proto: %s\r\n\r\n",
                      conn.peer.ToStringAddr(), conn.is_tls ? "https" : "http");
    const std::array<asio::const_buffer, 2> first{asio::buffer(head),
                                                  buffer.data()};
    auto [wec, wn] = co_await asio::async_write(
        upstream, first, asio::as_tuple(asio::use_awaitable));
    buffer.consume(buffer.size());
    if (wec) {
        co_return;
    }
    co_await (PumpBytes(stream, upstream) || PumpBytes(upstream, stream));
}

/** Endpoint class of a request, for metrics */
static node::HTTPEndpoint MetricsEndpoint(std::string_view target) {
    using E = node::HTTPEndpoint;
    const std::string_view path{TargetPath(target)};
    if (path == "/") {
        return E::RPC;
    }
    if (URIHasPathPrefix(path, "/wallet")) {
        return E::WALLET;
    }
    if (URIHasPathPrefix(path, "/rest")) {
        return E::REST;
    }
    if (URIHasPathPrefix(path, CHRONIK_PREFIX)) {
        return E::CHRONIK;
    }
    if (path == LIVEZ_PATH || path == READYZ_PATH || path == HEALTHZ_PATH) {
        return E::HEALTH;
    }
    if (path == "/metrics") {
        return E::METRICS;
    }
    return E::OTHER;
}

/** Count an answered request and its duration (since its header arrived) */
static void RecordHTTPMetrics(node::HTTPEndpoint endpoint, unsigned status,
                              std::chrono::steady_clock::time_point start) {
    auto *metrics{node::GetNodeMetrics()};
    if (!metrics) {
        return;
    }
    const size_t ep{size_t(endpoint)};
    const std::array<size_t, 2> idx{
        ep, status >= 100 && status < 600 ? status / 100 - 1 : 5};
    metrics->http_requests.Add(metrics->http_requests.SeriesIndex(idx));
    metrics->http_request_seconds.RecordDuration(
        std::chrono::steady_clock::now() - start, ep);
}

/**
 * Behind trusted proxies, a request's client is found by walking
 * X-Forwarded-For (see -trustedproxy). Everything that follows uses it:
 * -rpcallowip, the P2P peer address, logs and forwarded headers.
 */
static std::optional<HTTPConnectionInfo>
ForwardedClient(const BeastRequest &header, const HTTPConnectionInfo &conn) {
    std::optional<HTTPConnectionInfo> forwarded;
    if (IsTrustedProxy(conn.peer)) {
        std::vector<std::string_view> xff;
        const auto [first, last] = header.equal_range("X-Forwarded-For");
        for (auto f = first; f != last; ++f) {
            xff.push_back(f->value());
        }
        if (!xff.empty()) {
            forwarded.emplace(conn);
            forwarded->peer = proxy_protocol::ResolveForwardedClient(
                conn.peer, xff, IsTrustedProxy);
        }
    }
    return forwarded;
}

/**
 * Whether the WebSocket and Chronik endpoints serve this request: on public
 * listeners for anyone, on RPC listeners only for -rpcallowip clients.
 * Other requests go to DispatchRequest, which applies the same rules.
 */
static bool EndpointAllowed(const BeastRequest &req,
                            const HTTPConnectionInfo &conn,
                            const HTTPConnectionInfo &client) {
    return conn.p2p_port ? IsP2PWebSocketRequest(req, client)
           : conn.public_only ? IsPublicPath(req.target()) ||
                                    IsP2PWebSocketRequest(req, client)
                              : ClientAllowed(client.peer);
}

/**
 * Answer a complete request that is not a WebSocket upgrade: Chronik in
 * process, else the registered handlers. Counts an active request (see
 * HTTPConnectionTracker) that the caller removes once the reply is written.
 */
static asio::awaitable<BeastResponse>
RouteRequest(BeastRequest &&req, const HTTPConnectionInfo &client,
             bool endpoint_allowed) {
    if (endpoint_allowed && !client.p2p_port && g_chronik_enabled &&
        !g_reject_requests.load() &&
        URIHasPathPrefix(req.target(), CHRONIK_PREFIX)) {
        g_connections.AddRequest();
        if (auto handlers{GetChronikInProcess()}) {
            co_return co_await InProcessChronikHTTP(std::move(handlers), req,
                                                    client);
        }
        // Before Chronik started or after it was interrupted
        co_return MakeSimpleResponse(503, req.version(),
                                     "Chronik is not running");
    }
    co_return co_await DispatchRequest(std::move(req), client);
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
        // Request timing for metrics (one clock read, only when enabled)
        const auto request_start{node::GetNodeMetrics()
                                     ? std::chrono::steady_clock::now()
                                     : std::chrono::steady_clock::time_point{}};

        const std::optional<HTTPConnectionInfo> forwarded{
            ForwardedClient(header, conn)};
        const HTTPConnectionInfo &client{forwarded ? *forwarded : conn};

        if (!conn.p2p_port && IsHealthRequest(header, parser.is_done())) {
            BeastResponse res{HealthResponse(header)};
            res.keep_alive(header.keep_alive());
            const auto ec{co_await WriteResponse(stream, res)};
            RecordHTTPMetrics(node::HTTPEndpoint::HEALTH, res.result_int(),
                              request_start);
            if (ec || !header.keep_alive()) {
                co_return;
            }
            continue;
        }
        if (conn.public_only && g_public_fallback.enabled &&
            !g_reject_requests.load() &&
            !(conn.p2p_port ? ServedOnP2PPort(header, client)
                            : ServedPublicly(header, client))) {
            // Not ours: the fallback site answers (body and all).
            if (conn.disarm_deadline) {
                conn.disarm_deadline();
            }
            idle->busy = true;
            co_await RelayToPublicFallback(stream, buffer, header, client);
            co_return;
        }
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
        const node::HTTPEndpoint endpoint{MetricsEndpoint(req.target())};
        const bool keep_alive{req.keep_alive()};
        const unsigned version{req.version()};
        const bool is_head{req.method() == http::verb::head};

        const bool endpoint_allowed{EndpointAllowed(req, conn, client)};

        // Handlers may take arbitrarily long (e.g. long polling), as may
        // WebSocket sessions.
        idle->busy = true;
        if (endpoint_allowed && websocket::is_upgrade(req) &&
            !g_reject_requests.load() &&
            co_await TryHandleWebSocketUpgrade(stream, buffer, req, client)) {
            co_return;
        }

        BeastResponse res{
            co_await RouteRequest(std::move(req), client, endpoint_allowed)};

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
        RecordHTTPMetrics(endpoint, res.result_int(), request_start);
        g_connections.RemoveRequest();
        if (ec || close) {
            co_return;
        }
    }
}

#ifdef ENABLE_HTTP2
/** What an H2Tunnel needs from its connection */
class H2TunnelOwner {
public:
    virtual ~H2TunnelOwner() = default;
    virtual http2::ServerSession &Session() = 0;
    //! Frames were queued: let the connection's writer send them
    virtual void WakeWriter() = 0;
};

/**
 * One accepted extended CONNECT (RFC 8441) stream as an Asio AsyncStream:
 * reads return the client's DATA, writes become DATA frames. Beast's
 * WebSocket stream runs on it for Chronik, and P2P bytes are pumped through
 * it. Only used on the connection's strand.
 *
 * Flow control follows delivery: the client's window is reopened only by
 * what a read hands out, and writes wait while more than MAX_QUEUED bytes
 * are waiting for the client's window.
 *
 * Beast's server handshake (async_accept) needs an HTTP/1.1 upgrade request
 * and writes a 101 response. Until the tunnel is accepted, writes are
 * captured: the 101 becomes the HTTP/2 response (200, with the handshake's
 * other fields, e.g. Sec-WebSocket-Protocol), anything else is sent as that
 * status without a tunnel.
 */
class H2Tunnel : public std::enable_shared_from_this<H2Tunnel> {
public:
    using executor_type = asio::any_io_executor;
    static constexpr size_t MAX_QUEUED{256 * 1024};

    H2Tunnel(std::shared_ptr<H2TunnelOwner> owner, int32_t id,
             asio::any_io_executor ex)
        : m_owner{std::move(owner)}, m_id{id}, m_ex{ex},
          m_rx_wait{ex, asio::steady_timer::time_point::max()},
          m_tx_wait{ex, asio::steady_timer::time_point::max()} {}

    executor_type get_executor() const { return m_ex; }
    int32_t Id() const { return m_id; }

    // From the connection
    void OnData(std::string_view data) {
        if (m_read_stopped) {
            // Nobody reads any more: discard, but keep the window open.
            m_owner->Session().TunnelConsumed(m_id, data.size());
            m_owner->WakeWriter();
            return;
        }
        m_rx.emplace_back(data);
        m_rx_wait.cancel();
    }
    void OnEof() {
        m_rx_eof = true;
        m_rx_wait.cancel();
    }
    void OnClosed() {
        m_closed = true;
        m_rx_wait.cancel();
        m_tx_wait.cancel();
    }
    void OnWritable() {
        if (m_owner->Session().TunnelQueued(m_id) < MAX_QUEUED) {
            m_tx_wait.cancel();
        }
    }

    // From the application
    /** Accept with a 2xx response; the stream stays open both ways */
    void Accept(unsigned status, const http2::Headers &headers) {
        m_capturing = false;
        if (!m_closed) {
            m_owner->Session().AcceptTunnel(m_id, status, headers);
            m_owner->WakeWriter();
        }
    }
    /** Answer without a tunnel */
    void Refuse(http::status status) {
        m_capturing = false;
        if (!m_closed) {
            BeastResponse res{status, 11};
            res.prepare_payload();
            m_owner->Session().SubmitResponse(m_id, std::move(res));
            m_owner->WakeWriter();
        }
        m_closed = true;
    }
    /** End our side after what was written (END_STREAM) */
    void End() {
        if (!m_ended && !m_closed) {
            m_ended = true;
            m_owner->Session().TunnelEnd(m_id);
            m_owner->WakeWriter();
        }
    }
    /** Stop reading: the client's further bytes are discarded */
    void StopReading() {
        m_read_stopped = true;
        size_t pending{0};
        for (const auto &chunk : m_rx) {
            pending += chunk.size();
        }
        pending -= m_rx_offset;
        m_rx.clear();
        m_rx_offset = 0;
        if (pending > 0) {
            m_owner->Session().TunnelConsumed(m_id, pending);
            m_owner->WakeWriter();
        }
        m_rx_wait.cancel();
    }

    template <typename MutableBuffers, typename Token>
    auto async_read_some(const MutableBuffers &buffers, Token &&token) {
        return Launch([self = shared_from_this(),
                       buffers]() { return self->ReadSome(buffers); },
                      std::forward<Token>(token));
    }

    template <typename ConstBuffers, typename Token>
    auto async_write_some(const ConstBuffers &buffers, Token &&token) {
        return Launch(
            [self = shared_from_this(),
             data = beast::buffers_to_string(buffers)]() mutable {
                return self->WriteSome(std::move(data));
            },
            std::forward<Token>(token));
    }

    // What InProcessWsSession expects of the lowest layer
    void expires_never() {}
    H2Tunnel &socket() { return *this; }
    void close(boost::system::error_code &ec) {
        ec = {};
        End();
        StopReading();
    }

private:
    using Result = std::tuple<boost::system::error_code, size_t>;

    template <typename F, typename Token> auto Launch(F f, Token &&token) {
        return asio::async_initiate<Token,
                                    void(boost::system::error_code, size_t)>(
            [ex = m_ex](auto handler, F f) {
                asio::co_spawn(ex, std::move(f)(),
                               [h = std::move(handler)](std::exception_ptr e,
                                                        Result r) mutable {
                                   if (e) {
                                       std::move(h)(
                                           asio::error::operation_aborted, 0);
                                       return;
                                   }
                                   std::move(h)(std::get<0>(r), std::get<1>(r));
                               });
            },
            token, std::move(f));
    }

    static asio::awaitable<bool> Cancelled() {
        auto cs{co_await asio::this_coro::cancellation_state};
        co_return cs.cancelled() != asio::cancellation_type::none;
    }

    template <typename MutableBuffers>
    asio::awaitable<Result> ReadSome(MutableBuffers buffers) {
        if (asio::buffer_size(buffers) == 0) {
            co_return Result{{}, 0};
        }
        while (m_rx.empty() && !m_rx_eof && !m_closed && !m_read_stopped) {
            m_rx_wait.expires_at(asio::steady_timer::time_point::max());
            co_await m_rx_wait.async_wait(asio::as_tuple(asio::use_awaitable));
            if (co_await Cancelled()) {
                co_return Result{asio::error::operation_aborted, 0};
            }
        }
        if (!m_rx.empty()) {
            size_t n{0};
            auto out{beast::buffers_range_ref(buffers)};
            for (auto it = out.begin(); it != out.end() && !m_rx.empty();) {
                asio::mutable_buffer b{*it};
                const std::string &front{m_rx.front()};
                // One chunk (or what fits of it) per buffer.
                const size_t take{
                    std::min(b.size(), front.size() - m_rx_offset)};
                std::memcpy(b.data(), front.data() + m_rx_offset, take);
                n += take;
                m_rx_offset += take;
                if (m_rx_offset == front.size()) {
                    m_rx.pop_front();
                    m_rx_offset = 0;
                }
                ++it;
            }
            m_owner->Session().TunnelConsumed(m_id, n);
            m_owner->WakeWriter();
            co_return Result{{}, n};
        }
        if (m_rx_eof || m_read_stopped) {
            co_return Result{asio::error::eof, 0};
        }
        co_return Result{asio::error::connection_reset, 0};
    }

    asio::awaitable<Result> WriteSome(std::string data) {
        const size_t n{data.size()};
        if (m_capturing) {
            Capture(data);
            co_return Result{{}, n};
        }
        while (!m_closed && !m_ended &&
               m_owner->Session().TunnelQueued(m_id) >= MAX_QUEUED) {
            m_tx_wait.expires_at(asio::steady_timer::time_point::max());
            co_await m_tx_wait.async_wait(asio::as_tuple(asio::use_awaitable));
            if (co_await Cancelled()) {
                co_return Result{asio::error::operation_aborted, 0};
            }
        }
        if (m_closed || m_ended) {
            co_return Result{asio::error::broken_pipe, 0};
        }
        m_owner->Session().TunnelSend(m_id, data);
        m_owner->WakeWriter();
        co_return Result{{}, n};
    }

    /** Turn Beast's HTTP/1.1 handshake response into the HTTP/2 one */
    void Capture(std::string_view data) {
        m_handshake.append(data);
        const size_t end{m_handshake.find("\r\n\r\n")};
        if (end == std::string::npos) {
            return;
        }
        const std::string rest{m_handshake.substr(end + 4)};
        const auto lines{util::SplitString(m_handshake.substr(0, end), '\n')};
        unsigned status{500};
        if (!lines.empty() && lines[0].size() >= 12) {
            status = unsigned(std::atoi(lines[0].substr(9, 3).c_str()));
        }
        http2::Headers headers;
        for (size_t i = 1; i < lines.size(); ++i) {
            const auto colon{lines[i].find(':')};
            if (colon == std::string::npos) {
                continue;
            }
            const std::string name{util::TrimString(lines[i].substr(0, colon))};
            if (beast::iequals(name, "sec-websocket-accept") ||
                beast::iequals(name, "upgrade") ||
                beast::iequals(name, "connection") ||
                beast::iequals(name, "content-length") ||
                beast::iequals(name, "server")) {
                continue;
            }
            headers.emplace_back(name,
                                 util::TrimString(lines[i].substr(colon + 1)));
        }
        m_handshake.clear();
        if (status == 101) {
            Accept(200, headers);
            if (!rest.empty()) {
                m_owner->Session().TunnelSend(m_id, rest);
            }
        } else {
            Refuse(http::status(status));
        }
    }

    std::shared_ptr<H2TunnelOwner> m_owner;
    const int32_t m_id;
    asio::any_io_executor m_ex;
    asio::steady_timer m_rx_wait, m_tx_wait;
    std::deque<std::string> m_rx;
    size_t m_rx_offset{0};
    bool m_rx_eof{false};
    bool m_read_stopped{false};
    bool m_closed{false};
    bool m_ended{false};
    bool m_capturing{true};
    std::string m_handshake;
};

/** Beast's close_socket() for H2Tunnel (e.g. on a WebSocket timeout) */
inline void beast_close_socket(H2Tunnel &tunnel) {
    boost::system::error_code ignored;
    tunnel.close(ignored);
}

/** Beast WebSocket teardown for H2Tunnel: END_STREAM */
inline void teardown(beast::role_type, H2Tunnel &tunnel,
                     boost::system::error_code &ec) {
    tunnel.close(ec);
}

template <typename TeardownHandler>
void async_teardown(beast::role_type role, H2Tunnel &tunnel,
                    TeardownHandler &&handler) {
    boost::system::error_code ec;
    teardown(role, tunnel, ec);
    asio::post(
        tunnel.get_executor(),
        [h = std::forward<TeardownHandler>(handler), ec]() mutable { h(ec); });
}

/** Accept a P2P WebSocket over an HTTP/2 stream and hand it to CConnman */
static asio::awaitable<void>
AcceptP2PWebSocketH2(std::shared_ptr<H2Tunnel> tunnel, const BeastRequest &req,
                     const HTTPConnectionInfo &conn) {
#ifdef HAVE_P2P_WEBSOCKET_BRIDGE
    P2PWebSocketAcceptor acceptor{
        WITH_LOCK(g_p2p_websocket_mutex, return g_p2p_websocket_acceptor)};
    if (!acceptor) {
        tunnel->Refuse(http::status::service_unavailable);
        co_return;
    }
    // permessage-deflate needs the WebSocket bridge, which this path does
    // not use: only the zstd protocols or plain messages.
    auto [selected, compression] = p2pws::NegotiateP2PCompression(
        req[http::field::sec_websocket_protocol], /*deflate_offered=*/false);
    // CConnman polls a socket: it gets one end of a socketpair, and
    // WebSocketSock does the framing there exactly as for HTTP/1.1 peers.
    // This connection pumps the WebSocket bytes between the other end and
    // the HTTP/2 stream.
    const auto pair{p2pws::CreateBridgeSocketPair()};
    if (!pair) {
        tunnel->Refuse(http::status::internal_server_error);
        co_return;
    }
    p2pws::LocalSocket local{co_await asio::this_coro::executor};
    boost::system::error_code ec;
    local.assign(asio::local::stream_protocol{}, pair->second, ec);
    if (ec) {
        Sock unused{static_cast<SOCKET>(pair->first)};
        ::close(pair->second);
        tunnel->Refuse(http::status::internal_server_error);
        co_return;
    }
    auto info{std::make_shared<WebSocketTransportInfo>()};
    info->tls = conn.is_tls;
    info->compression = compression;
    info->peer_cert_fingerprint_hex = conn.client_cert_fingerprint_hex;
    info->peer_spki = conn.client_cert_spki;
    info->alpn = conn.alpn;
    http2::Headers headers;
    if (!selected.empty()) {
        headers.emplace_back("sec-websocket-protocol", selected);
    }
    if (conn.disarm_deadline) conn.disarm_deadline();
    tunnel->Accept(200, headers);
    const CService peer{P2PWebSocketPeerAddress(req, conn)};
    LogDebug(BCLog::NET, "P2P WebSocket peer %s connected (wss, %s, HTTP/2)\n",
             peer.ToStringAddrPort(), P2PWebSocketCompressionName(compression));
    acceptor(std::make_unique<WebSocketSock>(
                 SOCKET(pair->first), WebSocketCodec::Role::SERVER, info,
                 std::make_unique<PlainByteLayer>()),
             CAddress{peer, NODE_NONE}, CAddress{conn.local, NODE_NONE}, info);
    const auto from_client = [&]() -> asio::awaitable<void> {
        co_await PumpBytes(*tunnel, local);
        // The client ended the stream (or reset it): CConnman sees EOF.
        boost::system::error_code ignored;
        local.shutdown(asio::socket_base::shutdown_send, ignored);
    };
    const auto to_client = [&]() -> asio::awaitable<void> {
        co_await PumpBytes(local, *tunnel);
        // CConnman closed the peer: end the stream and stop reading it.
        tunnel->End();
        tunnel->StopReading();
    };
    co_await (from_client() && to_client());
    boost::system::error_code ignored;
    local.close(ignored);
#else
    (void)req;
    (void)conn;
    tunnel->Refuse(http::status::not_implemented);
    co_return;
#endif
}

/**
 * One HTTP/2 connection (ALPN h2 on a TLS listener). nghttp2 does the
 * framing (see http2_server.h); this drives it over our TLS stream on the
 * connection's strand: a reader feeds received bytes in, a writer sends what
 * it produces, and each stream's request runs as its own coroutine through
 * the same routing as an HTTP/1.1 request (ACL, -trustedproxy, public
 * listener rules, Chronik, handlers, zstd, metrics).
 *
 * The connection object outlives the stream it was given only as an inert
 * shell: request coroutines still waiting for a worker's reply when the
 * connection ends find it closed and drop their reply.
 */
class H2Connection : public std::enable_shared_from_this<H2Connection>,
                     public H2TunnelOwner {
public:
    H2Connection(OsslStream &stream, const HTTPConnectionInfo &conn,
                 asio::any_io_executor ex)
        : m_stream{stream}, m_conn{conn}, m_ex{ex},
          m_wake{ex, asio::steady_timer::time_point::max()}, m_deadline{ex},
          m_session{SessionLimits(), Handlers()} {}

    asio::awaitable<void> Run(beast::flat_buffer &buffer) {
        auto self{shared_from_this()};
        LogDebug(BCLog::HTTP, "HTTP/2 connection from %s\n",
                 m_conn.peer.ToStringAddrPort());
        // Anything already read past the TLS handshake (normally nothing).
        if (buffer.size() > 0) {
            const auto data{buffer.cdata()};
            m_reading = m_session.Receive(
                {static_cast<const uint8_t *>(data.data()), data.size()});
            buffer.consume(buffer.size());
            SpawnNewRequests();
        }
        asio::co_spawn(m_ex, WatchDeadlines(self), asio::detached);
        co_await (ReadLoop() && WriteLoop());
        Close();
    }

private:
    struct StreamState {
        //! g_connections.AddRequest() was done for it (see RouteRequest)
        bool counted{false};
        //! Its handler has not answered yet
        bool handler_running{false};
    };

    static http2::Limits SessionLimits() {
        http2::Limits limits{g_http2_limits};
        limits.max_body_size = g_max_body_size;
        // WebSockets over HTTP/2 (RFC 8441): /p2p/ws and /chronik/ws
        limits.enable_connect_protocol = true;
        return limits;
    }

    http2::ServerSession &Session() override { return m_session; }
    void WakeWriter() override { Wake(); }

    std::shared_ptr<H2Tunnel> FindTunnel(int32_t id) {
        const auto it{m_tunnels.find(id)};
        return it == m_tunnels.end() ? nullptr : it->second;
    }

    http2::ServerSession::Handlers Handlers() {
        http2::ServerSession::Handlers h;
        h.on_request = [this](int32_t id, BeastRequest &&req) {
            m_new_requests.emplace_back(id, std::move(req));
        };
        h.on_connect = [this](int32_t id, BeastRequest &&req,
                              std::string protocol) {
            m_new_connects.push_back({id, std::move(req), std::move(protocol)});
        };
        h.on_tunnel_data = [this](int32_t id, std::string_view data) {
            if (auto tunnel{FindTunnel(id)}) {
                tunnel->OnData(data);
            } else {
                // Not yet started (same Receive() as the CONNECT): keep it.
                m_early_tunnel_data[id].append(data);
            }
        };
        h.on_tunnel_eof = [this](int32_t id) {
            if (auto tunnel{FindTunnel(id)}) {
                tunnel->OnEof();
            } else {
                m_early_tunnel_eof.insert(id);
            }
        };
        h.on_stream_close = [this](int32_t id, uint32_t) {
            // A complete request and its RST_STREAM may arrive in one read,
            // before SpawnNewRequests() runs. Do not dispatch closed streams
            // or recreate their application bookkeeping after this callback.
            std::erase_if(m_new_requests, [id](const auto &request) {
                return request.first == id;
            });
            std::erase_if(m_new_connects, [id](const auto &connect) {
                return connect.id == id;
            });
            if (auto tunnel{FindTunnel(id)}) {
                tunnel->OnClosed();
                m_tunnels.erase(id);
            }
            m_early_tunnel_data.erase(id);
            m_early_tunnel_eof.erase(id);
            const auto it{m_streams.find(id)};
            if (it == m_streams.end()) {
                return;
            }
            if (it->second.counted) {
                // Once the bytes already framed for it are written.
                ++m_removals_after_write;
            }
            if (it->second.handler_running) {
                --m_handlers_running;
            }
            m_streams.erase(it);
        };
        return h;
    }

    /** Start the requests the last Receive() completed */
    void SpawnNewRequests() {
        auto connects{std::move(m_new_connects)};
        m_new_connects.clear();
        for (auto &c : connects) {
            auto tunnel{
                std::make_shared<H2Tunnel>(shared_from_this(), c.id, m_ex)};
            m_tunnels[c.id] = tunnel;
            if (auto it{m_early_tunnel_data.find(c.id)};
                it != m_early_tunnel_data.end()) {
                tunnel->OnData(it->second);
                m_early_tunnel_data.erase(it);
            }
            if (m_early_tunnel_eof.erase(c.id)) {
                tunnel->OnEof();
            }
            ++m_tunnels_running;
            asio::co_spawn(m_ex,
                           HandleConnect(shared_from_this(), tunnel,
                                         std::move(c.req),
                                         std::move(c.protocol)),
                           asio::detached);
        }
        auto requests{std::move(m_new_requests)};
        m_new_requests.clear();
        for (auto &[id, req] : requests) {
            m_streams[id].handler_running = true;
            ++m_handlers_running;
            asio::co_spawn(
                m_ex, HandleRequest(shared_from_this(), id, std::move(req)),
                asio::detached);
        }
    }

    /** One stream's request, routed like an HTTP/1.1 request */
    static asio::awaitable<void>
    HandleRequest(std::shared_ptr<H2Connection> self, int32_t id,
                  BeastRequest req) {
        const auto request_start{node::GetNodeMetrics()
                                     ? std::chrono::steady_clock::now()
                                     : std::chrono::steady_clock::time_point{}};
        const std::optional<HTTPConnectionInfo> forwarded{
            ForwardedClient(req, self->m_conn)};
        HTTPConnectionInfo client{forwarded ? *forwarded : self->m_conn};
        // The work queue runs the requests of one connection id on one
        // strand, one at a time (right for HTTP/1.1, where they are
        // sequential anyway). Streams are independent: no id, so each gets
        // its own strand and they run concurrently.
        client.connection_id = 0;
        const bool is_head{req.method() == http::verb::head};
        BeastResponse res;
        node::HTTPEndpoint endpoint{node::HTTPEndpoint::HEALTH};
        if (!self->m_conn.p2p_port && IsHealthRequest(req, /*body_done=*/true)) {
            res = HealthResponse(req);
        } else {
            endpoint = MetricsEndpoint(req.target());
            const bool allowed{EndpointAllowed(req, self->m_conn, client)};
            if (auto it{self->m_streams.find(id)};
                it != self->m_streams.end() && !self->m_closed) {
                it->second.counted = true;
            } else {
                // Reset by the client already: nothing to answer.
                co_return;
            }
            res = co_await RouteRequest(std::move(req), client, allowed);
        }
        self->Respond(id, std::move(res), is_head, endpoint, request_start);
    }

    /**
     * An extended CONNECT (RFC 8441): a WebSocket for /p2p/ws or /chronik/ws,
     * under the same rules as an HTTP/1.1 upgrade (-rpcallowip on RPC
     * listeners, public prefixes on public ones, upgrade tokens,
     * -trustedproxy). Anything else is answered without a tunnel.
     */
    static asio::awaitable<void>
    HandleConnect(std::shared_ptr<H2Connection> self,
                  std::shared_ptr<H2Tunnel> tunnel, BeastRequest req,
                  std::string protocol) {
        co_await ServeTunnel(self, tunnel, std::move(req), protocol);
        tunnel->End();
        --self->m_tunnels_running;
        self->m_last_activity = std::chrono::steady_clock::now();
    }

    static asio::awaitable<void> ServeTunnel(std::shared_ptr<H2Connection> self,
                                             std::shared_ptr<H2Tunnel> tunnel,
                                             BeastRequest req,
                                             const std::string &protocol) {
        if (!beast::iequals(protocol, "websocket")) {
            tunnel->Refuse(http::status::not_implemented);
            co_return;
        }
        if (g_reject_requests.load()) {
            tunnel->Refuse(http::status::service_unavailable);
            co_return;
        }
        if (req[http::field::sec_websocket_version] != "13") {
            tunnel->Refuse(http::status::bad_request);
            co_return;
        }
        // The HTTP/1.1 upgrade request this stands for, which the endpoint
        // checks and Beast's handshake expect. The key is ours: RFC 8441
        // has none, and the Accept derived from it is not sent.
        req.method(http::verb::get);
        req.set(http::field::upgrade, "websocket");
        req.set(http::field::connection, "Upgrade");
        std::vector<unsigned char> nonce(16);
        GetRandBytes(nonce);
        req.set(http::field::sec_websocket_key, EncodeBase64(nonce));
        // No extensions (permessage-deflate) over HTTP/2.
        req.erase(http::field::sec_websocket_extensions);

        const std::optional<HTTPConnectionInfo> forwarded{
            ForwardedClient(req, self->m_conn)};
        const HTTPConnectionInfo client{forwarded ? *forwarded : self->m_conn};
        const bool allowed{EndpointAllowed(req, self->m_conn, client)};
        if (allowed && IsP2PWebSocketRequest(req, client)) {
            co_await AcceptP2PWebSocketH2(tunnel, req, client);
            co_return;
        }
        if (allowed && g_chronik_enabled &&
            URIHasPathPrefix(req.target(), CHRONIK_PREFIX + "/ws")) {
            auto handlers{GetChronikInProcess()};
            if (!handlers) {
                tunnel->Refuse(http::status::service_unavailable);
            } else if (!co_await InProcessChronikWebSocket(
                           std::move(handlers), *tunnel, req, client)) {
                tunnel->Refuse(http::status::bad_request);
            }
            co_return;
        }
        // As for an HTTP/1.1 upgrade that is not served: 403 for a client
        // outside -rpcallowip on an RPC listener, else 404.
        tunnel->Refuse(!self->m_conn.public_only && !ClientAllowed(client.peer)
                           ? http::status::forbidden
                           : http::status::not_found);
    }

    void Respond(int32_t id, BeastResponse &&res, bool is_head,
                 node::HTTPEndpoint endpoint,
                 std::chrono::steady_clock::time_point request_start) {
        const auto it{m_streams.find(id)};
        if (it == m_streams.end() || m_closed) {
            // The stream (and its request count) is gone already.
            return;
        }
        if (it->second.handler_running) {
            it->second.handler_running = false;
            --m_handlers_running;
        }
        bool close{g_reject_requests.load()};
        if (auto c{res.find(http::field::connection)};
            c != res.end() && beast::iequals(c->value(), "close")) {
            close = true;
        }
        const unsigned status{res.result_int()};
        m_session.SubmitResponse(id, std::move(res), is_head);
        RecordHTTPMetrics(endpoint, status, request_start);
        if (close) {
            // Like Connection: close over HTTP/1.1: finish what is open,
            // take no new requests.
            m_session.Shutdown();
        }
        // Like HTTP/1.1, idle time counts from the handler's answer.
        m_last_activity = std::chrono::steady_clock::now();
        Wake();
    }

    asio::awaitable<void> ReadLoop() {
        std::vector<uint8_t> buf(64 * 1024);
        while (m_reading && m_session.WantsRead()) {
            auto [ec, n] = co_await m_stream.async_read_some(
                asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (ec) {
                // Gone, or cancelled by the writer or the deadline watcher.
                break;
            }
            m_last_activity = std::chrono::steady_clock::now();
            if (!m_session.Receive({buf.data(), n})) {
                LogDebug(BCLog::HTTP, "HTTP/2 connection from %s: %s\n",
                         m_conn.peer.ToStringAddrPort(),
                         m_session.Flooded() ? "flood, closing"
                                             : "protocol error, closing");
                m_reading = false;
            }
            SpawnNewRequests();
            Wake();
        }
        m_reading = false;
        Wake();
    }

    asio::awaitable<void> WriteLoop() {
        while (!m_closed) {
            http2::Output out;
            if (!m_session.Collect(out, MAX_WRITE_BATCH)) {
                break;
            }
            if (out.Empty()) {
                if (!m_reading || !m_session.WantsRead()) {
                    // Nothing more will come (the client is gone, or the
                    // session ended with GOAWAY): stop the reader too.
                    break;
                }
                co_await WaitWake();
                continue;
            }
            for (const auto &[id, tunnel] : m_tunnels) {
                tunnel->OnWritable();
            }
            const auto ec{co_await WriteAll(out)};
            out.Clear();
            for (; m_removals_after_write > 0; --m_removals_after_write) {
                g_connections.RemoveRequest();
            }
            if (ec) {
                break;
            }
            m_last_activity = std::chrono::steady_clock::now();
        }
        m_reading = false;
        boost::system::error_code ignored;
        beast::get_lowest_layer(m_stream).socket().cancel(ignored);
    }

    /** Write all of `out`: directly while the socket takes it, then async */
    asio::awaitable<boost::system::error_code>
    WriteAll(const http2::Output &out) {
        const auto buffers{out.Buffers()};
        beast::buffers_suffix<std::vector<asio::const_buffer>> rest{buffers};
        boost::system::error_code ec;
        while (!ec && beast::buffer_bytes(rest) > 0) {
            rest.consume(m_stream.write_some(rest, ec));
        }
        if (ec == asio::error::would_block) {
            auto [wec, n] = co_await asio::async_write(
                m_stream, rest, asio::as_tuple(asio::use_awaitable));
            ec = wec;
        }
        co_return ec;
    }

    void Wake() {
        m_wake_pending = true;
        m_wake.cancel();
    }

    asio::awaitable<void> WaitWake() {
        if (!m_wake_pending) {
            m_wake.expires_at(asio::steady_timer::time_point::max());
            co_await m_wake.async_wait(asio::as_tuple(asio::use_awaitable));
        }
        m_wake_pending = false;
    }

    /**
     * -rpcservertimeout for HTTP/2: the connection is closed when it made no
     * progress for that long while no handler ran, and a stream whose
     * request is still arriving after that long is reset (slow clients
     * cannot hold streams open by sending a byte now and then).
     */
    static asio::awaitable<void>
    WatchDeadlines(std::shared_ptr<H2Connection> self) {
        using namespace std::chrono_literals;
        const auto tick{std::min<std::chrono::steady_clock::duration>(
            g_server_timeout, 1s)};
        bool goaway_sent{false};
        while (!self->m_closed) {
            self->m_deadline.expires_after(tick);
            co_await self->m_deadline.async_wait(
                asio::as_tuple(asio::use_awaitable));
            if (self->m_closed) {
                break;
            }
            const auto now{std::chrono::steady_clock::now()};
            for (const int32_t id : self->m_session.IncompleteRequestsSince(
                     now - g_server_timeout)) {
                LogDebug(BCLog::HTTP,
                         "HTTP/2 request from %s timed out (stream %d)\n",
                         self->m_conn.peer.ToStringAddrPort(), id);
                self->m_session.Reset(id, NGHTTP2_CANCEL);
                // The connection is idle from now on, not before: an idle
                // GOAWAY in the same tick would cancel the reset.
                self->m_last_activity = now;
                self->Wake();
            }
            const bool busy{self->m_handlers_running > 0 ||
                            self->m_tunnels_running > 0};
            if (busy || now < self->m_last_activity + g_server_timeout) {
                continue;
            }
            if (!goaway_sent) {
                // Idle: say goodbye, then give the client one more timeout.
                goaway_sent = true;
                self->m_last_activity = now;
                self->m_session.Terminate(NGHTTP2_NO_ERROR);
                self->Wake();
                continue;
            }
            boost::system::error_code ec;
            auto &socket{beast::get_lowest_layer(self->m_stream).socket()};
            socket.shutdown(tcp::socket::shutdown_both, ec);
            socket.cancel(ec);
            break;
        }
    }

    void Close() {
        m_closed = true;
        m_deadline.cancel();
        m_wake.cancel();
        for (const auto &[id, state] : m_streams) {
            if (state.counted) {
                g_connections.RemoveRequest();
            }
        }
        for (; m_removals_after_write > 0; --m_removals_after_write) {
            g_connections.RemoveRequest();
        }
        m_streams.clear();
        m_handlers_running = 0;
        for (const auto &[id, tunnel] : m_tunnels) {
            tunnel->OnClosed();
        }
        m_tunnels.clear();
    }

    //! Bytes framed per write: one write per batch, bounded memory
    static constexpr size_t MAX_WRITE_BATCH{256 * 1024};

    OsslStream &m_stream;
    const HTTPConnectionInfo m_conn;
    asio::any_io_executor m_ex;
    asio::steady_timer m_wake;
    bool m_wake_pending{false};
    asio::steady_timer m_deadline;
    http2::ServerSession m_session;
    std::map<int32_t, StreamState> m_streams;
    std::vector<std::pair<int32_t, BeastRequest>> m_new_requests;
    struct NewConnect {
        int32_t id;
        BeastRequest req;
        std::string protocol;
    };
    std::vector<NewConnect> m_new_connects;
    std::map<int32_t, std::shared_ptr<H2Tunnel>> m_tunnels;
    //! Tunnel bytes and ends received with the CONNECT, before its tunnel
    std::map<int32_t, std::string> m_early_tunnel_data;
    std::set<int32_t> m_early_tunnel_eof;
    size_t m_handlers_running{0};
    size_t m_tunnels_running{0};
    size_t m_removals_after_write{0};
    std::chrono::steady_clock::time_point m_last_activity{
        std::chrono::steady_clock::now()};
    bool m_reading{true};
    bool m_closed{false};
};

static asio::awaitable<void> ServeHTTP2(OsslStream &stream,
                                        beast::flat_buffer &buffer,
                                        const HTTPConnectionInfo &conn) {
    beast::get_lowest_layer(stream).expires_never();
    auto connection{std::make_shared<H2Connection>(
        stream, conn, co_await asio::this_coro::executor)};
    co_await connection->Run(buffer);
}
#endif // ENABLE_HTTP2

static std::string ClientCertFingerprint(SSL *ssl) {
    X509 *cert{tls::PeerCertificate(ssl)};
    std::string hex{tls::CertSha256Hex(cert)};
    X509_free(cert);
    return hex;
}

/**
 * Read a PROXY protocol (v1 or v2) header from a trusted proxy, if the
 * connection starts with one. Returns the header (an empty source if there
 * was none, or for LOCAL/UNKNOWN), or std::nullopt for a malformed one.
 * Only header bytes are consumed, except when a v1 check reads the first
 * bytes of a plain HTTP request: those go to `buffer`, and `plain` is set.
 */
static asio::awaitable<std::optional<proxy_protocol::Header>>
ReadProxyHeader(tcp::socket &sock, beast::flat_buffer &buffer, bool &plain) {
    using proxy_protocol::Header;
    auto [wait_ec] = co_await sock.async_wait(
        tcp::socket::wait_read, asio::as_tuple(asio::use_awaitable));
    uint8_t first{0};
    if (wait_ec || ::recv(sock.native_handle(),
                          reinterpret_cast<char *>(&first), 1, MSG_PEEK) != 1) {
        co_return Header{};
    }
    if (first == proxy_protocol::V2_SIGNATURE[0]) {
        std::vector<uint8_t> header(proxy_protocol::V2_FIXED_SIZE);
        auto [ec, n] = co_await asio::async_read(
            sock, asio::buffer(header), asio::as_tuple(asio::use_awaitable));
        const auto len{ec ? std::nullopt
                          : proxy_protocol::V2PayloadSize(header)};
        if (!len) {
            co_return std::nullopt;
        }
        header.resize(proxy_protocol::V2_FIXED_SIZE + *len);
        auto [pec, pn] = co_await asio::async_read(
            sock,
            asio::buffer(header.data() + proxy_protocol::V2_FIXED_SIZE, *len),
            asio::as_tuple(asio::use_awaitable));
        if (pec) {
            co_return std::nullopt;
        }
        co_return proxy_protocol::ParseV2(header);
    }
    if (first != 'P') {
        // TLS, or an HTTP method not starting with P: no PROXY header.
        co_return Header{};
    }
    // "PROXY " or an HTTP method such as POST/PUT/PATCH: read 6 bytes to tell.
    std::string line(6, '\0');
    auto [ec, n] = co_await asio::async_read(
        sock, asio::buffer(line), asio::as_tuple(asio::use_awaitable));
    if (ec) {
        co_return std::nullopt;
    }
    if (line != "PROXY ") {
        // Plain HTTP: hand the bytes to the parser.
        buffer.commit(
            asio::buffer_copy(buffer.prepare(line.size()), asio::buffer(line)));
        plain = true;
        co_return Header{};
    }
    while (!line.ends_with("\r\n")) {
        if (line.size() >= proxy_protocol::V1_MAX_LINE) {
            co_return std::nullopt;
        }
        char c;
        auto [rec, rn] = co_await asio::async_read(
            sock, asio::buffer(&c, 1), asio::as_tuple(asio::use_awaitable));
        if (rec) {
            co_return std::nullopt;
        }
        line.push_back(c);
    }
    co_return proxy_protocol::ParseV1(line);
}

/** Connection coroutine: detect TLS, then serve HTTP on the resulting stream */
static asio::awaitable<void>
HandleConnection(tcp::socket socket, bool public_only, bool p2p_port = false) {
    HTTPConnectionInfo conn;
    conn.public_only = public_only || p2p_port;
    conn.p2p_port = p2p_port;
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
        // socket down, which completes any pending wait with an error. On
        // the P2P port it runs until the WebSocket upgrade: the connection
        // holds a pending slot until then.
        asio::steady_timer deadline{sock.get_executor(),
                                    p2p_port ? g_p2p_port_handshake_timeout
                                             : g_server_timeout};
        // Cleared when the socket may no longer be ours (handed to
        // CConnman): a deadline that already fired must not shut it down.
        auto armed{std::make_shared<bool>(true)};
        deadline.async_wait([fd = sock.native_handle(),
                             armed](const boost::system::error_code &wec) {
            if (!wec && *armed) {
                ::shutdown(fd, SHUT_RDWR);
            }
        });
        if (p2p_port) {
            conn.disarm_deadline = [&deadline, armed] {
                *armed = false;
                deadline.cancel();
            };
        }

        // A trusted proxy may start with a PROXY protocol header carrying the
        // real client address. It is read exactly, so that what follows (TLS
        // or HTTP) is still classified from the socket.
        bool plain_prefetched{false};
        conn.tcp_peer_trusted = IsTrustedProxy(conn.peer);
        if (conn.tcp_peer_trusted) {
            const auto proxied{
                co_await ReadProxyHeader(sock, buffer, plain_prefetched)};
            if (!proxied) {
                LogDebug(BCLog::HTTP, "Bad PROXY header from %s\n",
                         conn.peer.ToStringAddrPort());
                co_return;
            }
            if (proxied->source) {
                conn.peer = *proxied->source;
            }
            conn.proxy_tls = proxied->client_tls;
        }

        // The peer speaking HTTP: a proxy we trust, or anyone else.
        conn.from_trusted_proxy = conn.tcp_peer_trusted;

        if (p2p_port && !plain_prefetched) {
            // Raw P2P (the network magic) is not ours: it is classified
            // like CConnman does, from at most 4 bytes, read by none.
            P2PPortProtocol protocol{P2PPortProtocol::UNDECIDED};
            while (protocol == P2PPortProtocol::UNDECIDED) {
                auto [wait_ec] = co_await sock.async_wait(
                    tcp::socket::wait_read,
                    asio::as_tuple(asio::use_awaitable));
                uint8_t bytes[4];
                const ssize_t n{wait_ec
                                    ? -1
                                    : ::recv(sock.native_handle(),
                                             reinterpret_cast<char *>(bytes),
                                             sizeof(bytes), MSG_PEEK)};
                if (n <= 0) {
                    // Closed, or the deadline shut it down.
                    break;
                }
                protocol = ClassifyP2PPortBytes(
                    Span<const uint8_t>{bytes, size_t(n)}, Params().NetMagic());
                if (protocol == P2PPortProtocol::UNDECIDED) {
                    // Part of the first bytes: the socket stays readable,
                    // so wait a little rather than for readability.
                    asio::steady_timer pause{sock.get_executor(),
                                             std::chrono::milliseconds{50}};
                    co_await pause.async_wait(
                        asio::as_tuple(asio::use_awaitable));
                }
            }
            if (protocol != P2PPortProtocol::WEBSOCKET) {
                if (protocol == P2PPortProtocol::PLAIN) {
                    LogDebug(BCLog::NET,
                             "connection from %s dropped: raw P2P is not "
                             "accepted (-p2prawlisten=0)\n",
                             conn.peer.ToStringAddrPort());
                }
                g_connections.RemoveConnection(conn_id);
                co_return;
            }
        }

        // Classify the connection by its first byte, without consuming it:
        // 0x16 starts a TLS handshake record.
        uint8_t first{0};
        ssize_t peeked{1};
        if (!plain_prefetched) {
            auto [wait_ec] = co_await sock.async_wait(
                tcp::socket::wait_read, asio::as_tuple(asio::use_awaitable));
            peeked =
                wait_ec ? -1
                        : ::recv(sock.native_handle(),
                                 reinterpret_cast<char *>(&first), 1, MSG_PEEK);
        }
        if (peeked <= 0) {
            // Client went away (or timed out) before sending anything.
        } else if (plain_prefetched || first != 0x16) {
            if (!p2p_port) {
                deadline.cancel();
            }
            co_await ServeHTTP(stream, buffer, conn);
            sock.shutdown(tcp::socket::shutdown_send, ec);
        } else if (tls::SslPtr ssl{NewServerSsl()}; !ssl) {
            LogDebug(BCLog::HTTP,
                     "TLS connection from %s rejected: TLS is disabled\n",
                     conn.peer.ToStringAddrPort());
        } else {
            if (HTTP2Allowed(public_only)) {
                tls::AllowServerAlpnH2(ssl.get());
            }
            if (SSL_set_fd(ssl.get(), int(sock.native_handle())) == 1) {
                OsslStream tls_stream{stream, std::move(ssl)};
                auto [hs_ec, hs] = co_await tls_stream.async_handshake(
                    asio::as_tuple(asio::use_awaitable));
                if (!p2p_port) {
                    deadline.cancel();
                }
                if (auto *metrics{node::GetNodeMetrics()}) {
                    metrics->http_tls_handshakes.Add(hs_ec ? 1 : 0);
                }
                if (hs_ec) {
                    LogDebug(BCLog::HTTP,
                             "TLS handshake with %s failed: %s\n",
                             conn.peer.ToStringAddrPort(), tls::ErrorString());
                } else {
                    conn.is_tls = true;
                    conn.alpn = tls::NegotiatedAlpn(tls_stream.native_handle());
                    conn.client_cert_fingerprint_hex =
                        ClientCertFingerprint(tls_stream.native_handle());
                    if (X509 *cert{
                            tls::PeerCertificate(tls_stream.native_handle())}) {
                        const auto spki{tls::SpkiSha256(cert)};
                        X509_free(cert);
                        if (!spki.empty()) {
                            conn.client_cert_spki = EncodeSpkiPin(spki);
                        }
                    }
#ifdef ENABLE_HTTP2
                    if (conn.alpn == http2::ALPN_PROTOCOL) {
                        co_await ServeHTTP2(tls_stream, buffer, conn);
                    } else {
                        co_await ServeHTTP(tls_stream, buffer, conn);
                    }
#else
                    co_await ServeHTTP(tls_stream, buffer, conn);
#endif
                    if (tls_stream.native_handle()) {
                        // Not handed off: close_notify after the last
                        // response, even if the send buffer is full now
                        // (a single attempt could drop it, which reads as a
                        // truncated close). Bounded like the handshake.
                        *armed = true;
                        deadline.expires_after(CLOSE_NOTIFY_TIMEOUT);
                        deadline.async_wait(
                            [fd = sock.native_handle(),
                             armed](const boost::system::error_code &wec) {
                                if (!wec && *armed) {
                                    ::shutdown(fd, SHUT_RDWR);
                                }
                            });
                        co_await tls_stream.async_shutdown(
                            asio::as_tuple(asio::use_awaitable));
                        deadline.cancel();
                        sock.shutdown(tcp::socket::shutdown_send, ec);
                    }
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
            LogInfoEvent(BCLog::ALL, "rpc_allowip_without_bind",
                         "WARNING: option -rpcallowip was specified without "
                         "-rpcbind; this doesn't usually make sense");
        }
        if (gArgs.IsArgSet("-rpcbind")) {
            LogInfoEvent(
                BCLog::ALL, "rpc_bind_without_allowip",
                "WARNING: option -rpcbind was ignored because -rpcallowip was "
                "not specified, refusing to allow everyone to connect");
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
                LogInfoEvent(BCLog::ALL, "rpc_untrusted_network_warning",
                             "WARNING: the RPC server is not safe to expose to "
                             "untrusted networks such as the public internet");
            }
        } else {
            LogInfoEvent(
                BCLog::ALL, "rpc_listener_bind_failed",
                "Binding RPC on address {listen_address} port {listen_port} failed.")
                .Field(BCLog::LogField::ListenAddress, i->first)
                .Field(BCLog::LogField::ListenPort, i->second);
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
            LogInfoEvent(
                BCLog::ALL, "public_listener_port_missing",
                "Error: -publicbind={listen_address} needs an explicit port")
                .Field(BCLog::LogField::ListenAddress, strBind);
            return false;
        }
        if (!BindEndpoint(host, port, /*public_only=*/true)) {
            LogInfoEvent(
                BCLog::ALL, "public_listener_bind_failed",
                "Binding public HTTP endpoints on {listen_address} failed.")
                .Field(BCLog::LogField::ListenAddress, strBind);
            return false;
        }
        LogInfoEvent(
            BCLog::ALL, "public_listener_serving",
            "Serving {public_prefixes} on public listener {listen_address} (RPC, wallet and REST are not served there)")
            .Field(BCLog::LogField::PublicPrefixes,
                   util::Join(g_public_prefixes, ", "))
            .Field(BCLog::LogField::ListenAddress, strBind);
    }
    return true;
}

/** A random name shaped like an ordinary host name */
static std::string RandomHostName() {
    static constexpr const char *TLDS[]{"com", "net", "org", "io", "dev"};
    FastRandomContext rng;
    std::string name(6 + rng.randrange(6), 'a');
    for (char &c : name) {
        c = char('a' + rng.randrange(26));
    }
    return name + "." + TLDS[rng.randrange(std::size(TLDS))];
}

/**
 * The name a generated certificate is issued for: the first -externaldomain,
 * else the name already in use, else a random one. Never a string that
 * identifies the software (older versions used "bitcoind node").
 */
static std::string GeneratedCertificateName(
    const std::optional<tls::CertificateInfo> &current) {
    for (const auto &domain : gArgs.GetArgs("-externaldomain")) {
        uint16_t port;
        std::string host;
        if (SplitHostPort(domain, port, host) && !host.empty()) {
            return ToLower(host);
        }
    }
    if (current && !current->common_name.empty() &&
        current->common_name != "bitcoind node" &&
        current->common_name != "localhost") {
        return current->common_name;
    }
    return RandomHostName();
}

/**
 * Create the datadir certificate, or renew it when it nears expiry or its
 * name should change. Renewals keep the key, so SPKI pins stay valid.
 */
static bool EnsureGeneratedCertificate(const TlsFiles &files) {
    const auto key_pem{tls::ReadFile(files.key)};
    const auto info{tls::ReadCertificateInfo(files.cert)};
    const std::string name{GeneratedCertificateName(info)};
    const int64_t renew_before{
        std::chrono::seconds{GENERATED_CERT_RENEW_BEFORE}.count()};
    if (key_pem && info && info->common_name == name &&
        info->seconds_left > renew_before) {
        return true;
    }
    const auto pem{tls::GenerateSelfSigned(name, {name}, {},
                                           GENERATED_CERT_VALIDITY,
                                           key_pem.value_or(""))};
    if (!pem) {
        return false;
    }
    const bool ok{key_pem ? tls::ReplaceFile(files.cert, pem->cert_pem)
                          : tls::WritePemFiles(*pem, files.cert, files.key)};
    if (ok) {
        LogInfoEvent(
            BCLog::ALL, "tls_certificate_issued",
            "{certificate_action} TLS certificate {certificate_path} for {server_name} (valid {certificate_validity_days} days)")
            .Field(BCLog::LogField::CertificateAction,
                   key_pem ? "Renewed" : "Generated")
            .Field(BCLog::LogField::CertificatePath,
                   fs::PathToString(files.cert))
            .Field(BCLog::LogField::ServerName, name)
            .Field(BCLog::LogField::CertificateValidityDays,
                   std::chrono::duration_cast<std::chrono::hours>(
                       GENERATED_CERT_VALIDITY)
                           .count() /
                       24);
    }
    return ok;
}

static void FileTimes(TlsFiles &files) {
    std::error_code ec;
    files.cert_mtime = fs::last_write_time(files.cert, ec);
    files.key_mtime = fs::last_write_time(files.key, ec);
}

/** A server context for the certificate files, or nullptr */
static tls::SslCtxPtr LoadServerContext(const TlsFiles &files) {
    auto ctx{tls::NewContext(/*server=*/true)};
    if (!ctx || !tls::UseCertificateFiles(ctx.get(), files.cert, files.key)) {
        const auto tls_error{tls::ErrorString()};
        LogInfoEvent(
            BCLog::ALL, "tls_certificate_load_failed",
            "Error: unable to load TLS certificate {certificate_path} / key {key_path}: {error}")
            .Field(BCLog::LogField::CertificatePath,
                   fs::PathToString(files.cert))
            .Field(BCLog::LogField::KeyPath, fs::PathToString(files.key))
            .Field(BCLog::LogField::Error, tls_error);
        return {};
    }
    if (gArgs.GetBoolArg("-tlsmutual", DEFAULT_HTTP_TLS_MUTUAL) ||
        gArgs.IsArgSet("-p2pwebsocketpeer")) {
        // Ask for a client certificate, accept any (including self-signed
        // node certificates); the fingerprint is exposed per request.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER,
                           [](int, X509_STORE_CTX *) { return 1; });
    }
    return ctx;
}

/**
 * Pick up a replaced certificate (e.g. an ACME renewal of -tlscert) and
 * renew a generated one. New handshakes use the new context; existing
 * sessions keep theirs. A file that fails to load keeps the old context.
 */
static void ReloadTLSIfChanged() EXCLUSIVE_LOCKS_REQUIRED(g_tls_mutex) {
    const auto now{std::chrono::steady_clock::now()};
    if (now < g_tls_next_check || !g_tls_files) {
        return;
    }
    g_tls_next_check = now + TLS_RELOAD_CHECK_INTERVAL;
    TlsFiles &files{*g_tls_files};
    if (files.generated && now >= g_tls_next_renewal_check) {
        g_tls_next_renewal_check = now + TLS_RENEWAL_CHECK_INTERVAL;
        if (!EnsureGeneratedCertificate(files)) {
            LogInfoEvent(
                BCLog::ALL, "tls_certificate_renew_failed",
                "Error: failed to renew the TLS certificate {certificate_path}")
                .Field(BCLog::LogField::CertificatePath,
                       fs::PathToString(files.cert));
        }
    }
    TlsFiles current{files};
    FileTimes(current);
    if (current.cert_mtime == files.cert_mtime &&
        current.key_mtime == files.key_mtime) {
        return;
    }
    files = current;
    if (auto ctx{LoadServerContext(files)}) {
        g_ssl_ctx = std::move(ctx);
        LogInfoEvent(BCLog::ALL, "tls_certificate_reloaded",
                     "Reloaded TLS certificate {certificate_path}")
            .Field(BCLog::LogField::CertificatePath,
                   fs::PathToString(files.cert));
    }
}

/** A server session for a new TLS connection, or nullptr if TLS is off */
static tls::SslPtr NewServerSsl() {
    LOCK(g_tls_mutex);
    ReloadTLSIfChanged();
    return tls::SslPtr{g_ssl_ctx ? SSL_new(g_ssl_ctx.get()) : nullptr};
}

/** Set up g_ssl_ctx from -tlscert/-tlskey or the datadir certificate */
static bool InitTLS() {
    LOCK(g_tls_mutex);
    g_ssl_ctx.reset();
    g_tls_files.reset();
    TlsFiles files;
    if (gArgs.IsArgSet("-tlscert") || gArgs.IsArgSet("-tlskey")) {
        if (!gArgs.IsArgSet("-tlscert") || !gArgs.IsArgSet("-tlskey")) {
            LogInfoEvent(BCLog::ALL, "http_tls_pair_missing",
                         "Error: -tlscert and -tlskey must be used together");
            return false;
        }
        files.cert = gArgs.GetPathArg("-tlscert");
        files.key = gArgs.GetPathArg("-tlskey");
    } else if (gArgs.GetBoolArg("-tlsephemeral", DEFAULT_HTTP_TLS_EPHEMERAL)) {
        files.cert = gArgs.GetDataDirNet() / HTTP_TLS_CERT_FILENAME;
        files.key = gArgs.GetDataDirNet() / HTTP_TLS_KEY_FILENAME;
        files.generated = true;
        if (!EnsureGeneratedCertificate(files)) {
            LogInfoEvent(BCLog::ALL, "http_tls_certificate_failed",
                         "Error: failed to generate a TLS certificate");
            return false;
        }
    } else {
        LogInfoEvent(BCLog::ALL, "http_tls_disabled",
                     "TLS disabled on the RPC port");
        return true;
    }

    FileTimes(files);
    auto ctx{LoadServerContext(files)};
    if (!ctx) {
        return false;
    }
    g_ssl_ctx = std::move(ctx);
    const auto now{std::chrono::steady_clock::now()};
    g_tls_next_check = now + TLS_RELOAD_CHECK_INTERVAL;
    g_tls_next_renewal_check = now + TLS_RENEWAL_CHECK_INTERVAL;
    LogInfoEvent(BCLog::ALL, "rpc_tls_enabled",
                 "TLS enabled on the RPC port using {certificate_path}")
        .Field(BCLog::LogField::CertificatePath, fs::PathToString(files.cert));
    g_tls_files = std::move(files);
    return true;
}

bool InitHTTPServer(Config &config) {
    if (!InitHTTPAllowList()) {
        return false;
    }

    LogPrintf("Using %s\n", tls::LibraryDescription());
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
        LogInfoEvent(BCLog::ALL, "chronik_rpc_prefix_serving",
                     "Serving Chronik on the RPC port at {http_path}")
            .Field(BCLog::LogField::HttpPath, CHRONIK_PREFIX);
    }

    g_p2p_websocket_enabled = GetP2PWebSocketListen(gArgs);
    g_trusted_proxies.clear();
    for (const std::string &entry : gArgs.GetArgs("-trustedproxy")) {
        CSubNet subnet;
        if (!LookupSubNet(entry, subnet) || !subnet.IsValid()) {
            LogInfoEvent(
                BCLog::ALL, "trusted_proxy_invalid",
                "Error: invalid -trustedproxy '{addr}' (an address or subnet, e.g. 10.0.0.0/8)")
                .Field(BCLog::LogField::Addr, entry);
            return false;
        }
        g_trusted_proxies.push_back(subnet);
    }
    if (gArgs.GetBoolArg("-p2pwebsockettrustforwardedfor", false)) {
        // Older shorthand: a reverse proxy on this host.
        g_trusted_proxies.push_back(
            CSubNet{LookupHost("127.0.0.1", false).value(), 8});
        g_trusted_proxies.push_back(CSubNet{LookupHost("::1", false).value()});
    }
    // Health endpoints reveal a node to probes, so they are off by default
    // for a bridge (a token or a fallback site).
    g_health_enabled =
        gArgs.GetBoolArg("-httphealth", !gArgs.IsArgSet("-p2pwebsockettoken") &&
                                            !gArgs.IsArgSet("-publicfallback"));
    g_p2p_websocket_force_bridge =
        gArgs.GetBoolArg("-p2pwebsocketbridge", false);
    g_p2p_require_tls =
        gArgs.GetBoolArg("-p2prequiretls", DEFAULT_P2P_REQUIRE_TLS);
    g_p2p_port_handshake_timeout = std::chrono::seconds{std::max<int64_t>(
        gArgs.GetIntArg("-p2pporthandshaketimeout",
                        DEFAULT_P2P_PORT_HANDSHAKE_TIMEOUT.count()),
        1)};
    g_p2p_websocket_path =
        gArgs.GetArg("-p2pwebsocketpath", P2P_WEBSOCKET_PATH);
    if (g_p2p_websocket_path.size() < 2 || g_p2p_websocket_path[0] != '/' ||
        g_p2p_websocket_path.find_first_of("?#% \t\r\n") != std::string::npos ||
        g_p2p_websocket_path.back() == '/') {
        LogInfoEvent(
            BCLog::ALL, "p2p_websocket_path_invalid",
            "Error: invalid -p2pwebsocketpath '{http_path}' (an absolute path such as /p2p/ws, not / and without query or trailing /)")
            .Field(BCLog::LogField::HttpPath, g_p2p_websocket_path);
        return false;
    }
    g_public_fallback = {};
    if (const std::string fallback{gArgs.GetArg("-publicfallback", "")};
        !fallback.empty()) {
        uint16_t port{0};
        std::string host;
        if (!SplitHostPort(fallback, port, host) || host.empty() || port == 0) {
            LogInfoEvent(BCLog::ALL, "public_fallback_invalid",
                         "Error: invalid -publicfallback '{addr}' (host:port)")
                .Field(BCLog::LogField::Addr, fallback);
            return false;
        }
        g_public_fallback = {.enabled = true, .host = host, .port = port};
    }
    g_p2p_websocket_token_hashes.clear();
    for (const std::string &token : gArgs.GetArgs("-p2pwebsockettoken")) {
        if (!IsValidWebSocketToken(token)) {
            LogInfoEvent(BCLog::ALL, "websocket_token_invalid",
                         "Error: invalid -p2pwebsockettoken (use 1-256 of A-Z "
                         "a-z 0-9 . _ ~ -)");
            return false;
        }
        g_p2p_websocket_token_hashes.push_back(HashToken(token));
    }
    if (g_p2p_websocket_enabled && g_p2p_websocket_token_hashes.empty()) {
        // With a token, the path is only public for requests carrying it.
        RegisterPublicHTTPPrefix(g_p2p_websocket_path);
    }

#ifdef ENABLE_HTTP2
    g_http2_enabled = gArgs.GetBoolArg("-http2", DEFAULT_HTTP2);
    {
        bool ok{true};
        const auto arg = [&](const char *name, int64_t def, int64_t min,
                             int64_t max) {
            const int64_t v{gArgs.GetIntArg(name, def)};
            if (v < min || v > max) {
                LogPrintf("Error: %s=%d is out of range (%d-%d)\n", name, v,
                          min, max);
                ok = false;
            }
            return v;
        };
        http2::Limits l;
        l.max_concurrent_streams = uint32_t(
            arg("-http2maxstreams", DEFAULT_HTTP2_MAX_STREAMS, 1, 10000));
        l.max_header_list_size =
            uint32_t(arg("-http2maxheaderlistsize",
                         DEFAULT_HTTP2_MAX_HEADER_LIST_SIZE, 1024, 1 << 20));
        l.max_frame_size =
            uint32_t(arg("-http2maxframesize", DEFAULT_HTTP2_MAX_FRAME_SIZE,
                         16384, (1 << 24) - 1));
        l.stream_window =
            uint32_t(arg("-http2streamwindow", DEFAULT_HTTP2_STREAM_WINDOW,
                         65535, std::numeric_limits<int32_t>::max()));
        l.connection_window =
            uint32_t(arg("-http2connwindow", DEFAULT_HTTP2_CONNECTION_WINDOW,
                         65535, std::numeric_limits<int32_t>::max()));
        l.reset_burst = uint64_t(
            arg("-http2resetburst", DEFAULT_HTTP2_RESET_BURST, 1, 1000000));
        l.reset_rate = uint64_t(
            arg("-http2resetrate", DEFAULT_HTTP2_RESET_RATE, 1, 1000000));
        l.max_continuations =
            size_t(arg("-http2maxcontinuations",
                       DEFAULT_HTTP2_MAX_CONTINUATIONS, 0, 1000));
        if (!ok) {
            return false;
        }
        g_http2_limits = l;
    }
    if (g_http2_enabled) {
        LogPrintf("HTTP/2 offered on TLS listeners (nghttp2 %s)\n",
                  nghttp2_version(0)->version_str);
    }
#else
    g_http2_enabled = false;
    if (gArgs.GetBoolArg("-http2", false)) {
        LogPrintf("Warning: -http2 is ignored: this build has no HTTP/2 "
                  "support (configure with -DENABLE_HTTP2=ON)\n");
    }
#endif

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
        LogInfoEvent(BCLog::ALL, "rpc_bind_failed",
                     "Unable to bind any endpoint for RPC server");
        return false;
    }

    LogEvent(BCLog::HTTP, "http_server_initialized", "Initialized HTTP server");
    int workQueueDepth = std::max(
        (long)gArgs.GetIntArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L);
    LogDebug(BCLog::HTTP, "creating work queue of depth %d\n", workQueueDepth);

    g_work_queue = std::make_unique<HTTPCoroutinePool>(workQueueDepth);
    return true;
}

static std::vector<std::thread> g_thread_http_io;
static std::optional<asio::executor_work_guard<asio::io_context::executor_type>>
    g_io_work;

void StartHTTPServer() {
    const int rpcThreads = std::max(
        (long)gArgs.GetIntArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L);
    const int ioThreads = std::max(
        (long)gArgs.GetIntArg("-rpciothreads", DEFAULT_HTTP_IO_THREADS), 1L);
    LogInfoEvent(
        BCLog::ALL, "http_worker_threads_started",
        "Starting HTTP server with {coroutine_worker_threads} coroutine worker threads and {io_threads} I/O threads")
        .Field(BCLog::LogField::CoroutineWorkerThreads, rpcThreads)
        .Field(BCLog::LogField::IOThreads, ioThreads);
    if (g_work_queue) g_work_queue->Start(rpcThreads);
    g_io_work.emplace(asio::make_work_guard(*g_io));
    for (auto &listener : g_acceptors) {
        asio::co_spawn(listener.acceptor->get_executor(),
                       AcceptLoop(*listener.acceptor, listener.public_only),
                       asio::detached);
    }
    for (int i = 0; i < ioThreads; ++i) {
        g_thread_http_io.emplace_back([i] {
            util::ThreadRename(i == 0 ? std::string{"http"}
                                      : strprintf("http.%i", i));
            LogEvent(BCLog::HTTP, "http_io_started", "Entering http I/O loop");
            g_io->run();
            LogEvent(BCLog::HTTP, "http_io_stopped", "Exited http I/O loop");
        });
    }
}

void InterruptHTTPServer() {
    LogEvent(BCLog::HTTP, "http_server_interrupting",
             "Interrupting HTTP server");
    // Reject requests on current connections
    g_reject_requests = true;
    if (g_work_queue) {
        g_work_queue->Interrupt();
    }
}

void StopHTTPServer() {
    LogEvent(BCLog::HTTP, "http_server_stopping", "Stopping HTTP server");
    SetP2PWebSocketAcceptor(nullptr);
    SetHTTPReadinessCheck(nullptr);
    if (g_work_queue) {
        LogEvent(BCLog::HTTP, "http_workers_stopping",
                 "Waiting for HTTP worker threads to exit");
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
        LogEvent(BCLog::HTTP, "http_io_threads_stopping",
                 "Waiting for HTTP I/O threads to exit");
        g_io_work.reset();
        g_io->stop();
        for (auto &thread : g_thread_http_io) {
            thread.join();
        }
        g_thread_http_io.clear();
    }
    g_acceptors.clear();
    g_work_queue.reset();
    {
        LOCK(g_tls_mutex);
        g_ssl_ctx.reset();
        g_tls_files.reset();
    }
    LogEvent(BCLog::HTTP, "http_server_stopped", "Stopped HTTP server");
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
        LogInfoEvent(BCLog::ALL, "http_request_unhandled",
                     "{source_function}: Unhandled request")
            .Field(BCLog::LogField::SourceFunction, __func__);
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

std::string HTTPRequest::GetScheme() const {
    if (!m_impl) {
        return "http";
    }
    if (m_impl->is_tls) {
        return "https";
    }
    if (m_impl->tcp_peer_trusted) {
        // The right-most value is the one the nearest proxy added.
        const auto [first, last] =
            m_impl->beast_req.equal_range("X-Forwarded-Proto");
        std::string_view proto;
        for (auto f = first; f != last; ++f) {
            proto = f->value();
        }
        if (const size_t comma{proto.rfind(',')};
            comma != std::string_view::npos) {
            proto = proto.substr(comma + 1);
        }
        if (beast::iequals(util::TrimStringView(proto), "https")) {
            return "https";
        }
    }
    return "http";
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

void SetHTTPReadinessCheck(HTTPReadinessCheck check) {
    LOCK(g_readiness_mutex);
    g_readiness_check = std::move(check);
}

void HandOffP2PPortConnection(std::unique_ptr<Sock> &&sock,
                              const CService &peer, const CService &local) {
    if (!g_io || !g_io_work || g_reject_requests.load()) {
        // Not serving: closing it is all we can do.
        return;
    }
    {
        LOCK(g_p2p_port_mutex);
        size_t &from_addr{g_p2p_port_pending_by_addr[peer]};
        if (g_p2p_port_pending >= MAX_P2P_PORT_PENDING ||
            from_addr >= MAX_P2P_PORT_PENDING_PER_ADDR) {
            LogDebug(BCLog::NET,
                     "P2P port WebSocket connection from %s dropped: %u "
                     "pending (%u from this address)\n",
                     peer.ToStringAddrPort(), g_p2p_port_pending, from_addr);
            if (from_addr == 0) {
                g_p2p_port_pending_by_addr.erase(peer);
            }
            return;
        }
        ++g_p2p_port_pending;
        ++from_addr;
    }
    // Returns the slot when the connection is upgraded or closed.
    auto slot{std::shared_ptr<void>(nullptr, [peer](void *) {
        LOCK(g_p2p_port_mutex);
        --g_p2p_port_pending;
        if (--g_p2p_port_pending_by_addr[peer] == 0) {
            g_p2p_port_pending_by_addr.erase(peer);
        }
    })};
    tcp::socket socket{asio::make_strand(*g_io)};
    boost::system::error_code ec;
    const SOCKET fd{sock->Release()};
    socket.assign(local.IsIPv6() ? tcp::v6() : tcp::v4(), fd, ec);
    if (ec) {
        LogDebug(BCLog::NET, "P2P port connection from %s dropped: %s\n",
                 peer.ToStringAddrPort(), ec.message());
        // Close it.
        const Sock closing{fd};
        return;
    }
    auto executor{socket.get_executor()};
    asio::co_spawn(
        executor,
        [](tcp::socket socket,
           std::shared_ptr<void> slot) -> asio::awaitable<void> {
            co_await HandleConnection(std::move(socket), /*public_only=*/true,
                                      /*p2p_port=*/true);
        }(std::move(socket), std::move(slot)),
        asio::detached);
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
