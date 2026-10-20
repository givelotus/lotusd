// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <net.h>

#include <addrdb.h>
#include <addrman.h>
#include <avalanche/avalanche.h>
#include <banman.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/netif.h>
#include <compat/compat.h>
#include <config.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <dnsseeds.h>
#include <i2p.h>
#include <logging.h>
#include <logging/values.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/eviction.h>
#include <node/metrics.h>
#include <node/ui_interface.h>
#include <protocol.h>
#include <random.h>
#include <scheduler.h>
#include <util/fs.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>
#include <util/threadnames.h>
#include <util/trace.h>
#include <util/translation.h>

#ifdef WIN32
#include <cstring>
#else
#include <fcntl.h>
#endif

#ifdef USE_POLL
#include <poll.h>
#endif

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <unordered_map>

/** Maximum number of block-relay-only anchor connections */
static constexpr size_t MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;
static_assert(MAX_BLOCK_RELAY_ONLY_ANCHORS <=
                  static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS),
              "MAX_BLOCK_RELAY_ONLY_ANCHORS must not exceed "
              "MAX_BLOCK_RELAY_ONLY_CONNECTIONS.");
/** Anchor IP address database file name */
const char *const ANCHORS_DATABASE_FILENAME = "anchors.dat";

// How often to dump addresses to peers.dat
static constexpr std::chrono::minutes DUMP_PEERS_INTERVAL{15};

/**
 * Number of DNS seeds to query when the number of connections is low.
 */
static constexpr int DNSSEEDS_TO_QUERY_AT_ONCE = 3;

/**
 * How long to delay before querying DNS seeds
 *
 * If we have more than THRESHOLD entries in addrman, then it's likely
 * that we got those addresses from having previously connected to the P2P
 * network, and that we'll be able to successfully reconnect to the P2P
 * network via contacting one of them. So if that's the case, spend a
 * little longer trying to connect to known peers before querying the
 * DNS seeds.
 */
static constexpr std::chrono::seconds DNSSEEDS_DELAY_FEW_PEERS{11};
static constexpr std::chrono::minutes DNSSEEDS_DELAY_MANY_PEERS{5};
// "many" vs "few" peers
static constexpr int DNSSEEDS_DELAY_PEER_THRESHOLD = 1000;

/** The default timeframe for -maxuploadtarget. 1 day. */
static constexpr std::chrono::seconds MAX_UPLOAD_TIMEFRAME{60 * 60 * 24};

// A random time period (0 to 1 seconds) is added to feeler connections to
// prevent synchronization.
static constexpr auto FEELER_SLEEP_WINDOW{1s};

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE = 0,
    BF_EXPLICIT = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    /**
     * Do not call AddLocal() for our special addresses, e.g., for incoming
     * Tor connections, to prevent gossiping them over the network.
     */
    BF_DONT_ADVERTISE = (1U << 2),
};

// The set of sockets cannot be modified while waiting
// The sleep time needs to be small to avoid new sockets stalling
static const uint64_t SELECT_TIMEOUT_MILLISECONDS = 50;

const std::string NET_MESSAGE_TYPE_OTHER = "*other*";

// SHA256("netgroup")[0:8]
static const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL;
// SHA256("localhostnonce")[0:8]
static const uint64_t RANDOMIZER_ID_LOCALHOSTNONCE = 0xd93e69e2bbfa5735ULL;
// SHA256("localhostnonce")[8:16]
static const uint64_t RANDOMIZER_ID_EXTRAENTROPY = 0x94b05d41679a4ff7ULL;
// SHA256("addrcache")[0:8]
static const uint64_t RANDOMIZER_ID_ADDRCACHE = 0x1cf2e4ddd306dda9ULL;
//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
bool g_listen_plain_p2p = true;
GlobalMutex g_maplocalhost_mutex;
std::map<CNetAddr, LocalServiceInfo>
    mapLocalHost GUARDED_BY(g_maplocalhost_mutex);
static bool vfLimited[NET_MAX] GUARDED_BY(g_maplocalhost_mutex) = {};

void CConnman::AddAddrFetch(const std::string &strDest) {
    LOCK(m_addr_fetches_mutex);
    m_addr_fetches.push_back(strDest);
}

uint16_t GetListenPort() {
    // If -bind= is provided with ":port" part, use that (first one if multiple
    // are provided).
    for (const std::string &bind_arg : gArgs.GetArgs("-bind")) {
        constexpr uint16_t dummy_port = 0;

        const std::optional<CService> bind_addr{
            Lookup(bind_arg, dummy_port, /*fAllowLookup=*/false)};
        if (bind_addr.has_value() && bind_addr->GetPort() != dummy_port) {
            return bind_addr->GetPort();
        }
    }

    // Otherwise, if -whitebind= without NetPermissionFlags::NoBan is provided,
    // use that
    // (-whitebind= is required to have ":port").
    for (const std::string &whitebind_arg : gArgs.GetArgs("-whitebind")) {
        NetWhitebindPermissions whitebind;
        bilingual_str error;
        if (NetWhitebindPermissions::TryParse(whitebind_arg, whitebind,
                                              error)) {
            if (!NetPermissions::HasFlag(whitebind.m_flags,
                                         NetPermissionFlags::NoBan)) {
                return whitebind.m_service.GetPort();
            }
        }
    }

    // Otherwise, if -port= is provided, use that. Otherwise use the default
    // port.
    return static_cast<uint16_t>(
        gArgs.GetIntArg("-port", Params().GetDefaultPort()));
}

// find 'best' local address for a particular peer
bool GetLocal(CService &addr, const CNetAddr *paddrPeer) {
    if (!fListen) {
        return false;
    }

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(g_maplocalhost_mutex);
        for (const auto &entry : mapLocalHost) {
            if (!g_listen_plain_p2p && !entry.first.IsWSS()) {
                // Not reachable: we accept no plain P2P connections.
                continue;
            }
            int nScore = entry.second.nScore;
            int nReachability = entry.first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability ||
                (nReachability == nBestReachability && nScore > nBestScore)) {
                addr = CService(entry.first, entry.second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

//! Convert the pnSeed6 array into usable address objects.
static std::vector<CAddress>
convertSeed6(const std::vector<SeedSpec6> &vSeedsIn) {
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps. Seed nodes are given
    // a random 'last seen time' of between one and two weeks ago.
    const auto one_week{7 * 24h};
    std::vector<CAddress> vSeedsOut;
    vSeedsOut.reserve(vSeedsIn.size());
    FastRandomContext rng;
    // TODO: apply core#25284 when backporting core#21560
    for (const auto &seed_in : vSeedsIn) {
        struct in6_addr ip;
        memcpy(&ip, seed_in.addr, sizeof(ip));
        CAddress addr(CService(ip, seed_in.port),
                      GetDesirableServiceFlags(NODE_NONE));
        addr.nTime =
            rng.rand_uniform_delay(Now<NodeSeconds>() - one_week, -one_week);
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}

// Get best local address for a particular peer as a CService. Otherwise, return
// the unroutable 0.0.0.0 but filled in with the normal parameters, since the IP
// may be changed to a useful one by discovery.
CService GetLocalAddress(const CNetAddr &addrPeer) {
    CService ret{CNetAddr(), GetListenPort()};
    CService addr;
    if (GetLocal(addr, &addrPeer)) {
        ret = CService{addr};
    }
    return ret;
}

static int GetnScore(const CService &addr) {
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    return (it != mapLocalHost.end()) ? it->second.nScore : 0;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode) {
    CService addrLocal = pnode->GetAddrLocal();
    // The peer saw an IP address, which is only of use to peers if they can
    // reach us there with plain P2P.
    return g_listen_plain_p2p && fDiscover && pnode->addr.IsRoutable() &&
           addrLocal.IsRoutable() &&
           IsReachable(addrLocal.GetNetwork());
}

std::optional<CService> GetLocalAddrForPeer(CNode &node) {
    CService addrLocal{GetLocalAddress(node.addr)};
    // -addrmantest advertises a loopback plain P2P address.
    const bool addrmantest{g_listen_plain_p2p &&
                           gArgs.GetBoolArg("-addrmantest", false)};
    if (addrmantest) {
        // use IPv4 loopback during addrmantest
        addrLocal = CService(LookupNumeric("127.0.0.1", GetListenPort()));
    }
    // If discovery is enabled, sometimes give our peer the address it
    // tells us that it sees us as in case it has a better idea of our
    // address than we do.
    FastRandomContext rng;
    if (IsPeerAddrLocalGood(&node) &&
        (!addrLocal.IsRoutable() ||
         rng.randbits((GetnScore(addrLocal) > LOCAL_MANUAL) ? 3 : 1) == 0)) {
        if (node.IsInboundConn() && !node.m_websocket_info &&
            !node.m_quic_info) {
            // For inbound connections, assume both the address and the port
            // as seen from the peer.
            addrLocal = CService{node.GetAddrLocal()};
        } else {
            // For outbound connections, assume just the address as seen from
            // the peer and leave the port in `addrLocal` as returned by
            // `GetLocalAddress()` above. The peer has no way to observe our
            // listening port when we have initiated the connection.
            // The same holds for WebSocket peers: the port they reached is
            // the HTTP/WebSocket endpoint, not our TCP P2P port. And if the
            // best local address was a NET_WSS name, its port is that of the
            // wss:// endpoint, so use our P2P listening port.
            const uint16_t port{addrLocal.IsWSS() ? GetListenPort()
                                                  : addrLocal.GetPort()};
            addrLocal = CService{node.GetAddrLocal(), port};
        }
    }
    if (addrLocal.IsRoutable() || addrmantest) {
        LogEvent(BCLog::NET, "peer_address_advertised",
                 "Advertising address {addr} to peer={peer_id}")
            .Field(BCLog::LogField::Addr,
                   static_cast<const CService &>(addrLocal))
            .Field(BCLog::LogField::PeerId, node.GetId());
        return addrLocal;
    }
    // Address is unroutable. Don't advertise.
    return std::nullopt;
}

// Learn a new local address.
bool AddLocal(const CService &addr, int nScore) {
    if (!addr.IsRoutable()) {
        return false;
    }

    if (!fDiscover && nScore < LOCAL_MANUAL) {
        return false;
    }

    if (!g_listen_plain_p2p && !addr.IsWSS()) {
        // Peers could not use it: we accept no plain P2P connections.
        LogDebug(BCLog::NET,
                 "AddLocal(%s,%i) ignored: plain P2P is not accepted "
                 "(-p2prawlisten=0)\n",
                 addr.ToStringAddrPort(), nScore);
        return false;
    }

    if (!IsReachable(addr)) {
        return false;
    }

    LogInfoEvent(BCLog::ALL, "local_address_added",
                 "AddLocal({addr},{local_score})")
        .Field(BCLog::LogField::Addr, addr.ToStringAddrPort())
        .Field(BCLog::LogField::LocalScore, nScore);

    {
        LOCK(g_maplocalhost_mutex);
        const auto [it, is_newly_added] =
            mapLocalHost.emplace(addr, LocalServiceInfo());
        LocalServiceInfo &info = it->second;
        if (is_newly_added || nScore >= info.nScore) {
            info.nScore = nScore + !is_newly_added;
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore) {
    return AddLocal(CService(addr, GetListenPort()), nScore);
}

bool GetP2PWebSocketListen(const ArgsManager &args) {
    return args.GetBoolArg("-p2pwslisten", DEFAULT_P2P_WEBSOCKET);
}

std::optional<bilingual_str>
CheckP2PListenArgs(const ArgsManager &args,
                   std::vector<bilingual_str> &warnings) {
    if (!args.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // Nothing is accepted on any transport.
        return std::nullopt;
    }
    const bool plain{args.GetBoolArg("-p2prawlisten", DEFAULT_P2P_RAW_LISTEN)};
    const bool ws{GetP2PWebSocketListen(args)};
    if (plain) {
        return std::nullopt;
    }
    for (const std::string &bind : args.GetArgs("-bind")) {
        if (bind.ends_with("=onion")) {
            return _("-bind=...=onion is the target of a Tor onion service, "
                     "which carries raw P2P, so it cannot be used with "
                     "-p2prawlisten=0");
        }
    }
    if (!ws && (!args.GetArgs("-bind").empty() ||
                !args.GetArgs("-whitebind").empty())) {
        return _("-bind and -whitebind open P2P port listeners, which would "
                 "accept nothing with -p2prawlisten=0 and -p2pwslisten=0");
    }
    if (!args.GetArgs("-externalip").empty()) {
        return _("-externalip advertises an address for plain P2P, so it "
                 "cannot be used with -p2prawlisten=0 (use -externaldomain "
                 "to advertise a WebSocket endpoint)");
    }
    // Parameter interaction turned these off unless they were set
    // explicitly.
    if (args.GetBoolArg("-listenonion", false)) {
        return _("-listenonion creates a Tor onion service for plain P2P, so "
                 "it cannot be used with -p2prawlisten=0");
    }
    if (args.IsArgSet("-i2psam") &&
        args.GetBoolArg("-i2pacceptincoming", false)) {
        return _("-i2pacceptincoming accepts plain P2P over I2P, so it "
                 "cannot be used with -p2prawlisten=0");
    }
    if (!ws) {
        warnings.push_back(
            _("-p2prawlisten=0 and -p2pwslisten=0: no inbound P2P "
              "connections will be accepted, as with -listen=0"));
    } else if (!args.GetBoolArg("-server", false)) {
        warnings.push_back(
            _("-p2prawlisten=0 without -server: WebSocket peers need the "
              "HTTP server, so no inbound P2P connections will be accepted"));
    }
    return std::nullopt;
}

void RemoveLocal(const CService &addr) {
    LOCK(g_maplocalhost_mutex);
    LogInfoEvent(BCLog::ALL, "local_address_removed", "RemoveLocal({addr})")
        .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
    mapLocalHost.erase(addr);
}

void SetReachable(enum Network net, bool reachable) {
    if (net == NET_UNROUTABLE || net == NET_INTERNAL) {
        return;
    }
    LOCK(g_maplocalhost_mutex);
    vfLimited[net] = !reachable;
}

bool IsReachable(enum Network net) {
    LOCK(g_maplocalhost_mutex);
    return !vfLimited[net];
}

bool IsReachable(const CNetAddr &addr) {
    return IsReachable(addr.GetNetwork());
}

/** vote for a local address */
bool SeenLocal(const CService &addr) {
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    if (it == mapLocalHost.end()) {
        return false;
    }
    ++it->second.nScore;
    return true;
}

/** check whether a given address is potentially local */
bool IsLocal(const CService &addr) {
    LOCK(g_maplocalhost_mutex);
    return mapLocalHost.count(addr) > 0;
}

CNode *CConnman::FindNode(const CNetAddr &ip) {
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (static_cast<CNetAddr>(pnode->addr) == ip) {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const CSubNet &subNet) {
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (subNet.Match(static_cast<CNetAddr>(pnode->addr))) {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const std::string &addrName) {
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (pnode->m_addr_name == addrName) {
            return pnode;
        }
    }
    return nullptr;
}

CNode *CConnman::FindNode(const CService &addr) {
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (static_cast<CService>(pnode->addr) == addr) {
            return pnode;
        }
    }
    return nullptr;
}

bool CConnman::AlreadyConnectedToAddress(const CAddress &addr) {
    return FindNode(static_cast<CNetAddr>(addr)) ||
           FindNode(addr.ToStringAddrPort());
}

bool CConnman::CheckIncomingNonce(uint64_t nonce) {
    LOCK(m_nodes_mutex);
    for (const CNode *pnode : m_nodes) {
        if (!pnode->fSuccessfullyConnected && !pnode->IsInboundConn() &&
            pnode->GetLocalNonce() == nonce) {
            return false;
        }
    }
    return true;
}

/** Get the bind address for a socket as CAddress */
static CAddress GetBindAddress(const Sock &sock) {
    CAddress addr_bind;
    struct sockaddr_storage sockaddr_bind;
    socklen_t sockaddr_bind_len = sizeof(sockaddr_bind);
    if (!sock.GetSockName((struct sockaddr *)&sockaddr_bind,
                          &sockaddr_bind_len)) {
        addr_bind.SetSockAddr((const struct sockaddr *)&sockaddr_bind,
                              sockaddr_bind_len);
    } else {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning,
                      "getsockname failed\n");
    }
    return addr_bind;
}

CNode *CConnman::ConnectNode(CAddress addrConnect, const char *pszDest,
                             bool fCountFailure, ConnectionType conn_type) {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    assert(conn_type != ConnectionType::INBOUND);

    // P2P over WebTransport: wt:// URLs.
    if (pszDest != nullptr && IsWebTransportURL(pszDest)) {
        return ConnectWebTransportNode(pszDest, fCountFailure, conn_type);
    }
    // P2P over WebSocket: ws:// and wss:// URLs, and NET_WSS addresses.
    if (pszDest != nullptr && IsWebSocketURL(pszDest)) {
        return ConnectWebSocketNode(pszDest, nullptr, fCountFailure,
                                    conn_type);
    }
    if (pszDest == nullptr && addrConnect.IsWSS()) {
        if (!addrConnect.IsDialableWSS() || IsLocal(addrConnect) ||
            FindNode(static_cast<CService>(addrConnect))) {
            return nullptr;
        }
        return ConnectWebSocketNode(WebSocketURLForAddress(addrConnect),
                                    &addrConnect, fCountFailure, conn_type);
    }

    if (pszDest == nullptr) {
        if (IsLocal(addrConnect)) {
            return nullptr;
        }

        // Look for an existing connection
        CNode *pnode = FindNode(static_cast<CService>(addrConnect));
        if (pnode) {
            LogInfoEvent(BCLog::ALL, "connection_already_present",
                         "Failed to open new connection, already connected");
            return nullptr;
        }
    }

    LogPrintLevel(BCLog::NET, BCLog::Level::Debug,
                  "trying connection %s lastseen=%.1fhrs\n",
                  pszDest ? pszDest : addrConnect.ToStringAddrPort(),
                  Ticks<HoursDouble>(
                      pszDest ? 0h : Now<NodeSeconds>() - addrConnect.nTime));

    // Resolve
    const uint16_t default_port{pszDest != nullptr
                                    ? Params().GetDefaultPort(pszDest)
                                    : Params().GetDefaultPort()};
    if (pszDest) {
        const std::vector<CService> resolved{Lookup(
            pszDest, default_port, fNameLookup && !HaveNameProxy(), 256)};
        if (!resolved.empty()) {
            addrConnect = CAddress(
                resolved[FastRandomContext().randrange(resolved.size())],
                NODE_NONE);
            if (!addrConnect.IsValid()) {
                LogDebug(BCLog::NET,
                         "Resolver returned invalid address %s for %s\n",
                         addrConnect.ToStringAddrPort(), pszDest);
                return nullptr;
            }
            // It is possible that we already have a connection to the IP/port
            // pszDest resolved to. In that case, drop the connection that was
            // just created.
            LOCK(m_nodes_mutex);
            CNode *pnode = FindNode(static_cast<CService>(addrConnect));
            if (pnode) {
                LogInfoEvent(
                    BCLog::ALL, "connection_already_present",
                    "Failed to open new connection, already connected");
                return nullptr;
            }
        }
    }

    // -onlynet with wss (e.g. -onlynet=wss for a WebSocket-only node) also
    // binds manual plain P2P connections (-addnode, -connect, addnode RPC):
    // with only wss, no plain P2P connection is ever made. Without wss in
    // -onlynet, manual connections ignore -onlynet as before.
    if (IsReachable(NET_WSS)) {
        bool reachable{true};
        if (addrConnect.IsValid()) {
            // By the address family: local and private addresses (network
            // "unroutable", never limited by -onlynet) are plain P2P too.
            reachable = addrConnect.IsIPv4()   ? IsReachable(NET_IPV4)
                        : addrConnect.IsIPv6() ? IsReachable(NET_IPV6)
                                               : IsReachable(addrConnect);
        } else if (pszDest) {
            // A name for the proxy to resolve.
            std::string host;
            uint16_t port{0};
            SplitHostPort(pszDest, port, host);
            reachable = host.ends_with(".onion")
                            ? IsReachable(NET_ONION)
                            : IsReachable(NET_IPV4) || IsReachable(NET_IPV6);
        }
        if (!reachable) {
            LogPrintf("Not connecting to %s: plain P2P to network %s is not "
                      "allowed by -onlynet\n",
                      pszDest ? pszDest : addrConnect.ToStringAddrPort(),
                      !addrConnect.IsValid() ? "ipv4/ipv6"
                      : addrConnect.IsIPv4() ? "ipv4"
                      : addrConnect.IsIPv6()
                          ? "ipv6"
                          : GetNetworkName(addrConnect.GetNetwork()));
            return nullptr;
        }
    }

    // Connect
    std::unique_ptr<Sock> sock;
    Proxy proxy;
    CAddress addr_bind;
    assert(!addr_bind.IsValid());
    std::unique_ptr<i2p::sam::Session> i2p_transient_session;

    if (addrConnect.IsValid()) {
        const bool use_proxy{GetProxy(addrConnect.GetNetwork(), proxy)};
        bool proxyConnectionFailed = false;

        if (addrConnect.GetNetwork() == NET_I2P && use_proxy) {
            i2p::Connection conn;
            bool connected{false};

            if (m_i2p_sam_session) {
                connected = m_i2p_sam_session->Connect(addrConnect, conn,
                                                       proxyConnectionFailed);
            } else {
                {
                    LOCK(m_unused_i2p_sessions_mutex);
                    if (m_unused_i2p_sessions.empty()) {
                        i2p_transient_session =
                            std::make_unique<i2p::sam::Session>(proxy,
                                                                &interruptNet);
                    } else {
                        i2p_transient_session.swap(
                            m_unused_i2p_sessions.front());
                        m_unused_i2p_sessions.pop();
                    }
                }
                connected = i2p_transient_session->Connect(
                    addrConnect, conn, proxyConnectionFailed);
                if (!connected) {
                    LOCK(m_unused_i2p_sessions_mutex);
                    if (m_unused_i2p_sessions.size() <
                        MAX_UNUSED_I2P_SESSIONS_SIZE) {
                        m_unused_i2p_sessions.emplace(
                            i2p_transient_session.release());
                    }
                }
            }

            if (connected) {
                sock = std::move(conn.sock);
                addr_bind = CAddress{conn.me, NODE_NONE};
            }
        } else if (use_proxy) {
            LogPrintLevel(BCLog::PROXY, BCLog::Level::Debug,
                          "Using proxy: %s to connect to %s:%s\n",
                          proxy.ToString(), addrConnect.ToStringAddr(),
                          addrConnect.GetPort());
            sock = ConnectThroughProxy(proxy, addrConnect.ToStringAddr(),
                                       addrConnect.GetPort(),
                                       proxyConnectionFailed);
        } else {
            // no proxy needed (none set for target network)
            sock = ConnectDirectly(addrConnect,
                                   conn_type == ConnectionType::MANUAL);
        }
        if (!proxyConnectionFailed) {
            // If a connection to the node was attempted, and failure (if any)
            // is not caused by a problem connecting to the proxy, mark this as
            // an attempt.
            addrman.Attempt(addrConnect, fCountFailure);
        }
    } else if (pszDest && GetNameProxy(proxy)) {
        std::string host;
        uint16_t port{default_port};
        SplitHostPort(std::string(pszDest), port, host);
        bool proxyConnectionFailed;
        sock = ConnectThroughProxy(proxy, host, port, proxyConnectionFailed);
    }
    if (!sock) {
        return nullptr;
    }

    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    std::vector<NetWhitelistPermissions> whitelist_permissions =
        conn_type == ConnectionType::MANUAL
            ? vWhitelistedRangeOutgoing
            : std::vector<NetWhitelistPermissions>{};
    AddWhitelistPermissionFlags(permission_flags, addrConnect,
                                whitelist_permissions);

    // Add node
    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE)
                         .Write(id)
                         .Finalize();
    uint64_t extra_entropy =
        GetDeterministicRandomizer(RANDOMIZER_ID_EXTRAENTROPY)
            .Write(id)
            .Finalize();
    if (!addr_bind.IsValid()) {
        addr_bind = GetBindAddress(*sock);
    }
    CNode *pnode = new CNode(
        id, std::move(sock), addrConnect, CalculateKeyedNetGroup(addrConnect),
        nonce, extra_entropy, addr_bind, pszDest ? pszDest : "", conn_type,
        /* inbound_onion */ false,
        CNodeOptions{
            .i2p_sam_session = std::move(i2p_transient_session),
            .permission_flags = permission_flags,
            .recv_flood_size = nReceiveFloodSize,
        });
    pnode->AddRef();

    // We're making a new connection, harvest entropy from the time (and our
    // peer count)
    RandAddEvent(uint32_t(id));

    return pnode;
}

void CNode::CloseSocketDisconnect() {
    fDisconnect = true;
    LOCK(m_sock_mutex);
    if (m_sock) {
        LogEvent(BCLog::NET, "peer_disconnecting",
                 "disconnecting peer={peer_id}")
            .Field(BCLog::LogField::PeerId, id);
        m_sock.reset();
    }
    m_i2p_sam_session.reset();
}

void CConnman::AddWhitelistPermissionFlags(
    NetPermissionFlags &flags, const CNetAddr &addr,
    const std::vector<NetWhitelistPermissions> &ranges) const {
    for (const auto &subnet : ranges) {
        if (subnet.m_subnet.Match(addr)) {
            NetPermissions::AddFlag(flags, subnet.m_flags);
        }
    }
    if (NetPermissions::HasFlag(flags, NetPermissionFlags::Implicit)) {
        NetPermissions::ClearFlag(flags, NetPermissionFlags::Implicit);
        if (whitelist_forcerelay) {
            NetPermissions::AddFlag(flags, NetPermissionFlags::ForceRelay);
        }
        if (whitelist_relay) {
            NetPermissions::AddFlag(flags, NetPermissionFlags::Relay);
        }
        NetPermissions::AddFlag(flags, NetPermissionFlags::Mempool);
        NetPermissions::AddFlag(flags, NetPermissionFlags::NoBan);
    }
}

CService CNode::GetAddrLocal() const {
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService &addrLocalIn) {
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    if (addrLocal.IsValid()) {
        LogError(
            "Addr local already set for node: %i. Refusing to change from %s "
            "to %s\n",
            id, addrLocal.ToStringAddrPort(), addrLocalIn.ToStringAddrPort());
    } else {
        addrLocal = addrLocalIn;
    }
}

Network CNode::ConnectedThroughNetwork() const {
    return m_inbound_onion ? NET_ONION : addr.GetNetClass();
}

void CNode::copyStats(CNodeStats &stats) {
    stats.nodeid = this->GetId();
    stats.addr = addr;
    stats.addrBind = addrBind;
    stats.m_network = ConnectedThroughNetwork();
    stats.m_last_send = m_last_send;
    stats.m_last_recv = m_last_recv;
    stats.m_last_msg_start = m_last_msg_start;
    stats.m_last_tx_time = m_last_tx_time;
    stats.m_last_proof_time = m_last_proof_time;
    stats.m_last_block_time = m_last_block_time;
    stats.m_connected = m_connected;
    stats.nTimeOffset = nTimeOffset;
    stats.m_addr_name = m_addr_name;
    stats.nVersion = nVersion;
    {
        LOCK(m_subver_mutex);
        stats.cleanSubVer = cleanSubVer;
    }
    stats.fInbound = IsInboundConn();
    stats.m_bip152_highbandwidth_to = m_bip152_highbandwidth_to;
    stats.m_bip152_highbandwidth_from = m_bip152_highbandwidth_from;
    {
        LOCK(cs_vSend);
        stats.mapSendBytesPerMsgType = mapSendBytesPerMsgType;
        stats.nSendBytes = nSendBytes;
    }
    {
        LOCK(cs_vRecv);
        stats.mapRecvBytesPerMsgType = mapRecvBytesPerMsgType;
        stats.nRecvBytes = nRecvBytes;
    }
    stats.nInflightBytes = nInflightBytes;
    stats.m_permission_flags = m_permission_flags;

    stats.m_last_ping_time = m_last_ping_time;
    stats.m_min_ping_time = m_min_ping_time;

    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnlocked = GetAddrLocal();
    stats.addrLocal =
        addrLocalUnlocked.IsValid() ? addrLocalUnlocked.ToStringAddrPort() : "";

    stats.m_conn_type = m_conn_type;
    stats.m_websocket_info = m_websocket_info;
    stats.m_quic_info = m_quic_info;

    stats.m_availabilityScore = m_avalanche_enabled
                                    ? std::make_optional(getAvailabilityScore())
                                    : std::nullopt;
}

void CNode::pauseRecv(bool pause) {
    bool wasPaused = fPauseRecv.exchange(pause);
    if (wasPaused && !pause) {
        if (m_socket_wakeup) {
            // Wait for this socket being readable again.
            m_socket_wakeup->Wake();
        }
        // We were paused and are now unpaused, so update the last receive time
        // to prevent us from being disconnected for inactivity.
        const auto time = GetTime<std::chrono::microseconds>();
        m_last_recv = std::chrono::duration_cast<std::chrono::seconds>(time);
        m_last_msg_start =
            std::chrono::duration_cast<std::chrono::seconds>(time);
    }
}

bool CNode::ReceiveMsgBytes(const Config &config, Span<const uint8_t> msg_bytes,
                            bool &complete) {
    complete = false;
    const auto time = GetTime<std::chrono::microseconds>();
    LOCK(cs_vRecv);
    m_last_recv = std::chrono::duration_cast<std::chrono::seconds>(time);
    if (!m_deserializer->HasData()) {
        // If deserializer has no data, then we're starting to receive a new
        // message. Record the time that we started receiving the message.
        m_last_msg_start =
            std::chrono::duration_cast<std::chrono::seconds>(time);
    }

    nRecvBytes += msg_bytes.size();
    nInflightBytes += msg_bytes.size();

    while (msg_bytes.size() > 0) {
        // Absorb network data.
        int handled = m_deserializer->Read(config, msg_bytes);
        if (handled < 0) {
            // Serious header problem, disconnect from the peer.
            return false;
        }

        if (m_deserializer->Complete()) {
            // decompose a transport agnostic CNetMessage from the deserializer
            bool reject_message{false};
            CNetMessage msg = m_deserializer->GetMessage(time, reject_message);
            if (reject_message) {
                // Message deserialization failed.
                // Drop the message and disconnect the peer.
                // store the size of the corrupt message
                mapRecvBytesPerMsgType.at(NET_MESSAGE_TYPE_OTHER) +=
                    msg.m_raw_message_size;
                return false;
            }

            // Store received bytes per message command
            // to prevent a memory DOS, only allow valid commands
            auto i = mapRecvBytesPerMsgType.find(msg.m_type);
            if (i == mapRecvBytesPerMsgType.end()) {
                i = mapRecvBytesPerMsgType.find(NET_MESSAGE_TYPE_OTHER);
            }

            assert(i != mapRecvBytesPerMsgType.end());
            i->second += msg.m_raw_message_size;
            if (auto *metrics{node::GetNodeMetrics()}) {
                const size_t type{node::MetricMsgTypeIndex(i->first)};
                metrics->p2p_received_bytes.Add(type, msg.m_raw_message_size);
                metrics->p2p_received_messages.Add(type);
            }

            // push the message to the process queue,
            vRecvMsg.push_back(std::move(msg));

            nInflightBytes -= msg.m_raw_message_size;
            complete = true;

            // If we completed a message but still have more bytes, then we
            // started a new message.
            if (m_deserializer->HasData()) {
                m_last_msg_start =
                    std::chrono::duration_cast<std::chrono::seconds>(time);
            }
        }
    }

    return true;
}

int V1TransportDeserializer::readHeader(const Config &config,
                                        Span<const uint8_t> msg_bytes) {
    // copy data to temporary parsing buffer
    uint32_t nRemaining = CMessageHeader::HEADER_SIZE - nHdrPos;
    uint32_t nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), nCopy);
    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < CMessageHeader::HEADER_SIZE) {
        return nCopy;
    }

    // deserialize to CMessageHeader
    try {
        hdrbuf >> hdr;
    } catch (const std::exception &) {
        LogEvent(BCLog::NET, "peer_header_decode_failed",
                 "Header error: Unable to deserialize, peer={peer_id}")
            .Field(BCLog::LogField::PeerId, m_node_id);
        return -1;
    }

    // Check start string, network magic
    if (memcmp(std::begin(hdr.pchMessageStart),
               std::begin(m_config.GetChainParams().NetMagic()),
               CMessageHeader::MESSAGE_START_SIZE) != 0) {
        LogDebug(BCLog::NET,
                 "Header error: Wrong MessageStart %s received, peer=%d\n",
                 HexStr(hdr.pchMessageStart), m_node_id);
        return -1;
    }

    // Reject oversized messages
    if (hdr.IsOversized(config)) {
        LogEvent(BCLog::NET, "peer_message_oversized",
                 "Header error: Size too large ({msg_type}, {bytes} bytes), "
                 "peer={peer_id}")
            .Field(BCLog::LogField::MsgType,
                   SanitizeString(hdr.GetMessageType()))
            .Field(BCLog::LogField::Bytes, hdr.nMessageSize)
            .Field(BCLog::LogField::PeerId, m_node_id);
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}

int V1TransportDeserializer::readData(Span<const uint8_t> msg_bytes) {
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    if (vRecv.size() < nDataPos + nCopy) {
        // Allocate up to 256 KiB ahead, but never more than the total message
        // size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    hasher.Write(msg_bytes.first(nCopy));
    memcpy(&vRecv[nDataPos], msg_bytes.data(), nCopy);
    nDataPos += nCopy;

    return nCopy;
}

const uint256 &V1TransportDeserializer::GetMessageHash() const {
    assert(Complete());
    if (data_hash.IsNull()) {
        hasher.Finalize(data_hash);
    }
    return data_hash;
}

CNetMessage
V1TransportDeserializer::GetMessage(const std::chrono::microseconds time,
                                    bool &reject_message) {
    // Initialize out parameter
    reject_message = false;
    // decompose a single CNetMessage from the TransportDeserializer
    CNetMessage msg(std::move(vRecv));

    // store message type string, time and sizes
    msg.m_type = hdr.GetMessageType();
    msg.m_time = time;
    msg.m_message_size = hdr.nMessageSize;
    msg.m_raw_message_size = hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

    uint256 hash = GetMessageHash();

    // We just received a message off the wire, harvest entropy from the time
    // (and the message checksum)
    RandAddEvent(ReadLE32(hash.begin()));

    // Check checksum and header command string
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) !=
        0) {
        LogDebug(
            BCLog::NET,
            "Header error: Wrong checksum (%s, %u bytes), expected %s was %s, "
            "peer=%d\n",
            SanitizeString(msg.m_type), msg.m_message_size,
            HexStr(Span<uint8_t>(hash.begin(),
                                 hash.begin() + CMessageHeader::CHECKSUM_SIZE)),
            HexStr(hdr.pchChecksum), m_node_id);
        reject_message = true;
    } else if (!hdr.IsMessageTypeValid()) {
        LogEvent(BCLog::NET, "peer_message_type_invalid",
                 "Header error: Invalid message type ({msg_type}, {bytes} "
                 "bytes), peer={peer_id}")
            .Field(BCLog::LogField::MsgType,
                   SanitizeString(hdr.GetMessageType()))
            .Field(BCLog::LogField::Bytes, msg.m_message_size)
            .Field(BCLog::LogField::PeerId, m_node_id);
        reject_message = true;
    }

    // Always reset the network deserializer (prepare for the next message)
    Reset();
    return msg;
}

void V1TransportSerializer::prepareForTransport(
    const Config &config, CSerializedNetMsg &msg,
    std::vector<uint8_t> &header) const {
    // create header
    CMessageHeader hdr(config.GetChainParams().NetMagic(), msg.m_type.c_str(),
                       msg.data.size());
    if (msg.m_checksum) {
        memcpy(hdr.pchChecksum, msg.m_checksum->data(),
               CMessageHeader::CHECKSUM_SIZE);
    } else {
        // create dbl-sha256 checksum
        const uint256 hash = Hash(msg.data);
        memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
    }

    // serialize header
    header.reserve(CMessageHeader::HEADER_SIZE);
    VectorWriter{header, 0, hdr};
}

std::pair<size_t, bool> CConnman::SocketSendData(CNode &node) const {
    size_t nSentSize = 0;
    size_t nMsgCount = 0;

    for (auto it = node.vSendMsg.begin(); it != node.vSendMsg.end(); ++it) {
        const auto &data = *it;
        assert(data.size() > node.nSendOffset);
        int nBytes = 0;

        {
            LOCK(node.m_sock_mutex);
            if (!node.m_sock) {
                break;
            }
            int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
#ifdef MSG_MORE
            if (it + 1 != node.vSendMsg.end()) {
                flags |= MSG_MORE;
            }
#endif
            nBytes = node.m_sock->Send(
                reinterpret_cast<const char *>(data.data()) + node.nSendOffset,
                data.size() - node.nSendOffset, flags);
        }

        if (nBytes == 0) {
            // couldn't send anything at all
            break;
        }

        if (nBytes < 0) {
            // error
            int nErr = WSAGetLastError();
            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE &&
                nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                LogDebug(BCLog::NET, "socket send error for peer=%d: %s\n",
                         node.GetId(), NetworkErrorString(nErr));
                node.CloseSocketDisconnect();
            }

            break;
        }

        assert(nBytes > 0);
        node.m_last_send = GetTime<std::chrono::seconds>();
        node.nSendBytes += nBytes;
        node.nSendOffset += nBytes;
        nSentSize += nBytes;
        if (node.nSendOffset != data.size()) {
            // could not send full message; stop sending more
            break;
        }

        node.nSendOffset = 0;
        node.nSendSize -= data.size();
        node.fPauseSend = node.nSendSize > nSendBufferMaxSize;
        nMsgCount++;
    }

    node.vSendMsg.erase(node.vSendMsg.begin(),
                        node.vSendMsg.begin() + nMsgCount);

    if (node.vSendMsg.empty()) {
        assert(node.nSendOffset == 0);
        assert(node.nSendSize == 0);
    }

    return {nSentSize, !node.vSendMsg.empty()};
}
/** Try to find a connection to evict when the node is full.
 *  Extreme care must be taken to avoid opening the node to attacker
 *   triggered network partitioning.
 *  The strategy used here is to protect a small number of peers
 *   for each of several distinct characteristics which are difficult
 *   to forge.  In order to partition a node the attacker must be
 *   simultaneously better at all of them than honest peers.
 */
std::optional<NodeId> CConnman::SelectEvictionCandidate() {
    std::vector<NodeEvictionCandidate> vEvictionCandidates;
    {
        LOCK(m_nodes_mutex);
        for (const CNode *node : m_nodes) {
            if (node->fDisconnect) {
                continue;
            }

            NodeEvictionCandidate candidate = {
                .id = node->GetId(),
                .m_connected = node->m_connected,
                .m_min_ping_time = node->m_min_ping_time,
                .m_last_block_time = node->m_last_block_time,
                .m_last_proof_time = node->m_last_proof_time,
                .m_last_tx_time = node->m_last_tx_time,
                .fRelevantServices = node->m_has_all_wanted_services,
                .m_relay_txs = node->m_relays_txs.load(),
                .fBloomFilter = node->m_bloom_filter_loaded.load(),
                .nKeyedNetGroup = node->nKeyedNetGroup,
                .prefer_evict = node->m_prefer_evict,
                .m_is_local = node->addr.IsLocal(),
                .m_network = node->ConnectedThroughNetwork(),
                .m_noban = node->HasPermission(NetPermissionFlags::NoBan),
                .m_conn_type = node->m_conn_type,
                .availabilityScore =
                    node->m_avalanche_enabled
                        ? node->getAvailabilityScore()
                        : -std::numeric_limits<double>::infinity()};
            vEvictionCandidates.push_back(candidate);
        }
    }
    return SelectNodeToEvict(std::move(vEvictionCandidates));
}

bool CConnman::AttemptToEvictConnection() {
    const std::optional<NodeId> node_id_to_evict{SelectEvictionCandidate()};
    if (!node_id_to_evict) {
        return false;
    }
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (pnode->GetId() == *node_id_to_evict) {
            LogDebug(
                BCLog::NET,
                "selected %s connection for eviction peer=%d; disconnecting\n",
                pnode->ConnectionTypeAsString(), pnode->GetId());
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CConnman::AcceptConnection(const ListenSocket &hListenSocket) {
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    auto sock = hListenSocket.sock->Accept((struct sockaddr *)&sockaddr, &len);
    CAddress addr;

    if (!sock) {
        const int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK) {
            LogPrintf("socket error accept failed: %s\n",
                      NetworkErrorString(nErr));
        }
        return;
    }

    if (!addr.SetSockAddr((const struct sockaddr *)&sockaddr, len)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning,
                      "Unknown socket family\n");
    }

    const CAddress addr_bind = GetBindAddress(*sock);

    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    hListenSocket.AddSocketPermissionFlags(permission_flags);

    if (m_p2p_port_websocket && !g_listen_plain_p2p) {
        // WebSocket only: no raw P2P peer to keep compatible, so no node
        // until a WebSocket upgrade. The HTTP server reads nothing before
        // classifying the first bytes, and closes raw P2P. The checks that
        // need no data come first, so a banned peer or a full node does no
        // HTTP/TLS work.
        if (MayAcceptInbound(addr, permission_flags)) {
            m_p2p_port_websocket(std::move(sock), addr, addr_bind);
        }
        return;
    }
    // With WebSocket on the P2P port, the node is created as for any raw
    // P2P peer (same checks, timeouts and eviction, silent ones included),
    // and is classified on its first bytes before anything is read
    // (ClassifyP2PPortNode).
    CreateNodeFromAcceptedSocket(std::move(sock), permission_flags, addr_bind,
                                 addr, /*websocket_info=*/nullptr,
                                 /*classify=*/bool{m_p2p_port_websocket});
}

bool CConnman::MayAcceptInbound(const CAddress &addr,
                                NetPermissionFlags permission_flags) {
    AddWhitelistPermissionFlags(permission_flags, addr,
                                vWhitelistedRangeIncoming);
    if (!fNetworkActive) {
        LogDebug(BCLog::NET,
                 "connection from %s dropped: not accepting new connections\n",
                 addr.ToStringAddrPort());
        return false;
    }
    const bool noban{
        NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan)};
    if (!noban && m_banman && m_banman->IsBanned(addr)) {
        LogDebug(BCLog::NET, "connection from %s dropped (banned)\n",
                 addr.ToStringAddrPort());
        return false;
    }
    const int max_inbound{nMaxConnections - m_max_outbound};
    int inbound{0};
    {
        LOCK(m_nodes_mutex);
        for (const CNode *node : m_nodes) {
            inbound += node->IsInboundConn();
        }
    }
    if (!noban && inbound + 1 >= max_inbound && m_banman &&
        m_banman->IsDiscouraged(addr)) {
        LogDebug(BCLog::NET, "connection from %s dropped (discouraged)\n",
                 addr.ToStringAddrPort());
        return false;
    }
    // Eviction itself is left to the node's creation, after the upgrade.
    if (inbound >= max_inbound && !SelectEvictionCandidate()) {
        LogDebug(BCLog::NET, "failed to find an eviction candidate - "
                             "connection dropped (full)\n");
        return false;
    }
    return true;
}

P2PPortProtocol
ClassifyP2PPortBytes(Span<const uint8_t> first,
                     const CMessageHeader::MessageMagic &magic) {
    static constexpr uint8_t TLS_HANDSHAKE[]{0x16, 0x03};
    static constexpr uint8_t HTTP_GET[]{'G', 'E', 'T', ' '};
    const auto starts{[&](Span<const uint8_t> prefix) {
        const size_t n{std::min(first.size(), prefix.size())};
        return std::equal(first.begin(), first.begin() + n, prefix.begin());
    }};
    if (first.empty()) {
        return P2PPortProtocol::UNDECIDED;
    }
    const bool is_magic{starts(magic)};
    const bool is_tls{starts(TLS_HANDSHAKE)};
    const bool is_http{starts(HTTP_GET)};
    if (is_magic && (first.size() >= magic.size() || (!is_tls && !is_http))) {
        return P2PPortProtocol::PLAIN;
    }
    if (!is_magic && ((is_tls && first.size() >= sizeof(TLS_HANDSHAKE)) ||
                      (is_http && first.size() >= sizeof(HTTP_GET)))) {
        return P2PPortProtocol::WEBSOCKET;
    }
    if (is_magic || is_tls || is_http) {
        return P2PPortProtocol::UNDECIDED;
    }
    // Neither: plain P2P, which rejects it as before.
    return P2PPortProtocol::PLAIN;
}

bool CConnman::ClassifyP2PPortNode(CNode &node,
                                   const Sock::EventsPerSock &events_per_sock) {
    bool readable{node.m_p2p_port_partial};
    {
        LOCK(node.m_sock_mutex);
        if (!node.m_sock) {
            return true;
        }
        if (const auto it{events_per_sock.find(node.m_sock)};
            it != events_per_sock.end() &&
            (it->second.occurred & (Sock::RECV | Sock::ERR))) {
            readable = true;
        }
    }
    P2PPortProtocol protocol{P2PPortProtocol::UNDECIDED};
    if (readable) {
        uint8_t first[4];
        const ssize_t n{WITH_LOCK(
            node.m_sock_mutex,
            return node.m_sock ? node.m_sock->Recv(first, sizeof(first),
                                                   MSG_PEEK | MSG_DONTWAIT)
                               : -1)};
        if (n <= 0) {
            // Closed or failed: the ordinary receive path deals with it.
            node.m_p2p_port_unclassified = false;
            node.m_p2p_port_partial = false;
            return true;
        }
        protocol = ClassifyP2PPortBytes(Span<const uint8_t>{first, size_t(n)},
                                        config->GetChainParams().NetMagic());
        // Peeked again on each loop rather than waited for: its socket
        // stays readable.
        node.m_p2p_port_partial = protocol == P2PPortProtocol::UNDECIDED;
    }
    if (protocol == P2PPortProtocol::UNDECIDED) {
        if (std::chrono::steady_clock::now() < node.m_p2p_port_deadline) {
            return false;
        }
        // Silent, or a few bytes that are neither: what a raw P2P listener
        // would have got.
        protocol = P2PPortProtocol::PLAIN;
    }
    node.m_p2p_port_unclassified = false;
    node.m_p2p_port_partial = false;
    if (protocol == P2PPortProtocol::PLAIN) {
        if (g_listen_plain_p2p) {
            return true;
        }
        LogDebug(BCLog::NET,
                 "connection from %s dropped: raw P2P is not accepted "
                 "(-p2prawlisten=0) peer=%d\n",
                 node.addr.ToStringAddrPort(), node.GetId());
        node.CloseSocketDisconnect();
        return false;
    }
    // HTTP or TLS: the socket, nothing read from it, goes to the HTTP
    // server. This node never spoke P2P and is dropped.
    std::unique_ptr<Sock> sock;
    {
        LOCK(node.m_sock_mutex);
        if (!node.m_sock) {
            return false;
        }
        sock = std::make_unique<Sock>(std::move(*node.m_sock));
        node.m_sock.reset();
    }
    node.fDisconnect = true;
    LogDebug(BCLog::NET,
             "connection from %s on the P2P port is HTTP/TLS: handed to the "
             "WebSocket endpoint (peer=%d dropped)\n",
             node.addr.ToStringAddrPort(), node.GetId());
    m_p2p_port_websocket(std::move(sock), node.addr, node.addrBind);
    return false;
}

uint64_t GetP2PWebSocketMessageSizeLimit() {
    const uint64_t payload = std::max<uint64_t>(
        CMessageHeader::GetMaxPayloadSize(GetConfig(), NetMsgType::BLOCK),
        MAX_PROTOCOL_MESSAGE_LENGTH);
    // The legacy envelope is larger than p2p-v2's id/name envelope. The
    // native length prefix is uint32_t; never accept an unrepresentable body.
    return std::min<uint64_t>(
        payload, uint64_t{std::numeric_limits<uint32_t>::max()} -
                     CMessageHeader::HEADER_SIZE) + CMessageHeader::HEADER_SIZE;
}

std::string P2PWebSocketCompressionName(P2PWebSocketCompression c) {
    switch (c) {
        case P2PWebSocketCompression::NONE:
            return "none";
        case P2PWebSocketCompression::PERMESSAGE_DEFLATE:
            return "permessage-deflate";
        case P2PWebSocketCompression::ZSTD:
            return P2P_WS_PROTOCOL_ZSTD;
        case P2PWebSocketCompression::ZSTD_DICT:
            return P2P_WS_PROTOCOL_ZSTD_DICT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

WebSocketTransportTotals &GetWebSocketTransportTotals() {
    static WebSocketTransportTotals totals;
    return totals;
}

static GlobalMutex g_websocket_dialer_mutex;
static WebSocketDialer g_websocket_dialer GUARDED_BY(g_websocket_dialer_mutex);

void SetWebSocketDialer(WebSocketDialer dialer) {
    LOCK(g_websocket_dialer_mutex);
    g_websocket_dialer = std::move(dialer);
}

WebSocketDialer GetWebSocketDialer() {
    LOCK(g_websocket_dialer_mutex);
    return g_websocket_dialer;
}

bool IsWebSocketURL(std::string_view str) {
    return str.substr(0, 5) == "ws://" || str.substr(0, 6) == "wss://";
}

std::string WebSocketURLForAddress(const CService &addr) {
    return strprintf("wss://%s%s", addr.ToStringAddrPort(), addr.GetWSSPath());
}

std::string EncodeSpkiPin(Span<const unsigned char> sha256) {
    std::string out{EncodeBase64(sha256)};
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    out.erase(std::find(out.begin(), out.end(), '='), out.end());
    return out;
}

std::optional<std::vector<unsigned char>> DecodeSpkiPin(std::string_view pin) {
    std::string b64{pin};
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    b64.erase(std::find(b64.begin(), b64.end(), '='), b64.end());
    b64.append((4 - b64.size() % 4) % 4, '=');
    auto decoded{DecodeBase64(b64)};
    if (!decoded || decoded->size() != 32) {
        return std::nullopt;
    }
    return std::vector<unsigned char>(decoded->begin(), decoded->end());
}

bool IsValidWebSocketToken(std::string_view token) {
    return !token.empty() && token.size() <= 256 &&
           std::all_of(token.begin(), token.end(), [](char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                      c == '.' || c == '~';
           });
}

/**
 * Remove "token=<t>" from the query of a request target. Returns <t> ("" if
 * absent), or std::nullopt if it is not a valid token.
 */
static std::optional<std::string> TakeWebSocketToken(std::string &target) {
    const size_t q{target.find('?')};
    if (q == std::string::npos) {
        return std::string{};
    }
    std::string token;
    std::vector<std::string> kept;
    for (const auto &param : util::SplitString(target.substr(q + 1), '&')) {
        if (param.starts_with("token=")) {
            token = param.substr(6);
            if (!IsValidWebSocketToken(token)) {
                return std::nullopt;
            }
        } else if (!param.empty()) {
            kept.push_back(param);
        }
    }
    target = target.substr(0, q) +
             (kept.empty() ? std::string{} : "?" + util::Join(kept, "&"));
    return token;
}

std::string RedactWebSocketURL(std::string_view url) {
    std::string out{url};
    for (size_t pos{out.find("token=")}; pos != std::string::npos;
         pos = out.find("token=", pos + 1)) {
        if (pos == 0 || (out[pos - 1] != '?' && out[pos - 1] != '&')) {
            continue;
        }
        const size_t start{pos + 6};
        const size_t end{out.find_first_of("&#", start)};
        out.replace(start,
                    (end == std::string::npos ? out.size() : end) - start,
                    "***");
    }
    return out;
}

std::optional<ParsedWebSocketURL> ParseWebSocketURL(std::string_view url) {
    ParsedWebSocketURL out;
    if (const size_t hash{url.find('#')}; hash != std::string_view::npos) {
        const std::string_view fragment{url.substr(hash + 1)};
        url = url.substr(0, hash);
        if (fragment.substr(0, 5) != "spki=") {
            return std::nullopt;
        }
        out.spki_pin = DecodeSpkiPin(fragment.substr(5));
        if (!out.spki_pin) {
            return std::nullopt;
        }
    }
    if (url.substr(0, 6) == "wss://") {
        out.tls = true;
        url.remove_prefix(6);
    } else if (url.substr(0, 5) == "ws://") {
        url.remove_prefix(5);
    } else {
        return std::nullopt;
    }
    const size_t slash{url.find('/')};
    const std::string authority{url.substr(0, slash)};
    out.target = slash == std::string_view::npos
                     ? std::string{P2P_WEBSOCKET_PATH}
                     : std::string{url.substr(slash)};
    const auto token{TakeWebSocketToken(out.target)};
    if (!token) {
        return std::nullopt;
    }
    out.token = *token;
    uint16_t port{static_cast<uint16_t>(out.tls ? 443 : 80)};
    std::string host;
    if (authority.empty() || !SplitHostPort(authority, port, host) ||
        host.empty()) {
        return std::nullopt;
    }
    out.host = host;
    out.port = port;
    const bool ipv6{host.find(':') != std::string::npos};
    out.authority = strprintf(ipv6 ? "[%s]:%u" : "%s:%u", host, port);
    return out;
}

CNode *CConnman::ConnectWebSocketNode(const std::string &url,
                                      const CAddress *wss_addr,
                                      bool fCountFailure,
                                      ConnectionType conn_type) {
    const auto parsed{ParseWebSocketURL(url)};
    if (!parsed) {
        LogInfoEvent(BCLog::ALL, "websocket_peer_url_invalid",
                     "Not connecting to {addr}: invalid WebSocket peer URL")
            .Field(BCLog::LogField::Addr, RedactWebSocketURL(url));
        return nullptr;
    }
    const bool onion{parsed->host.ends_with(".onion")};
    if (!IsReachable(onion ? NET_ONION : NET_WSS)) {
        LogPrintf("Not connecting to %s: network %s is not reachable "
                  "(-onlynet)\n",
                  RedactWebSocketURL(url), onion ? "onion" : "wss");
        return nullptr;
    }
    if (!parsed->tls && !onion) {
        // Unencrypted ws:// is no more private than raw P2P over its IP
        // network: -onlynet=wss alone (TLS only) does not allow it.
        const std::optional<CNetAddr> literal{
            LookupHost(parsed->host, /*fAllowLookup=*/false)};
        const bool reachable{
            literal && literal->IsIPv4() ? IsReachable(NET_IPV4)
            : literal && literal->IsIPv6()
                ? IsReachable(NET_IPV6)
                : IsReachable(NET_IPV4) || IsReachable(NET_IPV6)};
        if (!reachable) {
            LogPrintf("Not connecting to %s: unencrypted ws:// needs network "
                      "ipv4 or ipv6, which -onlynet does not allow (use "
                      "wss://)\n",
                      RedactWebSocketURL(url));
            return nullptr;
        }
    }
    const WebSocketDialer dialer{GetWebSocketDialer()};
    if (!dialer) {
        LogInfoEvent(
            BCLog::ALL, "websocket_transport_unavailable",
            "Cannot connect to {addr}: P2P over WebSocket is unavailable")
            .Field(BCLog::LogField::Addr, RedactWebSocketURL(url));
        return nullptr;
    }
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug,
                  "trying WebSocket connection %s\n", RedactWebSocketURL(url));

    // Open the TCP connection exactly as for TCP peers: through the proxy
    // (which resolves the name: no local DNS lookup) when one applies,
    // never falling back to a direct connection.
    std::unique_ptr<Sock> sock;
    bool proxy_failed{false};
    std::optional<CService> direct;
    Proxy proxy;
    if (onion) {
        if (!GetProxy(NET_ONION, proxy)) {
            LogInfoEvent(BCLog::ALL, "websocket_onion_proxy_missing",
                         "Not connecting to {addr}: no -onion proxy")
                .Field(BCLog::LogField::Addr, RedactWebSocketURL(url));
            return nullptr;
        }
        sock = ConnectThroughProxy(proxy, parsed->host, parsed->port,
                                   proxy_failed);
    } else if (GetNameProxy(proxy)) {
        sock = ConnectThroughProxy(proxy, parsed->host, parsed->port,
                                   proxy_failed);
    } else {
        // Try each address the name resolves to (e.g. localhost may give
        // ::1 first while the peer only listens on 127.0.0.1).
        const std::vector<CService> resolved{
            Lookup(parsed->host, parsed->port, fNameLookup, 8)};
        if (resolved.empty()) {
            LogDebug(BCLog::NET, "Cannot resolve %s\n", parsed->host);
            return nullptr;
        }
        for (const CService &candidate : resolved) {
            if (!candidate.IsValid()) {
                continue;
            }
            if (GetProxy(candidate.GetNetwork(), proxy)) {
                sock = ConnectThroughProxy(proxy, candidate.ToStringAddr(),
                                           candidate.GetPort(), proxy_failed);
            } else {
                sock = ConnectDirectly(candidate,
                                       conn_type == ConnectionType::MANUAL);
            }
            if (sock || proxy_failed) {
                direct = candidate;
                break;
            }
        }
    }
    if (wss_addr && !proxy_failed) {
        addrman.Attempt(*wss_addr, fCountFailure);
    }
    if (!sock) {
        return nullptr;
    }
    const CAddress addr_bind{GetBindAddress(*sock)};
    std::optional<WebSocketDialResult> dialed{
        dialer(std::move(sock), *parsed, interruptNet)};
    if (!dialed) {
        return nullptr;
    }

    // The peer is known by its NET_WSS address if it came from addrman, by
    // the address it resolved to, or (through a proxy) only by its URL.
    const CAddress addrConnect{wss_addr ? *wss_addr
                               : direct ? CAddress{*direct, NODE_NONE}
                                        : CAddress{}};
    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    std::vector<NetWhitelistPermissions> whitelist_permissions =
        conn_type == ConnectionType::MANUAL
            ? vWhitelistedRangeOutgoing
            : std::vector<NetWhitelistPermissions>{};
    AddWhitelistPermissionFlags(permission_flags, addrConnect,
                                whitelist_permissions);

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE)
                         .Write(id)
                         .Finalize();
    uint64_t extra_entropy =
        GetDeterministicRandomizer(RANDOMIZER_ID_EXTRAENTROPY)
            .Write(id)
            .Finalize();
    CNode *pnode = new CNode(
        id, std::move(dialed->sock), addrConnect,
        CalculateKeyedNetGroup(addrConnect), nonce, extra_entropy, addr_bind,
        wss_addr ? "" : url, conn_type,
        /* inbound_onion */ false,
        CNodeOptions{
            .permission_flags = permission_flags,
            .recv_flood_size = nReceiveFloodSize,
            .websocket_info = std::move(dialed->info),
        });
    pnode->AddRef();
    RandAddEvent(uint32_t(id));
    return pnode;
}

void CConnman::AcceptWebSocketPeer(
    std::unique_ptr<Sock> &&sock, const CAddress &addr,
    const CAddress &addr_bind, std::shared_ptr<WebSocketTransportInfo> info) {
    NetPermissionFlags flags{NetPermissionFlags::None};
    // On the P2P port: the permissions of the listener reached (-whitebind),
    // matched by the address reached (any address of an any-address bind).
    for (const ListenSocket &listen : vhListenSocket) {
        if (listen.addr.GetPort() == addr_bind.GetPort() &&
            (listen.addr.IsBindAny() ||
             static_cast<const CNetAddr &>(listen.addr) ==
                 static_cast<const CNetAddr &>(addr_bind))) {
            listen.AddSocketPermissionFlags(flags);
        }
    }
    bool known{false};
    if (info && !info->peer_spki.empty()) {
        for (const auto &key : vWhitelistedKeys) {
            if (key.m_key == info->peer_spki) {
                NetPermissions::AddFlag(flags, key.m_flags);
                known = true;
            }
        }
        info->pinned = known;
    }
    if (m_websocket_require_known_key && !known) {
        LogDebug(BCLog::NET,
                 "WebSocket peer %s dropped: %s (-p2pwebsocketrequirecert)\n",
                 addr.ToStringAddrPort(),
                 info && !info->peer_spki.empty()
                     ? "its key is not listed in -p2pwebsocketpeer"
                     : "no client certificate");
        return;
    }
    CreateNodeFromAcceptedSocket(std::move(sock), flags, addr_bind, addr,
                                 std::move(info));
}

void CConnman::AcceptWebTransportPeer(
    std::unique_ptr<Sock> &&sock, const CAddress &addr,
    const CAddress &addr_bind, std::shared_ptr<QuicTransportInfo> info) {
    NetPermissionFlags flags{NetPermissionFlags::None};
    for (const auto &bind : gArgs.GetArgs("-whitebind")) {
        NetWhitebindPermissions parsed;
        bilingual_str error;
        if (NetWhitebindPermissions::TryParse(bind, parsed, error) &&
            parsed.m_service.GetPort() == addr_bind.GetPort() &&
            (parsed.m_service == addr_bind ||
             (parsed.m_service.IsBindAny() &&
              parsed.m_service.IsIPv4() == addr_bind.IsIPv4() &&
              parsed.m_service.IsIPv6() == addr_bind.IsIPv6()))) {
            NetPermissions::AddFlag(flags, parsed.m_flags);
        }
    }
    bool known{false};
    if (info && !info->peer_spki.empty()) {
        for (const auto &key : vWhitelistedKeys) {
            if (key.m_key == info->peer_spki) {
                NetPermissions::AddFlag(flags, key.m_flags);
                known = true;
            }
        }
        info->pinned = known;
    }
    if (m_websocket_require_known_key && !known) {
        LogDebug(BCLog::NET,
                 "WebTransport peer %s dropped: %s (-p2pwebsocketrequirecert)\n",
                 addr.ToStringAddrPort(),
                 info && !info->peer_spki.empty()
                     ? "its key is not listed in -p2pwebsocketpeer"
                     : "no client certificate");
        return;
    }
    CreateNodeFromAcceptedSocket(std::move(sock), flags, addr_bind, addr,
                                 nullptr, /*classify=*/false, std::move(info));
}

CNode *CConnman::ConnectWebTransportNode(const std::string &url,
                                         bool fCountFailure,
                                         ConnectionType conn_type) {
    const auto parsed{ParseWebTransportURL(url)};
    if (!parsed) {
        LogPrintf("Not connecting to %s: invalid WebTransport peer URL\n",
                  RedactWebTransportURL(url));
        return nullptr;
    }
    const WebTransportDialer dialer{GetWebTransportDialer()};
    if (!dialer) {
        LogPrintf("Cannot connect to %s: P2P over WebTransport is "
                  "unavailable (-p2pwebtransport)\n",
                  RedactWebTransportURL(url));
        return nullptr;
    }
    // QUIC is UDP: it cannot go through a SOCKS5 proxy. Fail closed
    // rather than reveal our address by dialing directly.
    Proxy proxy;
    if (parsed->host.ends_with(".onion") || GetNameProxy(proxy)) {
        LogPrintf("Not connecting to %s: WebTransport cannot use a proxy\n",
                  RedactWebTransportURL(url));
        return nullptr;
    }
    std::optional<CService> target;
    for (const CService &candidate :
         Lookup(parsed->host, parsed->port, fNameLookup, 8)) {
        if (!candidate.IsValid()) {
            continue;
        }
        // GetNetwork() calls private/loopback addresses UNROUTABLE;
        // policy still applies to their underlying IP family.
        const Network network{candidate.IsIPv4() ? NET_IPV4
                              : candidate.IsIPv6() ? NET_IPV6
                                                   : candidate.GetNetwork()};
        if (GetProxy(network, proxy)) {
            LogPrintf("Not connecting to %s: WebTransport cannot use a "
                      "proxy\n",
                      RedactWebTransportURL(url));
            return nullptr;
        }
        if (!IsReachable(network)) {
            continue;
        }
        target = candidate;
        break;
    }
    if (!target) {
        LogDebug(BCLog::NET, "Cannot resolve %s or its network is not "
                             "reachable (-onlynet)\n",
                 parsed->host);
        return nullptr;
    }
    if (FindNode(*target)) {
        LogPrintf("Failed to open new connection, already connected\n");
        return nullptr;
    }
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug,
                  "trying WebTransport connection %s\n",
                  RedactWebTransportURL(url));
    WebTransportDialError error{WebTransportDialError::NONE};
    std::optional<WebTransportDialResult> dialed{
        dialer(*target, *parsed, WEBTRANSPORT_DIAL_TIMEOUT, interruptNet,
               error)};
    if (!dialed) {
        LogDebug(BCLog::NET, "WebTransport connection to %s failed: %s\n",
                 RedactWebTransportURL(url), WebTransportDialErrorName(error));
        return nullptr;
    }
    const CAddress addrConnect{*target, NODE_NONE};
    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    std::vector<NetWhitelistPermissions> whitelist_permissions =
        conn_type == ConnectionType::MANUAL
            ? vWhitelistedRangeOutgoing
            : std::vector<NetWhitelistPermissions>{};
    AddWhitelistPermissionFlags(permission_flags, addrConnect,
                                whitelist_permissions);

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE)
                         .Write(id)
                         .Finalize();
    uint64_t extra_entropy =
        GetDeterministicRandomizer(RANDOMIZER_ID_EXTRAENTROPY)
            .Write(id)
            .Finalize();
    CNode *pnode = new CNode(
        id, std::move(dialed->sock), addrConnect,
        CalculateKeyedNetGroup(addrConnect), nonce, extra_entropy,
        CAddress{dialed->local, NODE_NONE}, url, conn_type,
        /* inbound_onion */ false,
        CNodeOptions{
            .permission_flags = permission_flags,
            .recv_flood_size = nReceiveFloodSize,
            .quic_info = std::move(dialed->info),
        });
    pnode->AddRef();
    RandAddEvent(uint32_t(id));
    return pnode;
}

void CConnman::CreateNodeFromAcceptedSocket(
    std::unique_ptr<Sock> &&sock, NetPermissionFlags permission_flags,
    const CAddress &addr_bind, const CAddress &addr,
    std::shared_ptr<WebSocketTransportInfo> websocket_info, bool classify,
    std::shared_ptr<QuicTransportInfo> quic_info) {
    int nInbound = 0;
    int nMaxInbound = nMaxConnections - m_max_outbound;

    AddWhitelistPermissionFlags(permission_flags, addr,
                                vWhitelistedRangeIncoming);

    {
        LOCK(m_nodes_mutex);
        for (const CNode *pnode : m_nodes) {
            if (pnode->IsInboundConn()) {
                nInbound++;
            }
        }
    }

    if (!fNetworkActive) {
        LogEvent(
            BCLog::NET, "connection_not_accepting",
            "connection from {addr} dropped: not accepting new connections")
            .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
        return;
    }

    if (!sock->IsSelectable()) {
        LogInfoEvent(BCLog::ALL, "connection_socket_unselectable",
                     "connection from {addr} dropped: non-selectable socket")
            .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted
    // sockets on all platforms.  Set it again here just to be sure.
    // (WebSocket and WebTransport peers use a local socketpair, which has no
    // such option.)
    const int on{1};
    if (!websocket_info && !quic_info &&
        sock->SetSockOpt(IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) ==
            SOCKET_ERROR) {
        LogEvent(BCLog::NET, "connection_tcp_nodelay_failed",
                 "connection from {addr}: unable to set TCP_NODELAY, "
                 "continuing anyway")
            .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
    }

    // Don't accept connections from banned peers.
    bool banned = m_banman && m_banman->IsBanned(addr);
    if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) &&
        banned) {
        LogEvent(BCLog::NET, "connection_address_banned",
                 "connection from {addr} dropped (banned)")
            .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
        return;
    }

    // Only accept connections from discouraged peers if our inbound slots
    // aren't (almost) full.
    bool discouraged = m_banman && m_banman->IsDiscouraged(addr);
    if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) &&
        nInbound + 1 >= nMaxInbound && discouraged) {
        LogEvent(BCLog::NET, "connection_address_discouraged",
                 "connection from {addr} dropped (discouraged)")
            .Field(BCLog::LogField::Addr, static_cast<const CService &>(addr));
        return;
    }

    if (nInbound >= nMaxInbound) {
        if (!AttemptToEvictConnection()) {
            // No connection to evict, disconnect the new connection
            LogEvent(BCLog::NET, "connection_slots_full",
                     "failed to find an eviction candidate - connection "
                     "dropped (full)");
            return;
        }
    }

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE)
                         .Write(id)
                         .Finalize();
    uint64_t extra_entropy =
        GetDeterministicRandomizer(RANDOMIZER_ID_EXTRAENTROPY)
            .Write(id)
            .Finalize();

    const bool inbound_onion =
        std::find(m_onion_binds.begin(), m_onion_binds.end(), addr_bind) !=
        m_onion_binds.end();
    CNode *pnode = new CNode(
        id, std::move(sock), addr, CalculateKeyedNetGroup(addr), nonce,
        extra_entropy, addr_bind, "", ConnectionType::INBOUND, inbound_onion,
        CNodeOptions{
            .permission_flags = permission_flags,
            .prefer_evict = discouraged,
            .recv_flood_size = nReceiveFloodSize,
            .websocket_info = std::move(websocket_info),
            .quic_info = std::move(quic_info),
        });
    pnode->AddRef();
    if (classify) {
        pnode->m_p2p_port_deadline =
            std::chrono::steady_clock::now() + m_p2p_port_handshake_timeout;
        pnode->m_p2p_port_unclassified = true;
    }
    for (auto interface : m_msgproc) {
        interface->InitializeNode(*config, *pnode, GetLocalServices());
    }

    LogDebug(BCLog::NET, "connection from %s accepted%s\n",
             addr.ToStringAddrPort(),
             pnode->m_websocket_info ? " (WebSocket)"
             : pnode->m_quic_info    ? " (WebTransport)"
                                     : "");

    {
        LOCK(m_nodes_mutex);
        AddNodeLocked(pnode);
    }

    // We received a new connection, harvest entropy from the time (and our peer
    // count)
    RandAddEvent(uint32_t(id));
}

bool CConnman::AddConnection(const std::string &address,
                             ConnectionType conn_type) {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::optional<int> max_connections;
    switch (conn_type) {
        case ConnectionType::INBOUND:
        case ConnectionType::MANUAL:
            return false;
        case ConnectionType::OUTBOUND_FULL_RELAY:
            max_connections = m_max_outbound_full_relay;
            break;
        case ConnectionType::BLOCK_RELAY:
            max_connections = m_max_outbound_block_relay;
            break;
        // no limit for ADDR_FETCH because -seednode has no limit either
        case ConnectionType::ADDR_FETCH:
            break;
        // no limit for FEELER connections since they're short-lived
        case ConnectionType::FEELER:
            break;
        case ConnectionType::AVALANCHE_OUTBOUND:
            max_connections = m_max_avalanche_outbound;
            break;
    } // no default case, so the compiler can warn about missing cases

    // Count existing connections
    int existing_connections =
        WITH_LOCK(m_nodes_mutex,
                  return std::count_if(
                      m_nodes.begin(), m_nodes.end(), [conn_type](CNode *node) {
                          return node->m_conn_type == conn_type;
                      }););

    // Max connections of specified type already exist
    if (max_connections != std::nullopt &&
        existing_connections >= max_connections) {
        return false;
    }

    // Max total outbound connections already exist
    CSemaphoreGrant grant(*semOutbound, true);
    if (!grant) {
        return false;
    }

    OpenNetworkConnection(CAddress(), false, &grant, address.c_str(),
                          conn_type);
    return true;
}

void CConnman::DisconnectNodes() {
    {
        LOCK(m_nodes_mutex);

        if (!fNetworkActive) {
            // Disconnect any connected nodes
            for (CNode *pnode : m_nodes) {
                if (!pnode->fDisconnect) {
                    LogDebug(BCLog::NET,
                             "Network not active, dropping peer=%d\n",
                             pnode->GetId());
                    pnode->fDisconnect = true;
                }
            }
        }

        // Disconnect unused nodes
        std::vector<CNode *> nodes_copy = m_nodes;
        for (CNode *pnode : nodes_copy) {
            if (pnode->fDisconnect) {
                // remove from m_nodes
                m_nodes.erase(remove(m_nodes.begin(), m_nodes.end(), pnode),
                              m_nodes.end());

                // release outbound grant (if any)
                pnode->grantOutbound.Release();

                // close socket and cleanup
                pnode->CloseSocketDisconnect();

                // hold in disconnected pool until all refs are released
                pnode->Release();
                m_nodes_disconnected.push_back(pnode);
            }
        }
    }
    {
        // Delete disconnected nodes
        std::list<CNode *> nodes_disconnected_copy = m_nodes_disconnected;
        for (CNode *pnode : nodes_disconnected_copy) {
            // Destroy the object only after other threads have stopped using
            // it.
            if (pnode->GetRefCount() <= 0) {
                m_nodes_disconnected.remove(pnode);
                DeleteNode(pnode);
            }
        }
    }
}

void CConnman::NotifyNumConnectionsChanged() {
    size_t nodes_size;
    {
        LOCK(m_nodes_mutex);
        nodes_size = m_nodes.size();
    }
    if (nodes_size != nPrevNodeCount) {
        nPrevNodeCount = nodes_size;
        if (m_client_interface) {
            m_client_interface->NotifyNumConnectionsChanged(nodes_size);
        }
    }
}

bool CConnman::ShouldRunInactivityChecks(const CNode &node,
                                         std::chrono::seconds now) const {
    return node.m_connected + m_peer_connect_timeout < now;
}

bool CConnman::InactivityCheck(const CNode &node) const {
    // Tests that see disconnects after using mocktime can start nodes with a
    // large timeout. For example, -peertimeout=999999999.
    const auto now{GetTime<std::chrono::seconds>()};
    const auto last_send{node.m_last_send.load()};
    const auto last_recv{node.m_last_recv.load()};
    const auto last_msg_start{node.m_last_msg_start.load()};

    if (!ShouldRunInactivityChecks(node, now)) {
        return false;
    }

    if (last_recv.count() == 0 || last_send.count() == 0) {
        LogDebug(BCLog::NET,
                 "socket no message in first %i seconds, %d %d peer=%d\n",
                 count_seconds(m_peer_connect_timeout), last_recv.count() != 0,
                 last_send.count() != 0, node.GetId());
        return true;
    }

    if (now > last_send + TIMEOUT_INTERVAL) {
        LogDebug(BCLog::NET, "socket sending timeout: %is peer=%d\n",
                 count_seconds(now - last_send), node.GetId());
        return true;
    }

    if (now > last_recv + TIMEOUT_INTERVAL) {
        LogDebug(BCLog::NET, "socket receive timeout: %is peer=%d\n",
                 count_seconds(now - last_recv), node.GetId());
        return true;
    }

    uint64_t inflight_bytes = node.nInflightBytes.load();
    if (inflight_bytes > 0 && !node.fPauseRecv) {
        // First check if the peer started sending us a message, but then
        // stalled without finishing it.
        if (now > last_recv + m_peer_connect_timeout) {
            LogDebug(BCLog::NET,
                     "socket receive timeout: stalled message, last data "
                     "received %i seconds ago, bytes=%d peer=%d\n",
                     count_seconds(now - last_recv), inflight_bytes,
                     node.GetId());
            return true;
        }

        // Second check if the peer sent us a message, but is too slow to
        // complete it in reasonable time (~2.13Mb/s for a 32MB block under
        // default settings).
        if (now > last_msg_start + 2 * m_peer_connect_timeout) {
            LogDebug(BCLog::NET,
                     "socket receive timeout: stalled message started %i "
                     "seconds ago, bytes=%d peer=%d\n",
                     count_seconds(now - last_msg_start), inflight_bytes,
                     node.GetId());
            return true;
        }
    }

    if (!node.fSuccessfullyConnected) {
        LogEvent(BCLog::NET, "peer_handshake_timeout",
                 "version handshake timeout peer={peer_id}")
            .Field(BCLog::LogField::PeerId, node.GetId());
        return true;
    }

    return false;
}

Sock::EventsPerSock CConnman::GenerateWaitSockets(Span<CNode *const> nodes) {
    Sock::EventsPerSock events_per_sock;

    for (const ListenSocket &hListenSocket : vhListenSocket) {
        events_per_sock.emplace(hListenSocket.sock, Sock::Events{Sock::RECV});
    }

    int inbound_candidates{0};
    for (CNode *pnode : nodes) {
        inbound_candidates += pnode->IsInboundConn();

        // Stop receiving if the peer is paused, or if we have enough inflight
        // data to process already in wich case we limit to outbounds and up to
        // 3 inbounds.
        // A P2P port connection that sent part of its first bytes is peeked
        // again on each loop (ClassifyP2PPortNode), not waited for.
        bool select_recv = !pnode->fPauseRecv && !pnode->m_p2p_port_partial &&
                           (!inflight_throttle || !pnode->IsInboundConn() ||
                            inbound_candidates <= 3);
        bool select_send =
            WITH_LOCK(pnode->cs_vSend, return !pnode->vSendMsg.empty());

        LOCK(pnode->m_sock_mutex);
        pnode->m_send_wait_on_recv = false;
        if (pnode->m_sock) {
            // Data the socket implementation buffered itself must make
            // progress even when CConnman has nothing queued.
            const Sock::Event pending{pnode->m_sock->PendingEvents()};
            // A user-space transport that blocked sending signals RECV once
            // it can take more: waiting for SEND could spin.
            if (select_send && pnode->m_sock->SendBlockedByTransport()) {
                select_send = false;
                pnode->m_send_wait_on_recv = true;
            }
            Sock::Event event =
                (select_send ? Sock::SEND : 0) |
                (select_recv || pnode->m_send_wait_on_recv ? Sock::RECV : 0) |
                pending;
            if (event != 0) {
                events_per_sock.emplace(pnode->m_sock, Sock::Events{event});
            }
        }
    }

    return events_per_sock;
}

void CConnman::SocketHandler() {
    Sock::EventsPerSock events_per_sock;

    {
        const NodesSnapshot snap{*this, /*shuffle=*/false};

        const auto timeout =
            std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS);

        // Check for the readiness of the already connected sockets and the
        // listening sockets in one call ("readiness" as in poll(2) or
        // select(2)). If none are ready, wait for a short while and return
        // empty sets.
        events_per_sock = GenerateWaitSockets(snap.Nodes());
        if (m_socket_wakeup) {
            events_per_sock.emplace(m_socket_wakeup->WaitSock(),
                                    Sock::Events{Sock::RECV});
        }

        // Sockets holding already decoded data are ready to receive whatever
        // the OS socket says, so don't block in that case.
        const auto has_buffered = [](const auto &entry) {
            return (entry.second.requested & Sock::RECV) &&
                   entry.first->HasBufferedRecv();
        };
        const bool buffered{std::any_of(events_per_sock.begin(),
                                        events_per_sock.end(), has_buffered)};
        if (events_per_sock.empty() ||
            !events_per_sock.begin()->first->WaitMany(
                buffered ? std::chrono::milliseconds{0} : timeout,
                events_per_sock)) {
            if (!buffered) {
                interruptNet.sleep_for(timeout);
            }
        }
        if (buffered) {
            for (auto &entry : events_per_sock) {
                if (has_buffered(entry)) {
                    entry.second.occurred |= Sock::RECV;
                }
            }
        }

        if (m_socket_wakeup) {
            // Before the next GenerateWaitSockets(): a wakeup for anything
            // after this point wakes the next wait.
            m_socket_wakeup->Drain();
        }

        // Service (send/receive) each of the already connected nodes.
        SocketHandlerConnected(snap.Nodes(), events_per_sock);
    }

    // Accept new connections from listening sockets.
    SocketHandlerListening(events_per_sock);
}

void CConnman::SocketHandlerConnected(
    const std::vector<CNode *> &nodes,
    const Sock::EventsPerSock &events_per_sock) {
    uint64_t nTotalInflightBytes{0};
    for (CNode *pnode : nodes) {
        if (interruptNet) {
            return;
        }

        // Always account for the node inflight bytes, even if the socket is
        // paused.
        nTotalInflightBytes += pnode->nInflightBytes;

        // A connection on a P2P port shared with WebSocket: see what it
        // speaks before reading from it.
        if (pnode->m_p2p_port_unclassified &&
            !ClassifyP2PPortNode(*pnode, events_per_sock)) {
            continue;
        }

        //
        // Receive
        //
        bool recvSet = false;
        bool sendSet = false;
        bool errorSet = false;
        bool send_unblocked = false;
        {
            LOCK(pnode->m_sock_mutex);
            if (!pnode->m_sock) {
                continue;
            }
            const auto it = events_per_sock.find(pnode->m_sock);
            if (it != events_per_sock.end()) {
                recvSet = it->second.occurred & Sock::RECV;
                sendSet = it->second.occurred & Sock::SEND;
                errorSet = it->second.occurred & Sock::ERR;
                // Flush data the socket implementation buffered itself.
                if (it->second.occurred & pnode->m_sock->PendingEvents()) {
                    if (!pnode->m_sock->FlushPending()) {
                        errorSet = true;
                    } else if (pnode->m_sock->HasBufferedRecv()) {
                        // e.g. a TLS read that was waiting to write
                        recvSet = true;
                    }
                }
            }
            // The transport that blocked sending can take more: send first
            // (below), receiving only what fPauseRecv allows.
            send_unblocked = pnode->m_send_wait_on_recv &&
                             it != events_per_sock.end() &&
                             (it->second.occurred & Sock::RECV) &&
                             !pnode->m_sock->SendBlockedByTransport();
            // The OS socket being readable was only requested on behalf of
            // FlushPending() or a blocked send: don't read past fPauseRecv.
            if (pnode->fPauseRecv && !errorSet) {
                recvSet = false;
            }
        }
        if (send_unblocked && !sendSet) {
            sendSet = WITH_LOCK(pnode->cs_vSend, return !pnode->vSendMsg.empty());
        }

        if (sendSet) {
            // Send data
            auto [bytes_sent, data_left] =
                WITH_LOCK(pnode->cs_vSend, return SocketSendData(*pnode));
            if (bytes_sent) {
                RecordBytesSent(bytes_sent);

                // If both receiving and (non-optimistic) sending were possible,
                // we first attempt sending. If that succeeds, but does not
                // fully drain the send queue, do not attempt to receive. This
                // avoids needlessly queueing data if the remote peer is slow at
                // receiving data, by means of TCP flow control. We only do this
                // when sending actually succeeded to make sure progress is
                // always made; otherwise a deadlock would be possible when both
                // sides have data to send, but neither is receiving.
                if (data_left) {
                    recvSet = false;
                }
            }
        }

        if (recvSet || errorSet) {
            // typical socket buffer is 8K-64K
            uint8_t pchBuf[0x10000];
            int32_t nBytes = 0;
            {
                LOCK(pnode->m_sock_mutex);
                if (!pnode->m_sock) {
                    continue;
                }
                nBytes =
                    pnode->m_sock->Recv(pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
            }
            if (nBytes > 0) {
                bool notify = false;
                if (!pnode->ReceiveMsgBytes(*config, {pchBuf, (size_t)nBytes},
                                            notify)) {
                    pnode->CloseSocketDisconnect();
                }
                RecordBytesRecv(nBytes);
                if (notify) {
                    pnode->MarkReceivedMsgsForProcessing();
                    WakeMessageHandler();
                }
            } else if (nBytes == 0) {
                // socket closed gracefully
                if (!pnode->fDisconnect) {
                    LogEvent(BCLog::NET, "peer_socket_closed",
                             "socket closed for peer={peer_id}")
                        .Field(BCLog::LogField::PeerId, pnode->GetId());
                }
                pnode->CloseSocketDisconnect();
            } else if (nBytes < 0) {
                // error
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE &&
                    nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                    if (!pnode->fDisconnect) {
                        LogDebug(BCLog::NET,
                                 "socket recv error for peer=%d: %s\n",
                                 pnode->GetId(), NetworkErrorString(nErr));
                    }
                    pnode->CloseSocketDisconnect();
                }
            }
        }

        if (InactivityCheck(*pnode)) {
            pnode->fDisconnect = true;
        }
    }

    const size_t max_inflight_bytes = DEFAULT_MAXINFLIGHTBUFFER * 1000;

    bool prev_inflight_throttle = inflight_throttle;
    inflight_throttle = nTotalInflightBytes > max_inflight_bytes;
    if (prev_inflight_throttle != inflight_throttle) {
        LogInfoEvent(
            BCLog::ALL, "network_inflight_throttling_changed",
            "Inflight throttling {inflight_state} ({inflight_bytes}/{inflight_limit_bytes})")
            .Field(BCLog::LogField::InflightState,
                   inflight_throttle ? "enabled" : "disabled")
            .Field(BCLog::LogField::InflightBytes, nTotalInflightBytes)
            .Field(BCLog::LogField::InflightLimitBytes, max_inflight_bytes);
    }
}

void CConnman::SocketHandlerListening(
    const Sock::EventsPerSock &events_per_sock) {
    for (const ListenSocket &listen_socket : vhListenSocket) {
        if (interruptNet) {
            return;
        }
        const auto it = events_per_sock.find(listen_socket.sock);
        if (it != events_per_sock.end() && it->second.occurred & Sock::RECV) {
            AcceptConnection(listen_socket);
        }
    }
}

void CConnman::AddNodeLocked(CNode *pnode) {
    pnode->m_socket_wakeup = m_socket_wakeup.get();
    m_nodes.push_back(pnode);
    // Wait on its socket now, not after the current wait times out.
    WakeSocketHandler();
}

void CConnman::ThreadSocketHandler() {
    while (!interruptNet) {
        DisconnectNodes();
        NotifyNumConnectionsChanged();
        SocketHandler();
    }
}

void CConnman::WakeMessageHandler() {
    {
        LOCK(mutexMsgProc);
        fMsgProcWake = true;
    }
    condMsgProc.notify_one();
}

void CConnman::ThreadDNSAddressSeed() {
    FastRandomContext rng;
    std::vector<std::string> seeds =
        GetRandomizedDNSSeeds(config->GetChainParams());
    // Number of seeds left before testing if we have enough connections
    int seeds_right_now = 0;
    int found = 0;

    if (gArgs.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED)) {
        // When -forcednsseed is provided, query all.
        seeds_right_now = seeds.size();
    } else if (addrman.size() == 0) {
        // If we have no known peers, query all.
        // This will occur on the first run, or if peers.dat has been
        // deleted.
        seeds_right_now = seeds.size();
    }

    // goal: only query DNS seed if address need is acute
    // * If we have a reasonable number of peers in addrman, spend
    //   some time trying them first. This improves user privacy by
    //   creating fewer identifying DNS requests, reduces trust by
    //   giving seeds less influence on the network topology, and
    //   reduces traffic to the seeds.
    // * When querying DNS seeds query a few at once, this ensures
    //   that we don't give DNS seeds the ability to eclipse nodes
    //   that query them.
    // * If we continue having problems, eventually query all the
    //   DNS seeds, and if that fails too, also try the fixed seeds.
    //   (done in ThreadOpenConnections)
    const std::chrono::seconds seeds_wait_time =
        (addrman.size() >= DNSSEEDS_DELAY_PEER_THRESHOLD
             ? DNSSEEDS_DELAY_MANY_PEERS
             : DNSSEEDS_DELAY_FEW_PEERS);

    for (const std::string &seed : seeds) {
        if (seeds_right_now == 0) {
            seeds_right_now += DNSSEEDS_TO_QUERY_AT_ONCE;

            if (addrman.size() > 0) {
                LogInfoEvent(
                    BCLog::ALL, "dns_seed_query_delayed",
                    "Waiting {wait_seconds} seconds before querying DNS seeds.")
                    .Field(BCLog::LogField::WaitSeconds,
                           seeds_wait_time.count());
                std::chrono::seconds to_wait = seeds_wait_time;
                while (to_wait.count() > 0) {
                    // if sleeping for the MANY_PEERS interval, wake up
                    // early to see if we have enough peers and can stop
                    // this thread entirely freeing up its resources
                    std::chrono::seconds w =
                        std::min(DNSSEEDS_DELAY_FEW_PEERS, to_wait);
                    if (!interruptNet.sleep_for(w)) {
                        return;
                    }
                    to_wait -= w;

                    int nRelevant = 0;
                    {
                        LOCK(m_nodes_mutex);
                        for (const CNode *pnode : m_nodes) {
                            if (pnode->fSuccessfullyConnected &&
                                pnode->IsFullOutboundConn()) {
                                ++nRelevant;
                            }
                        }
                    }
                    if (nRelevant >= 2) {
                        if (found > 0) {
                            LogInfoEvent(
                                BCLog::ALL, "dns_seed_addresses_found",
                                "{count} addresses found from DNS seeds")
                                .Field(BCLog::LogField::Count, found);
                            LogInfoEvent(
                                BCLog::ALL, "dns_seeding_finished_with_peers",
                                "P2P peers available. Finished DNS seeding.");
                        } else {
                            LogInfoEvent(
                                BCLog::ALL, "dns_seeding_skipped_with_peers",
                                "P2P peers available. Skipped DNS seeding.");
                        }
                        return;
                    }
                }
            }
        }

        if (interruptNet) {
            return;
        }

        // hold off on querying seeds if P2P network deactivated
        if (!fNetworkActive) {
            LogInfoEvent(
                BCLog::ALL, "dns_seeding_waiting_for_network",
                "Waiting for network to be reactivated before querying DNS seeds.");
            do {
                if (!interruptNet.sleep_for(std::chrono::seconds{1})) {
                    return;
                }
            } while (!fNetworkActive);
        }

        LogInfoEvent(BCLog::ALL, "dns_seed_loading",
                     "Loading addresses from DNS seed {name}")
            .Field(BCLog::LogField::Name, seed);
        if (HaveNameProxy()) {
            AddAddrFetch(seed);
        } else {
            std::vector<CAddress> vAdd;
            ServiceFlags requiredServiceBits =
                GetDesirableServiceFlags(NODE_NONE);
            std::string host = strprintf("x%x.%s", requiredServiceBits, seed);
            CNetAddr resolveSource;
            if (!resolveSource.SetInternal(host)) {
                continue;
            }

            // Limits number of IPs learned from a DNS seed
            unsigned int nMaxIPs = 256;
            const auto addresses{LookupHost(host, nMaxIPs, true)};
            if (!addresses.empty()) {
                for (const CNetAddr &ip : addresses) {
                    CAddress addr = CAddress(
                        CService(ip, config->GetChainParams().GetDefaultPort()),
                        requiredServiceBits);
                    // Use a random age between 3 and 7 days old.
                    addr.nTime = rng.rand_uniform_delay(
                        Now<NodeSeconds>() - 3 * 24h, -4 * 24h);
                    vAdd.push_back(addr);
                    found++;
                }
                addrman.Add(vAdd, resolveSource);
            } else {
                // We now avoid directly using results from DNS Seeds which do
                // not support service bit filtering, instead using them as a
                // addrfetch to get nodes with our desired service bits.
                AddAddrFetch(seed);
            }
        }
        --seeds_right_now;
    }
    LogInfoEvent(BCLog::ALL, "dns_seed_addresses_found",
                 "{count} addresses found from DNS seeds")
        .Field(BCLog::LogField::Count, found);
}

void CConnman::DumpAddresses() {
    int64_t nStart = GetTimeMillis();

    DumpPeerAddresses(config->GetChainParams(), ::gArgs, addrman);

    LogDebug(BCLog::NET, "Flushed %d addresses to peers.dat  %dms\n",
             addrman.size(), GetTimeMillis() - nStart);
}

void CConnman::ProcessAddrFetch() {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::string strDest;
    {
        LOCK(m_addr_fetches_mutex);
        if (m_addr_fetches.empty()) {
            return;
        }
        strDest = m_addr_fetches.front();
        m_addr_fetches.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant) {
        OpenNetworkConnection(addr, false, &grant, strDest.c_str(),
                              ConnectionType::ADDR_FETCH);
    }
}

bool CConnman::GetTryNewOutboundPeer() const {
    return m_try_another_outbound_peer;
}

void CConnman::SetTryNewOutboundPeer(bool flag) {
    m_try_another_outbound_peer = flag;
    LogDebug(BCLog::NET, "net: setting try another outbound peer=%s\n",
             flag ? "true" : "false");
}

// Return the number of peers we have over our outbound connection limit.
// Exclude peers that are marked for disconnect, or are going to be disconnected
// soon (eg ADDR_FETCH and FEELER).
// Also exclude peers that haven't finished initial connection handshake yet (so
// that we don't decide we're over our desired connection limit, and then evict
// some peer that has finished the handshake).
int CConnman::GetExtraFullOutboundCount() const {
    int full_outbound_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode *pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect &&
                pnode->IsFullOutboundConn()) {
                ++full_outbound_peers;
            }
        }
    }
    return std::max(full_outbound_peers - m_max_outbound_full_relay -
                        m_max_avalanche_outbound,
                    0);
}

int CConnman::GetExtraBlockRelayCount() const {
    int block_relay_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode *pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect &&
                pnode->IsBlockOnlyConn()) {
                ++block_relay_peers;
            }
        }
    }
    return std::max(block_relay_peers - m_max_outbound_block_relay, 0);
}

void CConnman::ThreadOpenConnections(
    const std::vector<std::string> connect,
    std::function<void(const CAddress &, ConnectionType)> mockOpenConnection) {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    FastRandomContext rng;
    // Connect to specific addresses
    if (!connect.empty()) {
        for (int64_t nLoop = 0;; nLoop++) {
            ProcessAddrFetch();
            for (const std::string &strAddr : connect) {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, nullptr, strAddr.c_str(),
                                      ConnectionType::MANUAL);
                for (int i = 0; i < 10 && i < nLoop; i++) {
                    if (!interruptNet.sleep_for(
                            std::chrono::milliseconds(500))) {
                        return;
                    }
                }
            }
            if (!interruptNet.sleep_for(std::chrono::milliseconds(500))) {
                return;
            }
        }
    }

    // Initiate network connections
    auto start = GetTime<std::chrono::microseconds>();

    // Minimum time before next feeler connection (in microseconds
    auto next_feeler = start + rng.rand_exp_duration(FEELER_INTERVAL);
    auto next_extra_block_relay =
        start + rng.rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
    const bool dnsseed = gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED);
    bool add_fixed_seeds = gArgs.GetBoolArg("-fixedseeds", DEFAULT_FIXEDSEEDS);
    const bool use_seednodes{gArgs.IsArgSet("-seednode")};

    if (!add_fixed_seeds) {
        LogInfoEvent(BCLog::ALL, "fixed_seeds_disabled",
                     "Fixed seeds are disabled");
    }

    while (!interruptNet) {
        ProcessAddrFetch();

        // No need to sleep the thread if we are mocking the network connection
        if (!mockOpenConnection &&
            !interruptNet.sleep_for(std::chrono::milliseconds(500))) {
            return;
        }

        CSemaphoreGrant grant(*semOutbound);
        if (interruptNet) {
            return;
        }

        if (add_fixed_seeds && addrman.size() == 0) {
            // When the node starts with an empty peers.dat, there are a few
            // other sources of peers before we fallback on to fixed seeds:
            // -dnsseed, -seednode, -addnode If none of those are available, we
            // fallback on to fixed seeds immediately, else we allow 60 seconds
            // for any of those sources to populate addrman.
            bool add_fixed_seeds_now = false;
            // It is cheapest to check if enough time has passed first.
            if (GetTime<std::chrono::seconds>() >
                start + std::chrono::minutes{1}) {
                add_fixed_seeds_now = true;
                LogInfoEvent(
                    BCLog::ALL, "fixed_seeds_added_after_wait",
                    "Adding fixed seeds as 60 seconds have passed and addrman is empty");
            } else if (!dnsseed && !use_seednodes) {
                // Lock the mutex after performing the above cheap checks.
                LOCK(m_added_nodes_mutex);
                if (m_added_nodes.empty()) {
                    add_fixed_seeds_now = true;
                    LogInfoEvent(
                        BCLog::ALL, "fixed_seeds_added_without_other_sources",
                        "Adding fixed seeds as -dnsseed=0 and neither -addnode nor -seednode are provided");
                }
            }

            if (add_fixed_seeds_now) {
                CNetAddr local;
                local.SetInternal("fixedseeds");
                addrman.Add(convertSeed6(config->GetChainParams().FixedSeeds()),
                            local);
                add_fixed_seeds = false;
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        int nOutboundFullRelay = 0;
        int nOutboundBlockRelay = 0;
        int nOutboundAvalanche = 0;
        std::set<std::vector<uint8_t>> setConnected;

        {
            // Connections being established count as made (see
            // PendingOutbound), so their slots, types and groups are not
            // dialed twice.
            LOCK(m_pending_mutex);
            for (const PendingOutbound &p : m_pending_outbound) {
                if (p.conn_type == ConnectionType::AVALANCHE_OUTBOUND) {
                    nOutboundAvalanche++;
                } else if (p.conn_type == ConnectionType::OUTBOUND_FULL_RELAY) {
                    nOutboundFullRelay++;
                } else if (p.conn_type == ConnectionType::BLOCK_RELAY) {
                    nOutboundBlockRelay++;
                }
                if (p.conn_type != ConnectionType::MANUAL && p.addr.IsValid()) {
                    setConnected.insert(p.addr.GetGroup(addrman.GetAsmap()));
                }
            }
        }
        {
            LOCK(m_nodes_mutex);
            for (const CNode *pnode : m_nodes) {
                if (pnode->IsAvalancheOutboundConnection()) {
                    nOutboundAvalanche++;
                } else if (pnode->IsFullOutboundConn()) {
                    nOutboundFullRelay++;
                } else if (pnode->IsBlockOnlyConn()) {
                    nOutboundBlockRelay++;
                }

                // Netgroups for inbound and manual peers are not excluded
                // because our goal here is to not use multiple of our
                // limited outbound slots on a single netgroup but inbound
                // and manual peers do not use our outbound slots. Inbound
                // peers also have the added issue that they could be attacker
                // controlled and could be used to prevent us from connecting
                // to particular hosts if we used them here.
                switch (pnode->m_conn_type) {
                    case ConnectionType::INBOUND:
                    case ConnectionType::MANUAL:
                        break;
                    case ConnectionType::AVALANCHE_OUTBOUND:
                    case ConnectionType::OUTBOUND_FULL_RELAY:
                    case ConnectionType::BLOCK_RELAY:
                    case ConnectionType::ADDR_FETCH:
                    case ConnectionType::FEELER:
                        setConnected.insert(
                            pnode->addr.GetGroup(addrman.GetAsmap()));
                } // no default case, so the compiler can warn about missing
                  // cases
            }
        }

        ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
        auto now = GetTime<std::chrono::microseconds>();
        bool anchor = false;
        bool fFeeler = false;

        // Determine what type of connection to open. Opening
        // BLOCK_RELAY connections to addresses from anchors.dat gets the
        // highest priority. Then we open AVALANCHE_OUTBOUND connection until we
        // hit our avalanche outbound peer limit, which is 0 if avalanche is not
        // enabled. We fallback after 50 retries to OUTBOUND_FULL_RELAY if the
        // peer is not avalanche capable until we meet our full-relay capacity.
        // Then we open BLOCK_RELAY connection until we hit our block-relay-only
        // peer limit.
        // GetTryNewOutboundPeer() gets set when a stale tip is detected, so we
        // try opening an additional OUTBOUND_FULL_RELAY connection. If none of
        // these conditions are met, check to see if it's time to try an extra
        // block-relay-only peer (to confirm our tip is current, see below) or
        // the next_feeler timer to decide if we should open a FEELER.

        if (!m_anchors.empty() &&
            (nOutboundBlockRelay < m_max_outbound_block_relay)) {
            conn_type = ConnectionType::BLOCK_RELAY;
            anchor = true;
        } else if (nOutboundAvalanche < m_max_avalanche_outbound) {
            conn_type = ConnectionType::AVALANCHE_OUTBOUND;
        } else if (nOutboundFullRelay < m_max_outbound_full_relay) {
            // OUTBOUND_FULL_RELAY
        } else if (nOutboundBlockRelay < m_max_outbound_block_relay) {
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (GetTryNewOutboundPeer()) {
            // OUTBOUND_FULL_RELAY
        } else if (now > next_extra_block_relay &&
                   m_start_extra_block_relay_peers) {
            // Periodically connect to a peer (using regular outbound selection
            // methodology from addrman) and stay connected long enough to sync
            // headers, but not much else.
            //
            // Then disconnect the peer, if we haven't learned anything new.
            //
            // The idea is to make eclipse attacks very difficult to pull off,
            // because every few minutes we're finding a new peer to learn
            // headers from.
            //
            // This is similar to the logic for trying extra outbound
            // (full-relay) peers, except:
            // - we do this all the time on an exponential timer, rather than
            //   just  when our tip is stale
            // - we potentially disconnect our next-youngest block-relay-only
            //   peer, if our newest block-relay-only peer delivers a block more
            //   recently.
            //   See the eviction logic in net_processing.cpp.
            //
            // Because we can promote these connections to block-relay-only
            // connections, they do not get their own ConnectionType enum
            // (similar to how we deal with extra outbound peers).
            next_extra_block_relay =
                now +
                rng.rand_exp_duration(EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (now > next_feeler) {
            next_feeler = now + rng.rand_exp_duration(FEELER_INTERVAL);
            conn_type = ConnectionType::FEELER;
            fFeeler = true;
        } else {
            // skip to next iteration of while loop
            continue;
        }

        addrman.ResolveCollisions();

        const auto current_time{NodeClock::now()};
        int nTries = 0;
        while (!interruptNet) {
            if (anchor && !m_anchors.empty()) {
                const CAddress addr = m_anchors.back();
                m_anchors.pop_back();
                if (!addr.IsValid() || IsLocal(addr) || !IsReachable(addr) ||
                    !HasAllDesirableServiceFlags(addr.nServices) ||
                    setConnected.count(addr.GetGroup(addrman.GetAsmap()))) {
                    continue;
                }
                addrConnect = addr;
                LogDebug(BCLog::NET,
                         "Trying to make an anchor connection to %s\n",
                         addrConnect.ToStringAddrPort());
                break;
            }
            // If we didn't find an appropriate destination after trying 100
            // addresses fetched from addrman, stop this loop, and let the outer
            // loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman
            // addresses.
            nTries++;
            if (nTries > 100) {
                break;
            }

            CAddress addr;
            NodeSeconds addr_last_try{0s};

            if (fFeeler) {
                // First, try to get a tried table collision address. This
                // returns an empty (invalid) address if there are no collisions
                // to try.
                std::tie(addr, addr_last_try) = addrman.SelectTriedCollision();

                if (!addr.IsValid()) {
                    // No tried table collisions. Select a new table address
                    // for our feeler.
                    std::tie(addr, addr_last_try) = addrman.Select(true);
                } else if (AlreadyConnectedToAddress(addr)) {
                    // If test-before-evict logic would have us connect to a
                    // peer that we're already connected to, just mark that
                    // address as Good(). We won't be able to initiate the
                    // connection anyway, so this avoids inadvertently evicting
                    // a currently-connected peer.
                    addrman.Good(addr);
                    // Select a new table address for our feeler instead.
                    std::tie(addr, addr_last_try) = addrman.Select(true);
                }
            } else {
                // Not a feeler
                std::tie(addr, addr_last_try) = addrman.Select();
            }

            // Require outbound connections, other than feelers and avalanche,
            // to be to distinct network groups
            if (!fFeeler && conn_type != ConnectionType::AVALANCHE_OUTBOUND &&
                setConnected.count(addr.GetGroup(addrman.GetAsmap()))) {
                break;
            }

            // if we selected an invalid or local address, restart
            if (!addr.IsValid() || IsLocal(addr)) {
                break;
            }

            if (!IsReachable(addr)) {
                continue;
            }

            // NET_WSS addresses of later versions are relayed, not dialed.
            if (addr.IsWSS() && !addr.IsDialableWSS()) {
                continue;
            }

            // only consider very recently tried nodes after 30 failed attempts
            if (current_time - addr_last_try < 10min && nTries < 30) {
                continue;
            }

            // for non-feelers, require all the services we'll want,
            // for feelers, only require they be a full node (only because most
            // SPV clients don't have a good address DB available)
            if (!fFeeler && !HasAllDesirableServiceFlags(addr.nServices)) {
                continue;
            }

            if (fFeeler && !MayHaveUsefulAddressDB(addr.nServices)) {
                continue;
            }

            // Do not connect to bad ports, unless 50 invalid addresses have
            // been selected already.
            if (nTries < 50 && (addr.IsIPv4() || addr.IsIPv6()) &&
                IsBadPort(addr.GetPort())) {
                continue;
            }

            // For avalanche peers, check they have the avalanche service bit
            // set.
            if (conn_type == ConnectionType::AVALANCHE_OUTBOUND &&
                !(addr.nServices & NODE_AVALANCHE)) {
                // If this peer is not suitable as an avalanche one and we tried
                // over 20 addresses already, see if we can fallback to a non
                // avalanche full outbound.
                if (nTries < 20 ||
                    nOutboundFullRelay >= m_max_outbound_full_relay ||
                    setConnected.count(addr.GetGroup(addrman.GetAsmap()))) {
                    // Fallback is not desirable or possible, try another one
                    continue;
                }

                // Fallback is possible, update the connection type accordingly
                conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
            }

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid()) {
            if (fFeeler) {
                // Add small amount of random noise before connection to avoid
                // synchronization.
                if (!interruptNet.sleep_for(
                        rng.rand_uniform_duration<CThreadInterrupt::Clock>(
                            FEELER_SLEEP_WINDOW))) {
                    return;
                }
                LogDebug(BCLog::NET, "Making feeler connection to %s\n",
                         addrConnect.ToStringAddrPort());
            }

            // This mock is for testing purpose only. It prevents the thread
            // from attempting the connection which is useful for testing.
            if (mockOpenConnection) {
                mockOpenConnection(addrConnect, conn_type);
            } else {
                OpenNetworkConnection(addrConnect,
                                      int(setConnected.size()) >=
                                          std::min(nMaxConnections - 1, 2),
                                      &grant, nullptr, conn_type);
            }
        }
    }
}

std::vector<CAddress> CConnman::GetCurrentBlockRelayOnlyConns() const {
    std::vector<CAddress> ret;
    LOCK(m_nodes_mutex);
    for (const CNode *pnode : m_nodes) {
        if (pnode->IsBlockOnlyConn()) {
            ret.push_back(pnode->addr);
        }
    }

    return ret;
}

std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo() const {
    std::vector<AddedNodeInfo> ret;

    std::list<std::string> lAddresses(0);
    {
        LOCK(m_added_nodes_mutex);
        ret.reserve(m_added_nodes.size());
        std::copy(m_added_nodes.cbegin(), m_added_nodes.cend(),
                  std::back_inserter(lAddresses));
    }

    // Build a map of all already connected addresses (by IP:port and by name)
    // to inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService>> mapConnectedByName;
    {
        LOCK(m_nodes_mutex);
        for (const CNode *pnode : m_nodes) {
            if (pnode->addr.IsValid()) {
                mapConnected[pnode->addr] = pnode->IsInboundConn();
            }
            std::string addrName{pnode->m_addr_name};
            if (!addrName.empty()) {
                mapConnectedByName[std::move(addrName)] =
                    std::make_pair(pnode->IsInboundConn(),
                                   static_cast<const CService &>(pnode->addr));
            }
        }
    }

    for (const std::string &strAddNode : lAddresses) {
        CService service(
            LookupNumeric(strAddNode, Params().GetDefaultPort(strAddNode)));
        AddedNodeInfo addedNode{strAddNode, CService(), false, false};
        if (service.IsValid()) {
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);
            if (it != mapConnected.end()) {
                addedNode.resolvedAddress = service;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second;
            }
        } else {
            // strAddNode is a name
            auto it = mapConnectedByName.find(strAddNode);
            if (it != mapConnectedByName.end()) {
                addedNode.resolvedAddress = it->second.second;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second.first;
            }
        }
        ret.emplace_back(std::move(addedNode));
    }

    return ret;
}

void CConnman::ThreadOpenAddedConnections() {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    while (true) {
        CSemaphoreGrant grant(*semAddnode);
        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo();
        bool tried = false;
        for (const AddedNodeInfo &info : vInfo) {
            if (!info.fConnected) {
                if (!grant.TryAcquire()) {
                    // If we've used up our semaphore and need a new one, let's
                    // not wait here since while we are waiting the
                    // addednodeinfo state might change.
                    break;
                }
                tried = true;
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, &grant,
                                      info.strAddedNode.c_str(),
                                      ConnectionType::MANUAL);
                if (!interruptNet.sleep_for(std::chrono::milliseconds(500))) {
                    return;
                }
            }
        }
        // Retry every 60 seconds if a connection was attempted, otherwise two
        // seconds.
        if (!interruptNet.sleep_for(std::chrono::seconds(tried ? 60 : 2))) {
            return;
        }
    }
}

// If successful, this moves the passed grant to the constructed node.
void CConnman::OpenNetworkConnection(const CAddress &addrConnect,
                                     bool fCountFailure,
                                     CSemaphoreGrant *grantOutbound,
                                     const char *pszDest,
                                     ConnectionType conn_type) {
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    assert(conn_type != ConnectionType::INBOUND);

    //
    // Initiate outbound network connection
    //
    if (interruptNet) {
        return;
    }
    if (!fNetworkActive) {
        return;
    }
    if (!pszDest) {
        bool banned_or_discouraged =
            m_banman && (m_banman->IsDiscouraged(addrConnect) ||
                         m_banman->IsBanned(addrConnect));
        if (IsLocal(addrConnect) || banned_or_discouraged ||
            AlreadyConnectedToAddress(addrConnect)) {
            return;
        }
    } else if (FindNode(std::string(pszDest))) {
        return;
    }

    const std::string dest{pszDest ? pszDest : ""};
    if (IsPendingOutbound(addrConnect, dest)) {
        return;
    }

    // Dial on a thread of its own: TCP, TLS and the WebSocket upgrade can
    // take a while, and must not stall the threads opening other
    // connections. The attempt keeps the outbound slot until it finishes.
    auto grant{std::make_unique<CSemaphoreGrant>()};
    if (grantOutbound) {
        grantOutbound->MoveTo(*grant);
    }
    auto done{std::make_shared<std::atomic<bool>>(false)};
    ReapDialThreads(/*all=*/false);
    LOCK(m_pending_mutex);
    const uint64_t id{m_next_pending_id++};
    m_pending_outbound.push_back({id, addrConnect, dest, conn_type});
    m_dial_threads.push_back(DialThread{
        std::thread{[this, id, addrConnect, dest, fCountFailure, conn_type,
                     grant = std::move(grant), done]() mutable {
            util::ThreadRename("p2pdial");
            CNode *pnode{ConnectNode(addrConnect,
                                     dest.empty() ? nullptr : dest.c_str(),
                                     fCountFailure, conn_type)};
            if (pnode && !interruptNet) {
                grant->MoveTo(pnode->grantOutbound);
                for (auto interface : m_msgproc) {
                    interface->InitializeNode(*config, *pnode, nLocalServices);
                }
                LOCK(m_nodes_mutex);
                AddNodeLocked(pnode);
            } else if (pnode) {
                // Shutting down: never handed to the message processors, so
                // there is nothing to finalize.
                pnode->CloseSocketDisconnect();
                delete pnode;
            }
            // Only now that the node is in m_nodes (or failed) does the
            // attempt stop counting as one, so nothing dials it twice.
            {
                LOCK(m_pending_mutex);
                m_pending_outbound.remove_if(
                    [id](const PendingOutbound &p) { return p.id == id; });
            }
            *done = true;
        }},
        done});
}

bool CConnman::IsPendingOutbound(const CAddress &addr,
                                 const std::string &name) const {
    LOCK(m_pending_mutex);
    return std::any_of(m_pending_outbound.begin(), m_pending_outbound.end(),
                       [&](const PendingOutbound &p) {
                           return name.empty()
                                      ? p.addr.IsValid() &&
                                            static_cast<CService>(p.addr) ==
                                                static_cast<CService>(addr)
                                      : p.name == name;
                       });
}

void CConnman::ReapDialThreads(bool all) {
    std::list<DialThread> finished;
    {
        LOCK(m_pending_mutex);
        for (auto it = m_dial_threads.begin(); it != m_dial_threads.end();) {
            if (all || *it->done) {
                finished.splice(finished.end(), m_dial_threads, it++);
            } else {
                ++it;
            }
        }
    }
    for (auto &dial : finished) {
        if (dial.thread.joinable()) {
            dial.thread.join();
        }
    }
}

Mutex NetEventsInterface::g_msgproc_mutex;

void CConnman::ThreadMessageHandler() {
    LOCK(NetEventsInterface::g_msgproc_mutex);

    while (!flagInterruptMsgProc) {
        bool fMoreWork = false;

        {
            // Randomize the order in which we process messages from/to our
            // peers. This prevents attacks in which an attacker exploits having
            // multiple consecutive connections in the vNodes list.
            const NodesSnapshot snap{*this, /*shuffle=*/true};

            for (auto interface : m_msgproc) {
                interface->PrepareMessageTurn(snap.Nodes(), flagInterruptMsgProc);
            }

            for (CNode *pnode : snap.Nodes()) {
                if (pnode->fDisconnect) {
                    continue;
                }

                bool fMoreNodeWork = false;
                // Receive messages
                for (auto interface : m_msgproc) {
                    fMoreNodeWork |= interface->ProcessMessages(
                        *config, pnode, flagInterruptMsgProc);
                }
                fMoreWork |= (fMoreNodeWork && !pnode->fPauseSend);
                if (flagInterruptMsgProc) {
                    return;
                }

                // Send messages
                for (auto interface : m_msgproc) {
                    interface->SendMessages(*config, pnode);
                }

                if (flagInterruptMsgProc) {
                    return;
                }
            }
        }

        WAIT_LOCK(mutexMsgProc, lock);
        if (!fMoreWork) {
            condMsgProc.wait_until(lock,
                                   std::chrono::steady_clock::now() +
                                       std::chrono::milliseconds(100),
                                   [this]() EXCLUSIVE_LOCKS_REQUIRED(
                                       mutexMsgProc) { return fMsgProcWake; });
        }
        fMsgProcWake = false;
    }
}

void CConnman::ThreadI2PAcceptIncoming() {
    static constexpr auto err_wait_begin = 1s;
    static constexpr auto err_wait_cap = 5min;
    auto err_wait = err_wait_begin;

    bool advertising_listen_addr = false;
    i2p::Connection conn;

    while (!interruptNet) {
        if (!m_i2p_sam_session->Listen(conn)) {
            if (advertising_listen_addr && conn.me.IsValid()) {
                RemoveLocal(conn.me);
                advertising_listen_addr = false;
            }

            interruptNet.sleep_for(err_wait);
            if (err_wait < err_wait_cap) {
                err_wait *= 2;
            }

            continue;
        }

        if (!advertising_listen_addr) {
            AddLocal(conn.me, LOCAL_MANUAL);
            advertising_listen_addr = true;
        }

        if (!m_i2p_sam_session->Accept(conn)) {
            continue;
        }

        CreateNodeFromAcceptedSocket(
            std::move(conn.sock), NetPermissionFlags::None,
            CAddress{conn.me, NODE_NONE}, CAddress{conn.peer, NODE_NONE});
    }
}

bool CConnman::BindListenPort(const CService &addrBind, bilingual_str &strError,
                              NetPermissionFlags permissions) {
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr *)&sockaddr, &len)) {
        strError =
            strprintf(Untranslated("Bind address family for %s not supported"),
                      addrBind.ToStringAddrPort());
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n",
                      strError.original);
        return false;
    }

    std::unique_ptr<Sock> sock =
        CreateSock(addrBind.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP);
    if (!sock) {
        strError =
            strprintf(Untranslated("Couldn't open socket for incoming "
                                   "connections (socket returned error %s)"),
                      NetworkErrorString(WSAGetLastError()));
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n",
                      strError.original);
        return false;
    }

    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    if (sock->SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&nOne,
                         sizeof(int)) == SOCKET_ERROR) {
        strError = strprintf(
            Untranslated(
                "Error setting SO_REUSEADDR on socket: %s, continuing anyway"),
            NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError.original);
    }

    // Some systems don't have IPV6_V6ONLY but are always v6only; others do have
    // the option and enable it by default or not. Try to enable it, if
    // possible.
    if (addrBind.IsIPv6()) {
#ifdef IPV6_V6ONLY
        if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_arg_type)&nOne,
                             sizeof(int)) == SOCKET_ERROR) {
            strError = strprintf(Untranslated("Error setting IPV6_V6ONLY on "
                                              "socket: %s, continuing anyway"),
                                 NetworkErrorString(WSAGetLastError()));
            LogPrintf("%s\n", strError.original);
        }
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_PROTECTION_LEVEL,
                             (sockopt_arg_type)&nProtLevel,
                             sizeof(int)) == SOCKET_ERROR) {
            strError =
                strprintf(Untranslated("Error setting IPV6_PROTECTION_LEVEL on "
                                       "socket: %s, continuing anyway"),
                          NetworkErrorString(WSAGetLastError()));
            LogPrintf("%s\n", strError.original);
        }
#endif
    }

    if (sock->Bind(reinterpret_cast<struct sockaddr *>(&sockaddr), len) ==
        SOCKET_ERROR) {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE) {
            strError = strprintf(_("Unable to bind to %s on this computer. %s "
                                   "is probably already running."),
                                 addrBind.ToStringAddrPort(), PACKAGE_NAME);
        } else {
            strError = strprintf(_("Unable to bind to %s on this computer "
                                   "(bind returned error %s)"),
                                 addrBind.ToStringAddrPort(),
                                 NetworkErrorString(nErr));
        }

        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n",
                      strError.original);
        return false;
    }
    LogInfoEvent(BCLog::ALL, "network_listener_bound", "Bound to {addr}")
        .Field(BCLog::LogField::Addr, static_cast<const CService &>(addrBind));

    // Listen for incoming connections
    if (sock->Listen(SOMAXCONN) == SOCKET_ERROR) {
        strError = strprintf(_("Listening for incoming connections "
                               "failed (listen returned error %s)"),
                             NetworkErrorString(WSAGetLastError()));
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n",
                      strError.original);
        return false;
    }

    vhListenSocket.emplace_back(std::move(sock), permissions, addrBind);
    return true;
}

void Discover() {
    if (!fDiscover) {
        return;
    }

    for (const CNetAddr &addr : GetLocalAddresses()) {
        if (AddLocal(addr, LOCAL_IF)) {
            LogInfoEvent(BCLog::ALL, "local_interface_discovered",
                         "{source_function}: {addr}")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Addr, addr.ToStringAddr());
        }
    }
}

void CConnman::SetNetworkActive(bool active) {
    LogInfoEvent(BCLog::ALL, "network_active_set",
                 "{source_function}: {network_active}")
        .Field(BCLog::LogField::SourceFunction, __func__)
        .Field(BCLog::LogField::NetworkActive, active);

    if (fNetworkActive == active) {
        return;
    }

    fNetworkActive = active;

    if (m_client_interface) {
        m_client_interface->NotifyNetworkActiveChanged(fNetworkActive);
    }
}

CConnman::CConnman(const Config &configIn, uint64_t nSeed0In, uint64_t nSeed1In,
                   AddrMan &addrmanIn, bool network_active)
    : config(&configIn), addrman(addrmanIn), nSeed0(nSeed0In),
      nSeed1(nSeed1In) {
    SetTryNewOutboundPeer(false);

    Options connOptions;
    Init(connOptions);
    SetNetworkActive(network_active);
}

NodeId CConnman::GetNewNodeId() {
    return nLastNodeId.fetch_add(1);
}

bool CConnman::Bind(const CService &addr, unsigned int flags,
                    NetPermissionFlags permissions) {
    if (!(flags & BF_EXPLICIT) && !IsReachable(addr)) {
        return false;
    }
    bilingual_str strError;
    if (!BindListenPort(addr, strError, permissions)) {
        if ((flags & BF_REPORT_ERROR) && m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(
                strError, "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    if (addr.IsRoutable() && fDiscover && !(flags & BF_DONT_ADVERTISE) &&
        !NetPermissions::HasFlag(permissions, NetPermissionFlags::NoBan)) {
        AddLocal(addr, LOCAL_BIND);
    }

    return true;
}

bool CConnman::InitBinds(const Options &options) {
    for (const auto &addrBind : options.vBinds) {
        if (!Bind(addrBind, BF_EXPLICIT | BF_REPORT_ERROR,
                  NetPermissionFlags::None)) {
            return false;
        }
    }
    for (const auto &addrBind : options.vWhiteBinds) {
        if (!Bind(addrBind.m_service, BF_EXPLICIT | BF_REPORT_ERROR,
                  addrBind.m_flags)) {
            return false;
        }
    }
    for (const auto &addr_bind : options.onion_binds) {
        if (!Bind(addr_bind, BF_EXPLICIT | BF_REPORT_ERROR | BF_DONT_ADVERTISE,
                  NetPermissionFlags::None)) {
            return false;
        }
    }
    if (options.bind_on_any) {
        // Don't consider errors to bind on IPv6 "::" fatal because the host OS
        // may not have IPv6 support and the user did not explicitly ask us to
        // bind on that.
        const CService ipv6_any{in6_addr(IN6ADDR_ANY_INIT),
                                GetListenPort()}; // ::
        Bind(ipv6_any, BF_NONE, NetPermissionFlags::None);

        struct in_addr inaddr_any;
        inaddr_any.s_addr = htonl(INADDR_ANY);
        const CService ipv4_any{inaddr_any, GetListenPort()}; // 0.0.0.0
        if (!Bind(ipv4_any, BF_REPORT_ERROR, NetPermissionFlags::None)) {
            return false;
        }
    }
    return true;
}

bool CConnman::Start(CScheduler &scheduler, const Options &connOptions) {
    Init(connOptions);

    // The P2P port listens for plain P2P and, with a WebSocket handler, for
    // WebSocket. With neither there is no listening socket at all.
    if (fListen && (g_listen_plain_p2p || m_p2p_port_websocket) &&
        !InitBinds(connOptions)) {
        if (m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(
                _("Failed to listen on any port. Use -listen=0 if you want "
                  "this."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    Proxy i2p_sam;
    if (GetProxy(NET_I2P, i2p_sam) && connOptions.m_i2p_accept_incoming) {
        m_i2p_sam_session = std::make_unique<i2p::sam::Session>(
            gArgs.GetDataDirNet() / "i2p_private_key", i2p_sam, &interruptNet);
    }

    for (const auto &strDest : connOptions.vSeedNodes) {
        AddAddrFetch(strDest);
    }

    if (m_use_addrman_outgoing) {
        // Load addresses from anchors.dat
        m_anchors =
            ReadAnchors(config->GetChainParams(),
                        gArgs.GetDataDirNet() / ANCHORS_DATABASE_FILENAME);
        if (m_anchors.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
            m_anchors.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
        }
        LogInfoEvent(
            BCLog::ALL, "block_relay_connection_anchors_ready",
            "{count} block-relay-only anchors will be tried for connections.")
            .Field(BCLog::LogField::Count, m_anchors.size());
    }

    if (m_client_interface) {
        m_client_interface->InitMessage(
            _("Starting network threads...").translated);
    }

    fAddressesInitialized = true;

    if (semOutbound == nullptr) {
        // initialize semaphore
        semOutbound = std::make_unique<CSemaphore>(
            std::min(m_max_outbound, nMaxConnections));
    }
    if (semAddnode == nullptr) {
        // initialize semaphore
        semAddnode = std::make_unique<CSemaphore>(nMaxAddnode);
    }

    //
    // Start threads
    //
    assert(m_msgproc.size() > 0);
    InterruptSocks5(false);
    if (!m_socket_wakeup) {
        m_socket_wakeup = SockWakeup::Make();
        if (!m_socket_wakeup) {
            LogInfoEvent(
                BCLog::ALL, "network_wakeup_socket_unavailable",
                "Warning: cannot create the network thread's wakeup socket; new connections may wait up to {wait_milliseconds} ms")
                .Field(BCLog::LogField::WaitMilliseconds,
                       SELECT_TIMEOUT_MILLISECONDS);
        }
    }
    interruptNet.reset();
    flagInterruptMsgProc = false;

    {
        LOCK(mutexMsgProc);
        fMsgProcWake = false;
    }

    // Send and receive from sockets, accept connections
    threadSocketHandler = std::thread(&util::TraceThread, "net",
                                      [this] { ThreadSocketHandler(); });

    if (!gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED)) {
        LogInfoEvent(BCLog::ALL, "dns_seeding_disabled",
                     "DNS seeding disabled");
    } else {
        threadDNSAddressSeed = std::thread(&util::TraceThread, "dnsseed",
                                           [this] { ThreadDNSAddressSeed(); });
    }

    // Initiate manual connections
    threadOpenAddedConnections = std::thread(
        &util::TraceThread, "addcon", [this] { ThreadOpenAddedConnections(); });

    if (connOptions.m_use_addrman_outgoing &&
        !connOptions.m_specified_outgoing.empty()) {
        if (m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(
                _("Cannot provide specific connections and have addrman find "
                  "outgoing connections at the same."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }
    if (connOptions.m_use_addrman_outgoing ||
        !connOptions.m_specified_outgoing.empty()) {
        threadOpenConnections =
            std::thread(&util::TraceThread, "opencon",
                        [this, connect = connOptions.m_specified_outgoing] {
                            ThreadOpenConnections(connect, nullptr);
                        });
    }

    // Process messages
    threadMessageHandler = std::thread(&util::TraceThread, "msghand",
                                       [this] { ThreadMessageHandler(); });

    if (m_i2p_sam_session) {
        threadI2PAcceptIncoming =
            std::thread(&util::TraceThread, "i2paccept",
                        [this] { ThreadI2PAcceptIncoming(); });
    }

    // Dump network addresses
    scheduler.scheduleEvery(
        [this]() {
            this->DumpAddresses();
            return true;
        },
        DUMP_PEERS_INTERVAL);

    return true;
}

class CNetCleanup {
public:
    CNetCleanup() = default;

    ~CNetCleanup() {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
};
static CNetCleanup instance_of_cnetcleanup;

void CConnman::Interrupt() {
    {
        LOCK(mutexMsgProc);
        flagInterruptMsgProc = true;
    }
    condMsgProc.notify_all();

    interruptNet();
    InterruptSocks5(true);

    if (semOutbound) {
        for (int i = 0; i < m_max_outbound; i++) {
            semOutbound->post();
        }
    }

    if (semAddnode) {
        for (int i = 0; i < nMaxAddnode; i++) {
            semAddnode->post();
        }
    }
}

void CConnman::StopThreads() {
    // Dials in progress end on interruptNet; their nodes are added before
    // StopNodes() cleans up, or deleted.
    ReapDialThreads(/*all=*/true);
    if (threadI2PAcceptIncoming.joinable()) {
        threadI2PAcceptIncoming.join();
    }
    if (threadMessageHandler.joinable()) {
        threadMessageHandler.join();
    }
    if (threadOpenConnections.joinable()) {
        threadOpenConnections.join();
    }
    if (threadOpenAddedConnections.joinable()) {
        threadOpenAddedConnections.join();
    }
    if (threadDNSAddressSeed.joinable()) {
        threadDNSAddressSeed.join();
    }
    if (threadSocketHandler.joinable()) {
        threadSocketHandler.join();
    }
}

void CConnman::StopNodes() {
    if (fAddressesInitialized) {
        DumpAddresses();
        fAddressesInitialized = false;

        if (m_use_addrman_outgoing) {
            // Anchor connections are only dumped during clean shutdown.
            std::vector<CAddress> anchors_to_dump =
                GetCurrentBlockRelayOnlyConns();
            if (anchors_to_dump.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
                anchors_to_dump.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
            }
            DumpAnchors(config->GetChainParams(),
                        gArgs.GetDataDirNet() / ANCHORS_DATABASE_FILENAME,
                        anchors_to_dump);
        }
    }

    // Delete peer connections.
    std::vector<CNode *> nodes;
    WITH_LOCK(m_nodes_mutex, nodes.swap(m_nodes));
    for (CNode *pnode : nodes) {
        pnode->CloseSocketDisconnect();
        DeleteNode(pnode);
    }

    for (CNode *pnode : m_nodes_disconnected) {
        DeleteNode(pnode);
    }
    m_nodes_disconnected.clear();
    vhListenSocket.clear();
    semOutbound.reset();
    semAddnode.reset();
}

void CConnman::DeleteNode(CNode *pnode) {
    assert(pnode);
    for (auto interface : m_msgproc) {
        interface->FinalizeNode(*config, *pnode);
    }
    delete pnode;
}

CConnman::~CConnman() {
    Interrupt();
    Stop();
}

std::vector<CAddress>
CConnman::GetAddresses(size_t max_addresses, size_t max_pct,
                       std::optional<Network> network) const {
    std::vector<CAddress> addresses =
        addrman.GetAddr(max_addresses, max_pct, network);
    if (m_banman) {
        addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                                       [this](const CAddress &addr) {
                                           return m_banman->IsDiscouraged(
                                                      addr) ||
                                                  m_banman->IsBanned(addr);
                                       }),
                        addresses.end());
    }
    return addresses;
}

std::vector<CAddress>
CConnman::GetAddresses(CNode &requestor, size_t max_addresses, size_t max_pct) {
    auto local_socket_bytes = requestor.addrBind.GetAddrBytes();
    uint64_t cache_id = GetDeterministicRandomizer(RANDOMIZER_ID_ADDRCACHE)
                            .Write(requestor.addr.GetNetwork())
                            .Write(local_socket_bytes)
                            .Finalize();
    const auto current_time = GetTime<std::chrono::microseconds>();
    auto r = m_addr_response_caches.emplace(cache_id, CachedAddrResponse{});
    CachedAddrResponse &cache_entry = r.first->second;
    // New CachedAddrResponse have expiration 0.
    if (cache_entry.m_cache_entry_expiration < current_time) {
        cache_entry.m_addrs_response_cache =
            GetAddresses(max_addresses, max_pct, /* network */ std::nullopt);
        // Choosing a proper cache lifetime is a trade-off between the privacy
        // leak minimization and the usefulness of ADDR responses to honest
        // users.
        //
        // Longer cache lifetime makes it more difficult for an attacker to
        // scrape enough AddrMan data to maliciously infer something useful. By
        // the time an attacker scraped enough AddrMan records, most of the
        // records should be old enough to not leak topology info by e.g.
        // analyzing real-time changes in timestamps.
        //
        // It takes only several hundred requests to scrape everything from an
        // AddrMan containing 100,000 nodes, so ~24 hours of cache lifetime
        // indeed makes the data less inferable by the time most of it could be
        // scraped (considering that timestamps are updated via ADDR
        // self-announcements and when nodes communicate). We also should be
        // robust to those attacks which may not require scraping *full*
        // victim's AddrMan (because even several timestamps of the same handful
        // of nodes may leak privacy).
        //
        // On the other hand, longer cache lifetime makes ADDR responses
        // outdated and less useful for an honest requestor, e.g. if most nodes
        // in the ADDR response are no longer active.
        //
        // However, the churn in the network is known to be rather low. Since we
        // consider nodes to be "terrible" (see IsTerrible()) if the timestamps
        // are older than 30 days, max. 24 hours of "penalty" due to cache
        // shouldn't make any meaningful difference in terms of the freshness of
        // the response.
        cache_entry.m_cache_entry_expiration =
            current_time + 21h +
            FastRandomContext().randrange<std::chrono::microseconds>(6h);
    }
    return cache_entry.m_addrs_response_cache;
}

bool CConnman::AddNode(const std::string &strNode) {
    LOCK(m_added_nodes_mutex);
    for (const std::string &it : m_added_nodes) {
        if (strNode == it) {
            return false;
        }
    }

    m_added_nodes.push_back(strNode);
    return true;
}

bool CConnman::RemoveAddedNode(const std::string &strNode) {
    LOCK(m_added_nodes_mutex);
    for (std::vector<std::string>::iterator it = m_added_nodes.begin();
         it != m_added_nodes.end(); ++it) {
        if (strNode == *it) {
            m_added_nodes.erase(it);
            return true;
        }
    }
    return false;
}

size_t CConnman::GetNodeCount(ConnectionDirection flags) const {
    LOCK(m_nodes_mutex);
    // Shortcut if we want total
    if (flags == ConnectionDirection::Both) {
        return m_nodes.size();
    }

    int nNum = 0;
    for (const auto &pnode : m_nodes) {
        if (flags & (pnode->IsInboundConn() ? ConnectionDirection::In
                                            : ConnectionDirection::Out)) {
            nNum++;
        }
    }

    return nNum;
}

void CConnman::GetNodeStats(std::vector<CNodeStats> &vstats) const {
    vstats.clear();
    LOCK(m_nodes_mutex);
    vstats.reserve(m_nodes.size());
    for (CNode *pnode : m_nodes) {
        vstats.emplace_back();
        pnode->copyStats(vstats.back());
        vstats.back().m_mapped_as = pnode->addr.GetMappedAS(addrman.GetAsmap());
    }
}

bool CConnman::GetNodeStats(NodeId id, CNodeStats &stats) const {
    LOCK(m_nodes_mutex);

    for (auto &&pnode : m_nodes) {
        if (pnode->GetId() == id) {
            pnode->copyStats(stats);
            stats.m_mapped_as = pnode->addr.GetMappedAS(addrman.GetAsmap());
            return true;
        }
    }

    return false;
}

bool CConnman::DisconnectNode(const std::string &strNode) {
    LOCK(m_nodes_mutex);
    if (CNode *pnode = FindNode(strNode)) {
        LogDebug(BCLog::NET,
                 "disconnect by address%s matched peer=%d; disconnecting\n",
                 (fLogIPs ? strprintf("=%s", strNode) : ""), pnode->GetId());
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CConnman::DisconnectNode(const CSubNet &subnet) {
    bool disconnected = false;
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (subnet.Match(pnode->addr)) {
            LogDebug(BCLog::NET,
                     "disconnect by subnet%s matched peer=%d; disconnecting\n",
                     (fLogIPs ? strprintf("=%s", subnet.ToString()) : ""),
                     pnode->GetId());
            pnode->fDisconnect = true;
            disconnected = true;
        }
    }
    return disconnected;
}

bool CConnman::DisconnectNode(const CNetAddr &addr) {
    return DisconnectNode(CSubNet(addr));
}

bool CConnman::DisconnectNode(NodeId id) {
    LOCK(m_nodes_mutex);
    for (CNode *pnode : m_nodes) {
        if (id == pnode->GetId()) {
            LogEvent(BCLog::NET, "peer_disconnect_requested",
                     "disconnect by id peer={peer_id}; disconnecting")
                .Field(BCLog::LogField::PeerId, pnode->GetId());
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CConnman::RecordBytesRecv(uint64_t bytes) {
    nTotalBytesRecv += bytes;
}

void CConnman::RecordBytesSent(uint64_t bytes) {
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;

    const auto now = GetTime<std::chrono::seconds>();
    if (nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME < now) {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    // TODO, exclude peers with download permission
    nMaxOutboundTotalBytesSentInCycle += bytes;
}

uint64_t CConnman::GetMaxOutboundTarget() const {
    LOCK(cs_totalBytesSent);
    return nMaxOutboundLimit;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeframe() const {
    return MAX_UPLOAD_TIMEFRAME;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeLeftInCycle() const {
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0) {
        return 0s;
    }

    if (nMaxOutboundCycleStartTime.count() == 0) {
        return MAX_UPLOAD_TIMEFRAME;
    }

    const std::chrono::seconds cycleEndTime =
        nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME;
    const auto now = GetTime<std::chrono::seconds>();
    return (cycleEndTime < now) ? 0s : cycleEndTime - now;
}

bool CConnman::OutboundTargetReached(bool historicalBlockServingLimit) const {
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0) {
        return false;
    }

    if (historicalBlockServingLimit) {
        // keep a large enough buffer to at least relay each block once.
        const std::chrono::seconds timeLeftInCycle =
            GetMaxOutboundTimeLeftInCycle();
        const uint64_t buffer =
            timeLeftInCycle / std::chrono::minutes{10} * ONE_MEGABYTE;
        if (buffer >= nMaxOutboundLimit ||
            nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer) {
            return true;
        }
    } else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) {
        return true;
    }

    return false;
}

uint64_t CConnman::GetOutboundTargetBytesLeft() const {
    LOCK(cs_totalBytesSent);
    if (nMaxOutboundLimit == 0) {
        return 0;
    }

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
               ? 0
               : nMaxOutboundLimit - nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CConnman::GetTotalBytesRecv() const {
    return nTotalBytesRecv;
}

uint64_t CConnman::GetTotalBytesSent() const {
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}

ServiceFlags CConnman::GetLocalServices() const {
    return nLocalServices;
}

void CNode::invsPolled(uint32_t count) {
    invCounters += count;
}

void CNode::invsVoted(uint32_t count) {
    invCounters += uint64_t(count) << 32;
}

void CNode::updateAvailabilityScore(double decayFactor) {
    if (!m_avalanche_enabled) {
        return;
    }

    uint64_t windowInvCounters = invCounters.exchange(0);
    double previousScore = availabilityScore;

    int64_t polls = windowInvCounters & std::numeric_limits<uint32_t>::max();
    int64_t votes = windowInvCounters >> 32;

    availabilityScore =
        decayFactor * (2 * votes - polls) + (1. - decayFactor) * previousScore;
}

double CNode::getAvailabilityScore() const {
    // The score is set atomically so there is no need to lock the statistics
    // when reading.
    return availabilityScore;
}

CNode::CNode(NodeId idIn, std::shared_ptr<Sock> sock, const CAddress &addrIn,
             uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn,
             uint64_t nLocalExtraEntropyIn, const CAddress &addrBindIn,
             const std::string &addrNameIn, ConnectionType conn_type_in,
             bool inbound_onion, CNodeOptions &&node_opts)
    : m_deserializer{std::make_unique<V1TransportDeserializer>(
          V1TransportDeserializer(GetConfig(), idIn))},
      m_serializer{
          std::make_unique<V1TransportSerializer>(V1TransportSerializer())},
      m_permission_flags{node_opts.permission_flags}, m_sock{sock},
      m_connected(GetTime<std::chrono::seconds>()), addr{addrIn},
      addrBind{addrBindIn},
      m_addr_name{addrNameIn.empty() ? addr.ToStringAddrPort() : addrNameIn},
      m_inbound_onion{inbound_onion}, m_prefer_evict{node_opts.prefer_evict},
      nKeyedNetGroup{nKeyedNetGroupIn}, m_conn_type{conn_type_in},
      m_websocket_info{std::move(node_opts.websocket_info)},
      m_quic_info{std::move(node_opts.quic_info)}, id{idIn},
      nLocalHostNonce{nLocalHostNonceIn},
      nLocalExtraEntropy{nLocalExtraEntropyIn},
      m_recv_flood_size{node_opts.recv_flood_size},
      m_i2p_sam_session{std::move(node_opts.i2p_sam_session)} {
    if (inbound_onion) {
        assert(conn_type_in == ConnectionType::INBOUND);
    }

    for (const std::string &msg : getAllNetMessageTypes()) {
        mapRecvBytesPerMsgType[msg] = 0;
    }
    mapRecvBytesPerMsgType[NET_MESSAGE_TYPE_OTHER] = 0;

    if (auto *metrics{node::GetNodeMetrics()}) {
        static_assert(NET_MAX == 8, "update node::metric_labels::Networks()");
        const bool inbound{IsInboundConn()};
        const bool websocket{m_websocket_info != nullptr};
        const size_t peer{metrics->PeerSeries(
            inbound, MetricTransport(), size_t(ConnectedThroughNetwork()))};
        metrics->peers.Add(1, peer);
        metrics->p2p_connections.Add(
            metrics->DirectionTransportSeries(inbound, MetricTransport()));
        m_metrics_connected_at = std::chrono::steady_clock::now();
        std::optional<size_t> ws;
        if (websocket) {
            const std::array<size_t, 2> idx{
                std::min<size_t>(size_t(m_websocket_info->compression), 3),
                m_websocket_info->tls ? 1U : 0U};
            ws = metrics->websocket_peers.SeriesIndex(idx);
            metrics->websocket_peers.Add(1, *ws);
        }
        m_metrics_series.emplace(peer, ws);
    }

    if (fLogIPs) {
        LogEvent(BCLog::NET, "peer_connection_added",
                 "Added connection to {addr} peer={peer_id}")
            .Field(BCLog::LogField::Addr, m_addr_name)
            .Field(BCLog::LogField::PeerId, id);
    } else {
        LogEvent(BCLog::NET, "peer_connection_added",
                 "Added connection peer={peer_id}")
            .Field(BCLog::LogField::PeerId, id);
    }
}

CNode::~CNode() {
    if (m_metrics_series) {
        // Counted at construction, so the metrics exist (never freed).
        auto &metrics{*Assert(node::GetNodeMetrics())};
        metrics.peers.Add(-1, m_metrics_series->first);
        if (m_metrics_series->second) {
            metrics.websocket_peers.Add(-1, *m_metrics_series->second);
        }
    }
}

void CNode::MarkReceivedMsgsForProcessing() {
    AssertLockNotHeld(m_msg_process_queue_mutex);

    size_t nSizeAdded = 0;
    for (const auto &msg : vRecvMsg) {
        // vRecvMsg contains only completed CNetMessage
        // the single possible partially deserialized message are held by
        // TransportDeserializer
        nSizeAdded += msg.m_raw_message_size;
    }

    LOCK(m_msg_process_queue_mutex);
    m_msg_process_queue.splice(m_msg_process_queue.end(), vRecvMsg);
    m_msg_process_queue_size += nSizeAdded;
    pauseRecv(m_msg_process_queue_size > m_recv_flood_size);
}

std::optional<DataStream> CNode::CopyIsolatedMessage(const std::string &type,
                                                    size_t max_bytes) {
    LOCK(m_msg_process_queue_mutex);
    if (m_msg_process_queue.empty()) return std::nullopt;
    const auto &first = m_msg_process_queue.front();
    if (first.m_type != type || first.m_recv.size() > max_bytes) {
        return std::nullopt;
    }
    const auto second = std::next(m_msg_process_queue.begin());
    if (second != m_msg_process_queue.end() && second->m_type == type) {
        return std::nullopt;
    }
    return DataStream{Span{first.m_recv.data(), first.m_recv.size()}};
}

std::optional<std::pair<CNetMessage, bool>> CNode::PollMessage() {
    LOCK(m_msg_process_queue_mutex);
    if (m_msg_process_queue.empty()) {
        return std::nullopt;
    }

    std::list<CNetMessage> msgs;
    // Just take one message
    msgs.splice(msgs.begin(), m_msg_process_queue, m_msg_process_queue.begin());
    m_msg_process_queue_size -= msgs.front().m_raw_message_size;
    pauseRecv(m_msg_process_queue_size > m_recv_flood_size);

    return std::make_pair(std::move(msgs.front()),
                          !m_msg_process_queue.empty());
}

bool CConnman::NodeFullyConnected(const CNode *pnode) {
    return pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect;
}

void CConnman::PushMessage(CNode *pnode, CSerializedNetMsg &&msg) {
    size_t nMessageSize = msg.data.size();
    LogEvent(BCLog::NETDEBUG, "peer_message_sent",
             "sending {msg_type} ({bytes} bytes) peer={peer_id}")
        .Field(BCLog::LogField::MsgType, msg.m_type)
        .Field(BCLog::LogField::Bytes, nMessageSize)
        .Field(BCLog::LogField::PeerId, pnode->GetId());
    if (gArgs.GetBoolArg("-capturemessages", false)) {
        CaptureMessage(pnode->addr, msg.m_type, msg.data,
                       /*is_incoming=*/false);
    }

    TRACE6(net, outbound_message, pnode->GetId(), pnode->m_addr_name.c_str(),
           pnode->ConnectionTypeAsString().c_str(), msg.m_type.c_str(),
           msg.data.size(), msg.data.data());

    // make sure we use the appropriate network transport format
    std::vector<uint8_t> serializedHeader;
    pnode->m_serializer->prepareForTransport(*config, msg, serializedHeader);
    size_t nTotalSize = nMessageSize + serializedHeader.size();

    size_t nBytesSent = 0;
    {
        LOCK(pnode->cs_vSend);
        bool optimisticSend(pnode->vSendMsg.empty());

        // log total amount of bytes per message type
        pnode->AccountForSentBytes(msg.m_type, nTotalSize);
        if (auto *metrics{node::GetNodeMetrics()}) {
            const size_t type{node::MetricMsgTypeIndex(msg.m_type)};
            metrics->p2p_sent_bytes.Add(type, nTotalSize);
            metrics->p2p_sent_messages.Add(type);
        }
        pnode->nSendSize += nTotalSize;

        if (pnode->nSendSize > nSendBufferMaxSize) {
            pnode->fPauseSend = true;
        }
        pnode->vSendMsg.push_back(std::move(serializedHeader));
        if (nMessageSize) {
            pnode->vSendMsg.push_back(std::move(msg.data));
        }

        // If write queue empty, attempt "optimistic write"
        bool data_left{!optimisticSend};
        if (optimisticSend) {
            std::tie(nBytesSent, data_left) = SocketSendData(*pnode);
            // Data left behind (in the queue, or buffered by the socket
            // itself): wait for the socket to be writable now.
            if (data_left || WITH_LOCK(pnode->m_sock_mutex,
                                       return pnode->m_sock &&
                                              pnode->m_sock->PendingEvents())) {
                WakeSocketHandler();
            }
        }
    }
    if (nBytesSent) {
        RecordBytesSent(nBytesSent);
    }
}

bool CConnman::ForNode(NodeId id, std::function<bool(CNode *pnode)> func) {
    CNode *found = nullptr;
    LOCK(m_nodes_mutex);
    for (auto &&pnode : m_nodes) {
        if (pnode->GetId() == id) {
            found = pnode;
            break;
        }
    }
    return found != nullptr && NodeFullyConnected(found) && func(found);
}

CSipHasher CConnman::GetDeterministicRandomizer(uint64_t id) const {
    return CSipHasher(nSeed0, nSeed1).Write(id);
}

uint64_t CConnman::CalculateKeyedNetGroup(const CAddress &ad) const {
    std::vector<uint8_t> vchNetGroup(ad.GetGroup(addrman.GetAsmap()));

    return GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP)
        .Write(vchNetGroup)
        .Finalize();
}

/**
 * This function convert MaxBlockSize from byte to
 * MB with a decimal precision one digit rounded down
 * E.g.
 * 1660000 -> 1.6
 * 2010000 -> 2.0
 * 1000000 -> 1.0
 * 230000  -> 0.2
 * 50000   -> 0.0
 *
 *  NB behavior for EB<1MB not standardized yet still
 *  the function applies the same algo used for
 *  EB greater or equal to 1MB
 */
std::string getSubVersionEB(uint64_t MaxBlockSize) {
    // Prepare EB string we are going to add to SubVer:
    // 1) translate from byte to MB and convert to string
    // 2) limit the EB string to the first decimal digit (floored)
    std::stringstream ebMBs;
    ebMBs << (MaxBlockSize / (ONE_MEGABYTE / 10));
    std::string eb = ebMBs.str();
    eb.insert(eb.size() - 1, ".", 1);
    if (eb.substr(0, 1) == ".") {
        eb = "0" + eb;
    }
    return eb;
}

std::string userAgent(const Config &config) {
    // format excessive blocksize value
    std::string eb = getSubVersionEB(config.GetMaxBlockSize());
    std::vector<std::string> uacomments;
    uacomments.push_back("EB" + eb);

    // Comments are checked for char compliance at startup, it is safe to add
    // them to the user agent string
    for (const std::string &cmt : gArgs.GetArgs("-uacomment")) {
        uacomments.push_back(cmt);
    }

    const std::string client_name = gArgs.GetArg("-uaclientname", CLIENT_NAME);
    const std::string client_version =
        gArgs.GetArg("-uaclientversion", FormatVersion(CLIENT_VERSION));

    // Size compliance is checked at startup, it is safe to not check it again
    return FormatUserAgent(client_name, client_version, uacomments);
}

void CaptureMessageToFile(const CAddress &addr, const std::string &msg_type,
                          Span<const uint8_t> data, bool is_incoming) {
    // Note: This function captures the message at the time of processing,
    // not at socket receive/send time.
    // This ensures that the messages are always in order from an application
    // layer (processing) perspective.
    auto now = GetTime<std::chrono::microseconds>();

    // Windows folder names can not include a colon
    std::string clean_addr = addr.ToStringAddrPort();
    std::replace(clean_addr.begin(), clean_addr.end(), ':', '_');

    fs::path base_path = gArgs.GetDataDirNet() / "message_capture" / clean_addr;
    fs::create_directories(base_path);

    fs::path path =
        base_path / (is_incoming ? "msgs_recv.dat" : "msgs_sent.dat");
    AutoFile f{fsbridge::fopen(path, "ab")};

    ser_writedata64(f, now.count());
    f << Span{msg_type};
    for (auto i = msg_type.length(); i < CMessageHeader::MESSAGE_TYPE_SIZE;
         ++i) {
        f << uint8_t{'\0'};
    }
    uint32_t size = data.size();
    ser_writedata32(f, size);
    f << data;
}

std::function<void(const CAddress &addr, const std::string &msg_type,
                   Span<const uint8_t> data, bool is_incoming)>
    CaptureMessage = CaptureMessageToFile;
