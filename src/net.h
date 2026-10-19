// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include <avalanche/proofid.h>
#include <avalanche/proofradixtreeadapter.h>
#include <chainparams.h>
#include <common/bloom.h>
#include <compat/compat.h>
#include <consensus/amount.h>
#include <crypto/siphash.h>
#include <hash.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <net_permissions.h>
#include <net_websocket.h>
#include <net_webtransport.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/connection_types.h>
#include <node/eviction.h>
#include <node/protocol_version.h>
#include <nodeid.h>
#include <protocol.h>
#include <pubkey.h>
#include <radix.h>
#include <random.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/sock.h>
#include <util/sockwakeup.h>
#include <util/time.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <thread>
#include <vector>

class AddrMan;
class ArgsManager;
class BanMan;
class Config;
class CNode;
class CScheduler;
class CThreadInterrupt;
struct bilingual_str;

/**
 * Time after which to disconnect, after waiting for a ping response (or
 * inactivity).
 */
static constexpr std::chrono::minutes TIMEOUT_INTERVAL{20};
/** Run the feeler connection loop once every 2 minutes. **/
static constexpr auto FEELER_INTERVAL = 2min;
/** Run the extra block-relay-only connection loop once every 5 minutes. **/
static constexpr auto EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min;
/** Maximum length of the user agent string in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;
/**
 * Maximum number of automatic outgoing nodes over which we'll relay everything
 * (blocks, tx, addrs, etc)
 */
static const int MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 16;
/** Maximum number of addnode outgoing nodes */
static const int MAX_ADDNODE_CONNECTIONS = 8;
/** Maximum number of block-relay-only outgoing connections */
static const int MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2;
/**
 * Maximum number of avalanche enabled outgoing connections by default.
 * Can be overridden with the -maxavalancheoutbound option.
 */
static const int DEFAULT_MAX_AVALANCHE_OUTBOUND_CONNECTIONS = 150;
/** Maximum number of feeler connections */
static const int MAX_FEELER_CONNECTIONS = 1;
/** -listen default */
static const bool DEFAULT_LISTEN = true;
/**
 * -p2prawlisten default: when listening, accept plain P2P (the ordinary,
 * non-WebSocket wire protocol) connections.
 */
static const bool DEFAULT_P2P_RAW_LISTEN = false;
/**
 * The maximum number of peer connections to maintain.
 * This quantity might not be reachable on some systems, especially on platforms
 * that do not provide a working poll() interface.
 */
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 1024;
/** The default for -maxuploadtarget. 0 = Unlimited */
static constexpr uint64_t DEFAULT_MAX_UPLOAD_TARGET = 0;
/** Default for blocks only*/
static const bool DEFAULT_BLOCKSONLY = false;
/** -peertimeout default */
static const int64_t DEFAULT_PEER_CONNECT_TIMEOUT = 60;
/** Number of file descriptors required for message capture **/
static const int NUM_FDS_MESSAGE_CAPTURE = 1;

static const bool DEFAULT_FORCEDNSSEED = false;
static const bool DEFAULT_DNSSEED = true;
static const bool DEFAULT_FIXEDSEEDS = true;
static const size_t DEFAULT_MAXRECEIVEBUFFER = 5 * 1000;
static const size_t DEFAULT_MAXSENDBUFFER = 1 * 1000;
static const size_t DEFAULT_MAXINFLIGHTBUFFER = 1 * 1000 * 1000;

struct AddedNodeInfo {
    std::string strAddedNode;
    CService resolvedAddress;
    bool fConnected;
    bool fInbound;
};

struct CNodeStats;
class CClientUIInterface;

struct CSerializedNetMsg {
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg &&) = default;
    CSerializedNetMsg &operator=(CSerializedNetMsg &&) = default;
    // No copying, only moves.
    CSerializedNetMsg(const CSerializedNetMsg &msg) = delete;
    CSerializedNetMsg &operator=(const CSerializedNetMsg &) = delete;

    CSerializedNetMsg Copy() const {
        CSerializedNetMsg copy;
        copy.data = data;
        copy.m_type = m_type;
        copy.m_checksum = m_checksum;
        return copy;
    }

    std::vector<uint8_t> data;
    std::string m_type;
    //! The first bytes of Hash(data), if already known (e.g. for a block
    //! message served to many peers); else computed when it is sent
    std::optional<std::array<uint8_t, CMessageHeader::CHECKSUM_SIZE>>
        m_checksum;
};

const std::vector<std::string> CONNECTION_TYPE_DOC{
    "outbound-full-relay (default automatic connections)",
    "block-relay-only (does not relay transactions or addresses)",
    "inbound (initiated by the peer)",
    "manual (added via addnode RPC or -addnode/-connect configuration options)",
    "addr-fetch (short-lived automatic connection for soliciting addresses)",
    "feeler (short-lived automatic connection for testing addresses)"};

/**
 * Look up IP addresses from all interfaces on the machine and add them to the
 * list of local addresses to self-advertise.
 * The loopback interface is skipped and only the first address from each
 * interface is used.
 */
void Discover();

uint16_t GetListenPort();

enum {
    // unknown
    LOCAL_NONE,
    // address a local interface listens on
    LOCAL_IF,
    // address explicit bound to
    LOCAL_BIND,
    // address reported by PCP
    LOCAL_MAPPED,
    // address explicitly specified (-externalip=)
    LOCAL_MANUAL,

    LOCAL_MAX
};

bool IsPeerAddrLocalGood(CNode *pnode);
/** Returns a local address that we should advertise to this peer. */
std::optional<CService> GetLocalAddrForPeer(CNode &node);

/**
 * Mark a network as reachable or unreachable (no automatic connects to it)
 * @note Networks are reachable by default
 */
void SetReachable(enum Network net, bool reachable);
/** @returns true if the network is reachable, false otherwise */
bool IsReachable(enum Network net);
/** @returns true if the address is in a reachable network, false otherwise */
bool IsReachable(const CNetAddr &addr);

bool AddLocal(const CService &addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr &addr, int nScore = LOCAL_NONE);
void RemoveLocal(const CService &addr);
bool SeenLocal(const CService &addr);
bool IsLocal(const CService &addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = nullptr);
CService GetLocalAddress(const CNetAddr &addrPeer);

extern bool fDiscover;
extern bool fListen;
/**
 * Whether a listening node accepts plain (non-WebSocket) P2P connections
 * (-p2prawlisten). When false, no plain P2P address is learned (AddLocal,
 * discovery, peers' view of us) or advertised as ours: only NET_WSS ones.
 */
extern bool g_listen_plain_p2p;

/**
 * -p2pwslisten: accept P2P connections over WebSocket when listening.
 */
bool GetP2PWebSocketListen(const ArgsManager &args);

/** What a connection on the P2P port speaks, judged from its first bytes */
enum class P2PPortProtocol {
    //! Not enough bytes yet
    UNDECIDED,
    //! Plain P2P: the network magic (or anything that is not the below)
    PLAIN,
    //! A TLS ClientHello (0x16 0x03) or an HTTP GET: WebSocket, or a request
    //! the HTTP server answers like any unserved one
    WEBSOCKET,
};

/**
 * Classify a connection on the P2P port from its first bytes (up to 4,
 * peeked). Plain P2P starts with the network magic, which is decided from
 * its first byte whenever that cannot also start TLS or "GET ", so stock
 * peers never wait for more data.
 */
P2PPortProtocol ClassifyP2PPortBytes(Span<const uint8_t> first,
                                     const CMessageHeader::MessageMagic &magic);

/**
 * Receives connections on the P2P port identified as WebSocket (HTTP or
 * TLS), with nothing consumed: the socket, the peer's address and ours.
 * It owns the socket from then on.
 */
using P2PPortWebSocketHandler = std::function<void(
    std::unique_ptr<Sock> &&sock, const CService &peer, const CService &local)>;

/**
 * Check the P2P transport listening options (-p2prawlisten, -p2pwslisten)
 * against each other and against the options that need a plain P2P
 * listener. Call after parameter interaction. Returns an error, or
 * std::nullopt; warnings are appended to `warnings`.
 */
std::optional<bilingual_str>
CheckP2PListenArgs(const ArgsManager &args,
                   std::vector<bilingual_str> &warnings);

struct LocalServiceInfo {
    int nScore;
    uint16_t nPort;
};

extern GlobalMutex g_maplocalhost_mutex;
extern std::map<CNetAddr, LocalServiceInfo>
    mapLocalHost GUARDED_BY(g_maplocalhost_mutex);

extern const std::string NET_MESSAGE_TYPE_OTHER;
typedef std::map</* message type */ std::string, /* total bytes */ uint64_t>
    mapMsgTypeSize;

/**
 * POD that contains various stats about a node.
 * Usually constructed from CConman::GetNodeStats. Stats are filled from the
 * node using CNode::copyStats.
 */
struct CNodeStats {
    NodeId nodeid;
    std::chrono::seconds m_last_send;
    std::chrono::seconds m_last_recv;
    std::chrono::seconds m_last_msg_start;
    std::chrono::seconds m_last_tx_time;
    std::chrono::seconds m_last_proof_time;
    std::chrono::seconds m_last_block_time;
    std::chrono::seconds m_connected;
    int64_t nTimeOffset;
    std::string m_addr_name;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    // We requested high bandwidth connection to peer
    bool m_bip152_highbandwidth_to;
    // Peer requested high bandwidth connection
    bool m_bip152_highbandwidth_from;
    int m_starting_height;
    uint64_t nSendBytes;
    mapMsgTypeSize mapSendBytesPerMsgType;
    uint64_t nRecvBytes;
    mapMsgTypeSize mapRecvBytesPerMsgType;
    uint64_t nInflightBytes;
    NetPermissionFlags m_permission_flags;
    std::chrono::microseconds m_last_ping_time;
    std::chrono::microseconds m_min_ping_time;
    // Our address, as reported by the peer
    std::string addrLocal;
    // Address of this peer
    CAddress addr;
    // Bind address of our side of the connection
    CAddress addrBind;
    // Network the peer connected through
    Network m_network;
    uint32_t m_mapped_as;
    ConnectionType m_conn_type;
    std::optional<double> m_availabilityScore;
    //! Set for peers connected over WebSocket (/p2p/ws)
    std::shared_ptr<const WebSocketTransportInfo> m_websocket_info;
    //! Set for peers connected over WebTransport (HTTP/3 over QUIC)
    std::shared_ptr<const QuicTransportInfo> m_quic_info;
};

/**
 * Transport protocol agnostic message container.
 * Ideally it should only contain receive time, payload,
 * type and size.
 */
class CNetMessage {
public:
    //! received message data
    DataStream m_recv;
    //! time of message receipt
    std::chrono::microseconds m_time{0};
    //! size of the payload
    uint32_t m_message_size{0};
    //! used wire size of the message (including header/checksum)
    uint32_t m_raw_message_size{0};
    std::string m_type;

    CNetMessage(DataStream &&recv_in) : m_recv(std::move(recv_in)) {}
    // Only one CNetMessage object will exist for the same message on either
    // the receive or processing queue. For performance reasons we therefore
    // delete the copy constructor and assignment operator to avoid the
    // possibility of copying CNetMessage objects.
    CNetMessage(CNetMessage &&) = default;
    CNetMessage(const CNetMessage &) = delete;
    CNetMessage &operator=(CNetMessage &&) = default;
    CNetMessage &operator=(const CNetMessage &) = delete;
};

/**
 * The TransportDeserializer takes care of holding and deserializing the
 * network receive buffer. It can deserialize the network buffer into a
 * transport protocol agnostic CNetMessage (message type & payload)
 */
class TransportDeserializer {
public:
    // returns true if the current deserialization is complete
    virtual bool Complete() const = 0;
    /** read and deserialize data, advances msg_bytes data pointer */
    virtual int Read(const Config &config, Span<const uint8_t> &msg_bytes) = 0;
    // decomposes a message from the context
    virtual CNetMessage GetMessage(std::chrono::microseconds time,
                                   bool &reject_message) = 0;
    virtual bool HasData() const = 0;

    virtual ~TransportDeserializer() = default;
};

class V1TransportDeserializer final : public TransportDeserializer {
private:
    const Config &m_config;
    // Only for logging
    const NodeId m_node_id;
    mutable CHash256 hasher;
    mutable uint256 data_hash;

    // Parsing header (false) or data (true)
    bool in_data;
    // Partially received header.
    DataStream hdrbuf{};
    // Complete header.
    CMessageHeader hdr;
    // Received message data.
    DataStream vRecv{};
    uint32_t nHdrPos;
    uint32_t nDataPos;

    const uint256 &GetMessageHash() const;
    int readHeader(const Config &config, Span<const uint8_t> msg_bytes);
    int readData(Span<const uint8_t> msg_bytes);

    void Reset() {
        vRecv.clear();
        hdrbuf.clear();
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        data_hash.SetNull();
        hasher.Reset();
    }

public:
    explicit V1TransportDeserializer(const Config &config, const NodeId node_id)
        : m_config(config), m_node_id(node_id) {
        Reset();
    }

    bool Complete() const override {
        if (!in_data) {
            return false;
        }

        return (hdr.nMessageSize == nDataPos);
    }

    int Read(const Config &config, Span<const uint8_t> &msg_bytes) override {
        int ret = in_data ? readData(msg_bytes) : readHeader(config, msg_bytes);
        if (ret < 0) {
            Reset();
        } else {
            msg_bytes = msg_bytes.subspan(ret);
        }
        return ret;
    }

    CNetMessage GetMessage(std::chrono::microseconds time,
                           bool &reject_message) override;

    bool HasData() const override { return in_data || nHdrPos > 0; }
};

/**
 * The TransportSerializer prepares messages for the network transport
 */
class TransportSerializer {
public:
    // prepare message for transport (header construction, error-correction
    // computation, payload encryption, etc.)
    virtual void prepareForTransport(const Config &config,
                                     CSerializedNetMsg &msg,
                                     std::vector<uint8_t> &header) const = 0;
    virtual ~TransportSerializer() {}
};

class V1TransportSerializer : public TransportSerializer {
public:
    void prepareForTransport(const Config &config, CSerializedNetMsg &msg,
                             std::vector<uint8_t> &header) const override;
};

/**
 * Lotus v2 P2P over WebSocket ("p2p-v2"). Between CConnman and the
 * WebSocketSock each message is [4-byte LE length][id][payload], where id is
 * a 1-byte message id or 0, a 1-byte name length and the name (see
 * GetP2PV2MessageId). There is no network magic and no checksum: TLS (or Tor)
 * protects the bytes, the WebSocket frames them, and no payload is hashed.
 * The WebSocketSock turns each such message into one WebSocket message.
 */
class P2PV2TransportDeserializer final : public TransportDeserializer {
public:
    P2PV2TransportDeserializer(const Config &config, NodeId node_id)
        : m_config{config}, m_node_id{node_id} {}

    bool Complete() const override { return m_state == State::DONE; }
    int Read(const Config &config, Span<const uint8_t> &msg_bytes) override;
    CNetMessage GetMessage(std::chrono::microseconds time,
                           bool &reject_message) override;
    bool HasData() const override { return m_state != State::LENGTH || m_pos; }

private:
    enum class State { LENGTH, ID, NAME_LENGTH, NAME, DATA, DONE };
    void Reset();

    const Config &m_config;
    //! Only for logging
    const NodeId m_node_id;
    State m_state{State::LENGTH};
    //! Bytes read of the current field
    uint32_t m_pos{0};
    uint8_t m_length_bytes[4]{};
    //! Length of the message (id and payload)
    uint32_t m_length{0};
    //! Bytes of it consumed by the id (1, or 2 + the name)
    uint32_t m_id_size{0};
    std::string m_type;
    uint8_t m_name_length{0};
    bool m_invalid_type{false};
    DataStream m_payload{};
};

class P2PV2TransportSerializer final : public TransportSerializer {
public:
    void prepareForTransport(const Config &config, CSerializedNetMsg &msg,
                             std::vector<uint8_t> &header) const override;
};

struct CNodeOptions {
    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    bool prefer_evict = false;
    size_t recv_flood_size{DEFAULT_MAXRECEIVEBUFFER * 1000};
    //! Set for peers connected over WebSocket (/p2p/ws)
    std::shared_ptr<WebSocketTransportInfo> websocket_info = nullptr;
    //! Set for peers connected over WebTransport (/p2p/wt)
    std::shared_ptr<QuicTransportInfo> quic_info = nullptr;
};

/** Information about a peer */
class CNode {
public:
    // Used only by SocketHandler thread
    const std::unique_ptr<TransportDeserializer> m_deserializer;
    const std::unique_ptr<const TransportSerializer> m_serializer;
    //! The last wait asked for RECV in place of SEND because the socket's
    //! transport blocked sending (Sock::SendBlockedByTransport()).
    //! Used only by SocketHandler thread.
    bool m_send_wait_on_recv{false};

    const NetPermissionFlags m_permission_flags{NetPermissionFlags::None};

    /**
     * Socket used for communication with the node.
     * May not own a Sock object (after `CloseSocketDisconnect()` or during
     * tests).
     * `shared_ptr` (instead of `unique_ptr`) is used to avoid premature close
     * of the underlying file descriptor by one thread while another thread is
     * poll(2)-ing it for activity.
     * @see https://github.com/bitcoin/bitcoin/issues/21744 for details.
     */
    std::shared_ptr<Sock> m_sock GUARDED_BY(m_sock_mutex);

    /** Total size of all vSendMsg entries. */
    size_t nSendSize GUARDED_BY(cs_vSend){0};
    /** Offset inside the first vSendMsg already sent */
    size_t nSendOffset GUARDED_BY(cs_vSend){0};
    uint64_t nSendBytes GUARDED_BY(cs_vSend){0};
    std::deque<std::vector<uint8_t>> vSendMsg GUARDED_BY(cs_vSend);
    Mutex cs_vSend;
    Mutex m_sock_mutex;
    Mutex cs_vRecv;

    uint64_t nRecvBytes GUARDED_BY(cs_vRecv){0};
    std::atomic<uint64_t> nInflightBytes{0};

    std::atomic<std::chrono::seconds> m_last_send{0s};
    std::atomic<std::chrono::seconds> m_last_recv{0s};
    std::atomic<std::chrono::seconds> m_last_msg_start{0s};

    //! Unix epoch time at peer connection
    const std::chrono::seconds m_connected;
    std::atomic<int64_t> nTimeOffset{0};
    // Address of this peer
    const CAddress addr;
    // Bind address of our side of the connection
    const CAddress addrBind;
    const std::string m_addr_name;
    //! Whether this peer is an inbound onion, i.e. connected via our Tor onion
    //! service.
    const bool m_inbound_onion;
    std::atomic<int> nVersion{0};
    // The nonce provided by the remote host.
    uint64_t nRemoteHostNonce{0};
    // The extra entropy provided by the remote host.
    uint64_t nRemoteExtraEntropy{0};
    /**
     * cleanSubVer is a sanitized string of the user agent byte array we read
     * from the wire. This cleaned string can safely be logged or displayed.
     */
    Mutex m_subver_mutex;
    std::string cleanSubVer GUARDED_BY(m_subver_mutex){};
    // This peer is preferred for eviction.
    const bool m_prefer_evict{false};
    bool HasPermission(NetPermissionFlags permission) const {
        return NetPermissions::HasFlag(m_permission_flags, permission);
    }
    std::atomic_bool fSuccessfullyConnected{false};
    // Setting fDisconnect to true will cause the node to be disconnected the
    // next time DisconnectNodes() runs
    std::atomic_bool fDisconnect{false};
    CSemaphoreGrant grantOutbound;
    std::atomic<int> nRefCount{0};

    const uint64_t nKeyedNetGroup;
    std::atomic_bool fPauseRecv{false};
    std::atomic_bool fPauseSend{false};
    //! Wakes the socket handler (e.g. when receiving resumes); set by
    //! CConnman before the node is added to m_nodes
    SockWakeup *m_socket_wakeup{nullptr};

    const ConnectionType m_conn_type;

    /**
     * Transport details if this peer is connected over WebSocket; m_sock is
     * then one end of a local socketpair bridged to the WebSocket.
     */
    const std::shared_ptr<WebSocketTransportInfo> m_websocket_info;
    /**
     * Accepted on a P2P port shared with WebSocket, and not yet known to
     * speak raw P2P: nothing is read from it until its first bytes say
     * which (CConnman::ClassifyP2PPortNode), or m_p2p_port_deadline passes.
     */
    std::atomic<bool> m_p2p_port_unclassified{false};
    //! Sent part of its first bytes (socket handler thread only)
    bool m_p2p_port_partial{false};
    std::chrono::steady_clock::time_point m_p2p_port_deadline;
    /**
     * Transport details if this peer is connected over WebTransport; m_sock
     * is then a QuicPeerSock (one end of a socketpair the QUIC engine
     * signals on).
     */
    const std::shared_ptr<QuicTransportInfo> m_quic_info;
    //! Series of the peer gauges this node was counted in (metrics on at
    //! construction), so that its destruction removes exactly that.
    std::optional<std::pair<size_t, std::optional<size_t>>> m_metrics_series;
    //! When the connection was created, if metrics were on (handshake time)
    std::chrono::steady_clock::time_point m_metrics_connected_at{};

    /** Transport label index: 0 = tcp, 1 = ws, 2 = wss, 3 = webtransport */
    size_t MetricTransport() const {
        return m_quic_info ? 3 : m_websocket_info ? (m_websocket_info->tls ? 2 : 1) : 0;
    }

    /** Move all messages from the received queue to the processing queue. */
    void MarkReceivedMsgsForProcessing()
        EXCLUSIVE_LOCKS_REQUIRED(!m_msg_process_queue_mutex);

    /**
     * Poll the next message from the processing queue of this connection.
     *
     * Returns std::nullopt if the processing queue is empty, or a pair
     * consisting of the message and a bool that indicates if the processing
     * queue has more entries.
     */
    /** Copy a bounded, isolated queue head for signature preverification.
     * Leaves ordering/accounting unchanged. Contiguous bursts use the existing
     * per-peer batch path instead. No caller retains a reference to queue data.
     */
    std::optional<DataStream> CopyIsolatedMessage(const std::string &type,
                                                 size_t max_bytes)
        EXCLUSIVE_LOCKS_REQUIRED(!m_msg_process_queue_mutex);

    std::optional<std::pair<CNetMessage, bool>> PollMessage()
        EXCLUSIVE_LOCKS_REQUIRED(!m_msg_process_queue_mutex);

    /**
     * Account for the total size of a sent message in the per msg type
     * connection stats.
     */
    void AccountForSentBytes(const std::string &msg_type, size_t sent_bytes)
        EXCLUSIVE_LOCKS_REQUIRED(cs_vSend) {
        mapSendBytesPerMsgType[msg_type] += sent_bytes;
    }

    bool IsOutboundOrBlockRelayConn() const {
        switch (m_conn_type) {
            case ConnectionType::OUTBOUND_FULL_RELAY:
            case ConnectionType::BLOCK_RELAY:
            case ConnectionType::AVALANCHE_OUTBOUND:
                return true;
            case ConnectionType::INBOUND:
            case ConnectionType::MANUAL:
            case ConnectionType::ADDR_FETCH:
            case ConnectionType::FEELER:
                return false;
        } // no default case, so the compiler can warn about missing cases

        assert(false);
    }

    bool IsFullOutboundConn() const {
        return m_conn_type == ConnectionType::OUTBOUND_FULL_RELAY ||
               m_conn_type == ConnectionType::AVALANCHE_OUTBOUND;
    }

    bool IsManualConn() const { return m_conn_type == ConnectionType::MANUAL; }

    bool IsBlockOnlyConn() const {
        return m_conn_type == ConnectionType::BLOCK_RELAY;
    }

    bool IsFeelerConn() const { return m_conn_type == ConnectionType::FEELER; }

    bool IsAddrFetchConn() const {
        return m_conn_type == ConnectionType::ADDR_FETCH;
    }

    bool IsInboundConn() const {
        return m_conn_type == ConnectionType::INBOUND;
    }

    bool IsAvalancheOutboundConnection() const {
        return m_conn_type == ConnectionType::AVALANCHE_OUTBOUND;
    }

    bool ExpectServicesFromConn() const {
        switch (m_conn_type) {
            case ConnectionType::INBOUND:
            case ConnectionType::MANUAL:
            case ConnectionType::FEELER:
                return false;
            case ConnectionType::OUTBOUND_FULL_RELAY:
            case ConnectionType::BLOCK_RELAY:
            case ConnectionType::ADDR_FETCH:
            case ConnectionType::AVALANCHE_OUTBOUND:
                return true;
        } // no default case, so the compiler can warn about missing cases

        assert(false);
    }

    /**
     * Get network the peer connected through.
     *
     * Returns Network::NET_ONION for *inbound* onion connections,
     * and CNetAddr::GetNetClass() otherwise. The latter cannot be used directly
     * because it doesn't detect the former, and it's not the responsibility of
     * the CNetAddr class to know the actual network a peer is connected
     * through.
     *
     * @return network the peer connected through.
     */
    Network ConnectedThroughNetwork() const;

    // We selected peer as (compact blocks) high-bandwidth peer (BIP152)
    std::atomic<bool> m_bip152_highbandwidth_to{false};
    // Peer selected us as (compact blocks) high-bandwidth peer (BIP152)
    std::atomic<bool> m_bip152_highbandwidth_from{false};

    /**
     * Whether this peer provides all services that we want.
     * Used for eviction decisions
     */
    std::atomic_bool m_has_all_wanted_services{false};

    /**
     * Whether we should relay transactions to this peer. This only changes
     * from false to true. It will never change back to false.
     */
    std::atomic_bool m_relays_txs{false};

    /**
     * Whether this peer has loaded a bloom filter. Used only in inbound
     * eviction logic.
     */
    std::atomic_bool m_bloom_filter_loaded{false};

    // True if we know this peer is using Avalanche (at least polling)
    std::atomic<bool> m_avalanche_enabled{false};

    mutable Mutex cs_avalanche_pubkey;
    // Pubkey used to verify signatures on Avalanche messages from this peer
    std::optional<CPubKey> m_avalanche_pubkey GUARDED_BY(cs_avalanche_pubkey);

    /** The node was polled for count invs */
    void invsPolled(uint32_t count);

    /** The node voted for count invs */
    void invsVoted(uint32_t count);

    /**
     * The availability score is calculated using an exponentially weighted
     * average.
     * This has several interesting properties:
     *  - The most recent polls/responses have more weight than the previous
     * ones. A node that recently stopped answering will see its ratio
     * decrease quickly.
     *  - This is a low-pass filter, so it causes delay. This means that a
     * node needs to have a track record for the ratio to be high. A node
     * that has been little requested will have a lower ratio than a node
     * that failed to answer a few polls but answered a lot of them.
     *  - It is cheap to compute.
     *
     * This is expected to be called at a fixed interval of
     * AVALANCHE_STATISTICS_REFRESH_PERIOD.
     */
    void updateAvailabilityScore(double decayFactor);
    double getAvailabilityScore() const;

    // The last time the node sent us a faulty message
    std::atomic<std::chrono::seconds> m_avalanche_last_message_fault{0s};
    /**
     * How much faulty messages did this node accumulate. This is reset if no
     * fault occured for one hour.
     */
    std::atomic<int> m_avalanche_message_fault_counter{0};
    /**
     * This score is incremented for every new faulty message received when
     * m_avalanche_message_fault_counter is higher than a threshold.
     * A score of 100 results in a disconnection.
     */
    std::atomic<int> m_avalanche_message_fault_score{0};

    SteadyMilliseconds m_last_poll{};

    /**
     * UNIX epoch time of the last block received from this peer that we had
     * not yet seen (e.g. not already received from another peer), that passed
     * preliminary validity checks and was saved to disk, even if we don't
     * connect the block or it eventually fails connection. Used as an inbound
     * peer eviction criterium in CConnman::AttemptToEvictConnection.
     */
    std::atomic<std::chrono::seconds> m_last_block_time{0s};

    /**
     * UNIX epoch time of the last transaction received from this peer that we
     * had not yet seen (e.g. not already received from another peer) and that
     * was accepted into our mempool. Used as an inbound peer eviction criterium
     * in CConnman::AttemptToEvictConnection.
     */
    std::atomic<std::chrono::seconds> m_last_tx_time{0s};

    /**
     * UNIX epoch time of the last proof received from this peer that we
     * had not yet seen (e.g. not already received from another peer) and that
     * was accepted into our proof pool. Used as an inbound peer eviction
     * criterium in CConnman::AttemptToEvictConnection.
     */
    std::atomic<std::chrono::seconds> m_last_proof_time{0s};

    /** Last measured round-trip time. Used only for RPC/GUI stats/debugging.*/
    std::atomic<std::chrono::microseconds> m_last_ping_time{0us};

    /**
     * Lowest measured round-trip time. Used as an inbound peer eviction
     * criterium in CConnman::AttemptToEvictConnection.
     */
    std::atomic<std::chrono::microseconds> m_min_ping_time{
        std::chrono::microseconds::max()};

    CNode(NodeId id, std::shared_ptr<Sock> sock, const CAddress &addrIn,
          uint64_t nKeyedNetGroupIn, uint64_t nLocalHostNonceIn,
          uint64_t nLocalExtraEntropyIn, const CAddress &addrBindIn,
          const std::string &addrNameIn, ConnectionType conn_type_in,
          bool inbound_onion, CNodeOptions &&node_opts = {});
    ~CNode();
    CNode(const CNode &) = delete;
    CNode &operator=(const CNode &) = delete;

    /**
     * A ping-pong round trip has completed successfully. Update latest and
     * minimum ping times.
     */
    void PongReceived(std::chrono::microseconds ping_time) {
        m_last_ping_time = ping_time;
        m_min_ping_time = std::min(m_min_ping_time.load(), ping_time);
    }

    NodeId GetId() const { return id; }

    uint64_t GetLocalNonce() const { return nLocalHostNonce; }
    uint64_t GetLocalExtraEntropy() const { return nLocalExtraEntropy; }

    int GetRefCount() const {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    /**
     * Receive bytes from the buffer and deserialize them into messages.
     *
     * @param[in]   msg_bytes   The raw data
     * @param[out]  complete    Set True if at least one message has been
     *                          deserialized and is ready to be processed
     * @return  True if the peer should stay connected,
     *          False if the peer should be disconnected from.
     */
    bool ReceiveMsgBytes(const Config &config, Span<const uint8_t> msg_bytes,
                         bool &complete) EXCLUSIVE_LOCKS_REQUIRED(!cs_vRecv);

    void SetCommonVersion(int greatest_common_version) {
        Assume(m_greatest_common_version == INIT_PROTO_VERSION);
        m_greatest_common_version = greatest_common_version;
    }
    int GetCommonVersion() const { return m_greatest_common_version; }

    CService GetAddrLocal() const EXCLUSIVE_LOCKS_REQUIRED(!m_addr_local_mutex);
    //! May not be called more than once
    void SetAddrLocal(const CService &addrLocalIn)
        EXCLUSIVE_LOCKS_REQUIRED(!m_addr_local_mutex);

    CNode *AddRef() {
        nRefCount++;
        return this;
    }

    void Release() { nRefCount--; }

    void CloseSocketDisconnect() EXCLUSIVE_LOCKS_REQUIRED(!m_sock_mutex);

    void copyStats(CNodeStats &stats)
        EXCLUSIVE_LOCKS_REQUIRED(!m_subver_mutex, !m_addr_local_mutex,
                                 !cs_vSend, !cs_vRecv);

    std::string ConnectionTypeAsString() const {
        return ::ConnectionTypeAsString(m_conn_type);
    }

    void pauseRecv(bool pause);

private:
    const NodeId id;
    const uint64_t nLocalHostNonce;
    const uint64_t nLocalExtraEntropy;
    std::atomic<int> m_greatest_common_version{INIT_PROTO_VERSION};

    const size_t m_recv_flood_size;
    // Used only by SocketHandler thread
    std::list<CNetMessage> vRecvMsg;

    Mutex m_msg_process_queue_mutex;
    std::list<CNetMessage>
        m_msg_process_queue GUARDED_BY(m_msg_process_queue_mutex);
    size_t m_msg_process_queue_size GUARDED_BY(m_msg_process_queue_mutex){0};

    // Our address, as reported by the peer
    mutable Mutex m_addr_local_mutex;
    CService addrLocal GUARDED_BY(m_addr_local_mutex);

    /**
     * The inventories polled and voted counters since last score
     * computation, stored as a pair of uint32_t with the poll counter
     * being the 32 lowest bits and the vote counter the 32 highest bits.
     */
    std::atomic<uint64_t> invCounters{0};

    /** The last computed score */
    std::atomic<double> availabilityScore{0.};

    mapMsgTypeSize mapSendBytesPerMsgType GUARDED_BY(cs_vSend);
    mapMsgTypeSize mapRecvBytesPerMsgType GUARDED_BY(cs_vRecv);
};

/**
 * Interface for message handling
 */
class NetEventsInterface {
public:
    /**
     * Mutex for anything that is only accessed via the msg processing thread
     */
    static Mutex g_msgproc_mutex;

    /** Initialize a peer (setup state, queue any initial messages) */
    virtual void InitializeNode(const Config &config, CNode &node,
                                ServiceFlags our_services) = 0;

    /** Handle removal of a peer (clear state) */
    virtual void FinalizeNode(const Config &config, const CNode &node) = 0;

    /**
     * Process protocol messages received from a given node
     *
     * @param[in]   config          The applicable configuration object.
     * @param[in]   pnode           The node which we have received messages
     * from.
     * @param[in]   interrupt       Interrupt condition for processing threads
     * @return                      True if there is more work to be done
     */
    virtual bool ProcessMessages(const Config &config, CNode *pnode,
                                 std::atomic<bool> &interrupt)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /** Preverify ready queue heads without dispatching or reordering messages.
     * Called with a connection snapshot that pins all nodes for this turn.
     */
    virtual void PrepareMessageTurn(Span<CNode *const>,
                                    const std::atomic<bool> &)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) {}

    /**
     * Send queued protocol messages to a given node.
     *
     * @param[in]   config          The applicable configuration object.
     * @param[in]   pnode           The node which we are sending messages to.
     * @return                      True if there is more work to be done
     */
    virtual bool SendMessages(const Config &config, CNode *pnode)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

protected:
    /**
     * Protected destructor so that instances can only be deleted by derived
     * classes. If that restriction is no longer desired, this should be made
     * public and virtual.
     */
    ~NetEventsInterface() = default;
};

namespace {
struct CConnmanTest;
}

class NetEventsInterface;
class CConnman {
public:
    struct Options {
        ServiceFlags nLocalServices = NODE_NONE;
        int nMaxConnections = 0;
        int m_max_outbound_full_relay = 0;
        int m_max_outbound_block_relay = 0;
        int m_max_avalanche_outbound = 0;
        int nMaxAddnode = 0;
        int nMaxFeeler = 0;
        CClientUIInterface *uiInterface = nullptr;
        std::vector<NetEventsInterface *> m_msgproc;
        BanMan *m_banman = nullptr;
        unsigned int nSendBufferMaxSize = 0;
        unsigned int nReceiveFloodSize = 0;
        uint64_t nMaxOutboundLimit = 0;
        int64_t m_peer_connect_timeout = DEFAULT_PEER_CONNECT_TIMEOUT;
        std::vector<std::string> vSeedNodes;
        std::vector<NetWhitelistPermissions> vWhitelistedRangeIncoming;
        std::vector<NetWhitelistPermissions> vWhitelistedRangeOutgoing;
        std::vector<NetWhitebindPermissions> vWhiteBinds;
        std::vector<CService> vBinds;
        std::vector<CService> onion_binds;
        /// True if the user did not specify -bind= or -whitebind= and thus
        /// we should bind on `0.0.0.0` (IPv4) and `::` (IPv6).
        bool bind_on_any;
        bool m_use_addrman_outgoing = true;
        std::vector<std::string> m_specified_outgoing;
        std::vector<std::string> m_added_nodes;
        bool whitelist_forcerelay = DEFAULT_WHITELISTFORCERELAY;
        bool whitelist_relay = DEFAULT_WHITELISTRELAY;
        //! P2P WebSocket peers known by their TLS key (canonical pins)
        std::vector<NetKeyPermissions> vWhitelistedKeys;
        //! Drop inbound P2P WebSocket peers whose key is not listed above
        bool m_websocket_require_known_key{false};
        //! Accept WebSocket peers on the P2P port by handing connections
        //! starting with HTTP or TLS to this (the HTTP server). Unset: the
        //! P2P port only speaks plain P2P, exactly as without WebSocket.
        P2PPortWebSocketHandler p2p_port_websocket;
        //! Share an already-bound HTTP listener, without opening a new socket.
        std::function<bool(const CService &)> share_http_listener;
        //! How long a P2P port connection may take to show what it speaks
        std::chrono::seconds p2p_port_handshake_timeout{
            DEFAULT_P2P_PORT_HANDSHAKE_TIMEOUT};
        WebTransportDialPolicy m_wt_dial_policy{WebTransportDialPolicy::PREFER};
        bool m_wt_bulk{true};
        std::chrono::milliseconds m_wt_dial_timeout{
            WEBTRANSPORT_DISCOVERY_TIMEOUT};
        std::chrono::seconds m_wt_retry_after{WEBTRANSPORT_RETRY_AFTER};
    };

    void Init(const Options &connOptions)
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex) {
        nLocalServices = connOptions.nLocalServices;
        nMaxConnections = connOptions.nMaxConnections;
        m_use_addrman_outgoing = connOptions.m_use_addrman_outgoing;
        nMaxAddnode = connOptions.nMaxAddnode;
        nMaxFeeler = connOptions.nMaxFeeler;
        {
            // Lock cs_main to prevent a potential race with the peer validation
            // logic thread.
            LOCK(::cs_main);
            m_max_outbound_full_relay =
                std::min(connOptions.m_max_outbound_full_relay,
                         connOptions.nMaxConnections);
            m_max_avalanche_outbound = connOptions.m_max_avalanche_outbound;
            m_max_outbound_block_relay = connOptions.m_max_outbound_block_relay;
            m_max_outbound = m_max_outbound_full_relay +
                             m_max_outbound_block_relay + nMaxFeeler +
                             m_max_avalanche_outbound;
        }
        m_client_interface = connOptions.uiInterface;
        m_banman = connOptions.m_banman;
        m_msgproc = connOptions.m_msgproc;
        nSendBufferMaxSize = connOptions.nSendBufferMaxSize;
        nReceiveFloodSize = connOptions.nReceiveFloodSize;
        m_peer_connect_timeout =
            std::chrono::seconds{connOptions.m_peer_connect_timeout};
        {
            LOCK(cs_totalBytesSent);
            nMaxOutboundLimit = connOptions.nMaxOutboundLimit;
        }
        vWhitelistedRangeIncoming = connOptions.vWhitelistedRangeIncoming;
        vWhitelistedRangeOutgoing = connOptions.vWhitelistedRangeOutgoing;
        {
            LOCK(m_added_nodes_mutex);
            m_added_nodes = connOptions.m_added_nodes;
        }
        m_onion_binds = connOptions.onion_binds;
        whitelist_forcerelay = connOptions.whitelist_forcerelay;
        whitelist_relay = connOptions.whitelist_relay;
        vWhitelistedKeys = connOptions.vWhitelistedKeys;
        m_websocket_require_known_key =
            connOptions.m_websocket_require_known_key;
        m_p2p_port_websocket = connOptions.p2p_port_websocket;
        m_share_http_listener = connOptions.share_http_listener;
        m_p2p_port_handshake_timeout = connOptions.p2p_port_handshake_timeout;
        m_wt_dial_policy = connOptions.m_wt_dial_policy;
        m_wt_bulk = connOptions.m_wt_bulk;
        m_wt_dial_timeout = connOptions.m_wt_dial_timeout;
        m_wt_negative_cache.SetRetryAfter(connOptions.m_wt_retry_after);
    }

    CConnman(const Config &configIn, uint64_t seed0, uint64_t seed1,
             AddrMan &addrmanIn, bool network_active = true);
    virtual ~CConnman();

    bool Start(CScheduler &scheduler, const Options &options)
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex, !m_addr_fetches_mutex,
                                 !mutexMsgProc);

    void StopThreads();
    void StopNodes();
    void Stop() {
        StopThreads();
        StopNodes();
    };

    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);
    bool GetNetworkActive() const { return fNetworkActive; };
    bool GetUseAddrmanOutgoing() const { return m_use_addrman_outgoing; };
    void SetNetworkActive(bool active);
    void OpenNetworkConnection(const CAddress &addrConnect, bool fCountFailure,
                               CSemaphoreGrant *grantOutbound,
                               const char *strDest, ConnectionType conn_type);
    bool CheckIncomingNonce(uint64_t nonce);

    bool ForNode(NodeId id, std::function<bool(CNode *pnode)> func);

    void PushMessage(CNode *pnode, CSerializedNetMsg &&msg);

    using NodeFn = std::function<void(CNode *)>;
    void ForEachNode(const NodeFn &func) {
        LOCK(m_nodes_mutex);
        for (auto &&node : m_nodes) {
            if (NodeFullyConnected(node)) {
                func(node);
            }
        }
    };

    void ForEachNode(const NodeFn &func) const {
        LOCK(m_nodes_mutex);
        for (auto &&node : m_nodes) {
            if (NodeFullyConnected(node)) {
                func(node);
            }
        }
    };

    // Addrman functions
    /**
     * Return all or many randomly selected addresses, optionally by network.
     *
     * @param[in] max_addresses  Maximum number of addresses to return
     *                           (0 = all).
     * @param[in] max_pct        Maximum percentage of addresses to return
     *                           (0 = all).
     * @param[in] network        Select only addresses of this network
     *                           (nullopt = all).
     */
    std::vector<CAddress> GetAddresses(size_t max_addresses, size_t max_pct,
                                       std::optional<Network> network) const;
    /**
     * Cache is used to minimize topology leaks, so it should
     * be used for all non-trusted calls, for example, p2p.
     * A non-malicious call (from RPC or a peer with addr permission) should
     * call the function without a parameter to avoid using the cache.
     */
    std::vector<CAddress> GetAddresses(CNode &requestor, size_t max_addresses,
                                       size_t max_pct);

    // This allows temporarily exceeding m_max_outbound_full_relay, with the
    // goal of finding a peer that is better than all our current peers.
    void SetTryNewOutboundPeer(bool flag);
    bool GetTryNewOutboundPeer() const;

    void StartExtraBlockRelayPeers() {
        LogDebug(BCLog::NET, "net: enabling extra block-relay-only peers\n");
        m_start_extra_block_relay_peers = true;
    }

    // Return the number of outbound peers we have in excess of our target (eg,
    // if we previously called SetTryNewOutboundPeer(true), and have since set
    // to false, we may have extra peers that we wish to disconnect). This may
    // return a value less than (num_outbound_connections - num_outbound_slots)
    // in cases where some outbound connections are not yet fully connected, or
    // not yet fully disconnected.
    int GetExtraFullOutboundCount() const;
    // Count the number of block-relay-only peers we have over our limit.
    int GetExtraBlockRelayCount() const;

    bool AddNode(const std::string &node)
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex);
    bool RemoveAddedNode(const std::string &node)
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex);
    std::vector<AddedNodeInfo> GetAddedNodeInfo() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex);

    /**
     * Accept an inbound peer whose WebTransport session (/p2p/wt) is
     * established, like AcceptWebSocketPeer(). Called on the QUIC engine's
     * thread.
     */
    void AcceptWebTransportPeer(std::unique_ptr<Sock> &&sock,
                                const CAddress &addr,
                                const CAddress &addr_bind,
                                std::shared_ptr<QuicTransportInfo> info);

    /**
     * Accept an inbound peer that connected over WebSocket (/p2p/ws).
     * Subject to the same limits, bans and eviction as TCP inbound peers.
     *
     * @param[in] sock   CConnman's end of the socketpair bridged to the
     *                   WebSocket.
     * @param[in] addr   The peer's address (as seen by the HTTP server).
     * @param[in] addr_bind Our address on the HTTP connection.
     * @param[in] info   Transport details shared with the bridge.
     */
    void AcceptWebSocketPeer(std::unique_ptr<Sock> &&sock, const CAddress &addr,
                             const CAddress &addr_bind,
                             std::shared_ptr<WebSocketTransportInfo> info);

    /**
     * Attempts to open a connection. Currently only used from tests.
     *
     * @param[in]   address     Address of node to try connecting to
     * @param[in]   conn_type   ConnectionType::OUTBOUND,
     *                          ConnectionType::BLOCK_RELAY,
     *                          ConnectionType::ADDR_FETCH, or
     *                          ConnectionType::FEELER
     * @return      bool        Returns false if there are no available
     *                          slots for this connection:
     *                          - conn_type not a supported ConnectionType
     *                          - Max total outbound connection capacity filled
     *                          - Max connection capacity for type is filled
     */
    bool AddConnection(const std::string &address, ConnectionType conn_type);

    size_t GetNodeCount(ConnectionDirection) const;
    void GetNodeStats(std::vector<CNodeStats> &vstats) const;
    bool GetNodeStats(NodeId id, CNodeStats &stats) const;
    bool DisconnectNode(const std::string &node);
    bool DisconnectNode(const CSubNet &subnet);
    bool DisconnectNode(const CNetAddr &addr);
    bool DisconnectNode(NodeId id);

    //! Used to convey which local services we are offering peers during node
    //! connection.
    //!
    //! The data returned by this is used in CNode construction,
    //! which is used to advertise which services we are offering
    //! that peer during `net_processing.cpp:PushNodeVersion()`.
    ServiceFlags GetLocalServices() const;
    size_t GetMaxInboundConnections() const {
        return size_t(std::max(0, nMaxConnections - m_max_outbound));
    }
    size_t WebTransportNegativeCacheSize() {
        return m_wt_negative_cache.Size();
    }
    std::array<uint64_t, 4> WebTransportFallbackCounts() const {
        return {m_wt_fallbacks[0].load(), m_wt_fallbacks[1].load(),
                m_wt_fallbacks[2].load(), m_wt_fallbacks[3].load()};
    }

    //! Updates the local services that this node advertises to other peers
    //! during connection handshake.
    void AddLocalServices(ServiceFlags services) {
        nLocalServices = ServiceFlags(nLocalServices | services);
    };
    void RemoveLocalServices(ServiceFlags services) {
        nLocalServices = ServiceFlags(nLocalServices & ~services);
    }

    uint64_t GetMaxOutboundTarget() const;
    std::chrono::seconds GetMaxOutboundTimeframe() const;

    //! check if the outbound target is reached. If param
    //! historicalBlockServingLimit is set true, the function will response true
    //! if the limit for serving historical blocks has been reached.
    bool OutboundTargetReached(bool historicalBlockServingLimit) const;

    //! response the bytes left in the current max outbound cycle in case of no
    //! limit, it will always response 0
    uint64_t GetOutboundTargetBytesLeft() const;

    //! returns the time in second left in the current max outbound cycle in
    //! case of no limit, it will always return 0
    std::chrono::seconds GetMaxOutboundTimeLeftInCycle() const;

    uint64_t GetTotalBytesRecv() const;
    uint64_t GetTotalBytesSent() const;

    /** Get a unique deterministic randomizer. */
    CSipHasher GetDeterministicRandomizer(uint64_t id) const;

    void WakeMessageHandler() EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);

    /**
     * Return true if we should disconnect the peer for failing an inactivity
     * check.
     */
    bool ShouldRunInactivityChecks(const CNode &node,
                                   std::chrono::seconds now) const;

private:
    struct ListenSocket {
    public:
        std::shared_ptr<Sock> sock;
        inline void AddSocketPermissionFlags(NetPermissionFlags &flags) const {
            NetPermissions::AddFlag(flags, m_permissions);
        }
        ListenSocket(std::shared_ptr<Sock> sock_,
                     NetPermissionFlags permissions_, const CService &addr_)
            : sock(sock_), m_permissions(permissions_), addr(addr_) {}

    private:
        NetPermissionFlags m_permissions;

    public:
        //! The address bound
        CService addr;
    };

    bool BindListenPort(const CService &bindAddr, bilingual_str &strError,
                        NetPermissionFlags permissions);
    bool Bind(const CService &addr, unsigned int flags,
              NetPermissionFlags permissions);
    bool InitBinds(const Options &options);

    void ThreadOpenAddedConnections()
        EXCLUSIVE_LOCKS_REQUIRED(!m_added_nodes_mutex);
    void AddAddrFetch(const std::string &strDest)
        EXCLUSIVE_LOCKS_REQUIRED(!m_addr_fetches_mutex);
    void ProcessAddrFetch() EXCLUSIVE_LOCKS_REQUIRED(!m_addr_fetches_mutex);
    void
    ThreadOpenConnections(std::vector<std::string> connect,
                          std::function<void(const CAddress &, ConnectionType)>
                              mockOpenConnection)
        EXCLUSIVE_LOCKS_REQUIRED(!m_addr_fetches_mutex, !m_added_nodes_mutex,
                                 !m_nodes_mutex);
    void ThreadMessageHandler() EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);
    void AcceptConnection(const ListenSocket &hListenSocket);

    /**
     * Create a `CNode` object from a socket that has just been accepted and add
     * the node to the `m_nodes` member.
     * @param[in] sock Connected socket to communicate with the peer.
     * @param[in] permission_flags The peer's permissions.
     * @param[in] addr_bind The address and port at our side of the connection.
     * @param[in] addr The address and port at the peer's side of the connection
     */
    void CreateNodeFromAcceptedSocket(
        std::unique_ptr<Sock> &&sock, NetPermissionFlags permission_flags,
        const CAddress &addr_bind, const CAddress &addr,
        std::shared_ptr<WebSocketTransportInfo> websocket_info = nullptr,
        bool classify = false,
        std::shared_ptr<QuicTransportInfo> quic_info = nullptr);

    void DisconnectNodes();
    void NotifyNumConnectionsChanged();
    /** Return true if the peer is inactive and should be disconnected. */
    bool InactivityCheck(const CNode &node) const;

    /**
     * Generate a collection of sockets to check for IO readiness.
     * @param[in] nodes Select from these nodes' sockets.
     * @return sockets to check for readiness
     */
    Sock::EventsPerSock GenerateWaitSockets(Span<CNode *const> nodes);

    /**
     * Check connected and listening sockets for IO readiness and process them
     * accordingly.
     */
    void SocketHandler() EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);

    /**
     * Do the read/write for connected sockets that are ready for IO.
     * @param[in] nodes Nodes to process. The socket of each node is checked
     *     against `what`.
     * @param[in] events_per_sock Sockets that are ready for IO.
     */
    void SocketHandlerConnected(const std::vector<CNode *> &nodes,
                                const Sock::EventsPerSock &events_per_sock)
        EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);

    /**
     * Accept incoming connections, one from each read-ready listening socket.
     * @param[in] events_per_sock Sockets that are ready for IO.
     */
    void SocketHandlerListening(const Sock::EventsPerSock &events_per_sock);
    /**
     * For a node accepted on a P2P port shared with WebSocket and not yet
     * classified: peek at its first bytes. Returns whether to go on with it
     * as a raw P2P node; otherwise it was handed to the WebSocket endpoint,
     * dropped, or is still undecided (until its deadline).
     */
    bool ClassifyP2PPortNode(CNode &node,
                             const Sock::EventsPerSock &events_per_sock);
    /**
     * Whether an inbound connection may go on to the HTTP server: the checks
     * of CreateNodeFromAcceptedSocket that need no data, without evicting
     * anyone (that is left to the node's creation).
     */
    bool MayAcceptInbound(const CAddress &addr,
                          NetPermissionFlags permission_flags);
    /** The peer to evict for a new inbound one, if any (none is evicted) */
    std::optional<NodeId> SelectEvictionCandidate();

    void ThreadSocketHandler() EXCLUSIVE_LOCKS_REQUIRED(!mutexMsgProc);
    void ThreadDNSAddressSeed()
        EXCLUSIVE_LOCKS_REQUIRED(!m_addr_fetches_mutex, !m_nodes_mutex);

    uint64_t CalculateKeyedNetGroup(const CAddress &ad) const;

    CNode *FindNode(const CNetAddr &ip);
    CNode *FindNode(const CSubNet &subNet);
    CNode *FindNode(const std::string &addrName);
    CNode *FindNode(const CService &addr);

    /**
     * Determine whether we're already connected to a given address, in order to
     * avoid initiating duplicate connections.
     */
    bool AlreadyConnectedToAddress(const CAddress &addr);

    bool AttemptToEvictConnection();
    CNode *ConnectNode(CAddress addrConnect, const char *pszDest,
                       bool fCountFailure, ConnectionType conn_type);
    /**
     * Open an outbound P2P connection over WebSocket to `url` (ws:// or
     * wss://), via the dialer set with SetWebSocketDialer(). `wss_addr` is
     * the NET_WSS address the URL was made from, if any.
     */
    CNode *ConnectWebSocketNode(const std::string &url,
                                const CAddress *wss_addr, bool fCountFailure,
                                ConnectionType conn_type,
                                const std::string &dest_name = "",
                                bool record_attempt = true);
    /**
     * Open an outbound P2P connection over WebTransport to `url` (wt://),
     * via the dialer set with SetWebTransportDialer(). Never through a
     * proxy: UDP cannot use one, so with -proxy/-onion it fails closed.
     */
    CNode *ConnectWebTransportNode(const std::string &url, bool fCountFailure,
                                   ConnectionType conn_type,
                                   const CAddress *discovered = nullptr,
                                   WebTransportDialError *dial_error = nullptr);
    void AddWhitelistPermissionFlags(
        NetPermissionFlags &flags, const CNetAddr &addr,
        const std::vector<NetWhitelistPermissions> &ranges) const;

    void DeleteNode(CNode *pnode);

    NodeId GetNewNodeId();

    /**
     * (Try to) send data from node's vSendMsg.
     * Returns (bytes_sent, data_left).
     */
    std::pair<size_t, bool> SocketSendData(CNode &node) const
        EXCLUSIVE_LOCKS_REQUIRED(node.cs_vSend);

    void DumpAddresses();

    // Network stats
    void RecordBytesRecv(uint64_t bytes);
    void RecordBytesSent(uint64_t bytes);

    /**
     * Return vector of current BLOCK_RELAY peers.
     */
    std::vector<CAddress> GetCurrentBlockRelayOnlyConns() const;

    // Whether the node should be passed out in ForEach* callbacks
    static bool NodeFullyConnected(const CNode *pnode);

    const Config *config;

    // Network usage totals
    mutable RecursiveMutex cs_totalBytesSent;
    std::atomic<uint64_t> nTotalBytesRecv{0};
    uint64_t nTotalBytesSent GUARDED_BY(cs_totalBytesSent){0};

    // outbound limit & stats
    uint64_t nMaxOutboundTotalBytesSentInCycle GUARDED_BY(cs_totalBytesSent){0};
    std::chrono::seconds
        nMaxOutboundCycleStartTime GUARDED_BY(cs_totalBytesSent){0};
    uint64_t nMaxOutboundLimit GUARDED_BY(cs_totalBytesSent);

    // P2P timeout in seconds
    std::chrono::seconds m_peer_connect_timeout;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<NetWhitelistPermissions> vWhitelistedRangeIncoming;
    // Whitelisted ranges for outgoing connections.
    std::vector<NetWhitelistPermissions> vWhitelistedRangeOutgoing;
    // P2P WebSocket peers known by their TLS public key (-p2pwebsocketpeer)
    std::vector<NetKeyPermissions> vWhitelistedKeys;
    bool m_websocket_require_known_key{false};
    WebTransportDialPolicy m_wt_dial_policy{WebTransportDialPolicy::PREFER};
    bool m_wt_bulk{true};
    std::chrono::milliseconds m_wt_dial_timeout{WEBTRANSPORT_DISCOVERY_TIMEOUT};
    WebTransportNegativeCache m_wt_negative_cache;
    // timeout, refused, unsupported, handshake; excludes shutdown/proxy skips.
    std::array<std::atomic<uint64_t>, 4> m_wt_fallbacks{};

    unsigned int nSendBufferMaxSize{0};
    unsigned int nReceiveFloodSize{0};

    std::vector<ListenSocket> vhListenSocket;

    //! See Options::p2p_port_websocket
    P2PPortWebSocketHandler m_p2p_port_websocket;
    std::function<bool(const CService &)> m_share_http_listener;
    std::vector<std::pair<CService, NetPermissionFlags>> m_shared_http_permissions;
    std::chrono::seconds m_p2p_port_handshake_timeout{
        DEFAULT_P2P_PORT_HANDSHAKE_TIMEOUT};

    std::atomic<bool> fNetworkActive{true};
    bool fAddressesInitialized{false};
    AddrMan &addrman;
    std::deque<std::string> m_addr_fetches GUARDED_BY(m_addr_fetches_mutex);
    Mutex m_addr_fetches_mutex;
    std::vector<std::string> m_added_nodes GUARDED_BY(m_added_nodes_mutex);
    mutable Mutex m_added_nodes_mutex;
    std::vector<CNode *> m_nodes GUARDED_BY(m_nodes_mutex);
    std::list<CNode *> m_nodes_disconnected;
    mutable RecursiveMutex m_nodes_mutex;
    std::atomic<NodeId> nLastNodeId{0};
    unsigned int nPrevNodeCount{0};

    /**
     * Cache responses to addr requests to minimize privacy leak.
     * Attack example: scraping addrs in real-time may allow an attacker
     * to infer new connections of the victim by detecting new records
     * with fresh timestamps (per self-announcement).
     */
    struct CachedAddrResponse {
        std::vector<CAddress> m_addrs_response_cache;
        std::chrono::microseconds m_cache_entry_expiration{0};
    };

    /**
     * Addr responses stored in different caches
     * per (network, local socket) prevent cross-network node identification.
     * If a node for example is multi-homed under Tor and IPv6,
     * a single cache (or no cache at all) would let an attacker
     * to easily detect that it is the same node by comparing responses.
     * Indexing by local socket prevents leakage when a node has multiple
     * listening addresses on the same network.
     *
     * The used memory equals to 1000 CAddress records (or around 40 bytes) per
     * distinct Network (up to 5) we have/had an inbound peer from,
     * resulting in at most ~196 KB. Every separate local socket may
     * add up to ~196 KB extra.
     */
    std::map<uint64_t, CachedAddrResponse> m_addr_response_caches;

    /**
     * Services this node offers.
     *
     * This data is replicated in each Peer instance we create.
     *
     * This data is not marked const, but after being set it should not
     * change. Unless AssumeUTXO is started, in which case, the peer
     * will be limited until the background chain sync finishes.
     *
     * \sa Peer::m_our_services
     */
    std::atomic<ServiceFlags> nLocalServices;

    std::unique_ptr<CSemaphore> semOutbound;
    std::unique_ptr<CSemaphore> semAddnode;
    int nMaxConnections;

    // How many full-relay (tx, block, addr) outbound peers we want
    int m_max_outbound_full_relay;

    // How many block-relay only outbound peers we want
    // We do not relay tx or addr messages with these peers
    int m_max_outbound_block_relay;

    // How many avalanche enabled outbound peers we want
    int m_max_avalanche_outbound;

    int nMaxAddnode;
    int nMaxFeeler;
    int m_max_outbound;
    bool m_use_addrman_outgoing;
    CClientUIInterface *m_client_interface;
    // FIXME m_msgproc is a terrible name
    std::vector<NetEventsInterface *> m_msgproc;
    /**
     * Pointer to this node's banman. May be nullptr - check existence before
     * dereferencing.
     */
    BanMan *m_banman;

    /**
     * Addresses that were saved during the previous clean shutdown. We'll
     * attempt to make block-relay-only connections to them.
     */
    std::vector<CAddress> m_anchors;

    /** SipHasher seeds for deterministic randomness */
    const uint64_t nSeed0, nSeed1;

    /** flag for waking the message processor. */
    bool fMsgProcWake GUARDED_BY(mutexMsgProc);

    std::condition_variable condMsgProc;
    Mutex mutexMsgProc;
    std::atomic<bool> flagInterruptMsgProc{false};

    /**
     * This is signaled when network activity should cease.
     */
    CThreadInterrupt interruptNet;

    /**
     * Wakes SocketHandler() from its wait when it should wait on something
     * new: a node was added, a node's receiving resumed, or a send left data
     * queued. Without it, these wait for the wait's timeout (up to
     * SELECT_TIMEOUT_MILLISECONDS). Created by Start().
     */
    std::unique_ptr<SockWakeup> m_socket_wakeup;
    void WakeSocketHandler() {
        if (m_socket_wakeup) {
            m_socket_wakeup->Wake();
        }
    }
    /** Add a fully set up node to m_nodes and wake SocketHandler() */
    void AddNodeLocked(CNode *pnode) EXCLUSIVE_LOCKS_REQUIRED(m_nodes_mutex);

    std::thread threadDNSAddressSeed;
    std::thread threadSocketHandler;
    std::thread threadOpenAddedConnections;
    std::thread threadOpenConnections;
    std::thread threadMessageHandler;

    /**
     * An outbound connection being established. Each is dialed (TCP, TLS,
     * WebSocket upgrade) on its own thread, so a slow or unresponsive peer
     * never holds up the threads opening other connections. Until it
     * finishes it counts as a connection of its type, address and group,
     * and keeps its outbound slot.
     */
    struct PendingOutbound {
        uint64_t id;
        CAddress addr;
        std::string name;
        ConnectionType conn_type;
    };
    struct DialThread {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    mutable Mutex m_pending_mutex;
    std::list<PendingOutbound> m_pending_outbound GUARDED_BY(m_pending_mutex);
    std::list<DialThread> m_dial_threads GUARDED_BY(m_pending_mutex);
    uint64_t m_next_pending_id GUARDED_BY(m_pending_mutex){0};

    /** Whether an outbound attempt to this address or name is in progress */
    bool IsPendingOutbound(const CAddress &addr, const std::string &name) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_mutex);
    /** Join the dial threads that are done (all, with `all`) */
    void ReapDialThreads(bool all) EXCLUSIVE_LOCKS_REQUIRED(!m_pending_mutex);

    /**
     * flag for deciding to connect to an extra outbound peer, in excess of
     * m_max_outbound_full_relay. This takes the place of a feeler connection.
     */
    std::atomic_bool m_try_another_outbound_peer;

    /**
     * flag for initiating extra block-relay-only peer connections.
     * this should only be enabled after initial chain sync has occurred,
     * as these connections are intended to be short-lived and low-bandwidth.
     */
    std::atomic_bool m_start_extra_block_relay_peers{false};

    /**
     * A vector of -bind=<address>:<port>=onion arguments each of which is
     * an address and port that are designated for incoming Tor connections.
     */
    std::vector<CService> m_onion_binds;

    /**
     * flag for adding 'forcerelay' permission to whitelisted inbound
     * and manual peers with default permissions.
     */
    bool whitelist_forcerelay;

    /**
     * flag for adding 'relay' permission to whitelisted inbound
     * and manual peers with default permissions.
     */
    bool whitelist_relay;

    std::atomic_bool inflight_throttle{false};

    /**
     * RAII helper to atomically create a copy of `m_nodes` and add a reference
     * to each of the nodes. The nodes are released when this object is
     * destroyed.
     */
    class NodesSnapshot {
    public:
        explicit NodesSnapshot(const CConnman &connman, bool shuffle) {
            {
                LOCK(connman.m_nodes_mutex);
                m_nodes_copy = connman.m_nodes;
                for (auto &node : m_nodes_copy) {
                    node->AddRef();
                }
            }
            if (shuffle) {
                Shuffle(m_nodes_copy.begin(), m_nodes_copy.end(),
                        FastRandomContext{});
            }
        }

        ~NodesSnapshot() {
            for (auto &node : m_nodes_copy) {
                node->Release();
            }
        }

        const std::vector<CNode *> &Nodes() const { return m_nodes_copy; }

    private:
        std::vector<CNode *> m_nodes_copy;
    };

    friend struct ::CConnmanTest;
    friend struct ConnmanTestMsg;
};

std::string getSubVersionEB(uint64_t MaxBlockSize);
std::string userAgent(const Config &config);

/** Dump binary message to file, with timestamp */
void CaptureMessageToFile(const CAddress &addr, const std::string &msg_type,
                          Span<const uint8_t> data, bool is_incoming);

/**
 * Defaults to `CaptureMessageToFile()`, but can be overridden by unit tests.
 */
extern std::function<void(const CAddress &addr, const std::string &msg_type,
                          Span<const uint8_t> data, bool is_incoming)>
    CaptureMessage;

#endif // BITCOIN_NET_H
