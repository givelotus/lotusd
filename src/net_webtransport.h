// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_WEBTRANSPORT_H
#define BITCOIN_NET_WEBTRANSPORT_H

#include <net_quic/quic_transport_info.h>
#include <netaddress.h>
#include <protocol.h>
#include <span.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/**
 * P2P over WebTransport (HTTP/3 over QUIC), see doc/p2p-webtransport.md.
 *
 * This header has no QUIC/HTTP/3/TLS dependency: it holds what net.cpp and
 * the tests need (URL parsing, message classification into streams and the
 * registries through which the QUIC engine hands connections to CConnman),
 * so it can be used in every library net.cpp is compiled into.
 */

//! Default request path of the extended CONNECT (-p2pwebtransportpath)
static const char *const P2P_WEBTRANSPORT_PATH = "/p2p/wt";
//! wt-protocol tokens (draft-ietf-webtrans-http3 §3.3): P2P framing inside
//! the class streams. This tier speaks p2p-v1 (24-byte message headers).
static const char *const P2P_WT_PROTOCOL_V1 = "p2p-v1";
//! Port of a wt:// URL without one
static constexpr uint16_t DEFAULT_WEBTRANSPORT_URL_PORT = 443;

/**
 * The bidirectional WebTransport stream a P2P message travels on. The
 * client opens one stream per class and tags it with this byte after the
 * WebTransport stream header. Lower values are sent first (CONTROL and
 * AVALANCHE share the top priority, round-robin).
 */
enum class StreamClass : uint8_t {
    CONTROL = 1,
    AVALANCHE = 2,
    TX_ANNOUNCE = 3,
    TX_BODY = 4,
    BLOCK = 5,
    //! An inventory message whose entries belong to several classes: split
    //! it with SplitByClass()
    MIXED = 0xff,
};
static constexpr size_t NUM_STREAM_CLASSES = QuicTransportInfo::NUM_CLASSES;
static constexpr StreamClass ALL_STREAM_CLASSES[NUM_STREAM_CLASSES] = {
    StreamClass::CONTROL, StreamClass::AVALANCHE, StreamClass::TX_ANNOUNCE,
    StreamClass::TX_BODY, StreamClass::BLOCK};

/** 0-based index of a (non-MIXED) class */
constexpr size_t StreamClassIndex(StreamClass c) {
    return static_cast<uint8_t>(c) - 1;
}
/** Whether a tag byte names one of the five classes */
constexpr bool IsValidStreamClass(uint8_t tag) {
    return tag >= 1 && tag <= NUM_STREAM_CLASSES;
}
/** Send priority: 0 is served first */
constexpr int StreamClassPriority(StreamClass c) {
    switch (c) {
        case StreamClass::CONTROL:
        case StreamClass::AVALANCHE:
            return 0;
        case StreamClass::TX_ANNOUNCE:
            return 1;
        case StreamClass::TX_BODY:
            return 2;
        case StreamClass::BLOCK:
        case StreamClass::MIXED:
            break;
    }
    return 3;
}

/** "control", "avalanche", "tx_announce", "tx_body", "block", "mixed" */
const char *StreamClassName(StreamClass c);

/** The class of an inventory entry type (CInv::type) in an inv message
 * (announcements) or a getdata/notfound (requests/answers) */
StreamClass ClassifyInventoryType(uint32_t inv_type, bool announcement);

/**
 * The stream a P2P message is sent on. Inventory-carrying messages (inv,
 * getdata, notfound) are classified by their entries and give MIXED when
 * those span classes; unknown message types are CONTROL.
 */
StreamClass ClassifyMessage(std::string_view type,
                            Span<const uint8_t> payload);

/** Whether a message type has an explicit class (not the CONTROL default
 * of unknown types); inventory messages count as explicit */
bool HasExplicitStreamClass(std::string_view type);

/**
 * Split a MIXED inventory message into one message per class, each with
 * the entries of its class in their original relative order, ordered by
 * the first entry of each class. Any other message is returned unchanged
 * as a single element with its class.
 */
std::vector<std::pair<StreamClass, std::vector<uint8_t>>>
SplitByClass(std::string_view type, Span<const uint8_t> payload);

/** A wt:// P2P peer URL */
struct ParsedWebTransportURL {
    std::string host;
    uint16_t port{DEFAULT_WEBTRANSPORT_URL_PORT};
    //! :authority, host:port with [] around IPv6 literals
    std::string authority;
    //! Request path, "/p2p/wt" if the URL has none
    std::string path;
    //! Access token (from "?t="), sent as the query of the request path
    std::string token;
    //! Required SHA-256 of the server's public key ("#spki=")
    std::optional<std::vector<unsigned char>> spki_pin;
    //! Required SHA-256 of the server's DER certificate ("#cert=", hex), as
    //! a browser's serverCertificateHashes
    std::optional<std::vector<unsigned char>> cert_sha256;
};

/**
 * Parse wt://host[:port][/path][?t=<token>][#spki=<pin>|#cert=<hex>]
 * (default port 443). A pin uses the same encoding as -p2pwebsocketpin
 * (see DecodeSpkiPin); a cert hash is 64 hex digits.
 */
std::optional<ParsedWebTransportURL> ParseWebTransportURL(std::string_view url);

/** Whether a -addnode/-connect string is a wt:// URL */
bool IsWebTransportURL(std::string_view str);

/** The URL with any access token replaced by "***", for logging */
std::string RedactWebTransportURL(std::string_view url);

/**
 * Receives inbound P2P peers whose WebTransport session is established:
 * the peer's Sock (a QuicPeerSock), its UDP address, our address and the
 * transport details shared with the engine.
 */
using P2PWebTransportAcceptor = std::function<void(
    std::unique_ptr<Sock> &&sock, const CAddress &addr,
    const CAddress &addr_bind, std::shared_ptr<QuicTransportInfo> info)>;

/** Set (or clear, with nullptr) the receiver of inbound sessions. While
 * unset, sessions are refused with 503. Thread-safe. */
void SetP2PWebTransportAcceptor(P2PWebTransportAcceptor acceptor);
P2PWebTransportAcceptor GetP2PWebTransportAcceptor();

/** Why an outbound WebTransport dial failed (metrics, fallback) */
enum class WebTransportDialError {
    NONE,
    //! No QUIC handshake within the timeout (UDP blocked, peer down)
    TIMEOUT,
    //! QUIC/TLS handshake failed (bad certificate, pin mismatch, ...)
    HANDSHAKE,
    //! The peer speaks HTTP/3 but not WebTransport (no SETTINGS codepoint)
    UNSUPPORTED,
    //! The CONNECT was refused (non-200 status) or the session closed
    REFUSED,
    //! Interrupted (shutdown) or not attempted
    INTERRUPTED,
};
const char *WebTransportDialErrorName(WebTransportDialError e);

/** An established outbound WebTransport P2P session */
struct WebTransportDialResult {
    //! A QuicPeerSock for CNode
    std::unique_ptr<Sock> sock;
    std::shared_ptr<QuicTransportInfo> info;
    //! Our local address of the connection
    CService local;
};

/**
 * Establishes a WebTransport P2P session to `target` (QUIC handshake,
 * HTTP/3 SETTINGS, extended CONNECT, class streams), blocking until done,
 * failed, `timeout` elapsed or `interrupt` fired. Provided by the QUIC
 * engine (net_quic/), registered at startup.
 */
using WebTransportDialer = std::function<std::optional<WebTransportDialResult>(
    const CService &target, const ParsedWebTransportURL &url,
    std::chrono::milliseconds timeout, CThreadInterrupt &interrupt,
    WebTransportDialError &error)>;
void SetWebTransportDialer(WebTransportDialer dialer);
WebTransportDialer GetWebTransportDialer();

#endif // BITCOIN_NET_WEBTRANSPORT_H
