// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_QUIC_TRANSPORT_INFO_H
#define BITCOIN_NET_QUIC_QUIC_TRANSPORT_INFO_H

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Details of a P2P connection carried over WebTransport (HTTP/3 over QUIC),
 * shared between the QUIC engine thread (which updates the counters) and a
 * CNode / RPC (which read them). No QUIC, TLS or Boost dependency, so net.h
 * can hold it in every library net.cpp is compiled into.
 */
struct QuicTransportInfo {
    //! Number of P2P stream classes (see StreamClass in net_webtransport.h)
    static constexpr size_t NUM_CLASSES = 5;

    //! Negotiated application protocol (wt-protocol), e.g. "p2p-v1"
    std::string protocol;
    //! The SETTINGS codepoint of the WebTransport draft the peer advertised
    //! (the newest one, e.g. 0x2c7cf000 for draft-15/16, 0x2b603742 for
    //! draft-02), or 0 for a node peer that only sent ours
    uint64_t draft{0};
    //! SHA-256 of the peer's DER certificate (hex), if it presented one
    std::string peer_cert_fingerprint_hex;
    //! base64url SHA-256 of the peer's public key (SPKI), if any
    std::string peer_spki;
    //! ALPN agreed in the TLS handshake ("h3")
    std::string alpn;
    //! The peer's key matched a pin (outbound) or a -p2pwebsocketpeer key
    //! (inbound)
    bool pinned{false};
    //! The request carried an Origin header (a browser peer)
    std::string origin;

    //! QUIC path statistics, refreshed by the engine
    std::atomic<uint64_t> rtt_us{0};
    std::atomic<uint64_t> min_rtt_us{0};
    std::atomic<uint64_t> cwnd{0};
    std::atomic<uint64_t> lost_pkts{0};
    std::atomic<uint64_t> udp_bytes_sent{0};
    std::atomic<uint64_t> udp_bytes_recv{0};

    //! Per stream class: P2P message bytes (uncompressed, tier framing
    //! included) and stream bytes (after [len][flags] framing and
    //! compression) in each direction
    std::array<std::atomic<uint64_t>, NUM_CLASSES> msg_bytes_sent{};
    std::array<std::atomic<uint64_t>, NUM_CLASSES> msg_bytes_recv{};
    std::array<std::atomic<uint64_t>, NUM_CLASSES> stream_bytes_sent{};
    std::array<std::atomic<uint64_t>, NUM_CLASSES> stream_bytes_recv{};
    //! Messages split into one message per stream class (mixed inventories)
    std::atomic<uint64_t> splits{0};
};

#endif // BITCOIN_NET_QUIC_QUIC_TRANSPORT_INFO_H
