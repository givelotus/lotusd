// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_QUIC_UDP_SOCKET_H
#define BITCOIN_NET_QUIC_UDP_SOCKET_H

#include <compat/compat.h>
#include <netaddress.h>
#include <span.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/** A UDP datagram with its addresses (sockaddr storage, as ngtcp2 wants) */
struct UdpDatagram {
    sockaddr_storage remote{};
    socklen_t remote_len{0};
    //! Our address the datagram was received on / is sent from (only set
    //! when the socket is bound to a wildcard address and the OS reports it)
    sockaddr_storage local{};
    socklen_t local_len{0};
    //! ECN bits of the IP header (received) or to set (sent), if known
    uint8_t ecn{0};
    //! Size of each segment when `data` holds several equal-sized UDP
    //! payloads for one send (UDP GSO); 0 for a single payload
    size_t segment_size{0};
    std::vector<uint8_t> data;
};

/**
 * A non-blocking UDP socket for the QUIC engine. Receives and sends in
 * batches: recvmmsg/sendmmsg where available (Linux), else one system call
 * per datagram. Asks the OS for the destination address of received
 * datagrams on wildcard binds (IP_PKTINFO / IPV6_RECVPKTINFO) so replies
 * leave from the address the peer used.
 */
class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(UdpSocket &&other) noexcept;
    UdpSocket &operator=(UdpSocket &&other) noexcept;
    UdpSocket(const UdpSocket &) = delete;
    UdpSocket &operator=(const UdpSocket &) = delete;

    /**
     * Bind to `addr` (port 0: an ephemeral port). Sets 4 MiB socket buffers
     * where the OS allows. On failure returns std::nullopt and a reason.
     */
    static std::optional<UdpSocket> Bind(const CService &addr,
                                         std::string &error);

    SOCKET Fd() const { return m_fd; }
    //! The bound address (with the actual port)
    const CService &Local() const { return m_local; }
    sa_family_t Family() const { return m_family; }

    /**
     * Receive up to `max` datagrams without blocking, appending to `out`
     * (whose elements and buffers are reused). Returns how many were
     * received; 0 when none are pending or on error.
     */
    size_t RecvBatch(std::vector<UdpDatagram> &out, size_t max);

    /**
     * Send datagrams without blocking. Returns how many were sent (a prefix
     * of `in`); the rest would block or failed.
     */
    size_t SendBatch(Span<const UdpDatagram> in);

    /** Send one datagram; false if it would block or failed */
    bool SendOne(const uint8_t *data, size_t len, const sockaddr *remote,
                 socklen_t remote_len, const sockaddr_storage *local = nullptr,
                 socklen_t local_len = 0, size_t segment_size = 0);

    /** Whether UDP segmentation offload (UDP_SEGMENT) works on this socket */
    bool GsoSupported() const { return m_gso; }
    /** Try to enable UDP GSO/GRO (Linux); returns whether it is on */
    bool EnableGso();

    //! Datagrams that the OS refused (other than EAGAIN), for metrics
    uint64_t SendErrors() const { return m_send_errors.load(); }

private:
    void Close();

    SOCKET m_fd{INVALID_SOCKET};
    sa_family_t m_family{AF_INET};
    CService m_local;
    //! Bound to 0.0.0.0 / :: : use packet info for the local address
    bool m_wildcard{false};
    bool m_gso{false};
    std::atomic<uint64_t> m_send_errors{0};
};

#endif // BITCOIN_NET_QUIC_UDP_SOCKET_H
