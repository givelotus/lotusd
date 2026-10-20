// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// IPV6_RECVPKTINFO on macOS
#define __APPLE_USE_RFC_3542 1

#include <net_quic/udp_socket.h>

#include <util/sock.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace {
//! Receive/send buffer size requested from the OS
constexpr int UDP_SOCKET_BUFFER = 4 * 1024 * 1024;
//! Largest UDP payload we receive (QUIC packets are at most 1452 bytes for
//! our settings; a coalesced/GRO read can be larger)
constexpr size_t MAX_UDP_PAYLOAD = 65535;

void SetLocal(UdpDatagram &d, const cmsghdr *cmsg, uint16_t port) {
#if defined(IP_PKTINFO)
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        in_pktinfo info;
        std::memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr = info.ipi_addr;
        sin.sin_port = htons(port);
        std::memcpy(&d.local, &sin, sizeof(sin));
        d.local_len = sizeof(sin);
        return;
    }
#endif
#if defined(IPV6_PKTINFO)
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        in6_pktinfo info;
        std::memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
        sockaddr_in6 sin6{};
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = info.ipi6_addr;
        sin6.sin6_port = htons(port);
        std::memcpy(&d.local, &sin6, sizeof(sin6));
        d.local_len = sizeof(sin6);
        return;
    }
#endif
}
} // namespace

UdpSocket::~UdpSocket() {
    Close();
}

UdpSocket::UdpSocket(UdpSocket &&other) noexcept {
    *this = std::move(other);
}

UdpSocket &UdpSocket::operator=(UdpSocket &&other) noexcept {
    if (this != &other) {
        Close();
        m_fd = other.m_fd;
        m_family = other.m_family;
        m_local = other.m_local;
        m_wildcard = other.m_wildcard;
        m_gso = other.m_gso;
        m_send_errors = other.m_send_errors.load();
        other.m_fd = INVALID_SOCKET;
    }
    return *this;
}

void UdpSocket::Close() {
    if (m_fd != INVALID_SOCKET) {
        ::close(m_fd);
        m_fd = INVALID_SOCKET;
    }
}

std::optional<UdpSocket> UdpSocket::Bind(const CService &addr,
                                         std::string &error) {
    sockaddr_storage ss{};
    socklen_t len{sizeof(ss)};
    if (!addr.GetSockAddr(reinterpret_cast<sockaddr *>(&ss), &len)) {
        error = "unsupported address " + addr.ToStringAddrPort();
        return std::nullopt;
    }
    UdpSocket sock;
    sock.m_family = ss.ss_family;
    sock.m_fd = ::socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.m_fd == INVALID_SOCKET) {
        error = NetworkErrorString(errno);
        return std::nullopt;
    }
    const int flags{::fcntl(sock.m_fd, F_GETFL, 0)};
    if (flags < 0 || ::fcntl(sock.m_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        error = NetworkErrorString(errno);
        return std::nullopt;
    }
    ::fcntl(sock.m_fd, F_SETFD, FD_CLOEXEC);
    const int one{1};
    if (ss.ss_family == AF_INET6) {
        // Separate IPv4 and IPv6 sockets, as for the TCP listeners.
        ::setsockopt(sock.m_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }
    int bufsize{UDP_SOCKET_BUFFER};
    ::setsockopt(sock.m_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    bufsize = UDP_SOCKET_BUFFER;
    ::setsockopt(sock.m_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    if (::bind(sock.m_fd, reinterpret_cast<const sockaddr *>(&ss), len) != 0) {
        error = NetworkErrorString(errno);
        return std::nullopt;
    }
    sockaddr_storage bound{};
    socklen_t bound_len{sizeof(bound)};
    if (::getsockname(sock.m_fd, reinterpret_cast<sockaddr *>(&bound),
                      &bound_len) != 0 ||
        !sock.m_local.SetSockAddr(reinterpret_cast<const sockaddr *>(&bound),
                                  bound_len)) {
        error = NetworkErrorString(errno);
        return std::nullopt;
    }
    CNetAddr any;
    sock.m_wildcard = !addr.IsValid() || addr.IsBindAny();
    if (sock.m_wildcard) {
        // Learn which of our addresses each datagram was sent to.
#if defined(IP_RECVPKTINFO)
        if (ss.ss_family == AF_INET) {
            ::setsockopt(sock.m_fd, IPPROTO_IP, IP_RECVPKTINFO, &one,
                         sizeof(one));
        }
#elif defined(IP_PKTINFO)
        if (ss.ss_family == AF_INET) {
            ::setsockopt(sock.m_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        }
#endif
#if defined(IPV6_RECVPKTINFO)
        if (ss.ss_family == AF_INET6) {
            ::setsockopt(sock.m_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one,
                         sizeof(one));
        }
#endif
    }
    return sock;
}

bool UdpSocket::EnableGso() {
    // UDP segmentation offload is Linux only (W10 adds it).
    m_gso = false;
    return m_gso;
}

size_t UdpSocket::RecvBatch(std::vector<UdpDatagram> &out, size_t max) {
    size_t n{0};
    const uint16_t port{m_local.GetPort()};
    while (n < max) {
        UdpDatagram d;
        d.data.resize(MAX_UDP_PAYLOAD);
        iovec iov{d.data.data(), d.data.size()};
        alignas(cmsghdr) uint8_t control[256];
        msghdr msg{};
        msg.msg_name = &d.remote;
        msg.msg_namelen = sizeof(d.remote);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        const ssize_t r{::recvmsg(m_fd, &msg, 0)};
        if (r < 0) {
            break;
        }
        d.remote_len = msg.msg_namelen;
        d.data.resize(static_cast<size_t>(r));
        if (m_wildcard) {
            for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr;
                 c = CMSG_NXTHDR(&msg, c)) {
                SetLocal(d, c, port);
            }
        }
        out.push_back(std::move(d));
        ++n;
    }
    return n;
}

bool UdpSocket::SendOne(const uint8_t *data, size_t len,
                        const sockaddr *remote, socklen_t remote_len,
                        const sockaddr_storage *local, socklen_t local_len,
                        size_t segment_size) {
    iovec iov{const_cast<uint8_t *>(data), len};
    msghdr msg{};
    msg.msg_name = const_cast<sockaddr *>(remote);
    msg.msg_namelen = remote_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
#if defined(__linux__) && defined(IP_PKTINFO)
    alignas(cmsghdr) uint8_t control[CMSG_SPACE(sizeof(in6_pktinfo))]{};
    if (m_wildcard && local != nullptr && local_len > 0) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        cmsghdr *c{CMSG_FIRSTHDR(&msg)};
        if (local->ss_family == AF_INET) {
            in_pktinfo info{};
            info.ipi_spec_dst =
                reinterpret_cast<const sockaddr_in *>(local)->sin_addr;
            c->cmsg_level = IPPROTO_IP;
            c->cmsg_type = IP_PKTINFO;
            c->cmsg_len = CMSG_LEN(sizeof(info));
            std::memcpy(CMSG_DATA(c), &info, sizeof(info));
            msg.msg_controllen = CMSG_SPACE(sizeof(info));
        } else {
            in6_pktinfo info{};
            info.ipi6_addr =
                reinterpret_cast<const sockaddr_in6 *>(local)->sin6_addr;
            c->cmsg_level = IPPROTO_IPV6;
            c->cmsg_type = IPV6_PKTINFO;
            c->cmsg_len = CMSG_LEN(sizeof(info));
            std::memcpy(CMSG_DATA(c), &info, sizeof(info));
            msg.msg_controllen = CMSG_SPACE(sizeof(info));
        }
    }
#else
    (void)local;
    (void)local_len;
#endif
    (void)segment_size;
    while (true) {
        const ssize_t r{::sendmsg(m_fd, &msg, 0)};
        if (r >= 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ++m_send_errors;
        }
        return false;
    }
}

size_t UdpSocket::SendBatch(Span<const UdpDatagram> in) {
    size_t n{0};
    for (const UdpDatagram &d : in) {
        if (!SendOne(d.data.data(), d.data.size(),
                     reinterpret_cast<const sockaddr *>(&d.remote),
                     d.remote_len, &d.local, d.local_len, d.segment_size)) {
            break;
        }
        ++n;
    }
    return n;
}
