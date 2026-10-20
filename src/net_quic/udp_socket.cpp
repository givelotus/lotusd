// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// IPV6_RECVPKTINFO on macOS
#define __APPLE_USE_RFC_3542 1
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <net_quic/udp_socket.h>

#include <util/sock.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#ifdef __linux__
#include <linux/udp.h>
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <unistd.h>

namespace {
//! Receive/send buffer size requested from the OS
constexpr int UDP_SOCKET_BUFFER = 4 * 1024 * 1024;
//! Largest UDP payload we receive (QUIC packets are at most 1452 bytes for
//! our settings; a coalesced/GRO read can be larger)
constexpr size_t MAX_UDP_PAYLOAD = 65535;
constexpr size_t MAX_BATCH = 64;

struct alignas(cmsghdr) Ancillary {
    std::array<uint8_t, 256> bytes{};
};

void SendMessage(msghdr &msg, iovec &iov, Ancillary &control,
                 const uint8_t *data, size_t len, const sockaddr *remote,
                 socklen_t remote_len, const sockaddr_storage *local,
                 socklen_t local_len, bool wildcard, uint16_t segment_size) {
    msg = {};
    iov = {const_cast<uint8_t *>(data), len};
    msg.msg_name = const_cast<sockaddr *>(remote);
    msg.msg_namelen = remote_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    size_t used{0};
#ifdef __linux__
    const auto append = [&](int level, int type, const auto &value) {
        const size_t space{CMSG_SPACE(sizeof(value))};
        assert(used + space <= control.bytes.size());
        auto *c{reinterpret_cast<cmsghdr *>(control.bytes.data() + used)};
        c->cmsg_level = level;
        c->cmsg_type = type;
        c->cmsg_len = CMSG_LEN(sizeof(value));
        std::memcpy(CMSG_DATA(c), &value, sizeof(value));
        used += space;
    };
#if defined(IP_PKTINFO)
    if (wildcard && local && local_len > 0) {
        if (local->ss_family == AF_INET) {
            in_pktinfo info{};
            info.ipi_spec_dst =
                reinterpret_cast<const sockaddr_in *>(local)->sin_addr;
            append(IPPROTO_IP, IP_PKTINFO, info);
        } else if (local->ss_family == AF_INET6) {
            in6_pktinfo info{};
            info.ipi6_addr =
                reinterpret_cast<const sockaddr_in6 *>(local)->sin6_addr;
            append(IPPROTO_IPV6, IPV6_PKTINFO, info);
        }
    }
#endif
#ifdef UDP_SEGMENT
    if (segment_size) append(IPPROTO_UDP, UDP_SEGMENT, segment_size);
#endif
#else
    (void)local;
    (void)local_len;
    (void)wildcard;
    (void)segment_size;
#endif
    if (used) {
        msg.msg_control = control.bytes.data();
        msg.msg_controllen = used;
    }
}

#ifdef __linux__
// Reused by the engine thread across its sockets: 64 UDP receive buffers,
// not 64 allocations per poll or per bound address. Never enable UDP_GRO:
// each returned element must still represent exactly one UDP datagram.
struct ReceiveStorage {
    std::array<std::array<uint8_t, MAX_UDP_PAYLOAD>, MAX_BATCH> payload;
    std::array<sockaddr_storage, MAX_BATCH> remote;
    std::array<Ancillary, MAX_BATCH> control;
    std::array<iovec, MAX_BATCH> iov;
    std::array<mmsghdr, MAX_BATCH> messages;
};
#endif

void SetLocal(UdpDatagram &d, const cmsghdr *cmsg, uint16_t port) {
#if defined(IP_PKTINFO)
    if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
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
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo))) {
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
        m_recv_batch_supported = other.m_recv_batch_supported;
        m_send_batch_supported = other.m_send_batch_supported;
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
    m_gso = false;
#if defined(__linux__) && defined(UDP_SEGMENT)
    // A zero default segment size leaves ordinary datagrams unchanged while
    // checking whether this kernel knows UDP_SEGMENT. Actual sends use a
    // uint16 ancillary value and can still reject hardware/path capabilities.
    const int zero{0};
    m_gso =
        ::setsockopt(m_fd, IPPROTO_UDP, UDP_SEGMENT, &zero, sizeof(zero)) == 0;
#endif
    return m_gso;
}

size_t UdpSocket::RecvBatch(std::vector<UdpDatagram> &out, size_t max) {
    if (max == 0) return 0;
#ifdef __linux__
    if (m_recv_batch_supported) {
        static thread_local std::unique_ptr<ReceiveStorage> cache;
        if (!cache) cache = std::make_unique<ReceiveStorage>();
        auto &storage{*cache};
        const size_t count{std::min(max, MAX_BATCH)};
        for (size_t i{0}; i < count; ++i) {
            storage.iov[i] = {storage.payload[i].data(), MAX_UDP_PAYLOAD};
            auto &message{storage.messages[i]};
            message = {};
            message.msg_hdr.msg_name = &storage.remote[i];
            message.msg_hdr.msg_namelen = sizeof(sockaddr_storage);
            message.msg_hdr.msg_iov = &storage.iov[i];
            message.msg_hdr.msg_iovlen = 1;
            message.msg_hdr.msg_control = storage.control[i].bytes.data();
            message.msg_hdr.msg_controllen = storage.control[i].bytes.size();
        }
        int received;
        do {
            received = ::recvmmsg(m_fd, storage.messages.data(), count,
                                  MSG_DONTWAIT, nullptr);
        } while (received < 0 && errno == EINTR);
        if (received >= 0) {
            size_t appended{0};
            for (int i{0}; i < received; ++i) {
                auto &message{storage.messages[i]};
                if (message.msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
                    continue;
                UdpDatagram d;
                d.remote = storage.remote[i];
                d.remote_len = message.msg_hdr.msg_namelen;
                d.data.assign(storage.payload[i].begin(),
                              storage.payload[i].begin() + message.msg_len);
                if (m_wildcard) {
                    for (auto *c{CMSG_FIRSTHDR(&message.msg_hdr)}; c;
                         c = CMSG_NXTHDR(&message.msg_hdr, c))
                        SetLocal(d, c, m_local.GetPort());
                }
                out.push_back(std::move(d));
                ++appended;
            }
            return appended;
        }
        if (errno != ENOSYS) return 0;
        m_recv_batch_supported = false;
    }
#endif
    size_t n{0};
    const uint16_t port{m_local.GetPort()};
    for (size_t attempts{0}; attempts < std::min(max, MAX_BATCH); ++attempts) {
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
            if (errno == EINTR) continue;
            break;
        }
        if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) continue;
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
    if (segment_size > UINT16_MAX) {
        ++m_send_errors;
        return false;
    }
    if (segment_size && len > segment_size && !m_gso) {
        // Preserve the UDP boundaries from ngtcp2 when offload is unavailable.
        for (size_t offset{0}; offset < len; offset += segment_size) {
            if (!SendOne(data + offset, std::min(segment_size, len - offset),
                         remote, remote_len, local, local_len, 0))
                return false;
        }
        return true;
    }
    iovec iov;
    msghdr message;
    Ancillary control;
    const uint16_t segment{segment_size && len > segment_size
                               ? static_cast<uint16_t>(segment_size)
                               : uint16_t{0}};
    SendMessage(message, iov, control, data, len, remote, remote_len, local,
                local_len, m_wildcard, segment);
    while (true) {
        const ssize_t result{::sendmsg(m_fd, &message, 0)};
        if (result >= 0) return true;
        const int error{errno};
        if (error == EINTR) continue;
        if (segment &&
            (error == EOPNOTSUPP || error == ENOPROTOOPT || error == EINVAL)) {
            m_gso = false;
            return SendOne(data, len, remote, remote_len, local, local_len,
                           segment_size);
        }
        if (error != EAGAIN && error != EWOULDBLOCK) ++m_send_errors;
        return false;
    }
}

size_t UdpSocket::SendBatch(Span<const UdpDatagram> in) {
    if (in.empty()) return 0;
#ifdef __linux__
    const size_t count{std::min(in.size(), MAX_BATCH)};
    const bool needs_split{
        std::any_of(in.begin(), in.begin() + count, [&](const UdpDatagram &d) {
            return d.segment_size && !m_gso;
        })};
    if (m_send_batch_supported && !needs_split) {
        std::array<mmsghdr, MAX_BATCH> messages{};
        std::array<iovec, MAX_BATCH> vectors;
        std::array<Ancillary, MAX_BATCH> controls;
        bool segmented{false};
        for (size_t i{0}; i < count; ++i) {
            const auto &d{in[i]};
            if (d.segment_size > UINT16_MAX) {
                ++m_send_errors;
                return 0;
            }
            const uint16_t segment{d.segment_size &&
                                           d.data.size() > d.segment_size
                                       ? static_cast<uint16_t>(d.segment_size)
                                       : uint16_t{0}};
            segmented |= segment != 0;
            SendMessage(
                messages[i].msg_hdr, vectors[i], controls[i], d.data.data(),
                d.data.size(), reinterpret_cast<const sockaddr *>(&d.remote),
                d.remote_len, &d.local, d.local_len, m_wildcard, segment);
        }
        int sent;
        do {
            sent = ::sendmmsg(m_fd, messages.data(), count, MSG_DONTWAIT);
        } while (sent < 0 && errno == EINTR);
        if (sent >= 0) return static_cast<size_t>(sent);
        const int error{errno};
        if (error == ENOSYS) {
            m_send_batch_supported = false;
        } else if (segmented && (error == EOPNOTSUPP || error == ENOPROTOOPT ||
                                 error == EINVAL)) {
            m_gso = false;
        } else {
            if (error != EAGAIN && error != EWOULDBLOCK) ++m_send_errors;
            return 0;
        }
    }
#endif
    size_t sent{0};
    for (const auto &d : in) {
        if (!SendOne(d.data.data(), d.data.size(),
                     reinterpret_cast<const sockaddr *>(&d.remote),
                     d.remote_len, &d.local, d.local_len, d.segment_size))
            break;
        ++sent;
    }
    return sent;
}
