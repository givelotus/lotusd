// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/sockwakeup.h>

#include <compat/compat.h>

#include <cstring>

std::optional<std::pair<std::unique_ptr<Sock>, std::unique_ptr<Sock>>>
SockWakeup::MakeLoopbackPair() {
    const SOCKET listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd == INVALID_SOCKET) {
        return std::nullopt;
    }
    Sock listener{listen_fd};
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len{sizeof(addr)};
    if (listener.Bind(reinterpret_cast<const sockaddr *>(&addr), len) != 0 ||
        listener.Listen(1) != 0 ||
        listener.GetSockName(reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        return std::nullopt;
    }
    const SOCKET connect_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect_fd == INVALID_SOCKET) {
        return std::nullopt;
    }
    auto send{std::make_unique<Sock>(connect_fd)};
    if (send->Connect(reinterpret_cast<const sockaddr *>(&addr), len) != 0) {
        return std::nullopt;
    }
    // Accept the connection, making sure it is ours: compare the peer
    // address with the connecting socket's own.
    sockaddr_in local, peer;
    socklen_t local_len{sizeof(local)}, peer_len{sizeof(peer)};
    if (send->GetSockName(reinterpret_cast<sockaddr *>(&local), &local_len) !=
        0) {
        return std::nullopt;
    }
    auto recv{listener.Accept(reinterpret_cast<sockaddr *>(&peer), &peer_len)};
    if (!recv || peer.sin_port != local.sin_port ||
        peer.sin_addr.s_addr != local.sin_addr.s_addr) {
        return std::nullopt;
    }
    const int one{1};
    (void)send->SetSockOpt(IPPROTO_TCP, TCP_NODELAY,
                           reinterpret_cast<const char *>(&one), sizeof(one));
    if (!send->SetNonBlocking() || !recv->SetNonBlocking()) {
        return std::nullopt;
    }
    return std::make_pair(std::move(recv), std::move(send));
}

std::unique_ptr<SockWakeup> SockWakeup::Make() {
#ifndef WIN32
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        auto recv{std::make_unique<Sock>(SOCKET(sv[0]))};
        auto send{std::make_unique<Sock>(SOCKET(sv[1]))};
        if (recv->SetNonBlocking() && send->SetNonBlocking()) {
            return std::unique_ptr<SockWakeup>{
                new SockWakeup{std::move(recv), std::move(send)}};
        }
        return nullptr;
    }
#endif
    auto pair{MakeLoopbackPair()};
    if (!pair) {
        return nullptr;
    }
    return std::unique_ptr<SockWakeup>{
        new SockWakeup{std::move(pair->first), std::move(pair->second)}};
}

void SockWakeup::Wake() {
    if (!m_pending.exchange(true)) {
        const uint8_t byte{0};
        // Nothing to do if this fails: the socket buffer then already holds
        // a byte that will wake the waiter.
        (void)m_send->Send(&byte, 1, MSG_NOSIGNAL);
    }
}

void SockWakeup::Drain() {
    uint8_t buf[64];
    while (m_recv->Recv(buf, sizeof(buf), 0) > 0) {
    }
    // Clear the flag only now. Cleared before reading, a Wake() in between
    // could set it and have its byte read here, after which no Wake() would
    // write again. Cleared after, a Wake() in between at worst leaves a byte
    // for one early return from the next wait.
    m_pending = false;
}
