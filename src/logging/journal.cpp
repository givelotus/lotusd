// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <logging/journal.h>

#include <cerrno>
#include <cstring>

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#endif

BCLog::JournalSink::~JournalSink() {
    Close();
}

void BCLog::JournalSink::Close() {
#ifdef __linux__
    if (m_fd >= 0) close(m_fd);
#endif
    m_fd = -1;
}

bool BCLog::JournalSink::Open(std::string_view path) {
    // Copy before Close: reconnect passes a view of m_path.
    const std::string copy{path};
    Close();
    m_path = copy;
#ifdef __linux__
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (m_path.empty() || m_path.size() >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        return false;
    }
    std::memcpy(addr.sun_path, m_path.c_str(), m_path.size() + 1);
    const int fd{socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (fd < 0) return false;
    const int size{1024 * 1024};
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    // The logger must not hang indefinitely on an unavailable collector.
    const timeval timeout{.tv_sec = 0, .tv_usec = 100000};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) <
        0) {
        const int error{errno};
        close(fd);
        errno = error;
        return false;
    }
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        const int error{errno};
        close(fd);
        errno = error;
        return false;
    }
    m_fd = fd;
    return true;
#else
    errno = ENOTSUP;
    return false;
#endif
}

bool BCLog::JournalSink::SendOnce(std::string_view entry) {
#ifdef __linux__
    ssize_t sent;
    do {
        sent = send(m_fd, entry.data(), entry.size(), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent >= 0) return size_t(sent) == entry.size();
    if (errno != EMSGSIZE) return false;

    // Native protocol: exactly one sealed fd with an empty datagram.
    const int fd{
        memfd_create("lotus-log-entry", MFD_CLOEXEC | MFD_ALLOW_SEALING)};
    if (fd < 0) return false;
    bool ok{false};
    size_t offset{0};
    while (offset < entry.size()) {
        const ssize_t n{
            write(fd, entry.data() + offset, entry.size() - offset)};
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        offset += size_t(n);
    }
    if (offset == entry.size() && lseek(fd, 0, SEEK_SET) == 0 &&
        fcntl(fd, F_ADD_SEALS,
              F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) == 0) {
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(fd))]{};
        msghdr msg{};
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        cmsghdr *header{CMSG_FIRSTHDR(&msg)};
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(fd));
        std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));
        do {
            sent = sendmsg(m_fd, &msg, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        ok = sent == 0;
    }
    const int error{errno};
    close(fd);
    errno = error;
    return ok;
#else
    errno = ENOTSUP;
    return false;
#endif
}

bool BCLog::JournalSink::Send(std::string_view entry) {
    if (entry.empty()) {
        errno = EINVAL;
        return false;
    }
    if (m_fd < 0) {
        errno = ENOTCONN;
        return false;
    }
    if (SendOnce(entry)) return true;
    // journald may have restarted and replaced its socket.
    if (errno != ECONNREFUSED && errno != ENOTCONN) return false;
    return Open(m_path) && SendOnce(entry);
}
