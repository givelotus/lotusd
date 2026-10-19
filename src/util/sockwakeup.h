// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SOCKWAKEUP_H
#define BITCOIN_UTIL_SOCKWAKEUP_H

#include <util/sock.h>

#include <atomic>
#include <memory>
#include <optional>
#include <utility>

/**
 * Wakes a thread blocked in Sock::Wait()/WaitMany(): the waiting thread
 * includes WaitSock() (for RECV) in what it waits on; other threads call
 * Wake().
 *
 * Wake() writes at most one byte per Drain(), so calling it often is cheap.
 * The waiting thread calls Drain() after each wait and before deciding what
 * to wait on next; a Wake() for anything that changes after that wakes the
 * following wait.
 */
class SockWakeup {
public:
    /** A wakeup on a connected socket pair, or nullptr on failure */
    static std::unique_ptr<SockWakeup> Make();

    /** The end to wait on */
    const std::shared_ptr<Sock> &WaitSock() const { return m_recv; }
    /** Make the next (or current) wait on WaitSock() return. Thread safe. */
    void Wake();
    /** Consume pending wakeups (only from the waiting thread) */
    void Drain();

    /**
     * A connected, non-blocking pair over loopback TCP: what Make() uses
     * where there is no socketpair(2) (Windows). Exposed for tests.
     */
    static std::optional<
        std::pair<std::unique_ptr<Sock>, std::unique_ptr<Sock>>>
    MakeLoopbackPair();

private:
    SockWakeup(std::unique_ptr<Sock> recv, std::unique_ptr<Sock> send)
        : m_recv{std::move(recv)}, m_send{std::move(send)} {}

    const std::shared_ptr<Sock> m_recv;
    const std::unique_ptr<Sock> m_send;
    std::atomic<bool> m_pending{false};
};

#endif // BITCOIN_UTIL_SOCKWAKEUP_H
