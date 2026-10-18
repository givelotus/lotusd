// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_ASYNC_WAITER_H
#define BITCOIN_RPC_ASYNC_WAITER_H

#include <httpserver.h>
#include <util/time.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>

/**
 * Non-blocking coroutine condition waiter for long-polling RPCs
 * (waitfornewblock, waitforblock, waitforblockheight, getblocktemplate).
 *
 * Replaces blocking std::condition_variable::wait_until on OS worker threads
 * with boost::asio::steady_timer suspension so suspended requests consume
 * zero OS threads while waiting.
 */
class AsyncBlockChangeWaiter {
private:
    std::mutex m_mutex;
    std::vector<std::weak_ptr<boost::asio::steady_timer>> m_timers;

public:
    AsyncBlockChangeWaiter() = default;


    /**
     * Wake all currently suspended coroutines by cancelling their timers.
     * Safe to call from any thread (validation, mempool, or shutdown).
     */
    void NotifyAll() {
        std::vector<std::shared_ptr<boost::asio::steady_timer>> active;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto &weak_timer : m_timers) {
                if (auto timer = weak_timer.lock()) {
                    active.push_back(std::move(timer));
                }
            }
            m_timers.clear();
        }
        for (auto &timer : active) {
            boost::asio::post(timer->get_executor(), [timer]() {
                try {
                    timer->cancel();
                } catch (...) {
                }
            });
        }
    }

    size_t WaiterCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t count = 0;
        for (const auto &weak_timer : m_timers) {
            if (!weak_timer.expired()) {
                ++count;
            }
        }
        return count;
    }

    /**
     * Suspend the calling coroutine until pred() returns true or deadline is
     * reached. Re-evaluates pred() under the waiter lock before suspending to
     * prevent missed wakeups.
     */
    template <typename Predicate>
    boost::asio::awaitable<void>
    WaitUntilDeadline(boost::asio::any_io_executor executor,
                      SteadyClock::time_point deadline, Predicate pred) {
        // Initiation and cancellation share a strand. Cancellation before
        // async_wait initiation would otherwise be lost, and direct concurrent
        // timer operations are not safe even when the executor is a strand.
        auto strand = boost::asio::make_strand(executor);
        co_await boost::asio::co_spawn(
            strand, [this, strand, deadline, pred = std::move(pred)]() mutable
                -> boost::asio::awaitable<void> {
                while (!pred()) {
                    const auto now = SteadyClock::now();
                    if (now >= deadline) {
                        break;
                    }
                    const auto remaining = std::min<SteadyClock::duration>(
                        deadline - now, std::chrono::hours(24));
                    auto timer = std::make_shared<boost::asio::steady_timer>(strand);
                    timer->expires_after(remaining);
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        if (pred()) {
                            break;
                        }
                        std::erase_if(m_timers, [](const auto &weak) { return weak.expired(); });
                        m_timers.push_back(timer);
                    }
                    HTTPScopedWaitSuspension suspend_guard;
                    boost::system::error_code ec;
                    co_await timer->async_wait(
                        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        std::erase_if(m_timers, [&timer](const auto &weak) {
                            auto active = weak.lock();
                            return !active || active == timer;
                        });
                    }
                }
                co_return;
            }, boost::asio::use_awaitable);
        co_return;
    }

    /**
     * Suspend the calling coroutine until pred() returns true or timeout
     * expires. If timeout == 0, waits indefinitely until pred() is true or
     * the server stops.
     */
    template <typename Predicate>
    boost::asio::awaitable<void>
    WaitUntil(boost::asio::any_io_executor executor,
              std::chrono::milliseconds timeout, Predicate pred) {
        const SteadyClock::time_point deadline =
            timeout.count() != 0 ? SteadyClock::now() + timeout
                                : SteadyClock::time_point::max();
        co_await WaitUntilDeadline(std::move(executor), deadline,
                                   std::move(pred));
    }
};

/** Global block/mempool change coroutine waiter notified on tip and mempool updates. */
inline AsyncBlockChangeWaiter &GetRPCBlockChangeWaiter() noexcept {
    static AsyncBlockChangeWaiter g_waiter;
    return g_waiter;
}

#endif // BITCOIN_RPC_ASYNC_WAITER_H
