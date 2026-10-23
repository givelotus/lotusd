// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_COMPLETION_SIGNAL_H
#define BITCOIN_UTIL_COMPLETION_SIGNAL_H
#include <cassert>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <utility>

namespace util {
/** Owned one-shot notification, with synchronous and callback-based waits.
 * The callback is always invoked outside the state mutex. Its ownership is
 * independent of the submitting RPC, including retained-then-throwing queues.
 */
class CompletionSignal {
    std::mutex m_mutex;
    std::condition_variable m_ready;
    std::atomic<bool> m_complete{false};
    bool m_attached{false};
    std::function<void()> m_callback;
public:
    void Complete() {
        std::function<void()> callback;
        {
            std::lock_guard lock(m_mutex);
            assert(!m_complete);
            m_complete.store(true, std::memory_order_release);
            callback = std::move(m_callback);
        }
        m_ready.notify_all();
        if (callback) callback();
    }
    void Then(std::function<void()> callback) {
        {
            std::lock_guard lock(m_mutex);
            assert(!m_attached);
            m_attached = true;
            if (!m_complete) {
                m_callback = std::move(callback);
                return;
            }
        }
        callback();
    }
    bool IsComplete() const noexcept {
        return m_complete.load(std::memory_order_acquire);
    }
    void Wait() {
        std::unique_lock lock(m_mutex);
        m_ready.wait(lock, [this] { return m_complete.load(std::memory_order_acquire); });
    }
};
} // namespace util
#endif // BITCOIN_UTIL_COMPLETION_SIGNAL_H
