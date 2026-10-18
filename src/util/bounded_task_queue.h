// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_BOUNDED_TASK_QUEUE_H
#define BITCOIN_UTIL_BOUNDED_TASK_QUEUE_H
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

/** Lossless while healthy. Overflow rejects the event and invokes a fatal
 * callback, rather than blocking a shared scheduler or silently losing events.
 * The byte/count reservations include the executing task, not only the FIFO.
 */
class BoundedTaskQueue {
    struct Task {
        size_t bytes;
        std::function<void()> run;
    };
    const size_t m_byte_limit, m_count_limit;
    std::function<void()> m_fail;
    mutable std::mutex m_mutex;
    std::condition_variable m_ready, m_drained;
    std::deque<Task> m_tasks;
    size_t m_bytes{0}, m_count{0};
    uint64_t m_submitted{0}, m_completed{0};
    bool m_stopping{false}, m_failed{false};
    std::thread m_worker;
    // Stable after construction: Sync/Enqueue may overlap Stop joining m_worker.
    const std::thread::id m_worker_id;
    void Run() {
        for (;;) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_ready.wait(lock,
                             [this] { return m_stopping || !m_tasks.empty(); });
                if (m_tasks.empty()) return;
                task = std::move(m_tasks.front());
                m_tasks.pop_front();
            }
            bool failed = false;
            try {
                task.run();
            } catch (...) {
                failed = true;
            }
            // Release captured payload before releasing its memory reservation.
            task.run = {};
            bool notify_failure = false;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_bytes -= task.bytes;
                --m_count;
                if (failed && !m_failed) {
                    m_failed = m_stopping = notify_failure = true;
                }
            }
            // A completed fence must also observe the fatal notification.
            if (notify_failure) m_fail();
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                ++m_completed;
            }
            m_drained.notify_all();
        }
    }

public:
    BoundedTaskQueue(size_t byte_limit, size_t count_limit,
                     std::function<void()> fail)
        : m_byte_limit(byte_limit), m_count_limit(count_limit),
          m_fail(std::move(fail)), m_worker([this] { Run(); }),
          m_worker_id(m_worker.get_id()) {}
    ~BoundedTaskQueue() { Stop(); }
    bool Enqueue(size_t bytes, std::function<void()> run) {
        bool notify_failure = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_stopping) return false;
            if (bytes > m_byte_limit - m_bytes || m_count >= m_count_limit) {
                m_failed = m_stopping = notify_failure = true;
            } else {
                try {
                    // Publish the reservation/sequence only after deque
                    // allocation succeeds. A failed append must not leave a
                    // phantom submission that Sync() can never complete.
                    m_tasks.push_back({bytes, std::move(run)});
                    m_bytes += bytes;
                    ++m_count;
                    ++m_submitted;
                } catch (...) {
                    m_failed = m_stopping = notify_failure = true;
                }
            }
        }
        m_ready.notify_one();
        if (notify_failure) m_fail();
        return !notify_failure;
    }
    void Sync() {
        if (std::this_thread::get_id() == m_worker_id) return;
        std::unique_lock<std::mutex> lock(m_mutex);
        const auto target = m_submitted;
        m_drained.wait(lock, [this, target] { return m_completed >= target; });
    }
    void Stop() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopping = true;
        }
        m_ready.notify_all();
        if (m_worker.joinable()) m_worker.join();
    }
    size_t BytesRetained() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_bytes;
    }
};
#endif // BITCOIN_UTIL_BOUNDED_TASK_QUEUE_H
