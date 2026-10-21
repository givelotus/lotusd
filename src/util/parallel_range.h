// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_PARALLEL_RANGE_H
#define BITCOIN_UTIL_PARALLEL_RANGE_H

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace util {

/** Synchronous range work with persistent, bounded workers and no task queue.
 * Concurrent or recursive submissions run on their caller instead of waiting
 * for the executor. Callers must finish before destroying the executor.
 */
class ParallelRangeExecutor {
    using Work = std::function<void(size_t, size_t)>;
    std::mutex m_dispatch, m_mutex;
    std::condition_variable m_start, m_done;
    std::vector<std::thread> m_workers;
    const Work *m_work{nullptr};
    size_t m_count{0}, m_participants{0}, m_remaining{0}, m_generation{0};
    std::exception_ptr m_error;
    bool m_stop{false};
    struct Activation {
        const ParallelRangeExecutor *executor;
        const Activation *previous;
    };
    inline static thread_local const Activation *s_active{nullptr};

    void Execute(size_t worker) noexcept {
        const Activation activation{this, s_active};
        s_active = &activation;
        try {
            const size_t chunk = m_count / m_participants;
            const size_t remainder = m_count % m_participants;
            const size_t begin = worker * chunk + std::min(worker, remainder);
            const size_t end = begin + chunk + (worker < remainder);
            (*m_work)(begin, end);
        } catch (...) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_error) m_error = std::current_exception();
        }
        s_active = activation.previous;
    }

    void Worker(size_t worker) {
        size_t generation = 0;
        for (;;) {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_start.wait(lock, [&] { return m_stop || generation != m_generation; });
            if (m_stop) return;
            generation = m_generation;
            if (worker >= m_participants) continue;
            lock.unlock();
            Execute(worker);
            lock.lock();
            if (--m_remaining == 0) m_done.notify_one();
        }
    }

    void Stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_start.notify_all();
        for (auto &worker : m_workers) worker.join();
    }

public:
    explicit ParallelRangeExecutor(size_t max_participants = 8) {
        const size_t participants = std::min(
            std::max<size_t>(max_participants, 1),
            std::max<size_t>(std::thread::hardware_concurrency(), 1));
        m_workers.reserve(participants - 1);
        try {
            for (size_t i = 1; i < participants; ++i) {
                m_workers.emplace_back([this, i] { Worker(i); });
            }
        } catch (...) {
            Stop();
            throw;
        }
    }

    ~ParallelRangeExecutor() { Stop(); }

    template <typename Fn> void Run(size_t count, size_t grain, Fn &&fn) {
        if (count == 0) return;
        grain = std::max<size_t>(grain, 1);
        const size_t participants = std::min(
            m_workers.size() + 1, count / grain + (count % grain != 0));
        bool recursive = false;
        for (const auto *active = s_active; active; active = active->previous) {
            recursive |= active->executor == this;
        }
        if (participants <= 1 || recursive) {
            fn(0, count);
            return;
        }
        std::unique_lock<std::mutex> dispatch(m_dispatch, std::try_to_lock);
        if (!dispatch.owns_lock()) {
            fn(0, count);
            return;
        }
        const Work work(std::forward<Fn>(fn));
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_work = &work;
            m_count = count;
            m_participants = participants;
            m_remaining = participants - 1;
            m_error = nullptr;
            ++m_generation;
        }
        m_start.notify_all();
        Execute(0);
        std::unique_lock<std::mutex> lock(m_mutex);
        m_done.wait(lock, [&] { return m_remaining == 0; });
        m_work = nullptr;
        if (m_error) std::rethrow_exception(m_error);
    }
};

} // namespace util
#endif // BITCOIN_UTIL_PARALLEL_RANGE_H
