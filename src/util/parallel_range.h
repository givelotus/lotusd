// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_PARALLEL_RANGE_H
#define BITCOIN_UTIL_PARALLEL_RANGE_H

#include <threadsafety.h>

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <limits>
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
    // A small CV-compatible scoped lock keeps state transitions visible to
    // clang without depending on sync.h's node/debug-lock infrastructure.
    class SCOPED_LOCKABLE StateLock : public std::unique_lock<StdMutex> {
        using Base = std::unique_lock<StdMutex>;
    public:
        explicit StateLock(StdMutex &mutex) EXCLUSIVE_LOCK_FUNCTION(mutex)
            : Base(mutex) {}
        ~StateLock() UNLOCK_FUNCTION() = default;
        void lock() EXCLUSIVE_LOCK_FUNCTION() { Base::lock(); }
        void unlock() UNLOCK_FUNCTION() { Base::unlock(); }
    };
    struct Job {
        const Work *work{nullptr};
        size_t count{0}, participants{0};
    };
    // Dispatch is never waited on. State publication/completion use m_mutex;
    // each participant snapshots the immutable descriptor before unlocking.
    std::mutex m_dispatch;
    StdMutex m_mutex;
    std::condition_variable_any m_start, m_done;
    std::vector<std::thread> m_workers;
    Job m_job GUARDED_BY(m_mutex);
    size_t m_remaining GUARDED_BY(m_mutex){0};
    size_t m_generation GUARDED_BY(m_mutex){0};
    std::exception_ptr m_error GUARDED_BY(m_mutex);
    bool m_stop GUARDED_BY(m_mutex){false};
    struct Activation {
        const ParallelRangeExecutor *executor;
        const Activation *previous;
    };
    inline static thread_local const Activation *s_active{nullptr};

    void Execute(size_t worker, const Job &job) noexcept LOCKS_EXCLUDED(m_mutex) {
        const Activation activation{this, s_active};
        s_active = &activation;
        try {
            const size_t chunk = job.count / job.participants;
            const size_t remainder = job.count % job.participants;
            const size_t begin = worker * chunk + std::min(worker, remainder);
            const size_t end = begin + chunk + (worker < remainder);
            (*job.work)(begin, end);
        } catch (...) {
            StateLock lock(m_mutex);
            if (!m_error) m_error = std::current_exception();
        }
        s_active = activation.previous;
    }

    void Worker(size_t worker) LOCKS_EXCLUDED(m_mutex) {
        size_t generation = 0;
        for (;;) {
            StateLock lock(m_mutex);
            m_start.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
                return m_stop || generation != m_generation;
            });
            if (m_stop) return;
            generation = m_generation;
            const Job job = m_job;
            if (worker >= job.participants) continue;
            lock.unlock();
            Execute(worker, job);
            lock.lock();
            if (--m_remaining == 0) m_done.notify_one();
        }
    }

    void Stop() noexcept LOCKS_EXCLUDED(m_mutex) {
        {
            StateLock lock(m_mutex);
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

    /** Return false without invoking fn when dispatch is busy or recursive.
     * The caller may then run inline without waiting for another pool user.
     * A successful call drains all participants before propagating exceptions.
     * max_participants limits physical concurrency, not logical range coverage.
     * A single-participant call needs no dispatch and runs on its caller.
     */
    template <typename Fn>
    bool TryRun(size_t count, size_t grain, Fn &&fn,
                size_t max_participants = std::numeric_limits<size_t>::max())
        LOCKS_EXCLUDED(m_mutex) {
        if (count == 0) return true;
        grain = std::max<size_t>(grain, 1);
        const size_t participants = std::min(
            {m_workers.size() + 1, count / grain + (count % grain != 0),
             std::max<size_t>(max_participants, 1)});
        for (const auto *active = s_active; active; active = active->previous) {
            if (active->executor == this) return false;
        }
        if (participants <= 1) {
            fn(0, count);
            return true;
        }
        std::unique_lock<std::mutex> dispatch(m_dispatch, std::try_to_lock);
        if (!dispatch.owns_lock()) return false;
        const Work work(std::forward<Fn>(fn));
        const Job job{&work, count, participants};
        {
            StateLock lock(m_mutex);
            m_job = job;
            m_remaining = participants - 1;
            m_error = nullptr;
            ++m_generation;
        }
        m_start.notify_all();
        Execute(0, job);
        StateLock lock(m_mutex);
        m_done.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
            return m_remaining == 0;
        });
        m_job = {};
        if (m_error) std::rethrow_exception(m_error);
        return true;
    }

    template <typename Fn>
    void Run(size_t count, size_t grain, Fn &&fn,
             size_t max_participants = std::numeric_limits<size_t>::max())
        LOCKS_EXCLUDED(m_mutex) {
        if (!TryRun(count, grain, fn, max_participants)) fn(0, count);
    }
};

/** One process-owned pool for synchronous CPU work across node subsystems.
 * Callers must finish before process teardown; contended/nested work runs on
 * its caller and never waits for this executor's current job.
 */
inline ParallelRangeExecutor &GetParallelRangeExecutor() {
    static ParallelRangeExecutor executor(
        std::max<size_t>(std::thread::hardware_concurrency(), 1));
    return executor;
}

} // namespace util
#endif // BITCOIN_UTIL_PARALLEL_RANGE_H
