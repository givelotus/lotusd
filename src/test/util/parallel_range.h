// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_TEST_UTIL_PARALLEL_RANGE_H
#define BITCOIN_TEST_UTIL_PARALLEL_RANGE_H

#include <util/parallel_range.h>

#include <future>
#include <thread>

/** Hold common executor work until released, including on test failure. */
class ScopedParallelRangeBlocker {
    std::promise<void> m_started, m_release;
    std::thread m_thread;
    bool m_released{false};

public:
    ScopedParallelRangeBlocker() {
        auto started = m_started.get_future();
        auto released = m_release.get_future().share();
        m_thread = std::thread([this, released] {
            util::GetParallelRangeExecutor().Run(2, 1,
                                                 [&](size_t begin, size_t) {
                                                     if (begin == 0)
                                                         m_started.set_value();
                                                     released.wait();
                                                 });
        });
        started.wait();
    }
    void Release() {
        if (!m_released) {
            m_released = true;
            m_release.set_value();
            m_thread.join();
        }
    }
    ~ScopedParallelRangeBlocker() { Release(); }
};

#endif // BITCOIN_TEST_UTIL_PARALLEL_RANGE_H
