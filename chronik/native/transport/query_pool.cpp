// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/transport/query_pool.h>

#include <algorithm>
#include <thread>

namespace chronik::native {

size_t QueryPool::DefaultThreads() {
    const size_t hw = std::thread::hardware_concurrency();
    return std::min<size_t>(8, std::max<size_t>(1, hw / 2));
}

QueryPool::QueryPool(size_t num_threads)
    : m_num_threads(std::max<size_t>(1, num_threads)),
      m_pool(m_num_threads) {}

QueryPool::~QueryPool() {
    Stop();
}

void QueryPool::Stop() {
    m_pool.stop();
    m_pool.join();
}

void QueryPool::Join() {
    m_pool.join();
}

} // namespace chronik::native
