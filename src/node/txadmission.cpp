// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txadmission.h>

#include <util/check.h>

#include <algorithm>

namespace node {

bool TxAdmissionQueue::HasRoom(NodeId peer, size_t tx_bytes, bool count_full) {
    LOCK(m_mutex);
    const auto it = m_queues.find(peer);
    const size_t mine = it == m_queues.end() ? 0 : it->second.size();
    if (mine < m_limits.max_per_peer && m_count < m_limits.max_total &&
        m_bytes <= m_limits.max_total_bytes &&
        tx_bytes <= m_limits.max_total_bytes - m_bytes) {
        return true;
    }
    if (count_full) {
        ++m_full;
    }
    return false;
}

bool TxAdmissionQueue::Push(TxAdmissionItem item) {
    {
        LOCK(m_mutex);
        const auto it = m_queues.find(item.peer);
        const size_t mine = it == m_queues.end() ? 0 : it->second.size();
        const size_t bytes = item.tx->GetTotalSize();
        if (mine >= m_limits.max_per_peer || m_count >= m_limits.max_total ||
            m_bytes > m_limits.max_total_bytes ||
            bytes > m_limits.max_total_bytes - m_bytes) {
            ++m_full;
            return false;
        }
        auto &q = m_queues[item.peer];
        if (q.empty()) {
            m_order.push_back(item.peer);
        }
        m_bytes += item.tx->GetTotalSize();
        ++m_count;
        ++m_pushed;
        q.push_back(std::move(item));
    }
    m_cv.notify_one();
    return true;
}

std::vector<TxAdmissionItem>
TxAdmissionQueue::TakeBatch(size_t max_items, std::chrono::milliseconds wait) {
    std::vector<TxAdmissionItem> out;
    WAIT_LOCK(m_mutex, lock);
    m_cv.wait_for(lock, wait, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        return m_interrupted || m_count > 0;
    });
    if (m_interrupted) {
        return out;
    }
    out.reserve(std::min(max_items, m_count));
    while (out.size() < max_items && !m_order.empty()) {
        const NodeId peer = m_order.front();
        m_order.pop_front();
        auto it = m_queues.find(peer);
        Assume(it != m_queues.end() && !it->second.empty());
        out.push_back(std::move(it->second.front()));
        it->second.pop_front();
        m_bytes -= out.back().tx->GetTotalSize();
        --m_count;
        if (it->second.empty()) {
            m_queues.erase(it);
        } else {
            m_order.push_back(peer);
        }
    }
    m_taken += out.size();
    return out;
}

std::vector<TxAdmissionItem> TxAdmissionQueue::TakeAll() {
    std::vector<TxAdmissionItem> out;
    LOCK(m_mutex);
    for (auto &[peer, q] : m_queues) {
        for (auto &item : q) {
            out.push_back(std::move(item));
        }
    }
    m_dropped += out.size();
    m_queues.clear();
    m_order.clear();
    m_count = 0;
    m_bytes = 0;
    return out;
}

std::vector<TxAdmissionItem> TxAdmissionQueue::DropPeer(NodeId peer) {
    std::vector<TxAdmissionItem> out;
    LOCK(m_mutex);
    auto it = m_queues.find(peer);
    if (it == m_queues.end()) {
        return out;
    }
    for (auto &item : it->second) {
        m_bytes -= item.tx->GetTotalSize();
        --m_count;
        out.push_back(std::move(item));
    }
    m_queues.erase(it);
    m_order.erase(std::remove(m_order.begin(), m_order.end(), peer),
                  m_order.end());
    m_dropped += out.size();
    return out;
}

void TxAdmissionQueue::Interrupt() {
    {
        LOCK(m_mutex);
        m_interrupted = true;
    }
    m_cv.notify_all();
}

TxAdmissionQueue::Stats TxAdmissionQueue::GetStats() const {
    LOCK(m_mutex);
    Stats s;
    s.queued = m_count;
    s.queued_bytes = m_bytes;
    s.peers = m_queues.size();
    s.pushed = m_pushed;
    s.taken = m_taken;
    s.dropped = m_dropped;
    s.full = m_full;
    return s;
}

} // namespace node
