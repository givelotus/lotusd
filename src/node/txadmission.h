// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXADMISSION_H
#define BITCOIN_NODE_TXADMISSION_H

#include <nodeid.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/time.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <vector>

namespace node {

/** Default for -parallelmempool. */
static constexpr bool DEFAULT_PARALLEL_MEMPOOL{true};
/** Default for -parallelmempoolthreads (0: one per core). */
static constexpr int DEFAULT_PARALLEL_MEMPOOL_THREADS{0};
/** Most script-check threads -parallelmempoolthreads may ask for. */
static constexpr int MAX_PARALLEL_MEMPOOL_THREADS{64};

/** A received transaction waiting for mempool admission. */
struct TxAdmissionItem {
    NodeId peer{-1};
    CTransactionRef tx;
    SteadyClock::time_point enqueued;
    /** Whatever the producer needs back with the verdict. */
    std::shared_ptr<void> owner;
};

/**
 * Transactions received from peers, waiting for the admission thread.
 *
 * Each peer has its own FIFO; batches are taken round-robin across peers,
 * one transaction per peer per turn, so a flooding peer cannot delay
 * others by more than one slot per turn, and a peer's own transactions
 * keep their order. The queue is bounded per peer and in total (count and
 * serialized bytes); producers must check HasRoom() first and, when it
 * says no, stop reading from that peer, which leaves its messages in the
 * receive buffer and applies TCP backpressure.
 *
 * Thread-safe.
 */
class TxAdmissionQueue {
public:
    struct Limits {
        size_t max_per_peer{256};
        size_t max_total{16384};
        size_t max_total_bytes{64 << 20};
    };

    struct Stats {
        size_t queued{0};
        size_t queued_bytes{0};
        size_t peers{0};
        uint64_t pushed{0};
        uint64_t taken{0};
        uint64_t dropped{0};
        /** HasRoom() said no (a producer had to pause a peer). */
        uint64_t full{0};
    };

    explicit TxAdmissionQueue(Limits limits) : m_limits{limits} {}

    /**
     * Whether `peer` may add one more transaction now. Counts a "full"
     * event when it may not and count_full is set.
     */
    bool HasRoom(NodeId peer, size_t tx_bytes, bool count_full = true)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Atomically check bounds and append, waking the consumer on success.
     * HasRoom is advisory and does not reserve space for concurrent producers.
     */
    bool Push(TxAdmissionItem item) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Take up to `max_items`, round-robin over peers, waiting up to `wait`
     * for the first one. Returns empty on timeout or after Interrupt().
     */
    std::vector<TxAdmissionItem> TakeBatch(size_t max_items,
                                           std::chrono::milliseconds wait)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Remove and return everything still queued, for every peer. */
    std::vector<TxAdmissionItem> TakeAll() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Remove and return everything still queued for `peer`. */
    std::vector<TxAdmissionItem> DropPeer(NodeId peer)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Make waiting and future TakeBatch calls return immediately. */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    Stats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    const Limits m_limits;
    mutable Mutex m_mutex;
    std::condition_variable m_cv;
    std::map<NodeId, std::deque<TxAdmissionItem>> m_queues GUARDED_BY(m_mutex);
    /** Peers with queued items, in round-robin order. */
    std::deque<NodeId> m_order GUARDED_BY(m_mutex);
    size_t m_count GUARDED_BY(m_mutex){0};
    size_t m_bytes GUARDED_BY(m_mutex){0};
    bool m_interrupted GUARDED_BY(m_mutex){false};
    uint64_t m_pushed GUARDED_BY(m_mutex){0};
    uint64_t m_taken GUARDED_BY(m_mutex){0};
    uint64_t m_dropped GUARDED_BY(m_mutex){0};
    uint64_t m_full GUARDED_BY(m_mutex){0};
};

} // namespace node

#endif // BITCOIN_NODE_TXADMISSION_H
