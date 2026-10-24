// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_RELAY_INVENTORY_QUEUE_H
#define BITCOIN_NET_RELAY_INVENTORY_QUEUE_H

#include <primitives/txid.h>
#include <util/hasher.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace txrelay {

struct RelayRankLess {
    bool operator()(uint64_t a, uint64_t b) const noexcept { return a < b; }
};

/** An indexed queue of pending transaction IDs, without transaction bodies.
 *
 * Live records precede stale records and are ordered by supplied admission ID.
 * Stale records retain their order of becoming stale. The caller supplies
 * authoritative rank updates: this container does not discover membership or
 * re-admission. In particular, Peek() is not a mempool membership check.
 *
 * There is one owning map node per TxId. Heap/stale links refer to that node;
 * erase and rekey leave no obsolete heap entries. No internal synchronization
 * is provided. The eventual caller must serialize every operation, including
 * reads, using its inventory ownership protocol.
 *
 * RankLess is injectable for operation-count tests and must not throw.
 */
template <typename RankLess = RelayRankLess> class BasicRelayInventoryQueue {
    static_assert(std::is_nothrow_invocable_r_v<bool, const RankLess &, uint64_t,
                                               uint64_t>);

public:
    struct Candidate {
        TxId txid;
        std::optional<uint64_t> entry_id;
    };

private:
    struct Record;
    using Entries = std::unordered_map<TxId, Record, SaltedTxIdHasher>;
    using Node = typename Entries::value_type;
    struct Record {
        std::optional<uint64_t> entry_id;
        size_t heap_index{0};
        Node *previous{nullptr};
        Node *next{nullptr};
    };

    Entries m_entries;
    // Unordered-map rehash preserves pointers to its nodes.
    std::vector<Node *> m_heap;
    Node *m_stale_head{nullptr};
    Node *m_stale_tail{nullptr};
    size_t m_stale_size{0};
    [[no_unique_address]] RankLess m_less;

    bool Earlier(const Node *a, const Node *b) const noexcept {
        assert(a->second.entry_id && b->second.entry_id);
        if (a->second.entry_id != b->second.entry_id) {
            return m_less(*a->second.entry_id, *b->second.entry_id);
        }
        // Admission IDs are unique in the mempool. Define ties so isolated
        // users/tests still have a deterministic strict ordering.
        return a->first < b->first;
    }

    void SwapHeap(size_t a, size_t b) noexcept {
        std::swap(m_heap[a], m_heap[b]);
        m_heap[a]->second.heap_index = a;
        m_heap[b]->second.heap_index = b;
    }

    void SiftUp(size_t index) noexcept {
        while (index != 0) {
            const size_t parent = (index - 1) / 2;
            if (!Earlier(m_heap[index], m_heap[parent])) break;
            SwapHeap(index, parent);
            index = parent;
        }
    }

    void SiftDown(size_t index) noexcept {
        // This form also avoids overflowing 2 * index + 1 at a leaf.
        while (index < m_heap.size() / 2) {
            size_t child = 2 * index + 1;
            if (child + 1 < m_heap.size() &&
                Earlier(m_heap[child + 1], m_heap[child])) {
                ++child;
            }
            if (!Earlier(m_heap[child], m_heap[index])) break;
            SwapHeap(index, child);
            index = child;
        }
    }

    void FixHeap(size_t index) noexcept {
        if (index != 0 && Earlier(m_heap[index], m_heap[(index - 1) / 2])) {
            SiftUp(index);
        } else {
            SiftDown(index);
        }
    }

    void RemoveHeap(size_t index) noexcept {
        const size_t last = m_heap.size() - 1;
        if (index != last) SwapHeap(index, last);
        m_heap.pop_back();
        if (index < m_heap.size()) FixHeap(index);
    }

    void AppendStale(Node *node) noexcept {
        node->second.previous = m_stale_tail;
        node->second.next = nullptr;
        if (m_stale_tail) {
            m_stale_tail->second.next = node;
        } else {
            m_stale_head = node;
        }
        m_stale_tail = node;
        ++m_stale_size;
    }

    void UnlinkStale(Node *node) noexcept {
        auto &record = node->second;
        if (record.previous) {
            record.previous->second.next = record.next;
        } else {
            m_stale_head = record.next;
        }
        if (record.next) {
            record.next->second.previous = record.previous;
        } else {
            m_stale_tail = record.previous;
        }
        record.previous = record.next = nullptr;
        --m_stale_size;
    }

    void EraseNode(Node *node) {
        if (node->second.entry_id) {
            RemoveHeap(node->second.heap_index);
        } else {
            UnlinkStale(node);
        }
        m_entries.erase(node->first);
    }

    Node *First() const noexcept {
        return m_heap.empty() ? m_stale_head : m_heap.front();
    }

public:
    explicit BasicRelayInventoryQueue(RankLess less = {})
        : m_less(std::move(less)) {}

    // A memberwise copy/move would leave node links owned by another queue.
    BasicRelayInventoryQueue(const BasicRelayInventoryQueue &) = delete;
    BasicRelayInventoryQueue &operator=(const BasicRelayInventoryQueue &) = delete;
    BasicRelayInventoryQueue(BasicRelayInventoryQueue &&) = delete;
    BasicRelayInventoryQueue &operator=(BasicRelayInventoryQueue &&) = delete;

    size_t Size() const noexcept { return m_entries.size(); }
    size_t LiveSize() const noexcept { return m_heap.size(); }
    size_t StaleSize() const noexcept { return m_stale_size; }
    bool Empty() const noexcept { return m_entries.empty(); }

    std::optional<Candidate> Find(const TxId &txid) const {
        const auto it = m_entries.find(txid);
        if (it == m_entries.end()) return std::nullopt;
        return Candidate{it->first, it->second.entry_id};
    }

    /** Insert or rekey the single record for txid. Return true on insertion.
     * A duplicate with unchanged rank does not change stale-tail position.
     * Allocation failure leaves existing membership/rank/order unchanged.
     */
    bool SetRank(const TxId &txid, std::optional<uint64_t> entry_id) {
        auto [it, inserted] = m_entries.try_emplace(txid);
        Node *node = &*it;
        auto &record = node->second;
        if (!inserted && record.entry_id == entry_id) return false;

        if (entry_id) {
            if (inserted || !record.entry_id) {
                // Allocate before unlinking a stale record. On failure an
                // existing record remains exactly where it was.
                try {
                    m_heap.push_back(node);
                } catch (...) {
                    if (inserted) m_entries.erase(it);
                    throw;
                }
                if (!inserted) UnlinkStale(node);
                record.entry_id = entry_id;
                record.heap_index = m_heap.size() - 1;
                SiftUp(record.heap_index);
            } else {
                record.entry_id = entry_id;
                FixHeap(record.heap_index);
            }
        } else {
            if (!inserted) RemoveHeap(record.heap_index);
            record.entry_id.reset();
            AppendStale(node);
        }
        return inserted;
    }

    bool Erase(const TxId &txid) {
        const auto it = m_entries.find(txid);
        if (it == m_entries.end()) return false;
        EraseNode(&*it);
        return true;
    }

    std::optional<Candidate> Peek() const {
        const Node *node = First();
        if (!node) return std::nullopt;
        return Candidate{node->first, node->second.entry_id};
    }

    /** Copy at most limit candidates in selection order without changing the
     * queue. Walk a heap-index frontier, not a copy/scan of the whole heap.
     * Work is O(k log(k + 1)) and temporary/result storage O(k), for k returned
     * candidates. All allocations affect local vectors only; failure leaves
     * the queue unchanged. Stale-tail records follow all live candidates.
     */
    std::vector<Candidate> PeekPrefix(size_t limit) const {
        std::vector<Candidate> result;
        if (limit == 0) return result;
        result.reserve(std::min(limit, Size()));
        std::vector<size_t> frontier;
        auto later = [&](size_t a, size_t b) noexcept {
            return Earlier(m_heap[b], m_heap[a]);
        };
        if (!m_heap.empty()) frontier.push_back(0);
        while (!frontier.empty() && result.size() < limit) {
            std::pop_heap(frontier.begin(), frontier.end(), later);
            const size_t index = frontier.back();
            frontier.pop_back();
            const Node *node = m_heap[index];
            result.push_back({node->first, node->second.entry_id});
            if (index < m_heap.size() / 2) {
                const size_t left = 2 * index + 1;
                frontier.push_back(left);
                std::push_heap(frontier.begin(), frontier.end(), later);
                if (left + 1 < m_heap.size()) {
                    frontier.push_back(left + 1);
                    std::push_heap(frontier.begin(), frontier.end(), later);
                }
            }
        }
        const Node *stale = m_stale_head;
        while (stale && result.size() < limit) {
            result.push_back({stale->first, std::nullopt});
            stale = stale->second.next;
        }
        return result;
    }

    std::optional<Candidate> Pop() {
        Node *node = First();
        if (!node) return std::nullopt;
        Candidate result{node->first, node->second.entry_id};
        EraseNode(node);
        return result;
    }

    void Clear() noexcept {
        m_heap.clear();
        m_stale_head = m_stale_tail = nullptr;
        m_stale_size = 0;
        m_entries.clear();
    }
};

using RelayInventoryQueue = BasicRelayInventoryQueue<>;

} // namespace txrelay

#endif // BITCOIN_NET_RELAY_INVENTORY_QUEUE_H
