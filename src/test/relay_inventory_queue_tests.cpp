// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/relay_inventory_queue.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace {

TxId QueueId(uint64_t value) {
    TxId id;
    for (size_t i = 0; i < sizeof(value); ++i) {
        id.begin()[i] = uint8_t(value >> (8 * i));
    }
    return id;
}

/** Full pending-set scan on every selection, deliberately independent of the
 * indexed heap/stale links in the implementation under test. */
class ReferenceQueue {
    struct Entry {
        std::optional<uint64_t> rank;
        uint64_t stale_order{0};
    };
    std::map<TxId, Entry> m_entries;
    uint64_t m_next_stale{0};

public:
    using Candidate = txrelay::RelayInventoryQueue::Candidate;

    bool SetRank(const TxId &id, std::optional<uint64_t> rank) {
        auto [it, inserted] = m_entries.try_emplace(id);
        if (!inserted && it->second.rank == rank) return false;
        if (!rank && (inserted || it->second.rank)) {
            it->second.stale_order = m_next_stale++;
        }
        it->second.rank = rank;
        return inserted;
    }

    std::optional<Candidate> Find(const TxId &id) const {
        const auto it = m_entries.find(id);
        if (it == m_entries.end()) return std::nullopt;
        return Candidate{it->first, it->second.rank};
    }

    bool Erase(const TxId &id) { return m_entries.erase(id) != 0; }
    void Clear() { m_entries.clear(); }
    size_t Size() const { return m_entries.size(); }
    size_t LiveSize() const {
        return std::count_if(m_entries.begin(), m_entries.end(),
                             [](const auto &entry) {
                                 return entry.second.rank.has_value();
                             });
    }

    std::optional<Candidate> Peek() const {
        const auto it = std::min_element(
            m_entries.begin(), m_entries.end(), [](const auto &a, const auto &b) {
                if (a.second.rank.has_value() != b.second.rank.has_value()) {
                    return a.second.rank.has_value();
                }
                if (a.second.rank) {
                    if (a.second.rank != b.second.rank) {
                        return a.second.rank < b.second.rank;
                    }
                    return a.first < b.first;
                }
                return a.second.stale_order < b.second.stale_order;
            });
        if (it == m_entries.end()) return std::nullopt;
        return Candidate{it->first, it->second.rank};
    }

    std::optional<Candidate> Pop() {
        auto first = Peek();
        if (first) m_entries.erase(first->txid);
        return first;
    }

    std::vector<Candidate> Prefix(size_t limit) const {
        ReferenceQueue remaining = *this;
        std::vector<Candidate> result;
        while (result.size() < limit) {
            auto first = remaining.Pop();
            if (!first) break;
            result.push_back(*first);
        }
        return result;
    }
};

template <typename Actual, typename Expected>
void CheckCandidate(const Actual &actual, const Expected &expected) {
    BOOST_REQUIRE_EQUAL(actual.has_value(), expected.has_value());
    if (!actual) return;
    BOOST_CHECK(actual->txid == expected->txid);
    BOOST_CHECK(actual->entry_id == expected->entry_id);
}

struct CountingRankLess {
    uint64_t *comparisons;
    bool operator()(uint64_t a, uint64_t b) const noexcept {
        ++*comparisons;
        return a < b;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(relay_inventory_queue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(live_rank_order_precedes_stale_tail) {
    txrelay::RelayInventoryQueue queue;
    BOOST_CHECK(!queue.Peek());
    BOOST_CHECK(!queue.Pop());
    BOOST_CHECK(!queue.Erase(QueueId(1)));
    BOOST_CHECK(queue.SetRank(QueueId(1), std::nullopt));
    BOOST_CHECK(queue.SetRank(QueueId(2), 30));
    BOOST_CHECK(queue.SetRank(QueueId(3), 10));
    BOOST_CHECK(queue.SetRank(QueueId(4), std::nullopt));
    BOOST_CHECK(queue.SetRank(QueueId(5), 20));
    BOOST_CHECK_EQUAL(queue.Size(), 5U);
    BOOST_CHECK_EQUAL(queue.LiveSize(), 3U);
    BOOST_CHECK_EQUAL(queue.StaleSize(), 2U);
    for (uint64_t value : {3, 5, 2, 1, 4}) {
        auto first = queue.Peek();
        BOOST_REQUIRE(first);
        BOOST_CHECK(first->txid == QueueId(value));
        CheckCandidate(queue.Pop(), first);
        BOOST_CHECK(!queue.Find(QueueId(value)));
    }
    BOOST_CHECK(queue.Empty());
    BOOST_CHECK_EQUAL(queue.LiveSize(), 0U);
    BOOST_CHECK_EQUAL(queue.StaleSize(), 0U);
}

BOOST_AUTO_TEST_CASE(rekey_and_admission_incarnation_lifecycle) {
    txrelay::RelayInventoryQueue queue;
    queue.SetRank(QueueId(1), std::nullopt);
    queue.SetRank(QueueId(2), 20);
    queue.SetRank(QueueId(3), 30);
    // Initially absent -> live must move ahead of an already queued later
    // admission; a heap that only repairs its old live top misses this case.
    BOOST_CHECK(!queue.SetRank(QueueId(1), 10));
    BOOST_CHECK(queue.Peek()->txid == QueueId(1));
    // Removal/re-admission raises the current rank and moves the former top.
    BOOST_CHECK(!queue.SetRank(QueueId(1), 40));
    BOOST_CHECK(queue.Peek()->txid == QueueId(2));
    queue.SetRank(QueueId(2), std::nullopt);
    queue.SetRank(QueueId(3), std::nullopt);
    BOOST_CHECK(queue.Pop()->txid == QueueId(1));
    // Duplicate stale updates preserve tail order and allocate no record.
    for (size_t i = 0; i < 1000; ++i) {
        BOOST_CHECK(!queue.SetRank(QueueId(2), std::nullopt));
        BOOST_CHECK_EQUAL(queue.Size(), 2U);
    }
    queue.SetRank(QueueId(2), 50);
    queue.SetRank(QueueId(2), std::nullopt);
    BOOST_CHECK(queue.Pop()->txid == QueueId(3));
    BOOST_CHECK(queue.Pop()->txid == QueueId(2));
    BOOST_CHECK(queue.Empty());
    // Full removal and re-enqueue has one new incarnation, not a tombstone
    // alongside the old rank. This also models erase when a peer knows a tx.
    queue.SetRank(QueueId(1), 60);
    BOOST_CHECK(queue.Erase(QueueId(1)));
    BOOST_CHECK(queue.SetRank(QueueId(1), 70));
    BOOST_CHECK_EQUAL(queue.Size(), 1U);
    BOOST_CHECK(queue.Pop()->entry_id == std::optional<uint64_t>{70});
    BOOST_CHECK(queue.Empty());
}

BOOST_AUTO_TEST_CASE(erase_heap_positions_and_stale_links) {
    txrelay::RelayInventoryQueue queue;
    ReferenceQueue reference;
    for (uint64_t i = 0; i < 64; ++i) {
        const std::optional<uint64_t> rank = i % 2
            ? std::optional<uint64_t>{100 - i} : std::nullopt;
        queue.SetRank(QueueId(i), rank);
        reference.SetRank(QueueId(i), rank);
    }
    // Includes live root/leaf/interior and stale head/tail/interior.
    for (uint64_t i : {63, 1, 31, 0, 62, 32}) {
        BOOST_CHECK_EQUAL(queue.Erase(QueueId(i)), reference.Erase(QueueId(i)));
    }
    queue.SetRank(QueueId(3), 1);
    reference.SetRank(QueueId(3), 1);
    queue.SetRank(QueueId(61), 200);
    reference.SetRank(QueueId(61), 200);
    while (!queue.Empty()) CheckCandidate(queue.Pop(), reference.Pop());
    BOOST_CHECK_EQUAL(reference.Size(), 0U);
    queue.Clear();
    queue.Clear();
    queue.SetRank(QueueId(9), std::nullopt);
    queue.SetRank(QueueId(10), 1);
    queue.Clear();
    BOOST_CHECK(!queue.Peek());
    BOOST_CHECK_EQUAL(queue.LiveSize(), 0U);
    BOOST_CHECK_EQUAL(queue.StaleSize(), 0U);
    BOOST_CHECK(queue.SetRank(QueueId(9), 2));
    BOOST_CHECK(queue.Pop()->txid == QueueId(9));
}

BOOST_AUTO_TEST_CASE(deterministic_reference_model_churn) {
    txrelay::RelayInventoryQueue queue;
    ReferenceQueue reference;
    uint64_t state = 0x123456789abcdef0;
    auto next = [&] {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return state;
    };
    for (size_t step = 0; step < 5000; ++step) {
        const auto id = QueueId((next() >> 16) % 128);
        const auto operation = (next() >> 16) % 16;
        if (operation < 10) {
            const std::optional<uint64_t> rank = operation < 3
                ? std::nullopt : std::optional<uint64_t>{next() % 1000};
            BOOST_CHECK_EQUAL(queue.SetRank(id, rank), reference.SetRank(id, rank));
        } else if (operation < 13) {
            BOOST_CHECK_EQUAL(queue.Erase(id), reference.Erase(id));
        } else if (operation < 15) {
            CheckCandidate(queue.Pop(), reference.Pop());
        } else {
            queue.Clear();
            reference.Clear();
        }
        BOOST_CHECK_EQUAL(queue.Size(), reference.Size());
        BOOST_CHECK_EQUAL(queue.LiveSize(), reference.LiveSize());
        BOOST_CHECK_EQUAL(queue.Size(), queue.LiveSize() + queue.StaleSize());
        CheckCandidate(queue.Peek(), reference.Peek());
        CheckCandidate(queue.Find(id), reference.Find(id));
    }
    while (!queue.Empty()) CheckCandidate(queue.Pop(), reference.Pop());
    BOOST_CHECK_EQUAL(reference.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(prefix_matches_reference_and_preserves_queue) {
    txrelay::RelayInventoryQueue queue;
    ReferenceQueue reference;
    for (uint64_t i = 0; i < 127; ++i) {
        const std::optional<uint64_t> rank = i % 3
            ? std::optional<uint64_t>{127 - i} : std::nullopt;
        queue.SetRank(QueueId(i), rank);
        reference.SetRank(QueueId(i), rank);
    }
    auto check_prefix = [&](size_t limit) {
        const size_t size_before = queue.Size();
        const size_t live_before = queue.LiveSize();
        const size_t stale_before = queue.StaleSize();
        const auto actual = queue.PeekPrefix(limit);
        const auto expected = reference.Prefix(limit);
        BOOST_REQUIRE_EQUAL(actual.size(), expected.size());
        for (size_t i = 0; i < actual.size(); ++i) {
            BOOST_CHECK(actual[i].txid == expected[i].txid);
            BOOST_CHECK(actual[i].entry_id == expected[i].entry_id);
        }
        BOOST_CHECK_EQUAL(queue.Size(), size_before);
        BOOST_CHECK_EQUAL(queue.LiveSize(), live_before);
        BOOST_CHECK_EQUAL(queue.StaleSize(), stale_before);
        CheckCandidate(queue.Peek(), reference.Peek());
    };
    // Includes zero, heap boundary, live/stale crossing and over-large limit.
    for (size_t limit : {size_t{0}, size_t{1}, size_t{17}, queue.LiveSize(),
                         queue.LiveSize() + 1, queue.Size(), queue.Size() + 1}) {
        check_prefix(limit);
    }
    for (uint64_t i = 0; i < 127; ++i) {
        const auto id = QueueId(i);
        if (i % 4 == 0) {
            queue.Erase(id);
            reference.Erase(id);
        } else {
            const std::optional<uint64_t> rank = i % 5
                ? std::optional<uint64_t>{i + 500} : std::nullopt;
            queue.SetRank(id, rank);
            reference.SetRank(id, rank);
        }
        check_prefix(17);
    }
    while (!queue.Empty()) CheckCandidate(queue.Pop(), reference.Pop());
    BOOST_CHECK(queue.PeekPrefix(100).empty());
    queue.SetRank(QueueId(1), std::nullopt);
    queue.SetRank(QueueId(2), std::nullopt);
    reference.SetRank(QueueId(1), std::nullopt);
    reference.SetRank(QueueId(2), std::nullopt);
    check_prefix(3);
    queue.Clear();
    reference.Clear();
    BOOST_CHECK(queue.PeekPrefix(1).empty());
}

BOOST_AUTO_TEST_CASE(unchanged_backlog_has_no_scan_or_rebuild) {
    uint64_t comparisons = 0;
    txrelay::BasicRelayInventoryQueue<CountingRankLess> queue{{&comparisons}};
    constexpr size_t backlog = 100000;
    constexpr size_t budget = 17;
    for (size_t i = 0; i < backlog; ++i) {
        queue.SetRank(QueueId(i), i + 1);
    }
    comparisons = 0;
    // Looking at an unchanged backlog does no comparisons or rank resolution.
    // The only index access is the existing root, even over repeated turns.
    for (size_t turn = 0; turn < 1000; ++turn) {
        BOOST_REQUIRE(queue.Peek());
        BOOST_CHECK(queue.Peek()->txid == QueueId(0));
    }
    BOOST_CHECK_EQUAL(comparisons, 0U);
    for (size_t turn = 0; turn < 10; ++turn) {
        const uint64_t before_prefix = comparisons;
        const auto prefix = queue.PeekPrefix(budget);
        BOOST_REQUIRE_EQUAL(prefix.size(), budget);
        for (size_t i = 0; i < prefix.size(); ++i) {
            BOOST_CHECK(prefix[i].txid == QueueId(turn * budget + i));
        }
        // A bounded read walks only the frontier; it does not copy/heapify
        // the 100K-entry backlog or change pending membership.
        BOOST_CHECK_LT(comparisons - before_prefix, 64 * budget);
        BOOST_CHECK_EQUAL(queue.Size(), backlog - turn * budget);
        const uint64_t before = comparisons;
        for (size_t sent = 0; sent < budget; ++sent) {
            auto first = queue.Pop();
            BOOST_REQUIRE(first);
            BOOST_CHECK(first->txid == QueueId(turn * budget + sent));
        }
        // 100K candidates have at most 17 heap levels. Allow 64 comparisons
        // per pop, far below one full-backlog pass even for this tiny budget.
        BOOST_CHECK_LT(comparisons - before, 64 * budget);
    }
    BOOST_CHECK_EQUAL(queue.Size(), backlog - 10 * budget);
    queue.Clear();
    BOOST_CHECK(queue.Empty());
    BOOST_CHECK_EQUAL(queue.LiveSize(), 0U);
    BOOST_CHECK_EQUAL(queue.StaleSize(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
