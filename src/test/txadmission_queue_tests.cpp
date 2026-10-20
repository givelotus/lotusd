// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txadmission.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <map>
#include <limits>
#include <thread>
#include <vector>

using node::TxAdmissionItem;
using node::TxAdmissionQueue;

namespace {

CTransactionRef MakeTx(uint32_t n) {
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(TxId(uint256::ONE), n));
    mtx.vout.emplace_back(Amount(int64_t(n) * SATOSHI), CScript());
    return MakeTransactionRef(std::move(mtx));
}

TxAdmissionItem Item(NodeId peer, uint32_t n) {
    return TxAdmissionItem{peer, MakeTx(n), SteadyClock::now(), nullptr};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(txadmission_queue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(retained_compact_bodies_share_a_lifetime_safe_byte_budget) {
    node::TxAdmissionRetainedBudget budget{64};
    auto a = budget.TryReserve(40);
    BOOST_REQUIRE(a.has_value());
    BOOST_CHECK(!budget.TryReserve(25));
    auto b = budget.TryReserve(24);
    BOOST_REQUIRE(b.has_value());
    BOOST_CHECK_EQUAL(budget.Used(), 64U);
    auto moved = std::move(*a);
    a.reset();
    BOOST_CHECK_EQUAL(budget.Used(), 64U);
    b.reset();
    BOOST_CHECK_EQUAL(budget.Used(), 40U);
    BOOST_CHECK(budget.TryReserve(24).has_value());
    BOOST_CHECK(!budget.TryReserve(std::numeric_limits<size_t>::max()));
    // A disconnected peer can retain a reservation after its manager dies.
    std::optional<node::TxAdmissionRetainedBudget::Reservation> surviving;
    {
        node::TxAdmissionRetainedBudget temporary{1};
        surviving.emplace(std::move(*temporary.TryReserve(1)));
    }
    surviving.reset();
}

BOOST_AUTO_TEST_CASE(retained_compact_body_budget_is_bounded_across_threads) {
    node::TxAdmissionRetainedBudget budget{64};
    std::atomic<bool> over_limit{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            for (int j = 0; j < 2000; ++j) {
                auto reservation = budget.TryReserve(17);
                if (budget.Used() > 64) over_limit.store(true);
            }
        });
    }
    for (auto &thread : threads) thread.join();
    BOOST_CHECK(!over_limit.load());
    BOOST_CHECK_EQUAL(budget.Used(), 0U);
}

BOOST_AUTO_TEST_CASE(round_robin_keeps_per_peer_order) {
    TxAdmissionQueue q{{}};
    // Peer 1 floods, peers 2 and 3 send a little.
    for (uint32_t i = 0; i < 10; ++i) {
        q.Push(Item(1, 100 + i));
    }
    q.Push(Item(2, 200));
    q.Push(Item(2, 201));
    q.Push(Item(3, 300));
    const auto batch = q.TakeBatch(6, std::chrono::milliseconds{0});
    std::vector<std::pair<NodeId, Amount>> got;
    for (const auto &item : batch) {
        got.emplace_back(item.peer, item.tx->vout[0].nValue);
    }
    // One per peer per turn; each peer's own order preserved.
    const std::vector<std::pair<NodeId, Amount>> expected{
        {1, 100 * SATOSHI}, {2, 200 * SATOSHI}, {3, 300 * SATOSHI},
        {1, 101 * SATOSHI}, {2, 201 * SATOSHI}, {1, 102 * SATOSHI}};
    BOOST_CHECK(got == expected);
    const auto rest = q.TakeBatch(100, std::chrono::milliseconds{0});
    BOOST_REQUIRE_EQUAL(rest.size(), 7U);
    for (size_t i = 0; i < rest.size(); ++i) {
        BOOST_CHECK_EQUAL(rest[i].peer, 1);
        BOOST_CHECK(rest[i].tx->vout[0].nValue == int64_t(103 + i) * SATOSHI);
    }
    BOOST_CHECK_EQUAL(q.GetStats().queued, 0U);
}

BOOST_AUTO_TEST_CASE(bounded_per_peer_total_and_bytes) {
    TxAdmissionQueue::Limits limits;
    limits.max_per_peer = 3;
    limits.max_total = 5;
    limits.max_total_bytes = 1 << 20;
    TxAdmissionQueue q{limits};
    for (uint32_t i = 0; i < 3; ++i) {
        BOOST_CHECK(q.HasRoom(1, MakeTx(0)->GetTotalSize()));
        q.Push(Item(1, i));
    }
    BOOST_CHECK(!q.HasRoom(1, MakeTx(0)->GetTotalSize()));
    BOOST_CHECK(q.HasRoom(2, MakeTx(0)->GetTotalSize()));
    q.Push(Item(2, 10));
    q.Push(Item(2, 11));
    // Total reached: nobody has room, including a new peer.
    BOOST_CHECK(!q.HasRoom(3, MakeTx(0)->GetTotalSize()));
    BOOST_CHECK(!q.HasRoom(2, MakeTx(0)->GetTotalSize(), /*count_full=*/false));
    auto stats = q.GetStats();
    BOOST_CHECK_EQUAL(stats.queued, 5U);
    BOOST_CHECK_EQUAL(stats.full, 2U);
    BOOST_CHECK_EQUAL(stats.peers, 2U);
    BOOST_CHECK(stats.queued_bytes > 0);

    // Bytes bound.
    limits.max_total_bytes = MakeTx(0)->GetTotalSize() * 2;
    TxAdmissionQueue small{limits};
    BOOST_CHECK(!small.HasRoom(1, limits.max_total_bytes + 1));
    small.Push(Item(1, 0));
    BOOST_CHECK(!small.HasRoom(2, MakeTx(0)->GetTotalSize() + 1));
    BOOST_CHECK(small.HasRoom(2, MakeTx(0)->GetTotalSize()));
    small.Push(Item(2, 1));
    BOOST_CHECK(!small.HasRoom(3, MakeTx(0)->GetTotalSize()));
    BOOST_CHECK(!small.Push(Item(3, 2)));
    BOOST_CHECK_EQUAL(small.GetStats().queued_bytes, limits.max_total_bytes);

    // A stale positive availability check cannot overfill the queue.
    TxAdmissionQueue race{{1, 1, 1 << 20}};
    BOOST_CHECK(race.HasRoom(1, MakeTx(0)->GetTotalSize()));
    BOOST_CHECK(race.HasRoom(2, MakeTx(0)->GetTotalSize()));
    BOOST_CHECK(race.Push(Item(1, 0)));
    BOOST_CHECK(!race.Push(Item(2, 1)));
    BOOST_CHECK_EQUAL(race.GetStats().queued, 1U);
}

BOOST_AUTO_TEST_CASE(drop_peer_take_all_and_interrupt) {
    TxAdmissionQueue q{{}};
    q.Push(Item(1, 0));
    q.Push(Item(2, 1));
    q.Push(Item(1, 2));
    const auto dropped = q.DropPeer(1);
    BOOST_CHECK_EQUAL(dropped.size(), 2U);
    BOOST_CHECK_EQUAL(q.GetStats().queued, 1U);
    const auto batch = q.TakeBatch(10, std::chrono::milliseconds{0});
    BOOST_REQUIRE_EQUAL(batch.size(), 1U);
    BOOST_CHECK_EQUAL(batch[0].peer, 2);

    q.Push(Item(3, 3));
    q.Push(Item(4, 4));
    BOOST_CHECK_EQUAL(q.TakeAll().size(), 2U);
    BOOST_CHECK_EQUAL(q.GetStats().queued_bytes, 0U);

    // A waiting consumer returns promptly when interrupted.
    std::thread consumer([&] {
        const auto none = q.TakeBatch(10, std::chrono::seconds{60});
        BOOST_CHECK(none.empty());
    });
    q.Interrupt();
    consumer.join();
    q.Push(Item(5, 5));
    BOOST_CHECK(q.TakeBatch(10, std::chrono::milliseconds{0}).empty());
}

BOOST_AUTO_TEST_CASE(concurrent_producers_and_consumer) {
    // Several producers and one consumer: everything pushed is taken exactly
    // once and each peer's order holds. Run under ThreadSanitizer.
    TxAdmissionQueue::Limits limits;
    limits.max_per_peer = 16;
    limits.max_total = 40;
    TxAdmissionQueue q{limits};
    constexpr int PEERS = 4;
    constexpr uint32_t PER_PEER = 500;
    std::vector<std::thread> producers;
    for (int p = 0; p < PEERS; ++p) {
        producers.emplace_back([&, p] {
            for (uint32_t i = 0; i < PER_PEER;) {
                if (q.HasRoom(p, MakeTx(0)->GetTotalSize(),
                              /*count_full=*/false)) {
                    if (q.Push(Item(p, i))) {
                        ++i;
                    }
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }
    std::map<NodeId, int64_t> last;
    size_t taken = 0;
    while (taken < PEERS * PER_PEER) {
        for (const auto &item :
             q.TakeBatch(32, std::chrono::milliseconds{10})) {
            const int64_t v = item.tx->vout[0].nValue / SATOSHI;
            auto it = last.find(item.peer);
            BOOST_CHECK(it == last.end() || it->second + 1 == v);
            last[item.peer] = v;
            ++taken;
        }
    }
    for (auto &t : producers) {
        t.join();
    }
    const auto stats = q.GetStats();
    BOOST_CHECK_EQUAL(stats.pushed, uint64_t{PEERS * PER_PEER});
    BOOST_CHECK_EQUAL(stats.taken, uint64_t{PEERS * PER_PEER});
    BOOST_CHECK_EQUAL(stats.queued, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
