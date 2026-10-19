// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the Rust tests in chronik-http subscription_limits.rs.

#include <chronik/native/subscription_limits.h>

#include <boost/test/unit_test.hpp>

#include <thread>
#include <vector>

using namespace chronik::native;

namespace {

SubscriptionClientKey IpKey(int octet) {
    return SubscriptionClientKey::Ip("1.2.3." + std::to_string(octet));
}

SubscriptionGuard Unwrap(SubscriptionAcquire acq) {
    BOOST_REQUIRE(acq);
    return std::move(*acq.guard);
}

SubscriptionLimitError UnwrapErr(SubscriptionAcquire acq) {
    BOOST_REQUIRE(!acq);
    BOOST_REQUIRE(acq.error);
    return *acq.error;
}

const SubscriptionLimitError PerClient(size_t n) {
    return {SubscriptionLimitError::Kind::PerClient, n};
}
const SubscriptionLimitError Global(size_t n) {
    return {SubscriptionLimitError::Kind::Global, n};
}

} // namespace

BOOST_AUTO_TEST_SUITE(ws_limits_tests)

BOOST_AUTO_TEST_CASE(enforces_per_client_limit) {
    auto limiter = SubscriptionLimiter::Create(100, 2);
    auto key = IpKey(1);
    auto guard1 = Unwrap(limiter->TryAcquire(key));
    auto guard2 = Unwrap(limiter->TryAcquire(key));
    BOOST_CHECK(UnwrapErr(limiter->TryAcquire(key)) == PerClient(2));
    BOOST_CHECK_EQUAL(limiter->Total(), 2u);
    BOOST_CHECK_EQUAL(limiter->ClientCount(key), 2u);
}

BOOST_AUTO_TEST_CASE(enforces_global_limit) {
    auto limiter = SubscriptionLimiter::Create(2, 100);
    auto guard1 = Unwrap(limiter->TryAcquire(IpKey(1)));
    auto guard2 = Unwrap(limiter->TryAcquire(IpKey(2)));
    BOOST_CHECK(UnwrapErr(limiter->TryAcquire(IpKey(3))) == Global(2));
    BOOST_CHECK_EQUAL(limiter->Total(), 2u);
}

BOOST_AUTO_TEST_CASE(release_on_drop_frees_slots) {
    auto limiter = SubscriptionLimiter::Create(10, 2);
    auto key = IpKey(1);
    {
        auto guard1 = Unwrap(limiter->TryAcquire(key));
        auto guard2 = Unwrap(limiter->TryAcquire(key));
        BOOST_CHECK_EQUAL(limiter->ClientCount(key), 2u);
    }
    BOOST_CHECK_EQUAL(limiter->Total(), 0u);
    BOOST_CHECK_EQUAL(limiter->ClientCount(key), 0u);
    BOOST_CHECK(!limiter->HasClient(key));
    auto guard3 = Unwrap(limiter->TryAcquire(key));
    BOOST_CHECK_EQUAL(limiter->ClientCount(key), 1u);
}

BOOST_AUTO_TEST_CASE(failed_acquire_does_not_insert_zero_count_entry) {
    auto limiter = SubscriptionLimiter::Create(1, 1);
    auto key1 = IpKey(1);
    auto key2 = IpKey(2);
    auto guard = Unwrap(limiter->TryAcquire(key1));

    BOOST_CHECK(UnwrapErr(limiter->TryAcquire(key1)) == PerClient(1));
    BOOST_CHECK_EQUAL(limiter->ClientCount(key1), 1u);

    BOOST_CHECK(UnwrapErr(limiter->TryAcquire(key2)) == Global(1));
    BOOST_CHECK(!limiter->HasClient(key2));
}

BOOST_AUTO_TEST_CASE(different_clients_are_independent) {
    auto limiter = SubscriptionLimiter::Create(10, 2);
    auto key1 = IpKey(1);
    auto key2 = IpKey(2);
    auto guard1_a = Unwrap(limiter->TryAcquire(key1));
    auto guard1_b = Unwrap(limiter->TryAcquire(key1));
    {
        auto guard2_a = Unwrap(limiter->TryAcquire(key2));
        auto guard2_b = Unwrap(limiter->TryAcquire(key2));
        BOOST_CHECK_EQUAL(limiter->ClientCount(key1), 2u);
        BOOST_CHECK_EQUAL(limiter->ClientCount(key2), 2u);
        BOOST_CHECK_EQUAL(limiter->Total(), 4u);
    }
    BOOST_CHECK_EQUAL(limiter->ClientCount(key1), 2u);
    BOOST_CHECK_EQUAL(limiter->ClientCount(key2), 0u);
    BOOST_CHECK_EQUAL(limiter->Total(), 2u);

    // Client 1 is still at its per-IP limit; client 2 can subscribe again.
    BOOST_CHECK(UnwrapErr(limiter->TryAcquire(key1)) == PerClient(2));
    auto guard2_c = Unwrap(limiter->TryAcquire(key2));
    BOOST_CHECK_EQUAL(limiter->ClientCount(key2), 1u);
    BOOST_CHECK_EQUAL(limiter->Total(), 3u);
}

BOOST_AUTO_TEST_CASE(guard_move_and_connection_keys) {
    auto limiter = SubscriptionLimiter::Create(10, 1);
    auto conn = SubscriptionClientKey::Connection(7);
    auto ip = SubscriptionClientKey::Ip("7");
    BOOST_CHECK(!(conn == ip));
    auto g1 = Unwrap(limiter->TryAcquire(conn));
    auto g2 = Unwrap(limiter->TryAcquire(ip));
    {
        SubscriptionGuard moved = std::move(g1);
        BOOST_CHECK_EQUAL(limiter->ClientCount(conn), 1u);
    }
    BOOST_CHECK_EQUAL(limiter->ClientCount(conn), 0u);
    BOOST_CHECK_EQUAL(limiter->Total(), 1u);
    // The guard keeps the limiter alive
    std::weak_ptr<SubscriptionLimiter> weak = limiter;
    limiter.reset();
    BOOST_CHECK(!weak.expired());
}

BOOST_AUTO_TEST_CASE(concurrent_acquire_respects_limits) {
    auto limiter = SubscriptionLimiter::Create(1000, 50);
    std::vector<std::thread> threads;
    std::vector<std::vector<SubscriptionGuard>> held(8);
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 100; ++i) {
                auto acq = limiter->TryAcquire(IpKey(t % 4));
                if (acq) {
                    held[t].push_back(std::move(*acq.guard));
                }
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }
    BOOST_CHECK_EQUAL(limiter->Total(), 200u);
    for (int k = 0; k < 4; ++k) {
        BOOST_CHECK_EQUAL(limiter->ClientCount(IpKey(k)), 50u);
    }
    held.clear();
    BOOST_CHECK_EQUAL(limiter->Total(), 0u);
}

BOOST_AUTO_TEST_CASE(error_messages) {
    BOOST_CHECK_EQUAL(Global(10'000'000).Message(),
                      "Global subscription limit of 10000000 exceeded");
    BOOST_CHECK_EQUAL(PerClient(75'000).Message(),
                      "Subscription limit of 75000 exceeded for this client");
    BOOST_CHECK_EQUAL(WsSubscriptionLimitErrorMessage(PerClient(2)),
                      "503: Subscription limit of 2 exceeded for this client");
    BOOST_CHECK_EQUAL(WsScriptTooLargeMessage(202, 201),
                      "400: Script subscription of 202 bytes exceeds the "
                      "maximum of 201 bytes");
    BOOST_CHECK_EQUAL(WsPluginGroupTooLargeMessage(5, 4),
                      "400: Plugin group of 5 bytes exceeds the maximum of 4 "
                      "bytes");
    BOOST_CHECK_EQUAL(MAX_WS_MESSAGE_SIZE, 20'000u);
}

BOOST_AUTO_TEST_CASE(optional_observer_preserves_limits_and_balances_guards) {
    int64_t active = 0;
    auto limiter = SubscriptionLimiter::Create(1, 1, [&](int32_t delta) {
        active += delta;
        throw 1;
    });
    {
        auto slot = limiter->TryAcquire(IpKey(1));
        BOOST_REQUIRE(slot);
        BOOST_CHECK_EQUAL(active, 1);
        BOOST_CHECK(!limiter->TryAcquire(IpKey(2)));
        BOOST_CHECK_EQUAL(active, 1);
        BOOST_CHECK_EQUAL(limiter->Total(), 1U);
    }
    BOOST_CHECK_EQUAL(active, 0);
    BOOST_CHECK_EQUAL(limiter->Total(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
