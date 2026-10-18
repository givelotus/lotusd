// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/async_waiter.h>
#include <test/util/setup_common.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <future>
#include <thread>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(rpc_async_waiter_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(notify_during_registration_and_worker_availability) {
    AsyncBlockChangeWaiter waiter;
    boost::asio::thread_pool pool(2);
    bool all_ready = true;
    bool workers_available = true;
    // Notify as soon as registration is visible, including the interval before
    // async_wait initiation. Missed cancellation must not wait for the deadline.
    for (unsigned round = 0; round < 100; ++round) {
        std::atomic<bool> ready{false};
        auto waiting = boost::asio::co_spawn(
            pool, waiter.WaitUntil(pool.get_executor(), 500ms,
                                   [&] { return ready.load(); }),
            boost::asio::use_future);
        const auto deadline = std::chrono::steady_clock::now() + 500ms;
        while (waiter.WaiterCount() == 0 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        std::promise<void> ping;
        auto ping_result = ping.get_future();
        boost::asio::post(pool, [&] { ping.set_value(); });
        workers_available &= ping_result.wait_for(100ms) == std::future_status::ready;
        ready = true;
        waiter.NotifyAll();
        all_ready &= waiting.wait_for(100ms) == std::future_status::ready;
        waiting.get();
        ping_result.get();
    }
    pool.join();
    BOOST_CHECK(workers_available);
    BOOST_CHECK(all_ready);
    BOOST_CHECK_EQUAL(waiter.WaiterCount(), 0U);
}

BOOST_AUTO_TEST_CASE(timeout_sign_and_zero_timeout_notification) {
    AsyncBlockChangeWaiter waiter;
    boost::asio::thread_pool pool(1);
    std::atomic<bool> cancel_negative{false};
    auto negative = boost::asio::co_spawn(
        pool, waiter.WaitUntil(pool.get_executor(), -1ms, [&] { return cancel_negative.load(); }),
        boost::asio::use_future);
    const bool negative_ready = negative.wait_for(100ms) == std::future_status::ready;
    cancel_negative = true;
    waiter.NotifyAll();
    // Use a mutable predicate for the unbounded timeout so cleanup is explicit.
    std::atomic<bool> done{false};
    auto zero = boost::asio::co_spawn(
        pool, waiter.WaitUntil(pool.get_executor(), 0ms, [&] { return done.load(); }),
        boost::asio::use_future);
    const bool initially_waiting = zero.wait_for(10ms) == std::future_status::timeout;
    done = true;
    waiter.NotifyAll();
    const bool notified = zero.wait_for(100ms) == std::future_status::ready;
    // Explicit predicate changes permit cleanup even when a timeout assertion fails.
    negative.get();
    zero.get();
    pool.join();
    BOOST_CHECK(negative_ready);
    BOOST_CHECK(initially_waiting);
    BOOST_CHECK(notified);
    BOOST_CHECK_EQUAL(waiter.WaiterCount(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
