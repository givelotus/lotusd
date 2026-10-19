// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/sockwakeup.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <thread>

using namespace std::chrono_literals;

namespace {
bool Woken(const SockWakeup &w, std::chrono::milliseconds timeout) {
    Sock::Event occurred{0};
    return w.WaitSock()->Wait(timeout, Sock::RECV, &occurred) &&
           (occurred & Sock::RECV);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(sockwakeup_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(wake_and_drain) {
    auto w{SockWakeup::Make()};
    BOOST_REQUIRE(w);
    BOOST_CHECK(!Woken(*w, 0ms));
    // Many wakeups before a drain: one byte, one wakeup.
    for (int i = 0; i < 1000; ++i) {
        w->Wake();
    }
    BOOST_CHECK(Woken(*w, 0ms));
    w->Drain();
    BOOST_CHECK(!Woken(*w, 0ms));
    // After a drain, the next Wake() writes again.
    w->Wake();
    BOOST_CHECK(Woken(*w, 0ms));
    w->Drain();
    BOOST_CHECK(!Woken(*w, 0ms));
}

BOOST_AUTO_TEST_CASE(wake_from_another_thread_ends_a_wait) {
    auto w{SockWakeup::Make()};
    BOOST_REQUIRE(w);
    const auto start{std::chrono::steady_clock::now()};
    std::thread waker{[&] {
        std::this_thread::sleep_for(20ms);
        w->Wake();
    }};
    BOOST_CHECK(Woken(*w, 10s));
    waker.join();
    BOOST_CHECK(std::chrono::steady_clock::now() - start < 5s);
    w->Drain();
}

BOOST_AUTO_TEST_CASE(no_lost_wakeup_under_contention) {
    // A waiter loops wait/drain while another thread wakes it after each
    // change: every change must be seen without waiting for a timeout.
    auto w{SockWakeup::Make()};
    BOOST_REQUIRE(w);
    std::atomic<int> changes{0};
    constexpr int N{2000};
    std::thread waker{[&] {
        for (int i = 0; i < N; ++i) {
            changes.fetch_add(1);
            w->Wake();
        }
    }};
    int seen{0};
    while (seen < N) {
        // Look at the state, then wait (as SocketHandler does): a change
        // after the look is always followed by a wakeup.
        seen = changes.load();
        if (seen == N) {
            break;
        }
        BOOST_REQUIRE_MESSAGE(Woken(*w, 5s), "lost wakeup at " << seen);
        w->Drain();
    }
    waker.join();
}

BOOST_AUTO_TEST_CASE(loopback_pair) {
    // The Windows path, exercised on every platform.
    auto pair{SockWakeup::MakeLoopbackPair()};
    BOOST_REQUIRE(pair);
    auto &[recv, send] = *pair;
    const uint8_t byte{7};
    BOOST_CHECK_EQUAL(send->Send(&byte, 1, 0), 1);
    Sock::Event occurred{0};
    BOOST_CHECK(recv->Wait(5s, Sock::RECV, &occurred));
    uint8_t got{0};
    BOOST_CHECK_EQUAL(recv->Recv(&got, 1, 0), 1);
    BOOST_CHECK_EQUAL(got, 7);
    // Non-blocking: nothing more to read.
    BOOST_CHECK_EQUAL(recv->Recv(&got, 1, 0), -1);
}

BOOST_AUTO_TEST_SUITE_END()
