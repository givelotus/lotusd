// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// pause.rs has no Rust #[test]s; these cover its watch-channel semantics.

#include <chronik/native/error.h>
#include <chronik/native/pause.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace chronik::native;
using namespace std::chrono_literals;

namespace {
bool HasMsg(const ChronikError &e, std::string_view msg) {
    return std::string(e.what()) == msg;
}
} // namespace

BOOST_AUTO_TEST_SUITE(pause_tests)

BOOST_AUTO_TEST_CASE(not_allowed) {
    auto [pause, notify] = Pause::NewPair(false);
    BOOST_CHECK(!notify.IsPauseAllowed());
    BOOST_CHECK_EXCEPTION(notify.DoPause(), ChronikError, [](auto &e) {
        return HasMsg(e, "403: Pause is not allowed on this node; enable with "
                         "-chronikallowpause");
    });
    BOOST_CHECK_EXCEPTION(notify.Resume(), ChronikError, [](auto &e) {
        return HasMsg(e, PAUSE_NOT_ALLOWED_MSG);
    });
    BOOST_CHECK(!pause.IsPaused());
    pause.BlockIfPaused(); // never blocks
}

BOOST_AUTO_TEST_CASE(not_paused_does_not_block) {
    auto [pause, notify] = Pause::NewPair(true);
    std::vector<std::string> logs;
    pause.BlockIfPaused(
        [&](LogLevel, std::string_view msg) { logs.emplace_back(msg); });
    BOOST_CHECK(logs.empty());
    notify.DoPause();
    notify.Resume();
    notify.Resume(); // idempotent
    pause.BlockIfPaused();
    BOOST_CHECK(!pause.IsPaused());
}

BOOST_AUTO_TEST_CASE(pause_blocks_until_resume) {
    auto [pause, notify] = Pause::NewPair(true);
    notify.DoPause();
    notify.DoPause(); // idempotent
    BOOST_CHECK(pause.IsPaused());
    std::atomic<bool> returned{false};
    std::vector<std::pair<LogLevel, std::string>> logs;
    std::thread t([&] {
        pause.BlockIfPaused([&](LogLevel level, std::string_view msg) {
            logs.emplace_back(level, std::string(msg));
        });
        returned = true;
    });
    std::this_thread::sleep_for(50ms);
    BOOST_CHECK(!returned);
    notify.Resume();
    t.join();
    BOOST_CHECK(returned);
    BOOST_REQUIRE_EQUAL(logs.size(), 1u);
    BOOST_CHECK(logs[0].first == LogLevel::Info);
    BOOST_CHECK_EQUAL(logs[0].second,
                      "Chronik is paused, resume by calling /resume. To "
                      "disallow pausing on this node, remove the "
                      "-chronikallowpause arg.\n");
}

BOOST_AUTO_TEST_CASE(dropping_notify_resumes) {
    auto pair = Pause::NewPair(true);
    Pause pause = std::move(pair.first);
    auto notify = std::make_unique<PauseNotify>(std::move(pair.second));
    notify->DoPause();
    auto fut = std::async(std::launch::async, [&] { pause.BlockIfPaused(); });
    BOOST_CHECK(fut.wait_for(50ms) == std::future_status::timeout);
    notify.reset();
    BOOST_CHECK(fut.wait_for(5s) == std::future_status::ready);
    // Closed channel: still paused value, but blocking returns immediately
    pause.BlockIfPaused();
}

BOOST_AUTO_TEST_CASE(dropping_pause_fails_send) {
    auto pair = Pause::NewPair(true);
    auto pause = std::make_unique<Pause>(std::move(pair.first));
    PauseNotify notify = std::move(pair.second);
    pause.reset();
    BOOST_CHECK_EXCEPTION(notify.DoPause(), ChronikError, [](auto &e) {
        return HasMsg(e, "channel closed");
    });
    BOOST_CHECK_EXCEPTION(notify.Resume(), ChronikError, [](auto &e) {
        return HasMsg(e, PAUSE_CHANNEL_CLOSED_MSG);
    });
}

BOOST_AUTO_TEST_CASE(latest_value_wins) {
    auto [pause, notify] = Pause::NewPair(true);
    notify.DoPause();
    std::atomic<bool> returned{false};
    std::thread t([&] {
        pause.BlockIfPaused();
        returned = true;
    });
    std::this_thread::sleep_for(20ms);
    // Resume + Pause before the waiter observes it: only Resume releases it
    notify.Resume();
    t.join();
    BOOST_CHECK(returned);
    notify.DoPause();
    BOOST_CHECK(pause.IsPaused());
    notify.Resume();
}

BOOST_AUTO_TEST_SUITE_END()
