// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/common.h>
#include <logging.h>
#include <logging/timer.h>
#include <scheduler.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/string.h>
#include <util/threadnames.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <future>
#include <ios>
#include <iostream>
#include <source_location>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>
#ifndef WIN32
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

using util::RemovePrefix;
using util::SplitString;
using util::TrimString;

namespace BCLog {
/** Test-only access: hold the consumer wake mutex while producers publish. */
struct LoggerTestAccess {
    static StdMutex &WakeMutex(Logger &logger) { return logger.m_wake_mutex; }
    static StdMutex &ConsumerMutex(Logger &logger) {
        return logger.m_consumer_mutex;
    }
    static void ResetWake(Logger &logger) { logger.m_wake_requested = false; }
};
} // namespace BCLog

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static void ResetLogger() {
    LogInstance().SetLogLevel(BCLog::DEFAULT_LOG_LEVEL);
    LogInstance().SetCategoryLogLevel({});
}

static const std::string FLUSH_SENTINEL_LOG_MESSAGE{
    "Sentinel log to reopen log file"};
static void flush_debug_log() {
    // Reopening the log file makes sure earlier lines reached the file
    // (the sentinel itself is skipped by ReadDebugLogLines).
    LogInstance().m_reopen_file = true;
    LogPrintf("%s\n", FLUSH_SENTINEL_LOG_MESSAGE);
}

/** Lines of the debug log (all queued lines written), without sentinels */
static std::vector<std::string> ReadDebugLogLines() {
    LogInstance().Flush();
    std::vector<std::string> lines;
    std::ifstream ifs{LogInstance().m_file_path};
    for (std::string line; std::getline(ifs, line);) {
        if (line.find(FLUSH_SENTINEL_LOG_MESSAGE) == std::string::npos) {
            lines.push_back(std::move(line));
        }
    }
    return lines;
}

struct LogSetup : public BasicTestingSetup {
    fs::path prev_log_path;
    fs::path tmp_log_path;
    bool prev_reopen_file;
    bool prev_print_to_file;
    bool prev_log_timestamps;
    bool prev_log_threadnames;
    bool prev_log_sourcelocations;
    BCLog::LogFormat prev_log_format;
    std::unordered_map<BCLog::LogFlags, BCLog::Level> prev_category_levels;
    BCLog::Level prev_log_level;
    uint32_t prev_category_mask;

    LogSetup()
        : prev_log_path{LogInstance().m_file_path},
          tmp_log_path{m_args.GetDataDirBase() / "tmp_debug.log"},
          prev_reopen_file{LogInstance().m_reopen_file},
          prev_print_to_file{LogInstance().m_print_to_file},
          prev_log_timestamps{LogInstance().m_log_timestamps},
          prev_log_threadnames{LogInstance().m_log_threadnames},
          prev_log_sourcelocations{LogInstance().m_log_sourcelocations},
          prev_log_format{LogInstance().m_log_format},
          prev_category_levels{LogInstance().CategoryLevels()},
          prev_log_level{LogInstance().LogLevel()},
          prev_category_mask{LogInstance().GetCategoryMask()} {
        // Lines queued so far belong to the previous log file.
        LogInstance().Flush();
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        // Prevent tests from failing when the line number of the logs changes.
        LogInstance().m_log_sourcelocations = false;

        LogInstance().SetLogLevel(BCLog::Level::Debug);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().SetCategoryLogLevel({});
        LogInstance().SetRateLimiting(nullptr);
    }

    ~LogSetup() {
        LogInstance().Flush();
        LogInstance().m_log_format = prev_log_format;
        LogInstance().m_file_path = prev_log_path;
        LogPrintf("Sentinel log to reopen log file\n");
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
        LogInstance().SetLogLevel(prev_log_level);
        LogInstance().SetCategoryLogLevel(prev_category_levels);
        LogInstance().SetRateLimiting(nullptr);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().EnableCategory(BCLog::LogFlags{prev_category_mask});
    }
};

#ifndef WIN32
BOOST_FIXTURE_TEST_CASE(logging_fork_preserves_delivery, LogSetup) {
    LogPrintf("fork parent queued once\n");
    // Exercise consecutive fork/restart cycles, child error barriers and
    // child delivery. Each wait is bounded so a lifecycle regression fails.
    for (int cycle{0}; cycle < 2; ++cycle) {
        const pid_t pid{LogInstance().ForkProcess()};
        BOOST_REQUIRE_GE(pid, 0);
        if (pid == 0) {
            LogWarning("fork child warning %d\n", cycle);
            LogError("fork child plain error %d\n", cycle);
            LogInstance().Flush();
            _exit(0);
        }
        int status{0};
        pid_t waited{0};
        const auto deadline{std::chrono::steady_clock::now() +
                            std::chrono::seconds{5}};
        do {
            waited = waitpid(pid, &status, WNOHANG);
            if (waited != 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        } while (std::chrono::steady_clock::now() < deadline);
        if (waited == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
        BOOST_REQUIRE_EQUAL(waited, pid);
        BOOST_REQUIRE(WIFEXITED(status));
        BOOST_CHECK_EQUAL(WEXITSTATUS(status), 0);
        LogError("fork parent continued %d\n", cycle);
    }
    const auto lines{ReadDebugLogLines()};
    const auto count = [&](std::string_view message) {
        return std::count_if(lines.begin(), lines.end(), [&](const auto &line) {
            return line.find(message) != std::string::npos;
        });
    };
    BOOST_CHECK_EQUAL(count("fork parent queued once"), 1);
    BOOST_CHECK_EQUAL(count("fork child warning"), 2);
    BOOST_CHECK_EQUAL(count("fork child plain error"), 2);
    BOOST_CHECK_EQUAL(count("fork parent continued"), 2);
}
#endif

BOOST_FIXTURE_TEST_CASE(logging_LogPrintf_, LogSetup) {
    LogInstance().m_log_sourcelocations = true;

    struct Case {
        std::string msg;
        BCLog::LogFlags category;
        BCLog::Level level;
        std::string prefix;
        std::source_location loc;
    };

    std::vector<Case> cases = {
        {"foo1: bar1", BCLog::NET, BCLog::Level::Debug, "[net] ",
         std::source_location::current()},
        {"foo2: bar2", BCLog::NET, BCLog::Level::Info, "[net:info] ",
         std::source_location::current()},
        {"foo3: bar3", BCLog::ALL, BCLog::Level::Debug, "[debug] ",
         std::source_location::current()},
        {"foo4: bar4", BCLog::ALL, BCLog::Level::Info, "",
         std::source_location::current()},
        {"foo5: bar5", BCLog::NONE, BCLog::Level::Debug, "[debug] ",
         std::source_location::current()},
        {"foo6: bar6", BCLog::NONE, BCLog::Level::Info, "",
         std::source_location::current()},
    };

    std::vector<std::string> expected;
    for (auto &[msg, category, level, prefix, loc] : cases) {
        std::ostringstream oss;
        tfm::format(oss, "[%s:%s] [%s] %s%s",
                    RemovePrefix(loc.file_name(), "./"), loc.line(),
                    loc.function_name(), prefix, msg);
        expected.push_back(oss.str());
        // Note: this test relies on LogPrintStr to automatically add the
        // trailing \n. This will be backported in PR #30929, for now we add it
        // manually.
        LogInstance().LogPrintStr(msg + "\n", std::move(loc), category, level,
                                  /*site=*/nullptr);
    }

    flush_debug_log();
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(),
                                  expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacrosDeprecated, LogSetup) {
    LogInstance().EnableCategory(BCLog::NET);
    LogPrintf("foo5: %s\n", "bar5");
    LogDebug(BCLog::NET, "foo6: %s\n", "bar6");
    // Trace is not logged by default
    LogPrintLevel(BCLog::NET, BCLog::Level::Trace, "foo4: %s\n", "bar4");
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "foo7: %s\n", "bar7");
    LogPrintLevel(BCLog::NET, BCLog::Level::Info, "foo8: %s\n", "bar8");
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo9: %s\n", "bar9");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo10: %s\n", "bar10");
    flush_debug_log();
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    std::vector<std::string> expected = {"foo5: bar5",
                                         "[net] foo6: bar6",
                                         "[net] foo7: bar7",
                                         "[net:info] foo8: bar8",
                                         "[net:warning] foo9: bar9",
                                         "[net:error] foo10: bar10"};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(),
                                  expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros, LogSetup) {
    LogInstance().EnableCategory(BCLog::NET);
    // Trace is not logged by default
    LogTrace(BCLog::NET, "foo6: %s\n", "bar6");
    LogDebug(BCLog::NET, "foo7: %s\n", "bar7");
    LogInfo("foo8: %s\n", "bar8");
    LogWarning("foo9: %s\n", "bar9");
    LogError("foo10: %s\n", "bar10");
    flush_debug_log();
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    std::vector<std::string> expected = {
        "[net] foo7: bar7",
        "foo8: bar8",
        "[warning] foo9: bar9",
        "[error] foo10: bar10",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(),
                                  expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros_CategoryName, LogSetup) {
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    const auto concatenated_category_names =
        LogInstance().LogCategoriesString();
    std::vector<std::pair<BCLog::LogFlags, std::string>>
        expected_category_names;
    const auto category_names = SplitString(concatenated_category_names, ',');
    for (const auto &category_name : category_names) {
        BCLog::LogFlags category;
        const auto trimmed_category_name = TrimString(category_name);
        BOOST_REQUIRE(GetLogCategory(category, trimmed_category_name));
        expected_category_names.emplace_back(category, trimmed_category_name);
    }

    std::vector<std::string> expected;
    for (const auto &[category, name] : expected_category_names) {
        LogDebug(category, "foo: %s\n", "bar");
        std::string expected_log = "[";
        expected_log += name;
        expected_log += "] foo: bar";
        expected.push_back(expected_log);
    }
    flush_debug_log();

    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(),
                                  expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_SeverityLevels, LogSetup) {
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    LogInstance().SetCategoryLogLevel(/*category_str=*/"net",
                                      /*level_str=*/"info");

    // Global log level
    LogPrintLevel(BCLog::HTTP, BCLog::Level::Info, "foo1: %s\n", "bar1");
    LogPrintLevel(BCLog::MEMPOOL, BCLog::Level::Trace,
                  "foo2: %s. This log level is lower than the global one.\n",
                  "bar2");
    LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Warning, "foo3: %s\n",
                  "bar3");
    LogPrintLevel(BCLog::RPC, BCLog::Level::Error, "foo4: %s\n", "bar4");

    // Category-specific log level
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo5: %s\n", "bar5");
    LogPrintLevel(
        BCLog::NET, BCLog::Level::Debug,
        "foo6: %s. This log level is the same as the global one but lower than "
        "the category-specific one, which takes precedence. \n",
        "bar6");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo7: %s\n", "bar7");
    flush_debug_log();

    std::vector<std::string> expected = {
        "[http:info] foo1: bar1", "[validation:warning] foo3: bar3",
        "[rpc:error] foo4: bar4", "[net:warning] foo5: bar5",
        "[net:error] foo7: bar7",
    };
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(),
                                  expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_Conf, LogSetup) {
    // Set global log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST);
        const char *argv_test[] = {"bitcoind", "-loglevel=debug"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));
        init::SetLoggingLevel(args);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);
    }

    // Set category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST);
        const char *argv_test[] = {"bitcoind", "-loglevel=net:trace"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));
        init::SetLoggingLevel(args);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::DEFAULT_LOG_LEVEL);

        const auto &category_levels{LogInstance().CategoryLevels()};
        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_REQUIRE(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);
    }

    // Set both global log level and category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST);
        const char *argv_test[] = {"bitcoind", "-loglevel=debug",
                                   "-loglevel=net:trace",
                                   "-loglevel=http:info"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(4, argv_test, err));
        init::SetLoggingLevel(args);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);

        const auto &category_levels{LogInstance().CategoryLevels()};
        BOOST_CHECK_EQUAL(category_levels.size(), 2);

        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_CHECK(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);

        const auto http_it{category_levels.find(BCLog::LogFlags::HTTP)};
        BOOST_CHECK(http_it != category_levels.end());
        BOOST_CHECK_EQUAL(http_it->second, BCLog::Level::Info);
    }
}

struct ScopedScheduler {
    CScheduler scheduler{};

    ScopedScheduler() {
        scheduler.m_service_thread =
            std::thread([this] { scheduler.serviceQueue(); });
    }
    ~ScopedScheduler() { scheduler.stop(); }
    void MockForwardAndSync(std::chrono::seconds duration) {
        scheduler.MockForward(duration);
        std::promise<void> promise;
        scheduler.scheduleFromNow([&promise] { promise.set_value(); }, 0ms);
        promise.get_future().wait();
    }
    std::shared_ptr<BCLog::LogRateLimiter>
    GetLimiter(size_t max_bytes, std::chrono::seconds window) {
        auto sched_func = [this](auto func, auto w) {
            scheduler.scheduleEvery(std::move(func), w);
        };
        return BCLog::LogRateLimiter::Create(sched_func, max_bytes, window);
    }
};

BOOST_AUTO_TEST_CASE(logging_log_rate_limiter) {
    uint64_t max_bytes{1024};
    auto reset_window{1min};
    ScopedScheduler scheduler{};
    auto limiter_{scheduler.GetLimiter(max_bytes, reset_window)};
    auto &limiter{*Assert(limiter_)};

    using Status = BCLog::LogRateLimiter::Status;
    BCLog::LogSiteLimit site_1, site_2;
    auto loc_1{std::source_location::current()};
    auto loc_2{std::source_location::current()};

    // A fresh limiter should not have any suppressions
    BOOST_CHECK(!limiter.SuppressionsActive());

    // Resetting an unused limiter is fine
    limiter.Reset();
    BOOST_CHECK(!limiter.SuppressionsActive());

    // No suppression should happen until more than max_bytes have been consumed
    BOOST_CHECK_EQUAL(limiter.Consume(site_1, loc_1, max_bytes - 1),
                      Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(site_1, loc_1, 1), Status::UNSUPPRESSED);
    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(site_1, loc_1, 1),
                      Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(site_1, loc_1, 1),
                      Status::STILL_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(site_1.dropped.load(), 2U);
    BOOST_CHECK_EQUAL(site_1.Available(), 0U);

    // Location 2 should not be affected by location 1's suppression
    BOOST_CHECK_EQUAL(limiter.Consume(site_2, loc_2, max_bytes),
                      Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(site_2, loc_2, 1),
                      Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // After reset_window time has passed, all suppressions should be cleared.
    scheduler.MockForwardAndSync(reset_window);

    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(site_1, loc_1, max_bytes),
                      Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(site_2, loc_2, max_bytes),
                      Status::UNSUPPRESSED);

    // A site last used by another limiter starts with a full quota.
    auto other{scheduler.GetLimiter(max_bytes, reset_window)};
    BOOST_CHECK_EQUAL(other->Consume(site_1, loc_1, max_bytes),
                      Status::UNSUPPRESSED);
}

BOOST_AUTO_TEST_CASE(logging_log_rate_limiter_threads) {
    // Many threads on one site: exactly the quota is let through, every
    // other byte is counted as dropped, and one thread sees the start of
    // the suppression.
    constexpr uint64_t MAX_BYTES{100'000};
    ScopedScheduler scheduler{};
    auto limiter{scheduler.GetLimiter(MAX_BYTES, 1h)};
    BCLog::LogSiteLimit site;
    const auto loc{std::source_location::current()};
    std::atomic<uint64_t> passed{0}, newly{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 10'000; ++i) {
                switch (limiter->Consume(site, loc, 10)) {
                    case BCLog::LogRateLimiter::Status::UNSUPPRESSED:
                        passed += 10;
                        break;
                    case BCLog::LogRateLimiter::Status::NEWLY_SUPPRESSED:
                        ++newly;
                        break;
                    case BCLog::LogRateLimiter::Status::STILL_SUPPRESSED:
                        break;
                }
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    BOOST_CHECK_EQUAL(passed.load(), MAX_BYTES);
    BOOST_CHECK_EQUAL(newly.load(), 1U);
    BOOST_CHECK_EQUAL(site.dropped.load(), 8U * 10'000 * 10 - MAX_BYTES);
}

namespace {

enum class Location {
    INFO_1,
    INFO_2,
    DEBUG_LOG,
    INFO_NOLIMIT,
};

void LogFromLocation(Location location, const std::string &message) {
    switch (location) {
        case Location::INFO_1:
            LogInfo("%s\n", message);
            return;
        case Location::INFO_2:
            LogInfo("%s\n", message);
            return;
        case Location::DEBUG_LOG:
            LogDebug(BCLog::LogFlags::HTTP, "%s\n", message);
            return;
        case Location::INFO_NOLIMIT:
            LogPrintLevel_(BCLog::LogFlags::ALL, BCLog::Level::Info,
                           /*should_ratelimit=*/false, "%s\n", message);
            return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/**
 * For a given `location` and `message`, ensure that the on-disk debug log
 * behaviour resembles what we'd expect it to be for `status` and
 * `suppressions_active`.
 */
void TestLogFromLocation(
    Location location, const std::string &message,
    BCLog::LogRateLimiter::Status status, bool suppressions_active,
    std::source_location source = std::source_location::current()) {
    BOOST_TEST_INFO_SCOPE("TestLogFromLocation called from "
                          << source.file_name() << ":" << source.line());
    using Status = BCLog::LogRateLimiter::Status;
    if (!suppressions_active) {
        // developer error
        assert(status == Status::UNSUPPRESSED);
    }

    // clear debug log
    std::ofstream ofs(LogInstance().m_file_path,
                      std::ios::out | std::ios::trunc);
    LogFromLocation(location, message);
    flush_debug_log();
    auto log_lines{ReadDebugLogLines()};
    // Remove the flush sentinel line if present
    if (!log_lines.empty() &&
        log_lines.front().find(FLUSH_SENTINEL_LOG_MESSAGE) !=
            std::string::npos) {
        log_lines.erase(log_lines.begin());
    }
    BOOST_TEST_INFO_SCOPE(log_lines.size() << " log_lines read: \n"
                                           << util::Join(log_lines, "\n"));

    if (status == Status::STILL_SUPPRESSED) {
        if (!log_lines.empty()) {
            BOOST_CHECK_EQUAL(log_lines[0], "b?");
        }
        BOOST_CHECK_EQUAL(log_lines.size(), 0);
        return;
    }

    if (status == Status::NEWLY_SUPPRESSED) {
        BOOST_REQUIRE_EQUAL(log_lines.size(), 2);
        BOOST_CHECK(log_lines[0].starts_with(
            "[*] [warning] Excessive logging detected"));
        log_lines.erase(log_lines.begin());
    }
    BOOST_REQUIRE_EQUAL(log_lines.size(), 1);
    auto &payload{log_lines.back()};
    BOOST_CHECK_EQUAL(suppressions_active, payload.starts_with("[*]"));
    BOOST_CHECK(payload.ends_with(message));
}

} // namespace

BOOST_FIXTURE_TEST_CASE(logging_filesize_rate_limit, LogSetup) {
    using Status = BCLog::LogRateLimiter::Status;
    LogInstance().m_log_timestamps = false;
    LogInstance().m_log_sourcelocations = false;
    LogInstance().m_log_threadnames = false;
    LogInstance().EnableCategory(BCLog::LogFlags::HTTP);

    constexpr int64_t line_length{1024};
    constexpr int64_t num_lines{10};
    constexpr int64_t bytes_quota{line_length * num_lines};
    constexpr auto time_window{1h};

    ScopedScheduler scheduler{};
    auto limiter{scheduler.GetLimiter(bytes_quota, time_window)};
    LogInstance().SetRateLimiting(limiter);

    // subtract one for newline
    const std::string log_message(line_length - 1, 'a');

    for (int i = 0; i < num_lines; ++i) {
        TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED,
                            /*suppressions_active=*/false);
    }
    TestLogFromLocation(Location::INFO_1, "a", Status::NEWLY_SUPPRESSED,
                        /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_1, "b", Status::STILL_SUPPRESSED,
                        /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_2, "c", Status::UNSUPPRESSED,
                        /*suppressions_active=*/true);
    {
        scheduler.MockForwardAndSync(time_window);
        flush_debug_log();
        BOOST_CHECK(ReadDebugLogLines().back().starts_with(
            "[warning] Restarting logging"));
    }
    // Check that logging from previously suppressed location is unsuppressed
    // again.
    TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED,
                        /*suppressions_active=*/false);
    // Check that conditional logging, and unconditional logging with
    // should_ratelimit=false is not being ratelimited.
    for (Location location : {Location::DEBUG_LOG, Location::INFO_NOLIMIT}) {
        for (int i = 0; i < num_lines + 2; ++i) {
            TestLogFromLocation(location, log_message, Status::UNSUPPRESSED,
                                /*suppressions_active=*/false);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(logging_reopened_file_unbuffered, LogSetup) {
    // The first line after a reopen (e.g. after SIGHUP for log rotation)
    // must reach the file at once, like every line before it: the new file
    // is unbuffered too. It used to sit in a stdio buffer until enough
    // lines filled it.
    LogInstance().m_reopen_file = true;
    LogPrintf("first line after reopen\n");
    const auto lines{ReadDebugLogLines()};
    BOOST_REQUIRE(!lines.empty());
    BOOST_CHECK_EQUAL(lines.back(), "first line after reopen");
}

BOOST_AUTO_TEST_CASE(logging_json_escape) {
    const auto esc{[](std::string_view in) {
        std::string out;
        BCLog::AppendJsonEscaped(out, in);
        return out;
    }};
    BOOST_CHECK_EQUAL(esc(""), "");
    BOOST_CHECK_EQUAL(esc("plain text 123"), "plain text 123");
    BOOST_CHECK_EQUAL(esc(R"(say "hi" \ bye)"), R"(say \"hi\" \\ bye)");
    BOOST_CHECK_EQUAL(esc("a\nb\rc\td"), R"(a\nb\rc\td)");
    BOOST_CHECK_EQUAL(esc(std::string_view{"\x00\x01\x1f\x7f", 4}),
                      R"(\u0000\u0001\u001f\u007f)");
    // Valid UTF-8 (2, 3 and 4 byte sequences) is kept as is.
    BOOST_CHECK_EQUAL(esc("\xc3\xa9 \xe8\xb2\x93 \xf0\x9f\x98\x80"),
                      "\xc3\xa9 \xe8\xb2\x93 \xf0\x9f\x98\x80");
    BOOST_CHECK_EQUAL(esc("\xef\xbf\xbf\xf4\x8f\xbf\xbf"),
                      "\xef\xbf\xbf\xf4\x8f\xbf\xbf");
    // Each invalid byte becomes U+FFFD.
    const std::string R{"\xef\xbf\xbd"};
    BOOST_CHECK_EQUAL(esc("a\x80z"), "a" + R + "z");
    // Overlong encodings
    BOOST_CHECK_EQUAL(esc("\xc0\x80"), R + R);
    BOOST_CHECK_EQUAL(esc("\xe0\x80\x80"), R + R + R);
    BOOST_CHECK_EQUAL(esc("\xf0\x80\x80\x80"), R + R + R + R);
    // UTF-16 surrogates, beyond U+10FFFF, invalid lead bytes
    BOOST_CHECK_EQUAL(esc("\xed\xa0\x80"), R + R + R);
    BOOST_CHECK_EQUAL(esc("\xf4\x90\x80\x80"), R + R + R + R);
    BOOST_CHECK_EQUAL(esc("\xf5\xff"), R + R);
    // Truncated sequences, at the end and before a plain character
    BOOST_CHECK_EQUAL(esc("\xe8\xb2"), R + R);
    BOOST_CHECK_EQUAL(esc("\xe8\xb2x"), R + R + "x");
    BOOST_CHECK_EQUAL(esc("\xf0\x9f\x98\""), R + R + R + "\\\"");
    // Every escaped output is valid JSON that round-trips the valid input.
    for (const std::string_view in :
         {"q\"\\\n\x01", "\xe8\xb2\x93", "x\xff\xfey", "\xed\xbf\xbf"}) {
        UniValue v;
        BOOST_CHECK(v.read("[\"" + esc(in) + "\"]"));
    }
    UniValue v;
    BOOST_REQUIRE(v.read("[\"" + esc("q\"\\\n\x01 \xe8\xb2\x93") + "\"]"));
    BOOST_CHECK_EQUAL(v[0].get_str(), "q\"\\\n\x01 \xe8\xb2\x93");
}

BOOST_AUTO_TEST_CASE(logging_parse_format) {
    BOOST_CHECK(BCLog::ParseLogFormat("text") == BCLog::LogFormat::TEXT);
    BOOST_CHECK(BCLog::ParseLogFormat("json") == BCLog::LogFormat::JSON);
    BOOST_CHECK(!BCLog::ParseLogFormat("JSON"));
    BOOST_CHECK(!BCLog::ParseLogFormat(""));
}

static std::vector<UniValue> ReadJsonLogLines() {
    std::vector<UniValue> records;
    for (const std::string &line : ReadDebugLogLines()) {
        if (line.empty()) {
            continue;
        }
        UniValue v;
        BOOST_REQUIRE_MESSAGE(v.read(line) && v.isObject(),
                              "not a JSON object: " + line);
        records.push_back(std::move(v));
    }
    return records;
}

BOOST_FIXTURE_TEST_CASE(logging_json_format, LogSetup) {
    LogInstance().m_log_format = BCLog::LogFormat::JSON;
    LogInstance().m_log_timestamps = true;
    LogInstance().EnableCategory(BCLog::NET);
    // Text-only options do not change the JSON fields.
    LogInstance().m_log_threadnames = false;
    LogInstance().m_log_sourcelocations = false;

    const auto loc{std::source_location::current()};
    LogInstance().LogPrintStr("hello \"world\"\n", std::source_location{loc},
                              BCLog::NET, BCLog::Level::Debug,
                              /*site=*/nullptr);
    LogInfo("two\nlines\n");
    LogWarning("bad byte \xff and tab\t\n");
    // A message without trailing newline, then its continuation
    LogInstance().LogPrintStr("partial ", std::source_location{loc}, BCLog::NET,
                              BCLog::Level::Debug,
                              /*site=*/nullptr);
    LogInstance().LogPrintStr("rest\n", std::source_location{loc}, BCLog::NET,
                              BCLog::Level::Debug,
                              /*site=*/nullptr);
    // Options apply when lines are written (by the logger thread).
    LogInstance().Flush();
    LogInstance().m_log_sourcelocations = true;
    LogDebug(BCLog::NET, "with function\n");
    LogInstance().Flush();
    LogInstance().m_log_timestamps = false;
    SetMockTime(1700000000);
    LogError("no timestamp, mocktime\n");
    SetMockTime(0);
    flush_debug_log();

    const auto records{ReadJsonLogLines()};
    BOOST_TEST_INFO_SCOPE(util::Join(ReadDebugLogLines(), "\n"));
    BOOST_REQUIRE_EQUAL(records.size(), 7U);

    const UniValue &r0{records[0]};
    const std::vector<std::string> keys{"ts",   "level", "category", "thread",
                                        "file", "line",  "msg"};
    BOOST_CHECK(r0.getKeys() == keys);
    const std::string &ts{r0["ts"].get_str()};
    // 2026-10-19T12:34:56.123456Z
    BOOST_CHECK_EQUAL(ts.size(), 27U);
    BOOST_CHECK_EQUAL(ts[10], 'T');
    BOOST_CHECK_EQUAL(ts[19], '.');
    BOOST_CHECK_EQUAL(ts.back(), 'Z');
    BOOST_CHECK_EQUAL(r0["level"].get_str(), "debug");
    BOOST_CHECK_EQUAL(r0["category"].get_str(), "net");
    BOOST_CHECK_EQUAL(r0["file"].get_str(),
                      RemovePrefix(loc.file_name(), "./"));
    BOOST_CHECK_EQUAL(r0["line"].getInt<int>(), int(loc.line()));
    BOOST_CHECK_EQUAL(r0["msg"].get_str(), "hello \"world\"");

    BOOST_CHECK_EQUAL(records[1]["level"].get_str(), "info");
    BOOST_CHECK_EQUAL(records[1]["category"].get_str(), "none");
    BOOST_CHECK_EQUAL(records[1]["msg"].get_str(), "two\nlines");

    BOOST_CHECK_EQUAL(records[2]["level"].get_str(), "warning");
    BOOST_CHECK_EQUAL(records[2]["msg"].get_str(),
                      "bad byte \xef\xbf\xbd and tab\t");

    BOOST_CHECK_EQUAL(records[3]["msg"].get_str(), "partial ");
    BOOST_CHECK(!records[3].exists("continued"));
    BOOST_CHECK_EQUAL(records[4]["msg"].get_str(), "rest");
    BOOST_CHECK(records[4]["continued"].get_bool());

    BOOST_CHECK(records[5]["func"].get_str().find("logging_json_format") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(records[5]["msg"].get_str(), "with function");

    BOOST_CHECK(!records[6].exists("ts"));
    BOOST_CHECK_EQUAL(records[6]["mocktime"].get_str(), "2023-11-14T22:13:20Z");
    BOOST_CHECK_EQUAL(records[6]["level"].get_str(), "error");
}

BOOST_FIXTURE_TEST_CASE(logging_json_rate_limit, LogSetup) {
    // The quota counts messages, not lines: the same number of messages
    // fit in text and JSON format, whatever the metadata adds.
    for (const auto format : {BCLog::LogFormat::TEXT, BCLog::LogFormat::JSON}) {
        LogInstance().Flush();
        LogInstance().m_log_format = format;
        LogInstance().m_log_timestamps = true;
        LogInstance().m_log_sourcelocations = true;
        ScopedScheduler scheduler{};
        LogInstance().SetRateLimiting(scheduler.GetLimiter(1000, 1h));
        std::ofstream{LogInstance().m_file_path, std::ios::trunc};
        for (int i = 0; i < 20; ++i) {
            // 100 bytes with the newline
            LogInfo("%s\n", std::string(99, 'x'));
        }
        flush_debug_log();
        size_t messages{0}, warnings{0};
        for (const std::string &line : ReadDebugLogLines()) {
            if (line.find("Excessive logging detected") != std::string::npos) {
                ++warnings;
            } else if (line.find(std::string(99, 'x')) != std::string::npos) {
                ++messages;
            }
        }
        BOOST_TEST_INFO_SCOPE("format " << int(format));
        BOOST_CHECK_EQUAL(warnings, 1U);
        // Ten fit in the quota; the eleventh starts the suppression and is
        // still written (as in text mode).
        BOOST_CHECK_EQUAL(messages, 11U);
        if (format == BCLog::LogFormat::JSON) {
            const auto records{ReadJsonLogLines()};
            BOOST_CHECK(records.back()["ratelimited"].get_bool());
        }
        LogInstance().SetRateLimiting(nullptr);
    }
}

BOOST_FIXTURE_TEST_CASE(logging_async_order_per_thread, LogSetup) {
    // Each thread's lines are written in the order it logged them, and
    // none is lost while the rings have room.
    LogInstance().EnableCategory(BCLog::NET);
    constexpr int THREADS{8}, LINES{300};
    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([t] {
            util::ThreadRename(strprintf("order.%d", t));
            for (int i = 0; i < LINES; ++i) {
                LogDebug(BCLog::NET, "order t=%d i=%d\n", t, i);
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    std::vector<int> next(THREADS, 0);
    for (const std::string &line : ReadDebugLogLines()) {
        int t, i;
        if (std::sscanf(line.c_str(), "[net] order t=%d i=%d", &t, &i) == 2) {
            BOOST_REQUIRE(t >= 0 && t < THREADS);
            BOOST_CHECK_EQUAL(i, next[t]);
            next[t] = i + 1;
        }
    }
    for (int t = 0; t < THREADS; ++t) {
        BOOST_CHECK_EQUAL(next[t], LINES);
    }
}

BOOST_FIXTURE_TEST_CASE(logging_async_saturation, LogSetup) {
    // With the logger thread stalled, a thread logging far more than its
    // ring holds drops debug lines (and counts them) but never a warning
    // or an error, and never blocks on a debug line.
    LogInstance().EnableCategory(BCLog::NET);
    const uint64_t dropped_before{LogInstance().DroppedLines()};
    LogInstance().PauseForTesting(true);
    constexpr int LINES{20 * int(BCLog::LogRing::CAPACITY)};
    std::thread producer{[] {
        util::ThreadRename("saturate");
        for (int i = 0; i < LINES; ++i) {
            LogDebug(BCLog::NET, "flood %d\n", i);
            if (i % 1000 == 999) {
                LogWarning("warning %d\n", i);
            }
        }
        LogError("error at the end\n");
    }};
    producer.join();
    LogInstance().PauseForTesting(false);
    const auto lines{ReadDebugLogLines()};
    size_t warnings{0}, errors{0}, floods{0}, notices{0};
    for (const std::string &line : lines) {
        warnings += line.starts_with("[warning] warning ");
        errors += line == "[error] error at the end";
        floods += line.starts_with("[net] flood ");
        notices += line.find("Logging could not keep up") != std::string::npos;
    }
    BOOST_CHECK_EQUAL(warnings, size_t(LINES / 1000));
    BOOST_CHECK_EQUAL(errors, 1U);
    const uint64_t dropped{LogInstance().DroppedLines() - dropped_before};
    BOOST_CHECK(dropped > 0);
    BOOST_CHECK_EQUAL(floods + dropped, uint64_t(LINES));
    BOOST_CHECK(notices >= 1);
}

BOOST_FIXTURE_TEST_CASE(logging_async_flush, LogSetup) {
    // Flush writes what is queued, also when the logger thread does not
    // run (as at shutdown and before an abort).
    LogInstance().PauseForTesting(true);
    LogPrintf("queued line\n");
    LogInstance().Flush();
    LogInstance().PauseForTesting(false);
    std::ifstream ifs{LogInstance().m_file_path};
    std::string content{std::istreambuf_iterator<char>{ifs}, {}};
    BOOST_CHECK(content.find("queued line\n") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(logging_async_reopen_under_load, LogSetup) {
    // Apply the fixture path before rename. A lightly filled larger ring may
    // otherwise remain below its wake threshold during the first rotation.
    LogInstance().Flush();

    // The log file is rotated (renamed, then reopened) while a thread logs:
    // every line is in exactly one of the files, in order, unless it was
    // dropped because the thread outran the logger (counted).
    LogInstance().EnableCategory(BCLog::NET);
    const uint64_t dropped_before{LogInstance().DroppedLines()};
    std::atomic<bool> stop{false};
    std::atomic<int> logged{0};
    std::thread producer{[&] {
        util::ThreadRename("rotate");
        for (int i = 0; !stop || i < 2000; ++i) {
            LogDebug(BCLog::NET, "rotate %d\n", i);
            logged = i + 1;
            if (i % 64 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds{50});
            }
        }
    }};
    const fs::path path{LogInstance().m_file_path};
    std::vector<fs::path> rotated;
    for (int r = 0; r < 5; ++r) {
        std::this_thread::sleep_for(std::chrono::milliseconds{3});
        rotated.push_back(
            fs::PathFromString(fs::PathToString(path) + strprintf(".%d", r)));
        fs::rename(path, rotated.back());
        LogInstance().m_reopen_file = true;
        // (Make sure the reopen happened before the next rename.)
        LogInstance().Flush();
    }
    stop = true;
    producer.join();
    LogInstance().Flush();
    rotated.push_back(path);
    int next{0};
    uint64_t dropped_lines{0};
    for (const fs::path &file : rotated) {
        std::ifstream ifs{file};
        for (std::string line; std::getline(ifs, line);) {
            int i;
            if (std::sscanf(line.c_str(), "[net] rotate %d", &i) == 1) {
                BOOST_CHECK(i >= next);
                dropped_lines += i - next;
                next = i + 1;
            }
        }
    }
    dropped_lines += logged.load() - next;
    BOOST_CHECK_EQUAL(dropped_lines,
                      LogInstance().DroppedLines() - dropped_before);
}

BOOST_FIXTURE_TEST_CASE(logging_producer_wake_does_not_lock, LogSetup) {
    LogInstance().EnableCategory(BCLog::NET);
    {
        LogInstance().PauseForTesting(true);
        LogInstance().Flush();
        std::promise<void> done;
        const auto future{done.get_future()};
        std::unique_lock<StdMutex> wake_lock{
            BCLog::LoggerTestAccess::WakeMutex(LogInstance())};
        BCLog::LoggerTestAccess::ResetWake(LogInstance());
        std::thread producer{[&] {
            util::ThreadRename("wake-test");
            for (size_t i = 0; i < BCLog::LogRing::CAPACITY / 2; ++i) {
                LogDebug(BCLog::NET, "wake probe\n");
            }
            done.set_value();
        }};
        // A producer must finish while another thread owns the wake mutex.
        const bool ready{future.wait_for(std::chrono::milliseconds{500}) ==
                         std::future_status::ready};
        wake_lock.unlock();
        producer.join();
        LogInstance().PauseForTesting(false);
        LogInstance().Flush();
        BOOST_CHECK_MESSAGE(ready, "plain producer blocked on wake mutex");
    }
}

BOOST_FIXTURE_TEST_CASE(logging_callback_severe_overflow, LogSetup) {
    LogInstance().EnableCategory(BCLog::NET);
    LogInstance().SetRateLimiting(nullptr);
    LogInstance().PauseForTesting(true);
    LogInstance().Flush();
    const uint64_t before{LogInstance().DroppedLines()};
    bool triggered{false};
    bool callback_line_intact{false};
    const size_t count{BCLog::LogRing::CAPACITY + 3};
    auto callback{LogInstance().PushBackCallback([&](const std::string &line) {
        if (triggered || line.find("callback seed") == std::string::npos)
            return;
        triggered = true;
        const std::string original{line};
        // Callback runs on the consuming thread. Its own ring cannot drain
        // until this callback returns, so this deterministically fills it.
        for (size_t i = 0; i < count; ++i) {
            LogWarning("callback warning %u\n", i);
        }
        LogError("callback plain error\n");
        callback_line_intact = line == original;
    })};
    LogPrintf("callback seed\n");
    LogInstance().Flush();
    LogInstance().Flush();
    LogInstance().DeleteCallback(callback);
    LogInstance().PauseForTesting(false);
    size_t warnings{0}, errors{0};
    for (const auto &line : ReadDebugLogLines()) {
        warnings += line.find("callback warning ") != std::string::npos;
        errors += line.find("callback plain error") != std::string::npos;
    }
    BOOST_REQUIRE(triggered);
    BOOST_CHECK(callback_line_intact);
    BOOST_CHECK_EQUAL(warnings, count);
    BOOST_CHECK_EQUAL(errors, 1U);
    BOOST_CHECK_EQUAL(LogInstance().DroppedLines() - before, 0U);
}

BOOST_FIXTURE_TEST_CASE(logging_error_is_flushed_by_consumer, LogSetup) {
    LogInstance().PauseForTesting(true);
    LogInstance().Flush();
    const auto producer{std::this_thread::get_id()};
    std::atomic<bool> seen{false}, rendered_on_producer{false};
    auto callback{LogInstance().PushBackCallback([&](const std::string &line) {
        if (line.find("consumer flush marker") != std::string::npos) {
            rendered_on_producer = std::this_thread::get_id() == producer;
            seen = true;
        }
    })};
    std::atomic<bool> locked{false}, go{false};
    std::thread blocker{[&] {
        std::unique_lock<StdMutex> lock{
            BCLog::LoggerTestAccess::WakeMutex(LogInstance())};
        locked = true;
        while (!go.load())
            std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }};
    while (!locked.load())
        std::this_thread::yield();
    LogInstance().PauseForTesting(false);
    go = true;
    LogError("consumer flush marker\n");
    // Read without calling Flush: returning from Error must already have
    // completed the consumer's stdio flush, not just published a slot.
    std::ifstream stream{LogInstance().m_file_path};
    const std::string content{std::istreambuf_iterator<char>{stream}, {}};
    blocker.join();
    LogInstance().DeleteCallback(callback);
    BOOST_CHECK(seen.load());
    BOOST_CHECK(!rendered_on_producer.load());
    BOOST_CHECK(content.find("consumer flush marker\n") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(logging_pause_rechecks_consumer_lock, LogSetup) {
    LogInstance().PauseForTesting(true);
    LogInstance().Flush();
    std::atomic<bool> seen{false};
    auto callback{LogInstance().PushBackCallback([&](const std::string &line) {
        if (line.find("paused consumer marker") != std::string::npos)
            seen = true;
    })};
    {
        std::unique_lock<StdMutex> consumer{
            BCLog::LoggerTestAccess::ConsumerMutex(LogInstance())};
        LogInstance().PauseForTesting(false);
        std::thread producer{[] {
            for (size_t i = 0; i < BCLog::LogRing::WAKE_THRESHOLD; ++i) {
                LogPrintf("paused consumer marker\n");
            }
        }};
        producer.join();
        // Let the notified worker pass the outer pause check and block on
        // this lock, then pause it before it can acquire the lock.
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        LogInstance().PauseForTesting(true);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    BOOST_CHECK(!seen.load());
    LogInstance().Flush();
    BOOST_CHECK(seen.load());
    LogInstance().DeleteCallback(callback);
    LogInstance().PauseForTesting(false);
}

BOOST_AUTO_TEST_SUITE_END()
