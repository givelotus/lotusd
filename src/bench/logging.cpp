// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <logging.h>
#include <test/util/setup_common.h>

#include <optional>
#include <string>

// All but 2 of the benchmarks should have roughly similar performance:
//
// LogPrintWithoutCategory should be ~3 orders of magnitude faster, as nothing
// is logged.
//
// LogWithoutWriteToFile should be ~2 orders of magnitude faster, as it avoids
// disk writes.

static void Logging(benchmark::Bench &bench,
                    const std::vector<const char *> &extra_args,
                    const std::function<void()> &log) {
    // Reset any enabled logging categories from a previous benchmark run.
    LogInstance().DisableCategory(BCLog::LogFlags::ALL);

    TestingSetup test_setup{
        ChainType::REGTEST,
        extra_args,
    };

    bench.run([&] { log(); });
}

static void LogWithDebug(benchmark::Bench &bench) {
    Logging(bench, {"-logthreadnames=0", "-debug=net"},
            [] { LogDebug(BCLog::NET, "%s\n", "test"); });
}

static void LogWithoutDebug(benchmark::Bench &bench) {
    Logging(bench, {"-logthreadnames=0", "-debug=0"},
            [] { LogDebug(BCLog::NET, "%s\n", "test"); });
}

static void LogWithThreadNames(benchmark::Bench &bench) {
    Logging(bench, {"-logthreadnames=1"}, [] { LogInfo("%s\n", "test"); });
}

static void LogWithoutThreadNames(benchmark::Bench &bench) {
    Logging(bench, {"-logthreadnames=0"}, [] { LogInfo("%s\n", "test"); });
}

static void LogWithoutWriteToFile(benchmark::Bench &bench) {
    // Disable writing the log to a file, as used for unit tests and fuzzing in
    // `MakeNoLogFileContext`.
    Logging(bench, {"-nodebuglogfile", "-debug=1"}, [] {
        LogPrintf("%s\n", "test");
        LogInfo("%s\n", "test");
        LogDebug(BCLog::NET, "%s\n", "test");
    });
}

// Text versus JSON (-logformat) for the same line, through the real sink.
// Both include a microsecond timestamp, the thread name and the category;
// JSON also has the level and source file:line. "File" writes debug.log
// (one unbuffered write per line); "NoFile" hands the finished line to a
// no-op print callback instead, isolating the cost of formatting it.
static const std::string LONG_MESSAGE{
    "Received block 00000000000000000123456789abcdef0123456789abcdef0123456789"
    "abcdef (height 1401052, 1830 txs, 712345 bytes) from peer=17 "
    "addr=203.0.113.7:10605 after 0.214s; \"quoted\" and a tab\tin it, "
    "UTF-8 \xc3\xa9\xe8\xb2\x93 and padding to make the line about 300 bytes "
    "long xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"};

static void LogFormat(benchmark::Bench &bench, const char *format, bool file,
                      bool long_message) {
    LogInstance().DisableCategory(BCLog::LogFlags::ALL);
    TestingSetup test_setup{
        ChainType::REGTEST,
        {"-logthreadnames=1", "-logsourcelocations=0", "-logtimemicros=1",
         "-debug=net", format,
         file ? "-debuglogfile=debug.log" : "-nodebuglogfile"},
    };
    std::optional<decltype(LogInstance().PushBackCallback({}))> callback;
    if (!file) {
        callback = LogInstance().PushBackCallback([](const std::string &line) {
            ankerl::nanobench::doNotOptimizeAway(line.size());
        });
    }
    bench.run([&] {
        if (long_message) {
            LogDebug(BCLog::NET, "%s\n", LONG_MESSAGE);
        } else {
            LogDebug(BCLog::NET, "connected peer=%d\n", 17);
        }
    });
    if (callback) {
        LogInstance().DeleteCallback(*callback);
    }
}

static void LogTextShortFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=text", true, false);
}
static void LogJsonShortFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=json", true, false);
}
static void LogTextLongFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=text", true, true);
}
static void LogJsonLongFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=json", true, true);
}
static void LogTextShortNoFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=text", false, false);
}
static void LogJsonShortNoFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=json", false, false);
}
static void LogTextLongNoFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=text", false, true);
}
static void LogJsonLongNoFile(benchmark::Bench &bench) {
    LogFormat(bench, "-logformat=json", false, true);
}

BENCHMARK(LogWithDebug);
BENCHMARK(LogWithoutDebug);
BENCHMARK(LogWithThreadNames);
BENCHMARK(LogWithoutThreadNames);
BENCHMARK(LogWithoutWriteToFile);
BENCHMARK(LogTextShortFile);
BENCHMARK(LogJsonShortFile);
BENCHMARK(LogTextLongFile);
BENCHMARK(LogJsonLongFile);
BENCHMARK(LogTextShortNoFile);
BENCHMARK(LogJsonShortNoFile);
BENCHMARK(LogTextLongNoFile);
BENCHMARK(LogJsonLongNoFile);
