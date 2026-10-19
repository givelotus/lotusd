// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <metrics/metrics.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

// Cost of recording a metric, per record. "Contended" variants run
// BACKGROUND_THREADS other threads recording into the same metric while
// the measured thread records, to show cache-line contention.

static constexpr int BACKGROUND_THREADS{7};

/** Runs f in BACKGROUND_THREADS threads until destroyed */
class Background {
public:
    template <typename F> explicit Background(F f) {
        for (int i = 0; i < BACKGROUND_THREADS; ++i) {
            m_threads.emplace_back([this, f] {
                while (!m_stop.load(std::memory_order_relaxed)) {
                    for (int j = 0; j < 64; ++j) {
                        f();
                    }
                }
            });
        }
    }
    ~Background() {
        m_stop = true;
        for (auto &t : m_threads) {
            t.join();
        }
    }

private:
    std::atomic<bool> m_stop{false};
    std::vector<std::thread> m_threads;
};

static void MetricsSteadyClockNow(benchmark::Bench &bench) {
    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(std::chrono::steady_clock::now());
    });
}

static metrics::Counter &MakeCounter(metrics::Registry &reg) {
    return reg.Add(std::make_unique<metrics::Counter>(
        "c_total", "C.",
        std::vector<metrics::LabelDim>{{"k", {"a", "b", "c", "d"}}}));
}

static void MetricsCounterAdd(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &c{MakeCounter(reg)};
    bench.run([&] { c.Add(1, 100); });
}

static void MetricsCounterAddContended(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &c{MakeCounter(reg)};
    Background bg{[&] { c.Add(1, 100); }};
    bench.run([&] { c.Add(1, 100); });
}

//! Baseline: one shared atomic, as an unsharded counter would be
static void MetricsSharedAtomicAddContended(benchmark::Bench &bench) {
    alignas(metrics::CACHE_LINE) std::atomic<uint64_t> shared{0};
    Background bg{[&] { shared.fetch_add(100, std::memory_order_relaxed); }};
    bench.run([&] { shared.fetch_add(100, std::memory_order_relaxed); });
}

static metrics::EventHistogram &MakeHistogram(metrics::Registry &reg) {
    return reg.Add(std::make_unique<metrics::EventHistogram>(
        "h_seconds", "H.", std::vector<double>{0.001, 0.01, 0.1, 1, 10}, 1e9,
        std::vector<metrics::LabelDim>{{"k", {"a", "b"}}}));
}

// The drain thread polls continuously here so that the rings keep up with
// a tight loop; in the node it wakes every 50 ms.
static void MetricsEventRecord(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &h{MakeHistogram(reg)};
    reg.Start(std::chrono::milliseconds{0});
    bench.run([&] { h.Record(12345, 1); });
    reg.Stop();
}

static void MetricsEventRecordContended(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &h{MakeHistogram(reg)};
    reg.Start(std::chrono::milliseconds{0});
    {
        Background bg{[&] { h.Record(12345, 0); }};
        bench.run([&] { h.Record(12345, 1); });
    }
    reg.Stop();
}

//! A full ring: the drop path (nothing drains)
static void MetricsEventRecordDropping(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &h{MakeHistogram(reg)};
    for (size_t i = 0; i < metrics::EventRing::CAPACITY; ++i) {
        h.Record(1);
    }
    bench.run([&] { h.Record(12345, 1); });
}

//! Duration measurement as done at a recording site: two clock reads
static void MetricsEventRecordDuration(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &h{MakeHistogram(reg)};
    reg.Start(std::chrono::milliseconds{0});
    bench.run([&] {
        const auto start{std::chrono::steady_clock::now()};
        h.RecordDuration(std::chrono::steady_clock::now() - start, 1);
    });
    reg.Stop();
}

//! As above, but drained in batches of 1024 by the measuring thread itself
//! (the drain work is included). The busy-polling drain thread above takes
//! the ring's cache lines after nearly every sample; the node's drain
//! thread, waking every 50 ms, finds large batches instead.
static void MetricsEventRecordDurationBatched(benchmark::Bench &bench) {
    metrics::Registry reg;
    auto &h{MakeHistogram(reg)};
    size_t n{0};
    bench.run([&] {
        const auto start{std::chrono::steady_clock::now()};
        h.RecordDuration(std::chrono::steady_clock::now() - start, 1);
        if (++n % 1024 == 0) {
            reg.Drain();
        }
    });
}

//! Two clock reads, the cost of measuring a duration
static void MetricsSteadyClockPair(benchmark::Bench &bench) {
    bench.run([&] {
        const auto start{std::chrono::steady_clock::now()};
        ankerl::nanobench::doNotOptimizeAway(std::chrono::steady_clock::now() -
                                             start);
    });
}

BENCHMARK(MetricsSteadyClockNow);
BENCHMARK(MetricsCounterAdd);
BENCHMARK(MetricsCounterAddContended);
BENCHMARK(MetricsSharedAtomicAddContended);
BENCHMARK(MetricsEventRecord);
BENCHMARK(MetricsEventRecordContended);
BENCHMARK(MetricsEventRecordDropping);
BENCHMARK(MetricsEventRecordDuration);
BENCHMARK(MetricsEventRecordDurationBatched);
BENCHMARK(MetricsSteadyClockPair);
