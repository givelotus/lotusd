// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_METRICS_METRICS_H
#define BITCOIN_METRICS_METRICS_H

#include <sync.h>
#include <util/threadinterrupt.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

/**
 * Operator metrics, exposed in the Prometheus text format (version 0.0.4).
 *
 * Recording never takes a lock, allocates or makes a system call:
 *
 * - Counter: monotonically increasing values, one per label combination.
 *   Each counter is split in shards (cache-line aligned rows of relaxed
 *   atomics); a thread adds to the shard picked for it at its first use,
 *   so threads rarely share a cache line. Shards are summed when scraped.
 * - Gauge: a single relaxed atomic, set where a value already changes
 *   (it mirrors state otherwise read under a lock).
 * - EventHistogram: samples (durations, sizes) are pushed into a bounded
 *   single-producer ring buffer owned by the recording thread; a full ring
 *   drops the sample and counts the drop. A background thread drains the
 *   rings into the histograms' buckets.
 *
 * See doc/metrics-design.md (METRICS-DESIGN.md) for the rationale.
 */
namespace metrics {

//! Apple arm64 cores have 128 byte cache lines; elsewhere 64 is enough
//! but 128 also avoids adjacent-line prefetch interference.
inline constexpr size_t CACHE_LINE{128};
//! Shards of each counter. Threads beyond this share shards.
inline constexpr size_t NUM_SHARDS{16};

/** Shard of the calling thread (assigned round robin at first use) */
size_t ThisThreadShard() noexcept;

/** A label dimension: its name and its fixed set of values */
struct LabelDim {
    std::string name;
    std::vector<std::string> values;
};

enum class MetricType { COUNTER, GAUGE, HISTOGRAM };

class Registry;

/** Base of every metric: name, help and labels */
class Metric {
public:
    Metric(std::string name, std::string help, std::vector<LabelDim> labels);
    virtual ~Metric() = default;
    Metric(const Metric &) = delete;
    Metric &operator=(const Metric &) = delete;

    const std::string &Name() const { return m_name; }
    const std::string &Help() const { return m_help; }
    const std::vector<LabelDim> &Labels() const { return m_labels; }
    //! Number of series (product of the label dimensions' sizes)
    size_t NumSeries() const { return m_num_series; }
    virtual MetricType Type() const = 0;
    /** Series index for one value index per label dimension */
    size_t SeriesIndex(std::span<const size_t> label_value_indexes) const;

protected:
    const std::string m_name;
    const std::string m_help;
    const std::vector<LabelDim> m_labels;
    const size_t m_num_series;
};

/** Sharded monotonically increasing counters */
class Counter final : public Metric {
public:
    Counter(std::string name, std::string help,
            std::vector<LabelDim> labels = {});
    MetricType Type() const override { return MetricType::COUNTER; }

    void Add(size_t series, uint64_t n = 1) noexcept {
        m_cells[ThisThreadShard() * m_stride + series].fetch_add(
            n, std::memory_order_relaxed);
    }
    void Inc() noexcept { Add(0, 1); }
    /** Sum over the shards (scrape time) */
    uint64_t Value(size_t series = 0) const noexcept;

private:
    //! Cells per shard, rounded up to whole cache lines
    const size_t m_stride;
    struct alignas(CACHE_LINE) Line {
        std::array<std::atomic<uint64_t>, CACHE_LINE / sizeof(uint64_t)> v{};
    };
    std::unique_ptr<Line[]> m_lines;
    std::atomic<uint64_t> *m_cells;
};

/** A counter kept elsewhere, read through a function when scraped */
class FunctionCounter final : public Metric {
public:
    FunctionCounter(std::string name, std::string help,
                    std::function<uint64_t()> value)
        : Metric{std::move(name), std::move(help), {}},
          m_value{std::move(value)} {}
    MetricType Type() const override { return MetricType::COUNTER; }
    uint64_t Value() const { return m_value(); }

private:
    const std::function<uint64_t()> m_value;
};

/** Values set where they change; read at scrape time */
class Gauge final : public Metric {
public:
    Gauge(std::string name, std::string help,
          std::vector<LabelDim> labels = {});
    MetricType Type() const override { return MetricType::GAUGE; }

    void Set(double v, size_t series = 0) noexcept {
        m_values[series].store(v, std::memory_order_relaxed);
    }
    //! For low-rate up/down counts (e.g. connected peers)
    void Add(double d, size_t series = 0) noexcept {
        auto &v{m_values[series]};
        double old{v.load(std::memory_order_relaxed)};
        while (
            !v.compare_exchange_weak(old, old + d, std::memory_order_relaxed)) {
        }
    }
    double Value(size_t series = 0) const noexcept {
        return m_values[series].load(std::memory_order_relaxed);
    }

private:
    std::unique_ptr<std::atomic<double>[]> m_values;
};

/** One sample travelling through an event ring */
struct Sample {
    uint32_t histogram;
    uint32_t series;
    uint64_t value;
};

/**
 * Bounded single-producer single-consumer ring of samples. The producer
 * (the thread owning it) pushes; the drain thread pops. Push never blocks:
 * when the ring is full the sample is dropped and counted.
 */
class EventRing {
public:
    static constexpr size_t CAPACITY{2048};
    static_assert((CAPACITY & (CAPACITY - 1)) == 0);

    //! User-provided, so that the (32 KiB) buffer is not zeroed: its pages
    //! are only touched once samples are written.
    EventRing() {}

    bool Push(const Sample &s) noexcept {
        const uint64_t head{m_head.load(std::memory_order_relaxed)};
        if (head - m_cached_tail >= CAPACITY) {
            m_cached_tail = m_tail.load(std::memory_order_acquire);
            if (head - m_cached_tail >= CAPACITY) {
                m_dropped.store(m_dropped.load(std::memory_order_relaxed) + 1,
                                std::memory_order_relaxed);
                return false;
            }
        }
        m_buf[head & (CAPACITY - 1)] = s;
        m_head.store(head + 1, std::memory_order_release);
        return true;
    }

    /** Consumer: hand every available sample to f, then release them */
    template <typename F> size_t Drain(F &&f) {
        const uint64_t tail{m_tail.load(std::memory_order_relaxed)};
        const uint64_t head{m_head.load(std::memory_order_acquire)};
        for (uint64_t i = tail; i != head; ++i) {
            f(m_buf[i & (CAPACITY - 1)]);
        }
        m_tail.store(head, std::memory_order_release);
        return size_t(head - tail);
    }
    bool Empty() const {
        return m_head.load(std::memory_order_acquire) ==
               m_tail.load(std::memory_order_relaxed);
    }
    uint64_t Dropped() const {
        return m_dropped.load(std::memory_order_relaxed);
    }

    /**
     * Consumer, once the producer has gone (orphaned and drained): make the
     * ring ready for another thread. Returns the drops it had counted.
     */
    uint64_t Recycle() {
        m_orphaned.store(false, std::memory_order_relaxed);
        return m_dropped.exchange(0, std::memory_order_relaxed);
    }

    //! Set when the owning thread exits; the drain thread then recycles the
    //! ring once it is drained.
    std::atomic<bool> m_orphaned{false};

private:
    // Producer-owned line
    alignas(CACHE_LINE) std::atomic<uint64_t> m_head{0};
    uint64_t m_cached_tail{0};
    std::atomic<uint64_t> m_dropped{0};
    // Consumer-owned line
    alignas(CACHE_LINE) std::atomic<uint64_t> m_tail{0};
    alignas(CACHE_LINE) std::array<Sample, CAPACITY> m_buf;
};

/**
 * Histogram of event samples with fixed bucket bounds. Values are recorded
 * as integers in a base unit (e.g. nanoseconds) and rendered divided by
 * `divisor` (e.g. 1e9 for seconds), as are the bounds.
 */
class EventHistogram final : public Metric {
public:
    EventHistogram(std::string name, std::string help,
                   std::vector<double> bounds, double divisor,
                   std::vector<LabelDim> labels = {});
    MetricType Type() const override { return MetricType::HISTOGRAM; }

    /** Record a sample (in base units). Lock-free; may drop if saturated. */
    void Record(uint64_t value, size_t series = 0) noexcept;
    void RecordDuration(std::chrono::steady_clock::duration d,
                        size_t series = 0) noexcept {
        Record(uint64_t(std::max<int64_t>(
                   0, std::chrono::duration_cast<std::chrono::nanoseconds>(d)
                          .count())),
               series);
    }

    const std::vector<double> &Bounds() const { return m_bounds; }
    double Divisor() const { return m_divisor; }
    /**
     * Render only series that have had a sample, e.g. one per RPC method
     * actually called out of the fixed set of methods.
     */
    EventHistogram &HideEmptySeries() {
        m_hide_empty = true;
        return *this;
    }

    struct Series {
        //! Non-cumulative count per bucket; the last one is +Inf
        std::vector<uint64_t> buckets;
        uint64_t count{0};
        //! Sum of values in base units
        uint64_t sum{0};
    };

private:
    friend class Registry;
    //! Set by the registry when added
    Registry *m_registry{nullptr};
    uint32_t m_id{0};
    const std::vector<double> m_bounds;
    //! Bounds in base units, for the drain thread's bucket search
    std::vector<uint64_t> m_raw_bounds;
    const double m_divisor;
    bool m_hide_empty{false};
    //! Aggregated by the drain thread, under Registry::m_data_mutex
    std::vector<Series> m_series;
    void Apply(const Sample &s);
};

/**
 * The set of metrics served at /metrics, the event rings of recording
 * threads and the drain thread. Metrics are added before recording starts
 * and live as long as the registry.
 */
class Registry {
public:
    /**
     * name_prefix is prepended to the registry's own metric
     * (metrics_dropped_samples_total); callers name their metrics in full.
     */
    explicit Registry(std::string name_prefix = "");
    ~Registry();

    /**
     * Labels added to every series (e.g. client and network), rendered
     * before each metric's own labels. Set before the first rendering.
     * Fails (and changes nothing) if a name is not a valid label name,
     * is repeated, is reserved (le, quantile, or a `__` prefix) or is
     * already a label of a registered metric.
     */
    [[nodiscard]] std::optional<std::string>
    SetConstLabels(std::vector<std::pair<std::string, std::string>> labels);

    /** Take ownership of a metric (before Start; not thread-safe) */
    template <typename T> T &Add(std::unique_ptr<T> metric) {
        T &ref{*metric};
        AddMetric(std::move(metric));
        return ref;
    }

    /** Push a sample to the calling thread's ring */
    void Record(const Sample &s) noexcept;

    /**
     * Give the calling thread its ring now (at thread start), so that its
     * first sample neither locks nor allocates. Rings of exited threads are
     * reused. A thread that records without having been prepared gets its
     * ring on its first sample instead (one lock, from the pool if any).
     */
    void PrepareThisThread() noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);

    /** Run f before each rendering (to set gauges computed at scrape time) */
    void AddCollector(std::function<void()> f) {
        m_collectors.push_back(std::move(f));
    }

    /** Start the drain thread, with `rings` rings ready for new threads */
    void Start(std::chrono::milliseconds drain_interval =
                   std::chrono::milliseconds{50},
               size_t rings = 32) EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);
    /** Stop and join the drain thread (rings are drained once more) */
    void Stop();

    /** Drain every ring into the histograms now */
    void Drain() EXCLUSIVE_LOCKS_REQUIRED(!m_data_mutex, !m_rings_mutex);

    /**
     * Render all metrics in the Prometheus text format. Drains first. If
     * called again within min_interval, returns the previous rendering.
     */
    std::string Render(
        std::chrono::milliseconds min_interval = std::chrono::milliseconds{0})
        EXCLUSIVE_LOCKS_REQUIRED(!m_data_mutex, !m_rings_mutex,
                                 !m_render_mutex);

    /** Rings allocated (in use or ready for reuse), for tests */
    size_t NumRings() const EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex) {
        LOCK(m_rings_mutex);
        return m_rings.size() + m_free.size();
    }

    /** Samples dropped because a ring was full (all rings, ever) */
    uint64_t DroppedSamples() const EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);

private:
    void AddMetric(std::unique_ptr<Metric> metric);

    const std::string m_name_prefix;
    //! Rendered constant labels (`a="x",b="y"`), or empty
    std::string m_const_labels;
    EventRing *ClaimRing() EXCLUSIVE_LOCKS_REQUIRED(!m_rings_mutex);

    //! Distinguishes registries in the threads' ring caches
    const uint64_t m_uid;

    std::vector<std::unique_ptr<Metric>> m_metrics;
    std::vector<EventHistogram *> m_histograms;
    std::vector<std::function<void()>> m_collectors;

    mutable Mutex m_rings_mutex;
    //! Rings in use by threads (and orphaned ones still to be drained)
    std::vector<std::shared_ptr<EventRing>> m_rings GUARDED_BY(m_rings_mutex);
    //! Rings ready for new threads
    std::vector<std::shared_ptr<EventRing>> m_free GUARDED_BY(m_rings_mutex);
    //! Drops counted by rings since recycled
    uint64_t m_dropped_retired GUARDED_BY(m_rings_mutex){0};

    Mutex m_data_mutex;

    Mutex m_render_mutex;
    std::string m_rendered GUARDED_BY(m_render_mutex);
    std::chrono::steady_clock::time_point
        m_rendered_at GUARDED_BY(m_render_mutex);

    CThreadInterrupt m_interrupt;
    std::thread m_thread;
};

/**
 * The registry whose rings threads get at start (see PrepareThisThread),
 * or nullptr. Called by util::ThreadRename, which every node thread calls
 * first.
 */
void SetThreadRegistry(Registry *registry) noexcept;
void PrepareThisThread() noexcept;

/** Whether s is a valid Prometheus metric name ([a-zA-Z_:][a-zA-Z0-9_:]*) */
bool IsValidMetricName(std::string_view s);
/**
 * Whether s is a valid Prometheus label name ([a-zA-Z_][a-zA-Z0-9_]*) that
 * is not reserved for internal use (a `__` prefix)
 */
bool IsValidLabelName(std::string_view s);

/** Escape a label value (backslash, double quote, newline) */
void AppendLabelValue(std::string &out, std::string_view value);
/** Escape HELP text (backslash, newline) */
void AppendHelp(std::string &out, std::string_view help);
/** Format a sample value as Prometheus expects (incl. +Inf, NaN) */
void AppendValue(std::string &out, double value);

} // namespace metrics

#endif // BITCOIN_METRICS_METRICS_H
