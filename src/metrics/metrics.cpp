// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <metrics/metrics.h>

#include <util/thread.h>

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cmath>
#include <functional>
#include <new>

namespace metrics {

namespace {
    std::atomic<size_t> g_next_shard{0};
    std::atomic<uint64_t> g_next_registry_uid{1};
    std::atomic<Registry *> g_thread_registry{nullptr};

    /** Rings of the current thread, one per registry it has recorded into */
    struct ThreadRings {
        struct Entry {
            uint64_t registry_uid;
            std::shared_ptr<EventRing> ring;
        };
        std::vector<Entry> entries;
        ~ThreadRings() {
            for (auto &e : entries) {
                e.ring->m_orphaned.store(true, std::memory_order_release);
            }
        }
    };
    thread_local ThreadRings t_rings;

    size_t Product(const std::vector<LabelDim> &labels) {
        size_t n{1};
        for (const auto &dim : labels) {
            assert(!dim.values.empty());
            n *= dim.values.size();
        }
        return n;
    }

    void AppendUInt(std::string &out, uint64_t v) {
        char buf[24];
        const auto res{std::to_chars(buf, buf + sizeof(buf), v)};
        out.append(buf, res.ptr);
    }

    const char *TypeName(MetricType t) {
        switch (t) {
            case MetricType::COUNTER:
                return "counter";
            case MetricType::GAUGE:
                return "gauge";
            case MetricType::HISTOGRAM:
                return "histogram";
        }
        assert(false);
    }

    /**
     * Append `{a="x",b="y"` (without the closing brace) for a series, or
     * nothing if the metric has no labels. Returns whether a brace was opened.
     */
    bool AppendLabels(std::string &out, const Metric &m, size_t series) {
        const auto &labels{m.Labels()};
        if (labels.empty()) {
            return false;
        }
        // Row-major: the last dimension varies fastest.
        std::array<size_t, 8> idx{};
        assert(labels.size() <= idx.size());
        for (size_t d = labels.size(); d-- > 0;) {
            idx[d] = series % labels[d].values.size();
            series /= labels[d].values.size();
        }
        out += '{';
        for (size_t d = 0; d < labels.size(); ++d) {
            if (d) {
                out += ',';
            }
            out += labels[d].name;
            out += "=\"";
            AppendLabelValue(out, labels[d].values[idx[d]]);
            out += '"';
        }
        return true;
    }
} // namespace

size_t ThisThreadShard() noexcept {
    thread_local const size_t shard{
        g_next_shard.fetch_add(1, std::memory_order_relaxed) % NUM_SHARDS};
    return shard;
}

void AppendLabelValue(std::string &out, std::string_view value) {
    for (char c : value) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            default:
                out += c;
        }
    }
}

void AppendHelp(std::string &out, std::string_view help) {
    for (char c : help) {
        switch (c) {
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            default:
                out += c;
        }
    }
}

void AppendValue(std::string &out, double value) {
    if (std::isnan(value)) {
        out += "NaN";
    } else if (std::isinf(value)) {
        out += value > 0 ? "+Inf" : "-Inf";
    } else {
        char buf[32];
        const auto res{std::to_chars(buf, buf + sizeof(buf), value)};
        out.append(buf, res.ptr);
    }
}

Metric::Metric(std::string name, std::string help, std::vector<LabelDim> labels)
    : m_name{std::move(name)}, m_help{std::move(help)},
      m_labels{std::move(labels)}, m_num_series{Product(m_labels)} {}

size_t Metric::SeriesIndex(std::span<const size_t> idx) const {
    assert(idx.size() == m_labels.size());
    size_t series{0};
    for (size_t d = 0; d < idx.size(); ++d) {
        assert(idx[d] < m_labels[d].values.size());
        series = series * m_labels[d].values.size() + idx[d];
    }
    return series;
}

Counter::Counter(std::string name, std::string help,
                 std::vector<LabelDim> labels)
    : Metric{std::move(name), std::move(help), std::move(labels)},
      m_stride{[&] {
          constexpr size_t per_line{CACHE_LINE / sizeof(uint64_t)};
          return (NumSeries() + per_line - 1) / per_line * per_line;
      }()} {
    const size_t lines{NUM_SHARDS * m_stride / (CACHE_LINE / sizeof(uint64_t))};
    m_lines = std::make_unique<Line[]>(lines);
    static_assert(sizeof(Line) == CACHE_LINE);
    m_cells = m_lines[0].v.data();
}

uint64_t Counter::Value(size_t series) const noexcept {
    uint64_t sum{0};
    for (size_t shard = 0; shard < NUM_SHARDS; ++shard) {
        sum +=
            m_cells[shard * m_stride + series].load(std::memory_order_relaxed);
    }
    return sum;
}

Gauge::Gauge(std::string name, std::string help, std::vector<LabelDim> labels)
    : Metric{std::move(name), std::move(help), std::move(labels)},
      m_values{std::make_unique<std::atomic<double>[]>(NumSeries())} {
    for (size_t i = 0; i < NumSeries(); ++i) {
        m_values[i].store(0, std::memory_order_relaxed);
    }
}

EventHistogram::EventHistogram(std::string name, std::string help,
                               std::vector<double> bounds, double divisor,
                               std::vector<LabelDim> labels)
    : Metric{std::move(name), std::move(help), std::move(labels)},
      m_bounds{std::move(bounds)}, m_divisor{divisor} {
    assert(std::is_sorted(m_bounds.begin(), m_bounds.end()));
    for (double b : m_bounds) {
        m_raw_bounds.push_back(uint64_t(std::llround(b * m_divisor)));
    }
    m_series.resize(NumSeries());
    for (auto &s : m_series) {
        s.buckets.assign(m_bounds.size() + 1, 0);
    }
}

void EventHistogram::Record(uint64_t value, size_t series) noexcept {
    assert(m_registry);
    m_registry->Record(
        Sample{.histogram = m_id, .series = uint32_t(series), .value = value});
}

void EventHistogram::Apply(const Sample &s) {
    if (s.series >= m_series.size()) {
        return;
    }
    Series &series{m_series[s.series]};
    // Bucket "le" bounds are inclusive: the first bound >= value.
    const size_t bucket{size_t(
        std::lower_bound(m_raw_bounds.begin(), m_raw_bounds.end(), s.value) -
        m_raw_bounds.begin())};
    ++series.buckets[bucket];
    ++series.count;
    series.sum += s.value;
}

Registry::Registry()
    : m_uid{g_next_registry_uid.fetch_add(1, std::memory_order_relaxed)} {}

Registry::~Registry() {
    Stop();
}

void Registry::AddMetric(std::unique_ptr<Metric> metric) {
    if (auto *h{dynamic_cast<EventHistogram *>(metric.get())}) {
        h->m_registry = this;
        h->m_id = uint32_t(m_histograms.size());
        m_histograms.push_back(h);
    }
    m_metrics.push_back(std::move(metric));
}

EventRing *Registry::ClaimRing() {
    std::shared_ptr<EventRing> ring;
    {
        LOCK(m_rings_mutex);
        if (!m_free.empty()) {
            ring = std::move(m_free.back());
            m_free.pop_back();
        }
    }
    if (!ring) {
        ring = std::make_shared<EventRing>();
    }
    t_rings.entries.push_back({m_uid, ring});
    LOCK(m_rings_mutex);
    m_rings.push_back(ring);
    return ring.get();
}

static EventRing *FindThreadRing(uint64_t uid) noexcept {
    for (const auto &e : t_rings.entries) {
        if (e.registry_uid == uid) {
            return e.ring.get();
        }
    }
    return nullptr;
}

void Registry::PrepareThisThread() noexcept {
    if (FindThreadRing(m_uid)) {
        return;
    }
    try {
        ClaimRing();
    } catch (const std::bad_alloc &) {
    }
}

void Registry::Record(const Sample &s) noexcept {
    EventRing *ring{FindThreadRing(m_uid)};
    if (!ring) {
        // A thread not prepared at its start: claim a ring now.
        try {
            ring = ClaimRing();
        } catch (const std::bad_alloc &) {
            return;
        }
    }
    ring->Push(s);
}

void SetThreadRegistry(Registry *registry) noexcept {
    g_thread_registry.store(registry, std::memory_order_release);
}

void PrepareThisThread() noexcept {
    if (Registry * r{g_thread_registry.load(std::memory_order_acquire)}) {
        r->PrepareThisThread();
    }
}

void Registry::Drain() {
    LOCK2(m_data_mutex, m_rings_mutex);
    const auto apply{[&](const Sample &s) {
        if (s.histogram < m_histograms.size()) {
            m_histograms[s.histogram]->Apply(s);
        }
    }};
    for (auto it = m_rings.begin(); it != m_rings.end();) {
        EventRing &ring{**it};
        // A ring is orphaned after its thread's last push, so draining
        // after seeing the flag collects everything.
        const bool orphaned{ring.m_orphaned.load(std::memory_order_acquire)};
        ring.Drain(apply);
        if (orphaned) {
            // Its thread is gone: keep the ring for the next new thread.
            m_dropped_retired += ring.Recycle();
            m_free.push_back(std::move(*it));
            it = m_rings.erase(it);
        } else {
            ++it;
        }
    }
}

uint64_t Registry::DroppedSamples() const {
    LOCK(m_rings_mutex);
    uint64_t dropped{m_dropped_retired};
    for (const auto &ring : m_rings) {
        dropped += ring->Dropped();
    }
    return dropped;
}

void Registry::Start(std::chrono::milliseconds drain_interval, size_t rings) {
    assert(!m_thread.joinable());
    {
        LOCK(m_rings_mutex);
        while (m_free.size() < rings) {
            m_free.push_back(std::make_shared<EventRing>());
        }
    }
    m_interrupt.reset();
    m_thread =
        std::thread{&util::TraceThread, "metrics", [this, drain_interval] {
                        while (m_interrupt.sleep_for(drain_interval)) {
                            Drain();
                        }
                    }};
}

void Registry::Stop() {
    if (m_thread.joinable()) {
        m_interrupt();
        m_thread.join();
        Drain();
    }
}

std::string Registry::Render(std::chrono::milliseconds min_interval) {
    LOCK(m_render_mutex);
    const auto now{std::chrono::steady_clock::now()};
    if (min_interval.count() > 0 && !m_rendered.empty() &&
        now - m_rendered_at < min_interval) {
        return m_rendered;
    }
    for (const auto &collect : m_collectors) {
        collect();
    }
    Drain();
    std::string out;
    out.reserve(std::max<size_t>(m_rendered.size() + 1024, 4096));
    {
        LOCK(m_data_mutex);
        for (const auto &metric : m_metrics) {
            const std::string &name{metric->Name()};
            out += "# HELP ";
            out += name;
            out += ' ';
            AppendHelp(out, metric->Help());
            out += "\n# TYPE ";
            out += name;
            out += ' ';
            out += TypeName(metric->Type());
            out += '\n';
            for (size_t i = 0; i < metric->NumSeries(); ++i) {
                if (metric->Type() == MetricType::HISTOGRAM) {
                    const auto &h{static_cast<const EventHistogram &>(*metric)};
                    if (h.m_hide_empty && h.m_series[i].count == 0) {
                        continue;
                    }
                }
                switch (metric->Type()) {
                    case MetricType::COUNTER: {
                        out += name;
                        if (AppendLabels(out, *metric, i)) {
                            out += '}';
                        }
                        out += ' ';
                        if (const auto *fc{
                                dynamic_cast<const FunctionCounter *>(
                                    metric.get())}) {
                            AppendUInt(out, fc->Value());
                        } else {
                            AppendUInt(
                                out,
                                static_cast<const Counter &>(*metric).Value(i));
                        }
                        out += '\n';
                        break;
                    }
                    case MetricType::GAUGE: {
                        out += name;
                        if (AppendLabels(out, *metric, i)) {
                            out += '}';
                        }
                        out += ' ';
                        AppendValue(
                            out, static_cast<const Gauge &>(*metric).Value(i));
                        out += '\n';
                        break;
                    }
                    case MetricType::HISTOGRAM: {
                        const auto &h{
                            static_cast<const EventHistogram &>(*metric)};
                        const auto &s{h.m_series[i]};
                        uint64_t cumulative{0};
                        for (size_t b = 0; b <= h.Bounds().size(); ++b) {
                            cumulative += s.buckets[b];
                            out += name;
                            out += "_bucket";
                            if (AppendLabels(out, h, i)) {
                                out += ',';
                            } else {
                                out += '{';
                            }
                            out += "le=\"";
                            AppendValue(out, b < h.Bounds().size()
                                                 ? h.Bounds()[b]
                                                 : INFINITY);
                            out += "\"} ";
                            AppendUInt(out, cumulative);
                            out += '\n';
                        }
                        out += name;
                        out += "_sum";
                        if (AppendLabels(out, h, i)) {
                            out += '}';
                        }
                        out += ' ';
                        AppendValue(out, double(s.sum) / h.Divisor());
                        out += '\n';
                        out += name;
                        out += "_count";
                        if (AppendLabels(out, h, i)) {
                            out += '}';
                        }
                        out += ' ';
                        AppendUInt(out, s.count);
                        out += '\n';
                        break;
                    }
                }
            }
        }
    }
    out += "# HELP lotus_metrics_dropped_samples_total Event samples dropped "
           "because a recording thread's buffer was full.\n"
           "# TYPE lotus_metrics_dropped_samples_total counter\n"
           "lotus_metrics_dropped_samples_total ";
    AppendUInt(out, DroppedSamples());
    out += '\n';
    m_rendered = out;
    m_rendered_at = now;
    return out;
}

} // namespace metrics
