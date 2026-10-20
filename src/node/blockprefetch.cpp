// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockprefetch.h>

#include <dbwrapper.h>
#include <logging.h>
#include <node/metrics.h>
#include <primitives/block.h>
#include <txdb.h>
#include <util/hasher.h>
#include <util/threadnames.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>
#include <string>
#include <unordered_set>

namespace node {

struct BlockPrefetcher::Job {
    std::shared_ptr<const CBlock> block;
    std::shared_ptr<DBBackgroundHandle> db;
    std::chrono::steady_clock::time_point started;
    //! Sorted, deduplicated coin keys; written before any stripe runs
    std::vector<std::vector<uint8_t>> keys;
    size_t stripes{1};
    std::atomic<size_t> stripes_left{1};
    std::atomic<bool> closed{false};
    std::atomic<bool> failed{false};
};

BlockPrefetcher::BlockPrefetcher(Options options)
    : m_options{std::move(options)} {}

BlockPrefetcher::~BlockPrefetcher() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stopping = true;
        m_tasks.clear();
    }
    m_work.notify_all();
    for (auto &t : m_threads) {
        t.join();
    }
}

BlockPrefetcher::Result
BlockPrefetcher::Start(std::shared_ptr<const CBlock> block,
                       std::shared_ptr<DBBackgroundHandle> db) {
    if (!Enabled() || !block || !db) {
        return Result::DISABLED;
    }
    if (block->vtx.size() < m_options.min_txs) {
        return Result::SMALL;
    }
    const BlockHash hash{block->GetHash()};
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_stopping) {
        return Result::DISABLED;
    }
    if (std::find(m_recent.begin(), m_recent.end(), hash) != m_recent.end()) {
        ++m_stats.duplicates;
        return Result::DUPLICATE;
    }
    if (m_in_flight >= m_options.max_in_flight) {
        ++m_stats.dropped;
        if (auto *m{GetNodeMetrics()}) {
            m->block_prefetch_dropped.Inc();
        }
        return Result::DROPPED;
    }
    m_recent[m_recent_next] = hash;
    m_recent_next = (m_recent_next + 1) % m_recent.size();
    ++m_in_flight;
    ++m_stats.started;
    if (auto *m{GetNodeMetrics()}) {
        m->block_prefetch_started.Inc();
    }
    auto job{std::make_shared<Job>()};
    job->block = std::move(block);
    job->db = std::move(db);
    job->started = std::chrono::steady_clock::now();
    Post(lock, [this, job] { RunJob(job); });
    return Result::STARTED;
}

void BlockPrefetcher::Post(std::unique_lock<std::mutex> &lock,
                           std::function<void()> task) {
    if (m_stopping) {
        return;
    }
    m_tasks.push_back(std::move(task));
    // Threads start on first use, so that a node (or test) that never sees
    // a large block never runs them. They are only created here, under
    // m_mutex and before m_stopping, so the destructor joins all of them.
    if (m_threads.empty()) {
        for (size_t id = 0; id < m_options.threads; ++id) {
            m_threads.emplace_back([this, id] { WorkerLoop(id); });
        }
    }
    lock.unlock();
    m_work.notify_one();
    lock.lock();
}

void BlockPrefetcher::WorkerLoop(size_t id) {
    util::ThreadRename("blkprefetch." + std::to_string(id));
    for (;;) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_work.wait(lock, [this] {
                return m_stopping || (!m_paused && !m_tasks.empty());
            });
            if (m_stopping) {
                return;
            }
            task = std::move(m_tasks.front());
            m_tasks.pop_front();
        }
        task();
    }
}

void BlockPrefetcher::RunJob(const std::shared_ptr<Job> &job) {
    const CBlock &block{*job->block};
    try {
        // Coins created in the block itself are not in the database.
        std::unordered_set<TxId, SaltedTxIdHasher> in_block;
        in_block.reserve(block.vtx.size());
        for (const auto &tx : block.vtx) {
            in_block.insert(tx->GetId());
        }
        std::vector<COutPoint> outpoints;
        outpoints.reserve(block.vtx.size() * 2);
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            for (const auto &in : block.vtx[i]->vin) {
                if (!in_block.count(in.prevout.GetTxId())) {
                    outpoints.push_back(in.prevout);
                }
            }
        }
        job->keys = CCoinsViewDB::CoinKeys(outpoints);
        std::sort(job->keys.begin(), job->keys.end());
        job->keys.erase(std::unique(job->keys.begin(), job->keys.end()),
                        job->keys.end());
    } catch (const std::exception &e) {
        LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Warning,
                      "block prefetch: %s\n", e.what());
        job->keys.clear();
        job->failed = true;
    }
    const size_t n{job->keys.size()};
    const size_t min_stripe{std::max<size_t>(1, m_options.min_stripe_keys)};
    job->stripes = std::clamp<size_t>((n + min_stripe - 1) / min_stripe, 1,
                                      std::max<size_t>(1, m_options.threads));
    job->stripes_left.store(job->stripes, std::memory_order_relaxed);
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_stats.outpoints += n;
        for (size_t s = 1; s < job->stripes && !m_stopping; ++s) {
            Post(lock, [this, job, s] { RunStripe(job, s); });
        }
    }
    RunStripe(job, 0);
}

void BlockPrefetcher::RunStripe(const std::shared_ptr<Job> &job,
                                size_t stripe) {
    const size_t n{job->keys.size()};
    const size_t begin{n * stripe / job->stripes};
    const size_t end{n * (stripe + 1) / job->stripes};
    if (begin < end) {
        try {
            const Span<const std::vector<uint8_t>> keys{
                job->keys.data() + begin, end - begin};
            if (!job->db->Use([&](const CDBWrapper &db) {
                    db.PrefetchSortedRawKeys(keys);
                })) {
                job->closed = true;
            }
        } catch (const std::exception &e) {
            LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Warning,
                          "block prefetch: %s\n", e.what());
            job->failed = true;
        }
    }
    FinishStripe(job);
}

void BlockPrefetcher::FinishStripe(const std::shared_ptr<Job> &job) {
    if (job->stripes_left.fetch_sub(1, std::memory_order_acq_rel) != 1) {
        return;
    }
    const auto elapsed{std::chrono::steady_clock::now() - job->started};
    if (auto *m{GetNodeMetrics()}) {
        m->block_prefetch_outpoints.Add(0, job->keys.size());
        m->block_prefetch_seconds.RecordDuration(elapsed);
        if (job->failed) {
            m->block_prefetch_errors.Inc();
        }
    }
    LogDebug(BCLog::BENCH,
             "Block prefetch %s: %u coins in %u stripes, %.2fms%s\n",
             job->block->GetHash().ToString(), job->keys.size(), job->stripes,
             std::chrono::duration<double, std::milli>(elapsed).count(),
             job->closed ? " (database closed)" : "");
    // Release the block and keys before the job is counted as done.
    job->keys = {};
    job->block.reset();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        --m_in_flight;
        ++m_stats.completed;
        m_stats.errors += job->failed ? 1 : 0;
        m_stats.closed += job->closed ? 1 : 0;
    }
    m_idle.notify_all();
}

void BlockPrefetcher::WaitIdle() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_idle.wait(lock, [this] { return m_in_flight == 0 || m_stopping; });
}

void BlockPrefetcher::Pause() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_paused = true;
}

void BlockPrefetcher::Resume() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_paused = false;
    }
    m_work.notify_all();
}

BlockPrefetcher::Stats BlockPrefetcher::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

} // namespace node
