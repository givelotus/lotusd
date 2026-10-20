// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKPREFETCH_H
#define BITCOIN_NODE_BLOCKPREFETCH_H

#include <primitives/blockhash.h>

#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

class CBlock;
class DBBackgroundHandle;

namespace node {

//! Default for -blockprefetch: background prefetch threads (0 disables).
static constexpr int DEFAULT_BLOCK_PREFETCH_THREADS{4};
//! Upper bound accepted for -blockprefetch.
static constexpr int MAX_BLOCK_PREFETCH_THREADS{16};
//! Blocks prefetched at once; further blocks are dropped, not queued.
static constexpr size_t BLOCK_PREFETCH_MAX_IN_FLIGHT{2};
//! Blocks with fewer transactions are not prefetched (as in ConnectBlock).
static constexpr size_t BLOCK_PREFETCH_MIN_TXS{9};
//! A block's sorted keys are walked in up to `threads` stripes of at least
//! this many keys each, so that several reads are outstanding at once.
static constexpr size_t BLOCK_PREFETCH_MIN_STRIPE_KEYS{256};

/**
 * Reads the UTXO database pages of the coins a block spends, on background
 * threads, as soon as the block arrives, so that the disk reads overlap with
 * the block's earlier checks (Merkle root, CheckBlock, writing it to disk)
 * instead of starting inside ConnectBlock.
 *
 * - Bounded: at most max_in_flight blocks at once; others are dropped.
 * - The workers never take cs_main: they only read the coins database
 *   through a DBBackgroundHandle (own MDBX read transaction and cursor),
 *   which turns into a no-op if the database is closed or reopened.
 * - Results only warm the OS page cache: nothing it does changes what
 *   validation reads or decides. ConnectBlock still issues its own
 *   (then cheap) prefetch.
 */
class BlockPrefetcher {
public:
    struct Options {
        size_t threads{DEFAULT_BLOCK_PREFETCH_THREADS};
        size_t max_in_flight{BLOCK_PREFETCH_MAX_IN_FLIGHT};
        size_t min_txs{BLOCK_PREFETCH_MIN_TXS};
        size_t min_stripe_keys{BLOCK_PREFETCH_MIN_STRIPE_KEYS};
    };
    enum class Result { STARTED, DISABLED, SMALL, DUPLICATE, DROPPED };
    struct Stats {
        uint64_t started{0};
        uint64_t dropped{0};
        uint64_t duplicates{0};
        uint64_t completed{0};
        uint64_t outpoints{0};
        uint64_t errors{0};
        //! Jobs that found the database closed (detached handle)
        uint64_t closed{0};
    };

    explicit BlockPrefetcher(Options options);
    ~BlockPrefetcher();
    BlockPrefetcher(const BlockPrefetcher &) = delete;
    BlockPrefetcher &operator=(const BlockPrefetcher &) = delete;

    bool Enabled() const { return m_options.threads > 0; }
    const Options &GetOptions() const { return m_options; }

    /**
     * Start prefetching the coins the block spends from db, unless the
     * block is small, was started recently, or max_in_flight blocks are
     * being prefetched. Never blocks on I/O.
     */
    Result Start(std::shared_ptr<const CBlock> block,
                 std::shared_ptr<DBBackgroundHandle> db);

    /** Wait until no block is being prefetched (tests). */
    void WaitIdle();
    /** Hold queued work (tests): workers start nothing until Resume(). */
    void Pause();
    void Resume();

    Stats GetStats() const;

private:
    struct Job;
    void Post(std::unique_lock<std::mutex> &lock, std::function<void()> task);
    void RunJob(const std::shared_ptr<Job> &job);
    void RunStripe(const std::shared_ptr<Job> &job, size_t stripe);
    void FinishStripe(const std::shared_ptr<Job> &job);
    void WorkerLoop(size_t id);

    const Options m_options;

    mutable std::mutex m_mutex;
    std::condition_variable m_work;
    std::condition_variable m_idle;
    std::deque<std::function<void()>> m_tasks;
    std::vector<std::thread> m_threads;
    size_t m_in_flight{0};
    bool m_stopping{false};
    bool m_paused{false};
    //! Recently started blocks, to start each only once
    std::array<BlockHash, 8> m_recent;
    size_t m_recent_next{0};
    Stats m_stats;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKPREFETCH_H
