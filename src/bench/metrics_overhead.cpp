// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Cost of the metrics recording added to hot paths: each benchmark runs the
// same work with the node's metrics off (as without -metrics) and on.

#include <bench/bench.h>
#include <coins.h>
#include <consensus/amount.h>
#include <kernel/mempool_entry.h>
#include <metrics/metrics.h>
#include <node/metrics.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <test/util/setup_common.h>
#include <txmempool.h>

#include <vector>

namespace {
/**
 * Turns the node's metrics on (as -metrics does, drain thread running) for
 * its lifetime. The metrics object is created once and never freed, as in
 * the node.
 */
class NodeMetricsOn {
public:
    NodeMetricsOn() {
        if (!s_metrics) {
            s_metrics = new node::NodeMetrics({});
            s_metrics->registry.Start();
        }
        node::detail::g_node_metrics.store(s_metrics,
                                           std::memory_order_release);
        metrics::SetThreadRegistry(&s_metrics->registry);
        metrics::PrepareThisThread();
    }
    ~NodeMetricsOn() {
        metrics::SetThreadRegistry(nullptr);
        node::detail::g_node_metrics.store(nullptr, std::memory_order_release);
    }
    node::NodeMetrics &Get() { return *s_metrics; }

private:
    static inline node::NodeMetrics *s_metrics{nullptr};
};

constexpr size_t NUM_COINS{1000};

std::vector<COutPoint> AddCoins(CCoinsViewCache &view) {
    std::vector<COutPoint> outpoints;
    for (size_t i = 0; i < NUM_COINS; ++i) {
        uint256 h;
        h.data()[0] = uint8_t(i);
        h.data()[1] = uint8_t(i >> 8);
        outpoints.emplace_back(TxId{h}, 0);
        view.AddCoin(outpoints.back(),
                     Coin{CTxOut{SATOSHI, CScript{} << OP_TRUE}, 1, false},
                     /*possible_overwrite=*/false);
    }
    return outpoints;
}

//! UTXO cache lookups that hit (the common case in block validation)
void UtxoCacheHit(benchmark::Bench &bench, bool metrics_on) {
    std::optional<NodeMetricsOn> on;
    if (metrics_on) {
        on.emplace();
    }
    CCoinsView empty;
    CCoinsViewCache base{&empty};
    const auto outpoints{AddCoins(base)};
    CCoinsViewCache cache{&base};
    if (on) {
        cache.SetLookupMetric(&on->Get().utxo_cache_lookups);
    }
    for (const auto &o : outpoints) {
        (void)cache.HaveCoin(o);
    }
    bench.batch(NUM_COINS).unit("lookup").run([&] {
        for (const auto &o : outpoints) {
            ankerl::nanobench::doNotOptimizeAway(cache.HaveCoin(o));
        }
    });
}

//! Signature cache lookups that hit the thread's first-level cache
void SigCacheHit(benchmark::Bench &bench, bool metrics_on) {
    std::optional<NodeMetricsOn> on;
    if (metrics_on) {
        on.emplace();
    }
    SignatureCache cache{1 << 20};
    uint256 entry;
    entry.data()[0] = 1;
    cache.Set(entry);
    bench.run(
        [&] { ankerl::nanobench::doNotOptimizeAway(cache.Get(entry, false)); });
}

void AddTx(const CTransactionRef &tx, const Amount &fee, CTxMemPool &pool)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
    LockPoints lp;
    pool.addUnchecked(CTxMemPoolEntryRef::make(tx, fee, /*time=*/0,
                                               /*height=*/1,
                                               /*sigchecks=*/1, lp));
}

/**
 * Mempool additions and size-limit evictions (as the MempoolEviction
 * bench): each addition publishes a mempool snapshot (counted and timed
 * with metrics on) and each eviction counts a removal.
 */
void MempoolAddEvict(benchmark::Bench &bench, bool metrics_on) {
    std::optional<NodeMetricsOn> on;
    if (metrics_on) {
        on.emplace();
    }
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    std::vector<CTransactionRef> txs;
    for (int i = 0; i < 8; ++i) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        uint256 prev;
        prev.data()[0] = uint8_t(i + 1);
        tx.vin[0].prevout = COutPoint(TxId{prev}, 0);
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout.resize(1);
        tx.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
        tx.vout[0].nValue = 10 * COIN;
        txs.push_back(MakeTransactionRef(tx));
    }
    CTxMemPool &pool = *Assert(testing_setup->m_node.mempool);
    LOCK2(cs_main, pool.cs);
    bench.batch(txs.size()).unit("tx").run([&]() NO_THREAD_SAFETY_ANALYSIS {
        int64_t fee{1000};
        for (const auto &tx : txs) {
            AddTx(tx, (fee += 1000) * SATOSHI, pool);
        }
        pool.TrimToSize(0);
    });
}
} // namespace

static void MetricsOverheadUtxoCacheHitOff(benchmark::Bench &bench) {
    UtxoCacheHit(bench, false);
}
static void MetricsOverheadUtxoCacheHitOn(benchmark::Bench &bench) {
    UtxoCacheHit(bench, true);
}
static void MetricsOverheadSigCacheHitOff(benchmark::Bench &bench) {
    SigCacheHit(bench, false);
}
static void MetricsOverheadSigCacheHitOn(benchmark::Bench &bench) {
    SigCacheHit(bench, true);
}
static void MetricsOverheadMempoolAddEvictOff(benchmark::Bench &bench) {
    MempoolAddEvict(bench, false);
}
static void MetricsOverheadMempoolAddEvictOn(benchmark::Bench &bench) {
    MempoolAddEvict(bench, true);
}

BENCHMARK(MetricsOverheadUtxoCacheHitOff);
BENCHMARK(MetricsOverheadUtxoCacheHitOn);
BENCHMARK(MetricsOverheadSigCacheHitOff);
BENCHMARK(MetricsOverheadSigCacheHitOn);
BENCHMARK(MetricsOverheadMempoolAddEvictOff);
BENCHMARK(MetricsOverheadMempoolAddEvictOn);
