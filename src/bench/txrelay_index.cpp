// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <net/txrelay_index.h>
#include <random.h>

#include <chrono>
#include <utility>
#include <vector>

// Cost of Nucleation relay's short-id index: re-keying at a new block (one
// SipHash and two hash-map inserts per mempool transaction), indexing one
// admitted transaction, and looking up an announced short id.

static std::vector<std::pair<TxId, std::chrono::microseconds>>
MakeMempool(size_t n) {
    FastRandomContext rng{true};
    std::vector<std::pair<TxId, std::chrono::microseconds>> txs;
    txs.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        txs.emplace_back(TxId{rng.rand256()},
                         std::chrono::microseconds{int64_t(i)});
    }
    return txs;
}

static void RelayIndexRekey(benchmark::Bench &bench, size_t n) {
    const auto txs{MakeMempool(n)};
    FastRandomContext rng{true};
    txrelay::TxRelayIndex index;
    // One run = one new epoch over the whole mempool.
    bench.batch(n).unit("tx").run([&] {
        index.SetEpoch(txrelay::MakeEpochKey(BlockHash{rng.rand256()}, 1),
                       [&] { return txs; });
    });
}

static void RelayIndexRekey10k(benchmark::Bench &bench) {
    bench.minEpochIterations(10);
    RelayIndexRekey(bench, 10'000);
}
static void RelayIndexRekey1M(benchmark::Bench &bench) {
    bench.epochs(1).epochIterations(3);
    RelayIndexRekey(bench, 1'000'000);
}

static void RelayIndexAddRemove(benchmark::Bench &bench) {
    const auto txs{MakeMempool(100'000)};
    txrelay::TxRelayIndex index;
    index.SetEpoch(txrelay::MakeEpochKey(BlockHash{}, 1), [&] { return txs; });
    FastRandomContext rng{true};
    bench.minEpochIterations(20'000).run([&] {
        const TxId txid{rng.rand256()};
        index.Add(txid, std::chrono::microseconds{0});
        index.Remove(txid);
    });
}

static void RelayIndexFind(benchmark::Bench &bench) {
    const auto txs{MakeMempool(100'000)};
    txrelay::TxRelayIndex index;
    const auto key{txrelay::MakeEpochKey(BlockHash{}, 1)};
    index.SetEpoch(key, [&] { return txs; });
    size_t i{0};
    std::vector<TxId> out;
    bench.minEpochIterations(200'000).run([&] {
        // Half present, half missing
        const uint64_t id{i % 2 ? index.ShortId(key, txs[i % txs.size()].first)
                                : uint64_t(i * 0x9e3779b97f4a7c15ULL)};
        out.clear();
        ankerl::nanobench::doNotOptimizeAway(
            index.Find(key.epoch_id, id, &out));
        ++i;
    });
}

BENCHMARK(RelayIndexRekey10k);
BENCHMARK(RelayIndexRekey1M);
BENCHMARK(RelayIndexAddRemove);
BENCHMARK(RelayIndexFind);
