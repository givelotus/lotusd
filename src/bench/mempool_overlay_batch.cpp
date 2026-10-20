// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <lotus_v2/mempool_overlay.h>
#include <random.h>

#include <vector>

/**
 * Cost of adding one small batch of transactions to a speculative Merklix
 * overlay that already holds a large mempool. Mempool admission publishes a
 * batch like this after every coalesced burst of peer transactions, so the
 * per-batch cost must not grow with the size of the overlay.
 */
namespace {

lotus::v2::Hash RandomHash(FastRandomContext &rng) {
    lotus::v2::Hash h;
    const uint256 r = rng.rand256();
    std::copy(r.begin(), r.end(), h.begin());
    return h;
}

std::vector<lotus::v2::OverlayTxEntry> MakeBatch(FastRandomContext &rng,
                                                 size_t n) {
    std::vector<lotus::v2::OverlayTxEntry> batch(n);
    for (auto &e : batch) {
        e.tx_id = RandomHash(rng);
        e.tx_hash = RandomHash(rng);
        e.linear_cost = 220;
        e.fee_sats = 500;
        e.sigchecks = 1;
        e.spent_outpoints.push_back({RandomHash(rng), 0});
        for (uint32_t i = 0; i < 2; ++i) {
            lotus::v2::Coin coin;
            coin.outpoint = {e.tx_id, i};
            coin.output.value = 1000;
            e.created_coins.push_back(std::move(coin));
        }
    }
    return batch;
}

void AddBatches(benchmark::Bench &bench, size_t pool_size, size_t batch_size) {
    FastRandomContext rng(/*fDeterministic=*/true);
    lotus::v2::MempoolOverlayLayer layer;
    for (size_t added = 0; added < pool_size; added += batch_size) {
        auto batch = MakeBatch(rng, batch_size);
        layer.AddTransactionBatch(batch);
    }
    bench.batch(batch_size).unit("tx").run([&] {
        auto batch = MakeBatch(rng, batch_size);
        layer.AddTransactionBatch(batch);
    });
}

} // namespace

static void MempoolOverlayAddBatch64To10k(benchmark::Bench &bench) {
    AddBatches(bench, 10'000, 64);
}
static void MempoolOverlayAddBatch64To100k(benchmark::Bench &bench) {
    AddBatches(bench, 100'000, 64);
}

BENCHMARK(MempoolOverlayAddBatch64To10k);
BENCHMARK(MempoolOverlayAddBatch64To100k);
