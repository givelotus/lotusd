// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block validation costs that grow with the number of transactions in a
// block: the Merkle root over the transaction ids, deserializing the block
// (which hashes every transaction for its id), and walking the UTXO database
// for the coins a block spends. Each is measured at several block sizes, so
// that a base and a patched build can be compared with the same benchmark
// names (see contrib/bench/block-validation/).

#include <bench/bench.h>

#include <coins.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <streams.h>
#include <txdb.h>
#include <uint256.h>
#include <validation.h>

#include <cassert>
#include <vector>

namespace {

/** A block of n_txs small transactions (one input, one output each). */
CBlock MakeSyntheticBlock(size_t n_txs) {
    FastRandomContext rng{/*fDeterministic=*/true};
    CBlock block;
    block.vtx.reserve(n_txs);
    for (size_t i = 0; i < n_txs; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        // The first is a coinbase (null prevout), as in a real block.
        mtx.vin[0].prevout =
            i == 0 ? COutPoint{}
                   : COutPoint(TxId(rng.rand256()), uint32_t(i & 3));
        mtx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(72, 1)
                                         << std::vector<uint8_t>(33, 2);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = int64_t(i + 1) * SATOSHI;
        mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                             << std::vector<uint8_t>(20, 3)
                                             << OP_EQUALVERIFY << OP_CHECKSIG;
        block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

/**
 * The Merkle check of block validation (CheckMerkleRoot, through
 * IsBlockMutated as net_processing calls it on arrival), which is where a
 * node computes a received block's Merkle root.
 */
void CheckBlockMerkleRootN(benchmark::Bench &bench, size_t n_txs) {
    const CBlock block{MakeSyntheticBlock(n_txs)};
    bench.batch(n_txs).unit("tx").run([&] {
        // Cached per block once checked: measure the computation each time.
        block.m_checked_merkle_root = false;
        const bool mutated{IsBlockMutated(block)};
        assert(!mutated);
    });
}

void BlockMerkleRootN(benchmark::Bench &bench, size_t n_txs) {
    const CBlock block{MakeSyntheticBlock(n_txs)};
    const uint256 expected{BlockMerkleRoot(block)};
    bench.batch(n_txs).unit("tx").run([&] {
        bool mutated{false};
        const uint256 root{BlockMerkleRoot(block, &mutated)};
        assert(root == expected && !mutated);
        ankerl::nanobench::doNotOptimizeAway(root);
    });
}

/**
 * ValidationBlockMerkleRoot forced onto `threads` threads at any size, to
 * find the size from which threading wins (compare with BlockMerkleRoot_<n>
 * in the same run).
 */
void MerkleRootThreadsN(benchmark::Bench &bench, size_t n_txs, size_t threads) {
    const CBlock block{MakeSyntheticBlock(n_txs)};
    const uint256 expected{BlockMerkleRoot(block)};
    bench.batch(n_txs).unit("tx").run([&] {
        bool mutated{false};
        const uint256 root{ValidationBlockMerkleRoot(
            block, &mutated, /*min_parallel_txs=*/0, threads)};
        assert(root == expected && !mutated);
    });
}

/** Deserialize a whole block: transaction layout plus one id hash each. */
void DeserializeBlockN(benchmark::Bench &bench, size_t n_txs) {
    DataStream stream{};
    stream << MakeSyntheticBlock(n_txs);
    const size_t size{stream.size()};
    // Prevent compaction
    std::byte a{0};
    stream.write({&a, 1});
    bench.batch(n_txs).unit("tx").run([&] {
        CBlock block;
        stream >> block;
        assert(block.vtx.size() == n_txs);
        const bool rewound{stream.Rewind(size)};
        assert(rewound);
    });
}

/** The transaction id hashing part of DeserializeBlockN alone. */
void HashBlockTxIdsN(benchmark::Bench &bench, size_t n_txs) {
    const CBlock block{MakeSyntheticBlock(n_txs)};
    std::vector<std::vector<uint8_t>> wires;
    wires.reserve(n_txs);
    for (const auto &tx : block.vtx) {
        DataStream s{};
        s << *tx;
        const auto span{MakeUCharSpan(s)};
        wires.emplace_back(span.begin(), span.end());
    }
    bench.batch(n_txs).unit("tx").run([&] {
        uint256 acc;
        for (const auto &wire : wires) {
            HashWriter hasher;
            hasher.write(MakeByteSpan(wire));
            acc = hasher.GetHash();
        }
        assert(acc == block.vtx.back()->GetId());
        ankerl::nanobench::doNotOptimizeAway(acc);
    });
}

/**
 * The synchronous UTXO prefetch walk (sorted cursor seeks plus readahead
 * hints) over n_outpoints random coins of a 500k-coin database. The
 * database is in memory here, so this is the walk's CPU cost on a warm
 * cache; it is what the mempool and ConnectBlock pay on their own thread.
 */
void CoinsPrefetchWalkN(benchmark::Bench &bench, size_t n_outpoints) {
    FastRandomContext rng{/*fDeterministic=*/true};
    DBParams params{};
    params.path = fs::path("bench_prefetch_walk");
    params.cache_bytes = 8 << 20;
    params.memory_only = true;
    CCoinsViewDB db{params, CoinsViewOptions{}};
    std::vector<COutPoint> all;
    constexpr size_t N_COINS{500'000};
    all.reserve(N_COINS);
    {
        CCoinsViewCache cache{&db};
        for (size_t i = 0; i < N_COINS; ++i) {
            const COutPoint op{TxId(rng.rand256()), uint32_t(i & 1)};
            Coin coin{CTxOut{int64_t(i + 1) * SATOSHI,
                             CScript() << OP_DUP << OP_HASH160
                                       << std::vector<uint8_t>(20, 3)
                                       << OP_EQUALVERIFY << OP_CHECKSIG},
                      1, false};
            cache.AddCoin(op, std::move(coin), false);
            all.push_back(op);
        }
        cache.SetBestBlock(BlockHash{rng.rand256()});
        cache.Flush();
    }
    std::vector<COutPoint> wanted;
    wanted.reserve(n_outpoints);
    for (size_t i = 0; i < n_outpoints; ++i) {
        wanted.push_back(all[rng.randrange(all.size())]);
    }
    bench.batch(n_outpoints).unit("outpoint").run([&] {
        db.PrefetchOutpointsAsync(wanted);
    });
}

} // namespace

#define BLOCK_SCALING_BENCH(fn, n)                                             \
    static void fn##_##n(benchmark::Bench &bench) {                            \
        fn##N(bench, n);                                                       \
    }                                                                          \
    BENCHMARK(fn##_##n)

BLOCK_SCALING_BENCH(BlockMerkleRoot, 1000);
BLOCK_SCALING_BENCH(BlockMerkleRoot, 5000);
BLOCK_SCALING_BENCH(BlockMerkleRoot, 10000);
BLOCK_SCALING_BENCH(BlockMerkleRoot, 50000);
BLOCK_SCALING_BENCH(BlockMerkleRoot, 100000);

BLOCK_SCALING_BENCH(CheckBlockMerkleRoot, 1000);
BLOCK_SCALING_BENCH(CheckBlockMerkleRoot, 5000);
BLOCK_SCALING_BENCH(CheckBlockMerkleRoot, 10000);
BLOCK_SCALING_BENCH(CheckBlockMerkleRoot, 50000);
BLOCK_SCALING_BENCH(CheckBlockMerkleRoot, 100000);

BLOCK_SCALING_BENCH(DeserializeBlock, 1000);
BLOCK_SCALING_BENCH(DeserializeBlock, 10000);
BLOCK_SCALING_BENCH(DeserializeBlock, 100000);

BLOCK_SCALING_BENCH(HashBlockTxIds, 1000);
BLOCK_SCALING_BENCH(HashBlockTxIds, 10000);
BLOCK_SCALING_BENCH(HashBlockTxIds, 100000);

BLOCK_SCALING_BENCH(CoinsPrefetchWalk, 100);
BLOCK_SCALING_BENCH(CoinsPrefetchWalk, 1000);
BLOCK_SCALING_BENCH(CoinsPrefetchWalk, 5000);

#define MERKLE_THREADS_BENCH(n, t)                                             \
    static void MerkleRootThreads_##n##_t##t(benchmark::Bench &bench) {        \
        MerkleRootThreadsN(bench, n, t);                                       \
    }                                                                          \
    BENCHMARK(MerkleRootThreads_##n##_t##t)

MERKLE_THREADS_BENCH(1000, 1);
MERKLE_THREADS_BENCH(1000, 2);
MERKLE_THREADS_BENCH(1000, 4);
MERKLE_THREADS_BENCH(1000, 8);
MERKLE_THREADS_BENCH(2500, 1);
MERKLE_THREADS_BENCH(2500, 4);
MERKLE_THREADS_BENCH(2500, 8);
MERKLE_THREADS_BENCH(5000, 1);
MERKLE_THREADS_BENCH(5000, 2);
MERKLE_THREADS_BENCH(5000, 4);
MERKLE_THREADS_BENCH(5000, 8);
MERKLE_THREADS_BENCH(10000, 2);
MERKLE_THREADS_BENCH(10000, 4);
MERKLE_THREADS_BENCH(10000, 8);
MERKLE_THREADS_BENCH(50000, 2);
MERKLE_THREADS_BENCH(50000, 4);
MERKLE_THREADS_BENCH(50000, 8);
MERKLE_THREADS_BENCH(100000, 2);
MERKLE_THREADS_BENCH(100000, 4);
MERKLE_THREADS_BENCH(100000, 8);
