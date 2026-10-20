// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockprefetch.h>

#include <coins.h>
#include <dbwrapper.h>
#include <primitives/block.h>
#include <script/standard.h>
#include <txdb.h>
#include <validation.h>

#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

using node::BlockPrefetcher;

namespace {

std::unique_ptr<CCoinsViewDB> MakeCoinsDB(std::vector<COutPoint> &coins,
                                          size_t n, FastRandomContext &rng) {
    DBParams params{};
    params.path = fs::path("blockprefetch_test");
    params.cache_bytes = 1 << 20;
    params.memory_only = true;
    auto db{std::make_unique<CCoinsViewDB>(params, CoinsViewOptions{})};
    CCoinsViewCache cache{db.get()};
    for (size_t i = 0; i < n; ++i) {
        const COutPoint op{TxId(rng.rand256()), uint32_t(i % 3)};
        cache.AddCoin(
            op,
            Coin{CTxOut{int64_t(i + 1) * SATOSHI, CScript() << OP_1}, 1, false},
            false);
        coins.push_back(op);
    }
    cache.SetBestBlock(BlockHash{rng.rand256()});
    cache.Flush();
    return db;
}

//! A block (PoW not checked here) whose transactions spend `spends`, one
//! input each, after a coinbase.
std::shared_ptr<const CBlock> MakeBlock(const std::vector<COutPoint> &spends,
                                        FastRandomContext &rng) {
    auto block{std::make_shared<CBlock>()};
    block->nNonce = uint32_t(rng.rand32());
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout = COutPoint{};
    cb.vout.resize(1);
    block->vtx.push_back(MakeTransactionRef(std::move(cb)));
    for (const COutPoint &op : spends) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = op;
        mtx.vout.resize(1);
        mtx.vout[0].nValue = SATOSHI;
        block->vtx.push_back(MakeTransactionRef(std::move(mtx)));
    }
    return block;
}

BlockPrefetcher::Options SmallOptions() {
    BlockPrefetcher::Options opts;
    opts.threads = 2;
    opts.max_in_flight = 2;
    opts.min_txs = 3;
    opts.min_stripe_keys = 4;
    return opts;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(blockprefetch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bounded_deduplicated_and_skips_small_blocks) {
    FastRandomContext rng{/*fDeterministic=*/true};
    std::vector<COutPoint> coins;
    auto db{MakeCoinsDB(coins, 1000, rng)};
    BlockPrefetcher prefetcher{SmallOptions()};
    using R = BlockPrefetcher::Result;

    const auto a{MakeBlock({coins.begin(), coins.begin() + 20}, rng)};
    const auto b{MakeBlock({coins.begin() + 20, coins.begin() + 40}, rng)};
    const auto c{MakeBlock({coins.begin() + 40, coins.begin() + 60}, rng)};
    const auto small{MakeBlock({coins[60]}, rng)};
    auto handle{db->GetBackgroundHandle()};

    prefetcher.Pause();
    BOOST_CHECK(prefetcher.Start(a, handle) == R::STARTED);
    BOOST_CHECK(prefetcher.Start(a, handle) == R::DUPLICATE);
    BOOST_CHECK(prefetcher.Start(b, handle) == R::STARTED);
    // Two in flight: the third is dropped, not queued.
    BOOST_CHECK(prefetcher.Start(c, handle) == R::DROPPED);
    BOOST_CHECK(prefetcher.Start(small, handle) == R::SMALL);
    BOOST_CHECK(prefetcher.Start(nullptr, handle) == R::DISABLED);
    prefetcher.Resume();
    prefetcher.WaitIdle();

    // Room again once the first two are done; c was dropped, not recorded.
    BOOST_CHECK(prefetcher.Start(c, handle) == R::STARTED);
    prefetcher.WaitIdle();

    const auto stats{prefetcher.GetStats()};
    BOOST_CHECK_EQUAL(stats.started, 3U);
    BOOST_CHECK_EQUAL(stats.completed, 3U);
    BOOST_CHECK_EQUAL(stats.dropped, 1U);
    BOOST_CHECK_EQUAL(stats.duplicates, 1U);
    BOOST_CHECK_EQUAL(stats.outpoints, 60U);
    BOOST_CHECK_EQUAL(stats.errors, 0U);
    BOOST_CHECK_EQUAL(stats.closed, 0U);

    BlockPrefetcher disabled{BlockPrefetcher::Options{.threads = 0}};
    BOOST_CHECK(!disabled.Enabled());
    BOOST_CHECK(disabled.Start(a, handle) == R::DISABLED);
}

BOOST_AUTO_TEST_CASE(reads_only_coins_from_outside_the_block) {
    FastRandomContext rng{/*fDeterministic=*/true};
    std::vector<COutPoint> coins;
    auto db{MakeCoinsDB(coins, 200, rng)};
    BlockPrefetcher prefetcher{SmallOptions()};

    // 30 database coins, one of them spent twice (an invalid block, which
    // the prefetch must handle all the same), plus spends of outputs of
    // transactions in the block itself.
    std::vector<COutPoint> spends{coins.begin(), coins.begin() + 30};
    spends.push_back(coins[0]);
    auto block{std::make_shared<CBlock>(*MakeBlock(spends, rng))};
    for (size_t i = 1; i <= 5; ++i) {
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint{block->vtx[i]->GetId(), 0};
        mtx.vout.resize(1);
        block->vtx.push_back(MakeTransactionRef(std::move(mtx)));
    }
    BOOST_CHECK(prefetcher.Start(block, db->GetBackgroundHandle()) ==
                BlockPrefetcher::Result::STARTED);
    prefetcher.WaitIdle();
    BOOST_CHECK_EQUAL(prefetcher.GetStats().outpoints, 30U);
    BOOST_CHECK_EQUAL(prefetcher.GetStats().completed, 1U);

    // The prefetch only reads: every coin is still there and unchanged.
    for (size_t i = 0; i < coins.size(); ++i) {
        const auto coin{db->GetCoin(coins[i])};
        BOOST_REQUIRE(coin);
        BOOST_CHECK_EQUAL(coin->GetTxOut().nValue, int64_t(i + 1) * SATOSHI);
    }
}

BOOST_AUTO_TEST_CASE(database_closed_before_or_during_prefetch) {
    FastRandomContext rng{/*fDeterministic=*/true};
    std::vector<COutPoint> coins;
    auto db{MakeCoinsDB(coins, 500, rng)};
    BlockPrefetcher prefetcher{SmallOptions()};

    // Queued, then the database is closed (as on a cache resize, which
    // reopens it, or shutdown): the job finds the handle detached.
    prefetcher.Pause();
    BOOST_CHECK(
        prefetcher.Start(MakeBlock(coins, rng), db->GetBackgroundHandle()) ==
        BlockPrefetcher::Result::STARTED);
    auto handle{db->GetBackgroundHandle()};
    BOOST_CHECK(handle->IsOpen());
    db.reset();
    BOOST_CHECK(!handle->IsOpen());
    prefetcher.Resume();
    prefetcher.WaitIdle();
    BOOST_CHECK_EQUAL(prefetcher.GetStats().completed, 1U);
    BOOST_CHECK_EQUAL(prefetcher.GetStats().closed, 1U);
    BOOST_CHECK(!handle->Use([](const CDBWrapper &) { BOOST_ERROR("ran"); }));
}

BOOST_AUTO_TEST_CASE(database_destructor_waits_for_running_use) {
    DBParams params{};
    params.path = fs::path("blockprefetch_wait");
    params.cache_bytes = 1 << 20;
    params.memory_only = true;
    auto db{std::make_unique<CDBWrapper>(params)};
    db->Write(uint256::ONE, uint64_t{7});
    auto handle{db->GetBackgroundHandle()};

    std::atomic<bool> entered{false}, finished{false};
    std::thread reader{[&] {
        handle->Use([&](const CDBWrapper &d) {
            entered = true;
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            uint64_t v{0};
            BOOST_CHECK(d.Read(uint256::ONE, v));
            BOOST_CHECK_EQUAL(v, 7U);
            finished = true;
        });
    }};
    while (!entered) {
        std::this_thread::yield();
    }
    db.reset();
    // The destructor returned only after the reader was done with it.
    BOOST_CHECK(finished);
    reader.join();
}

BOOST_AUTO_TEST_CASE(prefetch_concurrent_with_database_writes) {
    // Background walks while the owner keeps writing (and the MDBX file
    // grows several times): each side uses its own transaction.
    FastRandomContext rng{/*fDeterministic=*/true};
    DBParams params{};
    params.path = fs::path("blockprefetch_concurrent");
    params.cache_bytes = 1 << 20;
    params.memory_only = true;
    CDBWrapper db{params};

    std::vector<uint256> keys;
    for (int i = 0; i < 2000; ++i) {
        keys.push_back(rng.rand256());
        db.Write(keys.back(), uint64_t(i));
    }
    std::vector<std::vector<uint8_t>> raw;
    for (const uint256 &k : keys) {
        DataStream s{};
        s << k;
        const auto span{MakeUCharSpan(s)};
        raw.emplace_back(span.begin(), span.end());
    }
    std::sort(raw.begin(), raw.end());

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> walks{0};
    std::vector<std::thread> readers;
    for (int t = 0; t < 3; ++t) {
        readers.emplace_back([&] {
            while (!stop) {
                db.GetBackgroundHandle()->Use(
                    [&](const CDBWrapper &d) { d.PrefetchSortedRawKeys(raw); });
                ++walks;
            }
        });
    }
    // About 40 MB of new entries, in batches.
    const std::vector<uint8_t> value(1000, 0x5a);
    for (int b = 0; b < 40; ++b) {
        CDBBatch batch{db};
        for (int i = 0; i < 1000; ++i) {
            batch.Write(rng.rand256(), value);
        }
        db.WriteBatch(batch);
    }
    stop = true;
    for (auto &t : readers) {
        t.join();
    }
    BOOST_CHECK(walks > 0);
    for (size_t i = 0; i < keys.size(); ++i) {
        uint64_t v{0};
        BOOST_REQUIRE(db.Read(keys[i], v));
        BOOST_CHECK_EQUAL(v, i);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(blockprefetch_chain_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(process_new_block_prefetches_spent_coins) {
    // Ten spends of mature coinbases plus one spend of a transaction in the
    // same block: the block is connected as usual and its ten database
    // coins were prefetched in the background.
    // Mature the first ten coinbases.
    mineBlocks(10);
    std::vector<CMutableTransaction> txs;
    const CScript p2pk{CScript()
                       << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    for (int i = 0; i < 10; ++i) {
        txs.push_back(CreateValidMempoolTransaction(
            m_coinbase_txns[i], 0, i + 1, coinbaseKey, p2pk, 10 * COIN,
            /*submit=*/false));
    }
    txs.push_back(CreateValidMempoolTransaction(
        MakeTransactionRef(txs[0]), 0, 111, coinbaseKey, p2pk, 5 * COIN,
        /*submit=*/false));

    auto &prefetcher{m_node.chainman->GetBlockPrefetcher()};
    BOOST_CHECK(prefetcher.Enabled());
    const int height{
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight())};
    const CBlock block{CreateAndProcessBlock(txs, p2pk)};
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main,
                  return m_node.chainman->ActiveTip()->GetBlockHash()),
        block.GetHash());
    BOOST_CHECK_EQUAL(
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveHeight()),
        height + 1);
    prefetcher.WaitIdle();
    const auto stats{prefetcher.GetStats()};
    BOOST_CHECK_EQUAL(stats.started, 1U);
    BOOST_CHECK_EQUAL(stats.completed, 1U);
    BOOST_CHECK_EQUAL(stats.outpoints, 10U);
    BOOST_CHECK_EQUAL(stats.errors, 0U);

    // A block too small to prefetch is not started.
    CreateAndProcessBlock({}, p2pk);
    BOOST_CHECK_EQUAL(prefetcher.GetStats().started, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
