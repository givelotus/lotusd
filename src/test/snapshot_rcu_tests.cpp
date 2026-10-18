// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <config.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <core_io.h>
#include <kernel/disconnected_transactions.h>
#include <key_io.h>
#include <minerfund.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/native_snapshot_setup.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(snapshot_rcu_tests, NativeSnapshotChainSetup)

// Published copies must survive writer churn and may be retired by readers.
BOOST_AUTO_TEST_CASE(entry_tree_copy_and_cross_thread_retirement) {
    auto published = std::allocate_shared<node::MempoolSnapshotTree>(
        node::SnapshotAllocator<node::MempoolSnapshotTree>{});
    constexpr uint64_t count = 4096;
    for (uint64_t i = 0; i < count; ++i) {
        node::MempoolEntrySnapshot entry;
        entry.txid = TxId{ArithToUint256(arith_uint256(i))};
        entry.entry_id = i;
        BOOST_REQUIRE(published->insert(
            RCUPtr<node::ImmutableMempoolEntry>::make(std::move(entry))));
    }
    auto writer = *published;
    for (uint64_t i = 0; i < count; i += 2) {
        BOOST_REQUIRE(
            writer.remove(Uint256RadixKey(ArithToUint256(arith_uint256(i)))));
    }
    for (uint64_t i = 0; i < count; ++i) {
        const auto old =
            published->get(Uint256RadixKey(ArithToUint256(arith_uint256(i))));
        BOOST_REQUIRE(old);
        BOOST_CHECK_EQUAL(old->entry.entry_id, i);
        BOOST_CHECK_EQUAL(
            bool(writer.get(Uint256RadixKey(ArithToUint256(arith_uint256(i))))),
            i % 2 != 0);
    }
    std::atomic<uint64_t> reader_count{0};
    std::thread reader(
        [snapshot = std::move(published), &reader_count]() mutable {
            snapshot->forEachLeaf([&](const auto &) {
                ++reader_count;
                return true;
            });
            snapshot.reset();
            RCULock::synchronize();
        });
    reader.join();
    BOOST_CHECK_EQUAL(reader_count.load(), count);
    // The writer's shared subtrees remain valid after reader reclamation.
    uint64_t remaining = 0;
    writer.forEachLeaf([&](const auto &) {
        ++remaining;
        return true;
    });
    BOOST_CHECK_EQUAL(remaining, count / 2);
}

BOOST_AUTO_TEST_CASE(snapshot_publication_concurrent_coherent_scalars) {
    node::SnapshotPublisher publisher;
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads_completed{0};

    constexpr int kNumReaders = 4;
    constexpr int kNumPublishes = 2500;

    std::atomic<int> readers_started{0};
    std::atomic<bool> reader_failed{false};
    std::vector<std::thread> readers;
    readers.reserve(kNumReaders);
    for (int r = 0; r < kNumReaders; ++r) {
        readers.emplace_back([&]() {
            readers_started.fetch_add(1, std::memory_order_release);
            int last_height = -1;
            while (!stop.load(std::memory_order_relaxed)) {
                auto snap = publisher.Load();
                if (!snap) {
                    reader_failed.store(true, std::memory_order_relaxed);
                    break;
                }
                if (snap->chain_valid) {
                    if (snap->height < last_height ||
                        snap->mempool_size !=
                            static_cast<size_t>(snap->height % 17)) {
                        reader_failed.store(true, std::memory_order_relaxed);
                        break;
                    }
                    last_height = snap->height;
                }
                reads_completed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    while (readers_started.load(std::memory_order_acquire) < kNumReaders) {
        std::this_thread::yield();
    }

    for (int i = 1; i <= kNumPublishes; ++i) {
        auto next = std::make_shared<node::ChainAndMempoolSnapshot>();
        next->chain_valid = true;
        next->height = i;
        next->headers_height = i;
        next->mempool_valid = true;
        next->mempool_size = static_cast<size_t>(i % 17);
        publisher.Publish(std::move(next));
    }

    while (reads_completed.load(std::memory_order_relaxed) == 0) {
        std::this_thread::yield();
    }
    stop.store(true, std::memory_order_relaxed);
    for (auto &t : readers) {
        t.join();
    }

    BOOST_CHECK(!reader_failed.load());
    auto final_snap = publisher.Load();
    BOOST_REQUIRE(final_snap != nullptr);
    BOOST_CHECK_EQUAL(final_snap->height, kNumPublishes);
    BOOST_CHECK_GT(reads_completed.load(), 0U);
}

namespace {
struct PruneModeTag {
    using type = const bool node::BlockManager::*;
    friend type GetPruneModePtr(PruneModeTag);
};
template <typename Tag, typename Tag::type M>
struct RobPruneMode {
    friend typename Tag::type GetPruneModePtr(Tag) { return M; }
};
template struct RobPruneMode<PruneModeTag, &node::BlockManager::m_prune_mode>;

struct OptsTag {
    using type = const kernel::BlockManagerOpts node::BlockManager::*;
    friend type GetOptsPtr(OptsTag);
};
template <typename Tag, typename Tag::type M>
struct RobOpts {
    friend typename Tag::type GetOptsPtr(Tag) { return M; }
};
template struct RobOpts<OptsTag, &node::BlockManager::m_opts>;
} // namespace

BOOST_AUTO_TEST_CASE(snapshot_prune_height_and_difficulty_shift_branches) {
    LOCK(::cs_main);
    auto &blockman = m_node.chainman->m_blockman;
    auto &chain = m_node.chainman->ActiveChain();
    CBlockIndex *tip = chain.Tip();
    BOOST_REQUIRE(tip != nullptr);

    const uint32_t orig_bits = tip->nBits;
    tip->nBits = 0x1c00ffffU; // nShift == 28 (< 29)

    bool &prune_mode =
        const_cast<bool &>(blockman.*GetPruneModePtr(PruneModeTag{}));
    auto &opts =
        const_cast<kernel::BlockManagerOpts &>(blockman.*GetOptsPtr(OptsTag{}));
    const bool orig_prune_mode = prune_mode;
    const uint64_t orig_prune_target = opts.prune_target;

    prune_mode = true;
    opts.prune_target = 600'000'000ULL;

    // 1. All blocks have data and undo -> ComputePruneHeight returns std::nullopt (prune_height == 0)
    node::PublishChainTipSnapshot(*m_node.chainman, nullptr);
    auto snap1 = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE(snap1 != nullptr);
    BOOST_CHECK(snap1->pruned);
    BOOST_CHECK(snap1->automatic_pruning);
    BOOST_CHECK_EQUAL(snap1->prune_target_size, 600'000'000ULL);
    BOOST_CHECK_EQUAL(snap1->prune_height, 0);

    // 2. Blocks 1..50 pruned -> ComputePruneHeight returns 50 (snap->prune_height == 51)
    for (int h = 1; h <= 50; ++h) {
        chain[h]->nStatus = chain[h]->nStatus.withData(false);
    }
    node::PublishChainTipSnapshot(*m_node.chainman, nullptr);
    auto snap2 = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE(snap2 != nullptr);
    BOOST_CHECK_EQUAL(snap2->prune_height, 51);

    // 3. Tip itself missing data -> ComputePruneHeight returns tip->nHeight
    const BlockStatus orig_tip_status = tip->nStatus;
    tip->nStatus = tip->nStatus.withData(false);
    node::PublishChainTipSnapshot(*m_node.chainman, nullptr);
    auto snap3 = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE(snap3 != nullptr);
    BOOST_CHECK_EQUAL(snap3->prune_height, tip->nHeight + 1);

    // Restore block statuses and options
    tip->nStatus = orig_tip_status;
    for (int h = 1; h <= 50; ++h) {
        chain[h]->nStatus = chain[h]->nStatus.withData(true);
    }
    tip->nBits = orig_bits;
    prune_mode = orig_prune_mode;
    opts.prune_target = orig_prune_target;
}

BOOST_AUTO_TEST_CASE(
    abc_mempool_batch_removal_and_prioritisation_snapshot_coalescing) {
    std::vector<CTransactionRef> block_txs;
    constexpr size_t kNumTxs = 4;
    CTransactionRef prev_tx = m_coinbase_txns[0];
    Amount cur_val = prev_tx->vout[0].nValue;
    for (size_t i = 0; i < kNumTxs; ++i) {
        cur_val -= 2000 * SATOSHI;
        CMutableTransaction mtx = CreateNativeMempoolTransaction(prev_tx, 0, cur_val);
        prev_tx = MakeTransactionRef(mtx);
        block_txs.push_back(prev_tx);
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), kNumTxs);

    node::SnapshotPublisher &publisher = node::GetGlobalSnapshotPublisher();

    // Exercise lightweight PublishMempoolUnbroadcastSnapshot on AddUnbroadcastTx / RemoveUnbroadcastTx
    m_node.mempool->AddUnbroadcastTx(block_txs[0]->GetId());
    m_node.mempool->RemoveUnbroadcastTx(block_txs[0]->GetId(),
                                        /*unchecked=*/false);
    m_node.mempool->AddUnbroadcastTx(block_txs[0]->GetId());

    // 1. ClearPrioritisation on an unprioritized transaction must NOT publish
    // a redundant RCU snapshot.
    {
        LOCK(m_node.mempool->cs);
        const auto snap_before = publisher.Load();
        m_node.mempool->ClearPrioritisation(block_txs[0]->GetId());
        BOOST_CHECK_EQUAL(publisher.Load().get(), snap_before.get());
    }

    // 2. Prioritising and then clearing prioritisation on a transaction MUST
    // publish a snapshot when a delta actually existed.
    m_node.mempool->PrioritiseTransaction(block_txs[0]->GetId(),
                                          1000 * SATOSHI);
    {
        LOCK(m_node.mempool->cs);
        const auto snap_before = publisher.Load();
        m_node.mempool->ClearPrioritisation(block_txs[0]->GetId());
        BOOST_CHECK_NE(publisher.Load().get(), snap_before.get());
    }

    // 3. DisconnectedBlockTransactions::removeForBlock must coalesce per-tx
    // mempool removals under ScopedSnapshotDefer into a single snapshot
    // publication, independent of any later mining-template implementation.
    {
        LOCK2(::cs_main, m_node.mempool->cs);
        const auto publications_before = publisher.PublicationCount();
        DisconnectedBlockTransactions disconnectpool;
        disconnectpool.removeForBlock(block_txs, *m_node.mempool);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
        const auto snap_after = publisher.Load();
        BOOST_REQUIRE(snap_after != nullptr);
        BOOST_CHECK_EQUAL(snap_after->mempool_size, 0U);
        BOOST_CHECK_EQUAL(publisher.PublicationCount(),
                          publications_before + 1);
        disconnectpool.clear();
    }
}


BOOST_AUTO_TEST_CASE(lazy_mempool_snapshots_pin_historical_values) {
    auto &pool = *m_node.mempool;
    auto &publisher = node::GetGlobalSnapshotPublisher();
    std::vector<std::shared_ptr<const node::ChainAndMempoolSnapshot>> snapshots;
    std::vector<CTransactionRef> txs;
    CTransactionRef parent = m_coinbase_txns[0];
    Amount value = parent->vout[0].nValue;
    for (size_t i = 0; i < 4; ++i) {
        value -= 2000 * SATOSHI;
        auto tx = MakeTransactionRef(CreateNativeMempoolTransaction(parent, 0, value));
        txs.push_back(tx);
        parent = tx;
        snapshots.push_back(publisher.Load());
    }
    auto before_fee = snapshots.back();
    pool.PrioritiseTransaction(txs[1]->GetId(), 1000 * SATOSHI);
    auto after_fee = publisher.Load();
    pool.AddUnbroadcastTx(txs[1]->GetId());
    auto after_unbroadcast = publisher.Load();
    pool.clear();
    auto after_clear = publisher.Load();
    // Materialize only AFTER all mutations, including clear. No live mempool
    // lookups may leak into any of these historical snapshots.
    for (size_t i = 0; i < snapshots.size(); ++i) {
        const auto &snap = snapshots[i];
        snap->EnsureMempoolVectors();
        BOOST_CHECK_EQUAL(snap->mempool_size, i + 1);
        BOOST_CHECK_EQUAL(snap->mempool_entries.size(), i + 1);
        for (size_t j = 0; j <= i; ++j) {
            const auto *entry = snap->FindMempoolEntry(txs[j]->GetId());
            BOOST_REQUIRE(entry);
            BOOST_CHECK_EQUAL(entry->depends.size(), j == 0 ? 0U : 1U);
            BOOST_CHECK_EQUAL(entry->spentby.size(), j == i ? 0U : 1U);
        }
    }
    const auto *old_entry = before_fee->FindMempoolEntry(txs[1]->GetId());
    const auto *new_entry = after_fee->FindMempoolEntry(txs[1]->GetId());
    BOOST_REQUIRE(old_entry);
    BOOST_REQUIRE(new_entry);
    BOOST_CHECK_EQUAL(old_entry->modified_fee, old_entry->fee);
    BOOST_CHECK_EQUAL(new_entry->modified_fee, new_entry->fee + 1000 * SATOSHI);
    BOOST_CHECK(!new_entry->unbroadcast);
    BOOST_REQUIRE(after_unbroadcast->FindMempoolEntry(txs[1]->GetId()));
    BOOST_CHECK(after_unbroadcast->FindMempoolEntry(txs[1]->GetId())->unbroadcast);
    after_clear->EnsureMempoolVectors();
    BOOST_CHECK_EQUAL(after_clear->mempool_size, 0U);
    BOOST_CHECK(after_clear->mempool_entries.empty());
}

BOOST_AUTO_TEST_CASE(lazy_snapshot_materialization_avoids_chain_and_mempool_locks) {
    auto &pool = *m_node.mempool;
    CreateNativeMempoolTransaction(m_coinbase_txns[0], 0,
        m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI);
    const auto snap = node::GetGlobalSnapshotPublisher().Load();
    std::promise<void> begin;
    auto start = begin.get_future();
    auto reader = std::async(std::launch::async, [&] {
        start.wait();
        snap->EnsureMempoolVectors();
        return snap->mempool_entries.size();
    });
    bool completed;
    {
        LOCK2(cs_main, pool.cs);
        begin.set_value();
        completed = reader.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
    }
    BOOST_CHECK(completed);
    BOOST_CHECK_EQUAL(reader.get(), 1U);
}

BOOST_AUTO_TEST_CASE(chain_and_mempool_rebuild_publish_only_completed_state) {
    auto &pool = *m_node.mempool;
    auto &chainman = *m_node.chainman;
    auto &publisher = node::GetGlobalSnapshotPublisher();
    CreateNativeMempoolTransaction(m_coinbase_txns[0], 0,
        m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI);
    LOCK2(cs_main, pool.cs);
    node::PublishChainTipSnapshot(chainman, &pool);
    const auto before = publisher.Load();
    BOOST_REQUIRE(before);
    BOOST_CHECK_EQUAL(before->mempool_size, 1U);
    const auto publications = publisher.PublicationCount();
    {
        node::ScopedChainSnapshotDefer outer(chainman, &pool);
        pool.clear();
        node::PublishChainTipSnapshot(chainman, &pool);
        BOOST_CHECK_EQUAL(publisher.Load().get(), before.get());
        {
            node::ScopedChainSnapshotDefer inner(chainman, &pool);
            pool.SetLoadTried(true);
            node::PublishChainTipSnapshot(chainman, &pool);
        }
        BOOST_CHECK_EQUAL(publisher.Load().get(), before.get());
        BOOST_CHECK_EQUAL(publisher.PublicationCount(), publications);
    }
    const auto after = publisher.Load();
    BOOST_REQUIRE(after);
    BOOST_CHECK_NE(after.get(), before.get());
    BOOST_CHECK_EQUAL(publisher.PublicationCount(), publications + 1);
    BOOST_CHECK_EQUAL(after->best_block_hash, chainman.ActiveTip()->GetBlockHash());
    BOOST_CHECK_EQUAL(after->mempool_size, 0U);
    BOOST_CHECK(after->mempool_loaded);
    before->EnsureMempoolVectors();
    BOOST_CHECK_EQUAL(before->mempool_entries.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
