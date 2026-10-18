// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#include <rpc/async_waiter.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <set>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(rpc_snapshot_mining_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(publication_defers_overlay_and_mining_pins_its_generation) {
    // Both independent coinbase inputs must be mature at the next block.
    mineBlocks(1);
    const CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    auto &pool = *m_node.mempool;
    auto &publisher = node::GetGlobalSnapshotPublisher();
    const Amount fee = 2000 * SATOSHI;
    const auto first = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey, spk,
        m_coinbase_txns[0]->vout[0].nValue - fee, /*submit=*/true));
    const auto pinned = publisher.Load();
    BOOST_REQUIRE(pinned);
    BOOST_REQUIRE_EQUAL(pinned->mempool_size, 1U);
    {
        LOCK(pool.cs);
        BOOST_CHECK(pool.HasPendingOverlayChanges());
    }
    BOOST_CHECK(!pinned->mining->ready);
    BOOST_CHECK(!pinned->overlay_all_fit_candidate);

    const auto second = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[1], 0, 2, coinbaseKey, spk,
        m_coinbase_txns[1]->vout[0].nValue - fee, /*submit=*/true));
    const auto current = publisher.Load();
    BOOST_REQUIRE(current);
    BOOST_REQUIRE_EQUAL(current->mempool_size, 2U);

    // Materialize only after the live pool has advanced. The fallback must
    // select the pinned generation, retain exact fees, and cache its roots.
    const auto &old_template = pinned->GetMiningTemplate();
    BOOST_REQUIRE_EQUAL(old_template.non_coinbase_txs.size(), 1U);
    BOOST_CHECK(old_template.non_coinbase_txs[0]->GetId() == first->GetId());
    BOOST_CHECK(old_template.total_fees == fee);
    BOOST_REQUIRE_EQUAL(old_template.tx_fees.size(), 1U);
    BOOST_CHECK(old_template.tx_fees[0] == fee);
    BOOST_CHECK_EQUAL(old_template.non_cb_serialized_size,
                      GetSerializeSize(*first));
    old_template.EnsureTemplateRoots();
    const auto old_root = old_template.subtree_a_root;
    BOOST_CHECK(old_root != lotus::v2::Hash{});

    const auto &new_template = current->GetMiningTemplate();
    BOOST_REQUIRE_EQUAL(new_template.non_coinbase_txs.size(), 2U);
    BOOST_CHECK(new_template.total_fees == fee + fee);
    std::set<TxId> selected;
    for (const auto &tx : new_template.non_coinbase_txs) {
        selected.insert(tx->GetId());
    }
    BOOST_CHECK(selected == std::set<TxId>({first->GetId(), second->GetId()}));
    new_template.EnsureTemplateRoots();
    BOOST_CHECK(new_template.subtree_a_root != old_root);
    BOOST_CHECK(pinned->GetMiningTemplate().subtree_a_root == old_root);
    {
        LOCK(pool.cs);
        BOOST_CHECK(pool.HasPendingOverlayChanges());
        BOOST_CHECK_EQUAL(pool.size(), 2U);
    }
}

BOOST_AUTO_TEST_CASE(
    abc_mempool_batch_removal_and_prioritisation_snapshot_coalescing) {
    CScript spk = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    std::vector<CTransactionRef> block_txs;
    constexpr size_t kNumTxs = 4;
    CTransactionRef prev_tx = m_coinbase_txns[0];
    int prev_height = 1;
    Amount cur_val = prev_tx->vout[0].nValue;
    for (size_t i = 0; i < kNumTxs; ++i) {
        cur_val -= 2000 * SATOSHI;
        CMutableTransaction mtx = CreateValidMempoolTransaction(
            prev_tx, 0, prev_height, coinbaseKey, spk, cur_val,
            /*submit=*/true);
        prev_tx = MakeTransactionRef(mtx);
        prev_height = 101;
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
    // publication (template_id + 1 instead of + 2*kNumTxs).
    {
        LOCK2(::cs_main, m_node.mempool->cs);
        const auto snap_before = publisher.Load();
        BOOST_REQUIRE(snap_before != nullptr);
        DisconnectedBlockTransactions disconnectpool;
        disconnectpool.removeForBlock(block_txs, *m_node.mempool);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
        const auto snap_after = publisher.Load();
        BOOST_REQUIRE(snap_after != nullptr);
        BOOST_CHECK_EQUAL(snap_after->mempool_size, 0U);
        BOOST_CHECK_EQUAL(snap_after->GetMiningTemplate().template_id,
                          snap_before->GetMiningTemplate().template_id + 1);
        disconnectpool.clear();
    }
}

BOOST_AUTO_TEST_CASE(snapshot_publisher_concurrent_rcu_stress) {
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
        next->mining->value.template_valid = true;
        next->mining->value.template_id = publisher.AllocateTemplateId();
        next->mining->value.next_height = i + 1;
        next->mining->ready = true;
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
    auto latest_tmpl = publisher.FindMiningTemplate(0);
    BOOST_REQUIRE(latest_tmpl.has_value());
    BOOST_CHECK_EQUAL(latest_tmpl->next_height, kNumPublishes + 1);
}

BOOST_AUTO_TEST_CASE(getblocktemplate_o1_and_submitsealedheader) {
    GlobalConfig config;
    CScript pubKeyScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    CMutableTransaction mempool_mtx = CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey, pubKeyScript,
        50 * COIN - 2000 * SATOSHI, /*submit=*/true);
    const std::string mempool_txid = mempool_mtx.GetId().GetHex();

    {
        LOCK(::cs_main);
        node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get());
    }

    // 1. Call getblocktemplate via executeAsync ( hits O(1) snapshot fast path)
    boost::asio::thread_pool pool(2);
    std::promise<UniValue> gbt_promise;
    auto gbt_future = gbt_promise.get_future();

    boost::asio::co_spawn(
        pool,
        [this, &config, &pool, &gbt_promise]() -> boost::asio::awaitable<void> {
            JSONRPCRequest req;
            req.context = &m_node;
            req.strMethod = "getblocktemplate";
            req.params = UniValue(UniValue::VARR);
            UniValue res = co_await tableRPC.executeAsync(
                config, req, pool.get_executor());
            gbt_promise.set_value(std::move(res));
        },
        boost::asio::detached);

    UniValue gbt_res = gbt_future.get();
    pool.join();

    BOOST_CHECK_EQUAL(gbt_res.find_value("height").getInt<int>(), 101);
    const uint64_t template_id =
        gbt_res.find_value("templateid").getInt<uint64_t>();
    BOOST_CHECK_GT(template_id, 0U);
    const UniValue &txs_arr = gbt_res.find_value("transactions").get_array();
    BOOST_REQUIRE_EQUAL(txs_arr.size(), 1U);
    BOOST_CHECK_EQUAL(txs_arr[0].find_value("txid").get_str(), mempool_txid);
    BOOST_CHECK_EQUAL(gbt_res.find_value("subtreearoot").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(gbt_res.find_value("merkleroot").get_str().size(), 64U);

    // Native submission includes all 134-byte header fields, the exact
    // coinbase bytes and roots returned by this template generation.
    const auto snap = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE(snap != nullptr);
    const auto &tmpl = snap->GetMiningTemplate();
    BOOST_REQUIRE(tmpl.template_valid);
    BOOST_CHECK_EQUAL(tmpl.template_id, template_id);
    CBlockHeader header;
    BOOST_REQUIRE(DecodeHexBlockHeader(header, gbt_res.find_value("headerhex").get_str()));
    BOOST_CHECK_EQUAL(header.nHeaderVersion, lotus::v2::kHeaderVersion);
    BOOST_CHECK_EQUAL(header.nHeight, 101U);
    const auto &consensusParams = config.GetChainParams().GetConsensus();
    while (!CheckProofOfWork(header.GetHash(), header.nBits, consensusParams)) {
        ++header.nNonce;
    }
    DataStream ss_hdr{};
    ss_hdr << header;
    const std::string header_hex = HexStr(ss_hdr);
    BOOST_CHECK_EQUAL(header_hex.size(), 268U);
    const std::string coinbase_hex = gbt_res.find_value("coinbasetxhex").get_str();
    BOOST_REQUIRE(!coinbase_hex.empty());

    JSONRPCRequest submit_req;
    submit_req.context = &m_node;
    submit_req.strMethod = "submitsealedheader";
    submit_req.params = UniValue(UniValue::VARR);
    submit_req.params.push_back(header_hex);
    submit_req.params.push_back(coinbase_hex);
    submit_req.params.push_back(template_id);

    UniValue submit_res = tableRPC.execute(config, submit_req);
    BOOST_CHECK_MESSAGE(submit_res.isNull(), submit_res.write());

    // Block 101 is now active tip and mempool transaction was mined.
    JSONRPCRequest count_req;
    count_req.context = &m_node;
    count_req.strMethod = "getblockcount";
    count_req.params = UniValue(UniValue::VARR);
    BOOST_CHECK_EQUAL(tableRPC.execute(config, count_req).getInt<int>(), 101);
}

BOOST_AUTO_TEST_CASE(getblocktemplate_mineraddress_and_submitsealedblock) {
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();

    CKey minerKey;
    minerKey.MakeNewKey(true);
    const PKHash minerDest(minerKey.GetPubKey());
    const std::string minerAddr = EncodeDestination(minerDest, config);
    const CScript expectedMinerSpk = GetScriptForDestination(minerDest);

    {
        LOCK(::cs_main);
        node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get());
    }

    boost::asio::thread_pool pool(2);
    std::promise<UniValue> gbt_promise;
    auto gbt_future = gbt_promise.get_future();

    boost::asio::co_spawn(
        pool,
        [this, &config, &pool, &gbt_promise,
         &minerAddr]() -> boost::asio::awaitable<void> {
            JSONRPCRequest req;
            req.context = &m_node;
            req.strMethod = "getblocktemplate";
            UniValue tmpl_req(UniValue::VOBJ);
            tmpl_req.pushKV("mode", "compact_template");
            tmpl_req.pushKV("mineraddress", minerAddr);
            req.params = UniValue(UniValue::VARR);
            req.params.push_back(std::move(tmpl_req));
            UniValue res = co_await tableRPC.executeAsync(
                config, req, pool.get_executor());
            gbt_promise.set_value(std::move(res));
        },
        boost::asio::detached);

    UniValue gbt_res = gbt_future.get();
    pool.join();

    // Verify native 134-byte CBlockHeader, coinbasetxhex, and blocksize
    const std::string header_hex = gbt_res.find_value("headerhex").get_str();
    const std::string cb_hex = gbt_res.find_value("coinbasetxhex").get_str();
    BOOST_CHECK_EQUAL(header_hex.size(), 268U);
    BOOST_CHECK(!cb_hex.empty());
    BOOST_CHECK_GT(gbt_res.find_value("blocksize").getInt<int64_t>(), 80);

    CMutableTransaction decoded_cb;
    BOOST_REQUIRE(DecodeHexTx(decoded_cb, cb_hex));
    BOOST_REQUIRE(!decoded_cb.vout.empty());
    BOOST_CHECK(decoded_cb.vout[0].scriptPubKey == expectedMinerSpk);

    CBlockHeader header;
    BOOST_REQUIRE(DecodeHexBlockHeader(header, header_hex));
    const Consensus::Params &consensusParams = chainparams.GetConsensus();
    while (!CheckProofOfWork(header.GetHash(), header.nBits, consensusParams)) {
        ++header.nNonce;
    }

    DataStream ss_solved{};
    ss_solved << header;
    const uint64_t template_id =
        gbt_res.find_value("templateid").getInt<uint64_t>();

    JSONRPCRequest submit_req;
    submit_req.context = &m_node;
    submit_req.strMethod = "submitsealedblock";
    submit_req.params = UniValue(UniValue::VARR);
    submit_req.params.push_back(HexStr(ss_solved));
    submit_req.params.push_back(cb_hex);
    submit_req.params.push_back(template_id);

    UniValue submit_res = tableRPC.execute(config, submit_req);
    BOOST_CHECK_MESSAGE(submit_res.isNull(), submit_res.write());
}

BOOST_AUTO_TEST_CASE(snapshot_mining_template_history_lookup) {
    // 4. Exercise RecordMiningTemplate and FindMiningTemplate ring history
    {
        auto &pub = node::GetGlobalSnapshotPublisher();
        node::MiningTemplateSnapshot invalid_tmpl{};
        invalid_tmpl.template_valid = false;
        pub.RecordMiningTemplate(invalid_tmpl);

        node::MiningTemplateSnapshot custom_tmpl{};
        custom_tmpl.template_valid = true;
        custom_tmpl.template_id = pub.AllocateTemplateId();
        custom_tmpl.prev_block_hash = BlockHash(uint256S("42"));
        custom_tmpl.next_height = 777;
        pub.RecordMiningTemplate(custom_tmpl);

        auto found_by_id =
            pub.FindMiningTemplate(custom_tmpl.template_id, BlockHash());
        BOOST_REQUIRE(found_by_id.has_value());
        BOOST_CHECK_EQUAL(found_by_id->next_height, 777);

        auto found_by_prev =
            pub.FindMiningTemplate(0, custom_tmpl.prev_block_hash);
        BOOST_REQUIRE(found_by_prev.has_value());
        BOOST_CHECK_EQUAL(found_by_prev->template_id, custom_tmpl.template_id);

        pub.Publish(nullptr);
        BOOST_CHECK(!pub.FindMiningTemplate(999999999ULL, BlockHash()).has_value());
        auto fallback_curr =
            pub.FindMiningTemplate(0, BlockHash(uint256S("deadbeef")));
        BOOST_CHECK(fallback_curr.has_value());
    }
}

BOOST_AUTO_TEST_CASE(lazy_mining_template_pins_old_generation_and_warm_rpc_avoids_writer_locks) {
    GlobalConfig config;
    const CScript spk = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    const auto tx = CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1,
        coinbaseKey, spk, m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI, true);
    { LOCK(cs_main); node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get()); }
    const auto old = node::GetGlobalSnapshotPublisher().Load();
    m_node.mempool->clear(true);
    const auto empty = node::GetGlobalSnapshotPublisher().Load();
    // Neither template was materialized before clearing the live pool.
    BOOST_REQUIRE_EQUAL(old->GetMiningTemplate().non_coinbase_txs.size(), 1U);
    BOOST_CHECK(old->GetMiningTemplate().non_coinbase_txs[0]->GetId() == tx.GetId());
    BOOST_CHECK(empty->GetMiningTemplate().non_coinbase_txs.empty());
    BOOST_CHECK_NE(old->GetMiningTemplate().template_id, empty->GetMiningTemplate().template_id);
    boost::asio::thread_pool pool(2);
    JSONRPCRequest req;
    req.context = &m_node; req.strMethod = "getblocktemplate";
    req.params = UniValue(UniValue::VARR);
    auto cold = boost::asio::co_spawn(pool, tableRPC.executeAsync(config, req, pool.get_executor()), boost::asio::use_future);
    const auto result = cold.get();
    {
        LOCK2(cs_main, m_node.mempool->cs);
        auto warm = boost::asio::co_spawn(pool, tableRPC.executeAsync(config, req, pool.get_executor()), boost::asio::use_future);
        // Check without waiting indefinitely while holding locks.
        BOOST_REQUIRE(warm.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
        BOOST_CHECK_EQUAL(warm.get().find_value("templateid").getInt<uint64_t>(),
                          result.find_value("templateid").getInt<uint64_t>());
    }
    pool.join();
}

BOOST_AUTO_TEST_CASE(snapshot_template_rejects_unchecked_invalid_p2sh) {
    GlobalConfig config;
    const CScript redeem = CScript() << OP_0;
    const CScript destination = GetScriptForDestination(ScriptHash(redeem));
    const auto parent = CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1,
        coinbaseKey, destination, m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI, true);
    CMutableTransaction bad;
    bad.vin.emplace_back(COutPoint(parent.GetId(), 0),
        CScript() << std::vector<uint8_t>(redeem.begin(), redeem.end()));
    bad.vout.emplace_back(parent.vout[0].nValue - 2000 * SATOSHI,
                         GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    while (::GetSerializeSize(bad) < MIN_TX_SIZE) bad.vout[0].scriptPubKey << OP_NOP;
    { LOCK2(cs_main, m_node.mempool->cs);
      m_node.mempool->addUnchecked(TestMemPoolEntryHelper().Fee(2000 * SATOSHI).FromTx(bad));
      node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get()); }
    BOOST_REQUIRE_EQUAL(node::GetGlobalSnapshotPublisher().Load()->GetMiningTemplate().non_coinbase_txs.size(), 2U);
    boost::asio::thread_pool pool(2);
    JSONRPCRequest req;
    req.context = &m_node; req.strMethod = "getblocktemplate";
    req.params = UniValue(UniValue::VARR);
    auto result = boost::asio::co_spawn(pool, tableRPC.executeAsync(config, req, pool.get_executor()), boost::asio::use_future);
    BOOST_CHECK_EXCEPTION(result.get(), UniValue, [](const UniValue &e) {
        return e.find_value("message").get_str().find("mandatory-script-verify-flag-failed") != std::string::npos;
    });
    pool.join();
}

BOOST_AUTO_TEST_CASE(cached_merkle_branch_does_not_certify_duplicate_transactions) {
    node::MiningTemplateSnapshot tmpl;
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(TxId(uint256S("1234")), 0));
    tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    const auto ref = MakeTransactionRef(tx);
    tmpl.non_coinbase_txs = {ref, ref};
    tmpl.EnsureTemplateRoots();
    BOOST_CHECK(!tmpl.merkle_cache_safe);
}

BOOST_AUTO_TEST_SUITE_END()
