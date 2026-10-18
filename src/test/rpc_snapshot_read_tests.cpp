// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <core_io.h>
#include <kernel/disconnected_transactions.h>
#include <key_io.h>
#include <lotus_v2/commitment.h>
#include <minerfund.h>
#include <node/miner.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/native_snapshot_setup.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>
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

BOOST_FIXTURE_TEST_SUITE(rpc_snapshot_read_tests, NativeSnapshotChainSetup)

BOOST_AUTO_TEST_CASE(header_only_snapshot_rechecks_new_block_metadata) {
    auto &manager = *m_node.chainman;
    BlockHash hash;
    unsigned int expected;
    {
        LOCK(::cs_main);
        auto *index = manager.ActiveChain()[50];
        hash = index->GetBlockHash();
        expected = index->nTx;
        // Capture the headers-only state before background download fills the
        // mutable block index, without changing the active chain's tip.
        index->nTx = 0;
        node::PublishChainTipSnapshot(manager, m_node.mempool.get());
        index->nTx = expected;
    }
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = "getblockheader";
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(hash.GetHex());
    const auto result = tableRPC.execute(GlobalConfig{}, request);
    BOOST_CHECK_EQUAL(result["nTx"].getInt<int>(), expected);
}

BOOST_AUTO_TEST_CASE(lockfree_rpc_reads_while_cs_main_and_mempool_locked) {
    GlobalConfig config;
    auto call_rpc_params = [&](const std::string &method,
                               UniValue params) -> UniValue {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = method;
        req.params = std::move(params);
        return tableRPC.execute(config, req);
    };
    auto call_rpc = [&](const std::string &method) -> UniValue {
        return call_rpc_params(method, UniValue(UniValue::VARR));
    };

    const auto mempool_mtx = CreateNativeMempoolTransaction(
        m_coinbase_txns[0], 0, m_coinbase_txns[0]->vout[0].nValue - 1000 * SATOSHI);
    const std::string mempool_txid = mempool_mtx.GetId().GetHex();
    const std::string confirmed_txid = m_coinbase_txns[1]->GetId().GetHex();
    const std::string spent_cb_txid = m_coinbase_txns[0]->GetId().GetHex();

    {
        LOCK(::cs_main);
        node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get());
    }

    // Ensure initial snapshot is published and matches active state.
    BOOST_CHECK_EQUAL(call_rpc("getblockcount").getInt<int>(), 100);
    const std::string block1_hash = [&]() {
        UniValue p(UniValue::VARR);
        p.push_back(1);
        return call_rpc_params("getblockhash", std::move(p)).get_str();
    }();
    const std::string block2_hash = [&]() {
        UniValue p(UniValue::VARR);
        p.push_back(2);
        return call_rpc_params("getblockhash", std::move(p)).get_str();
    }();

    std::promise<void> locks_acquired;
    std::promise<void> release_locks;
    auto release_future = release_locks.get_future();

    std::thread locker([&]() {
        LOCK2(::cs_main, m_node.mempool->cs);
        locks_acquired.set_value();
        release_future.wait();
    });

    locks_acquired.get_future().wait();

    // All migrated read-only RPCs must complete without blocking on cs_main
    // or mempool.cs while both locks are held exclusively by `locker`.
    const auto start = std::chrono::steady_clock::now();
    const UniValue count_res = call_rpc("getblockcount");
    const UniValue hash_res = call_rpc("getbestblockhash");
    const UniValue diff_res = call_rpc("getdifficulty");
    const UniValue info_res = call_rpc("getblockchaininfo");
    const UniValue mp_info_res = call_rpc("getmempoolinfo");
    const UniValue raw_mp_res = call_rpc("getrawmempool");

    UniValue verbose_mp_params(UniValue::VARR);
    verbose_mp_params.push_back(true);
    const UniValue raw_mp_verbose_res =
        call_rpc_params("getrawmempool", std::move(verbose_mp_params));

    UniValue mp_entry_params(UniValue::VARR);
    mp_entry_params.push_back(mempool_txid);
    const UniValue mp_entry_res =
        call_rpc_params("getmempoolentry", std::move(mp_entry_params));

    UniValue blockhash_params(UniValue::VARR);
    blockhash_params.push_back(2);
    const UniValue blockhash_res =
        call_rpc_params("getblockhash", std::move(blockhash_params));

    UniValue hdr_verbose_params(UniValue::VARR);
    hdr_verbose_params.push_back(block2_hash);
    hdr_verbose_params.push_back(true);
    const UniValue hdr_verbose_res =
        call_rpc_params("getblockheader", std::move(hdr_verbose_params));

    UniValue hdr_hex_params(UniValue::VARR);
    hdr_hex_params.push_back(block2_hash);
    hdr_hex_params.push_back(false);
    const UniValue hdr_hex_res =
        call_rpc_params("getblockheader", std::move(hdr_hex_params));

    UniValue txout_mempool_params(UniValue::VARR);
    txout_mempool_params.push_back(mempool_txid);
    txout_mempool_params.push_back(0);
    txout_mempool_params.push_back(true);
    const UniValue txout_mempool_res =
        call_rpc_params("gettxout", std::move(txout_mempool_params));

    UniValue txout_spent_params(UniValue::VARR);
    txout_spent_params.push_back(spent_cb_txid);
    txout_spent_params.push_back(0);
    txout_spent_params.push_back(true);
    const UniValue txout_spent_res =
        call_rpc_params("gettxout", std::move(txout_spent_params));

    UniValue rawtx_mp_params(UniValue::VARR);
    rawtx_mp_params.push_back(mempool_txid);
    rawtx_mp_params.push_back(true);
    const UniValue rawtx_mp_res =
        call_rpc_params("getrawtransaction", std::move(rawtx_mp_params));

    UniValue rawtx_blk_params(UniValue::VARR);
    rawtx_blk_params.push_back(confirmed_txid);
    rawtx_blk_params.push_back(true);
    rawtx_blk_params.push_back(block2_hash);
    const UniValue rawtx_blk_res =
        call_rpc_params("getrawtransaction", std::move(rawtx_blk_params));

    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start)
            .count();

    release_locks.set_value();
    locker.join();

    BOOST_CHECK_LT(elapsed_ms, 500);
    BOOST_CHECK_EQUAL(count_res.getInt<int>(), 100);
    BOOST_CHECK_EQUAL(hash_res.get_str(),
                      info_res.find_value("bestblockhash").get_str());
    BOOST_CHECK_GT(diff_res.get_real(), 0.0);
    BOOST_CHECK_EQUAL(info_res.find_value("blocks").getInt<int>(), 100);
    BOOST_CHECK_EQUAL(mp_info_res.find_value("size").getInt<int>(), 1);
    BOOST_CHECK(raw_mp_res.isArray());
    BOOST_CHECK_EQUAL(raw_mp_res.size(), 1U);
    BOOST_CHECK(raw_mp_verbose_res.isObject());
    BOOST_CHECK(raw_mp_verbose_res.exists(mempool_txid));
    BOOST_CHECK_EQUAL(mp_entry_res.find_value("height").getInt<int>(), 100);
    BOOST_CHECK_EQUAL(blockhash_res.get_str(), block2_hash);
    BOOST_CHECK_EQUAL(hdr_verbose_res.find_value("hash").get_str(),
                      block2_hash);
    BOOST_CHECK_EQUAL(hdr_verbose_res.find_value("height").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(hdr_verbose_res.find_value("previousblockhash").get_str(),
                      block1_hash);
    BOOST_CHECK(!hdr_hex_res.get_str().empty());
    BOOST_CHECK(txout_mempool_res.isObject());
    BOOST_CHECK_EQUAL(
        txout_mempool_res.find_value("confirmations").getInt<int>(), 0);
    BOOST_CHECK(!txout_mempool_res.find_value("coinbase").get_bool());
    BOOST_CHECK(txout_spent_res.isNull());
    BOOST_CHECK_EQUAL(rawtx_mp_res.find_value("txid").get_str(), mempool_txid);
    BOOST_CHECK_EQUAL(rawtx_blk_res.find_value("txid").get_str(),
                      confirmed_txid);
    BOOST_CHECK_EQUAL(rawtx_blk_res.find_value("blockhash").get_str(),
                      block2_hash);
    BOOST_CHECK(rawtx_blk_res.find_value("in_active_chain").get_bool());
    BOOST_CHECK_EQUAL(rawtx_blk_res.find_value("confirmations").getInt<int>(),
                      99);
}

BOOST_FIXTURE_TEST_CASE(mempool_info_preserves_deferred_overlay_for_root_readers,
                        NativeSnapshotChainSetup) {
    CTxMemPool &pool = *m_node.mempool;
    // Keep a reference to the manager itself, without invoking its flushing
    // accessor again until the explicit root-read phase below.
    auto &manager = WITH_LOCK(pool.cs, return pool.GetMerklixOverlay());
    BOOST_REQUIRE_EQUAL(
        WITH_LOCK(pool.cs, return manager.GetSpeculativeOverlay().GetTxCount()),
        0U);
    std::vector<lotus::v2::TxIdentityPair> identities;
    CTransactionRef previous = m_coinbase_txns[0];
    for (size_t i = 0; i < 3; ++i) {
        const auto tx = CreateNativeMempoolTransaction(
            previous, 0, previous->vout[0].nValue - 1000 * SATOSHI);
        previous = MakeTransactionRef(tx);
        lotus::v2::TxIdentityPair identity;
        std::memcpy(identity.tx_id.data(), previous->GetId().begin(), 32);
        std::memcpy(identity.tx_hash.data(), previous->GetHash().begin(), 32);
        identities.push_back(identity);

        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = "getmempoolinfo";
        request.params = UniValue(UniValue::VARR);
        const auto snapshot = node::GetGlobalSnapshotPublisher().Load();
        BOOST_REQUIRE(snapshot);
        const auto result = tableRPC.execute(GlobalConfig{}, request);
        BOOST_CHECK_EQUAL(result["size"].getInt<uint64_t>(), i + 1);
        BOOST_CHECK_EQUAL(result["bytes"].getInt<uint64_t>(), snapshot->mempool_bytes);
        BOOST_CHECK_EQUAL(result["usage"].getInt<uint64_t>(), snapshot->mempool_usage);
        UniValue expected(UniValue::VOBJ);
        expected.pushKV("total_fee", snapshot->total_fee);
        BOOST_CHECK_EQUAL(result["total_fee"].write(), expected["total_fee"].write());
        // Status polling must not drain deferred transactions or construct
        // whole-mempool roots as an unrelated read side effect.
        BOOST_CHECK_EQUAL(
            WITH_LOCK(pool.cs, return manager.GetSpeculativeOverlay().GetTxCount()),
            0U);
    }
    // The first real mining snapshot read must still construct the complete
    // commitment from this pinned generation after scalar polling did no work.
    const auto snapshot = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE(snapshot);
    snapshot->EnsureMiningTemplate();
    snapshot->mining_template.EnsureRoots();
    BOOST_CHECK_EQUAL(snapshot->mining_template.non_coinbase_txs.size(),
                      identities.size());
    BOOST_CHECK(snapshot->mining_template.subtree_a_root ==
                lotus::v2::TransactionSubtreeARoot(identities));
    // Its actual root consumer drained all accepted transactions, with exactly
    // the same transaction commitment as an independent construction.
    LOCK(pool.cs);
    const auto &overlay = pool.GetMerklixOverlay().GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(overlay.GetTxCount(), identities.size());
    BOOST_CHECK(overlay.GetSubtreeARoot() ==
                lotus::v2::TransactionSubtreeARoot(identities));
}

BOOST_AUTO_TEST_SUITE_END()
