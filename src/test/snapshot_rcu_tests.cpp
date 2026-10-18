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
#include <boost/asio/use_future.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

struct NativeSnapshotRcuSetup : NativeSnapshotChainSetup {
    CBlock MineNativeBlock() {
        const auto &config = GetConfig();
        auto block = node::BlockAssembler(
                         config, m_node.chainman->ActiveChainstate(),
                         m_node.mempool.get())
                         .CreateNewBlock(CScript(program.begin(), program.end()))->block;
        while (!CheckProofOfWork(block.GetHash(), block.nBits,
                                 config.GetChainParams().GetConsensus())) {
            ++block.nNonce;
        }
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
            std::make_shared<const CBlock>(block), true, true, nullptr));
        BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
        return block;
    }
};

BOOST_FIXTURE_TEST_SUITE(snapshot_rcu_tests, NativeSnapshotRcuSetup)

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
        next->mining_template.template_valid = true;
        next->mining_template.template_id = publisher.AllocateTemplateId();
        next->mining_template.next_height = i + 1;
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

    CMutableTransaction mempool_mtx = CreateNativeMempoolTransaction(
        m_coinbase_txns[0], 0,
        m_coinbase_txns[0]->vout[0].nValue - 1000 * SATOSHI);
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

    // All 12 migrated read-only RPCs must complete without blocking on cs_main
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

    UniValue txout_confirmed_params(UniValue::VARR);
    txout_confirmed_params.push_back(confirmed_txid);
    txout_confirmed_params.push_back(0);
    txout_confirmed_params.push_back(true);
    const UniValue txout_confirmed_res =
        call_rpc_params("gettxout", std::move(txout_confirmed_params));

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
    BOOST_CHECK(txout_confirmed_res.isObject());
    BOOST_CHECK_EQUAL(
        txout_confirmed_res.find_value("confirmations").getInt<int>(), 99);
    BOOST_CHECK(txout_confirmed_res.find_value("coinbase").get_bool());
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

BOOST_AUTO_TEST_CASE(coro_50_waiters_non_blocking_on_4_threads) {
    GlobalConfig config;
    StartRPC();
    {
        LOCK(::cs_main);
        RPCNotifyBlockChange(m_node.chainman->ActiveChain().Tip());
    }
    boost::asio::thread_pool pool(4);

    constexpr int kNumWaiters = 50;
    std::vector<std::future<UniValue>> waiter_futures;
    waiter_futures.reserve(kNumWaiters);

    for (int i = 0; i < kNumWaiters; ++i) {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "waitfornewblock";
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(5000);
        waiter_futures.push_back(boost::asio::co_spawn(
            pool,
            [&, req = std::move(req)]() -> boost::asio::awaitable<UniValue> {
                co_return co_await tableRPC.executeAsync(config, req,
                                                         pool.get_executor());
            },
            boost::asio::use_future));
    }

    // Give the 4 worker threads a brief moment to suspend all 50 coroutines.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Even with 50 waitfornewblock coroutines suspended on the 4-thread pool,
    // a 51st coroutine executing getblockcount must run immediately without
    // head-of-line blocking.
    const auto start = std::chrono::steady_clock::now();
    JSONRPCRequest count_req;
    count_req.context = &m_node;
    count_req.strMethod = "getblockcount";
    count_req.params = UniValue(UniValue::VARR);
    auto count_fut = boost::asio::co_spawn(
        pool, tableRPC.executeAsync(config, count_req, pool.get_executor()),
        boost::asio::use_future);
    BOOST_REQUIRE(count_fut.wait_for(std::chrono::milliseconds(500)) ==
                  std::future_status::ready);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start)
            .count();
    BOOST_CHECK_LT(elapsed_ms, 50);
    BOOST_CHECK_EQUAL(count_fut.get().getInt<int>(), 100);

    // Mine a block and notify RPC waiters, then verify all 50 suspended
    // waitfornewblock coroutines wake up and return the new tip.
    MineNativeBlock();
    {
        LOCK(::cs_main);
        RPCNotifyBlockChange(m_node.chainman->ActiveChain().Tip());
    }

    for (auto &fut : waiter_futures) {
        BOOST_REQUIRE(fut.wait_for(std::chrono::seconds(2)) ==
                      std::future_status::ready);
        UniValue res = fut.get();
        BOOST_CHECK_EQUAL(res.find_value("height").getInt<int>(), 101);
    }

    pool.join();
    InterruptRPC();
    StopRPC();
}

BOOST_AUTO_TEST_CASE(getblocktemplate_o1_and_submitsealedheader) {
    GlobalConfig config;
    gArgs.ForceSetArg("-gbtwithoutpeers", "1");
    if (m_node.args) {
        m_node.args->ForceSetArg("-gbtwithoutpeers", "1");
    }

    // Add 1 valid transaction to the mempool and refresh snapshot.
    CMutableTransaction mempool_mtx = CreateNativeMempoolTransaction(
        m_coinbase_txns[0], 0,
        m_coinbase_txns[0]->vout[0].nValue - 1000 * SATOSHI);
    {
        LOCK(::cs_main);
        node::PublishMempoolSnapshot(*m_node.mempool);
        node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get());
    }

    auto call_gbt = [&](const std::string &mode) -> UniValue {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "getblocktemplate";
        UniValue param(UniValue::VOBJ);
        param.pushKV("mode", mode);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(param));
        return tableRPC.execute(config, req);
    };

    const UniValue tmpl_full = call_gbt("template");
    const UniValue tmpl_compact = call_gbt("compact_template");

    BOOST_CHECK(tmpl_full.exists("transactions"));
    BOOST_CHECK_EQUAL(tmpl_full.find_value("transactions").get_array().size(),
                      1U);
    BOOST_CHECK(!tmpl_compact.exists("transactions"));

    const uint64_t template_id =
        tmpl_compact.find_value("templateid").getInt<uint64_t>();
    BOOST_CHECK_GT(template_id, 0U);
    BOOST_CHECK_EQUAL(tmpl_full.find_value("subtreearoot").get_str(),
                      tmpl_compact.find_value("subtreearoot").get_str());
    BOOST_CHECK_EQUAL(tmpl_full.find_value("stateroot").get_str(),
                      tmpl_compact.find_value("stateroot").get_str());
    BOOST_CHECK_EQUAL(tmpl_full.find_value("merkleroot").get_str(),
                      tmpl_compact.find_value("merkleroot").get_str());

    // Reconstruct the exact dummy coinbase transaction used by getblocktemplate
    // and mine a block using submitsealedheader.
    const auto cached_tmpl =
        node::GetGlobalSnapshotPublisher().FindMiningTemplate(template_id);
    BOOST_REQUIRE(cached_tmpl.has_value());

    const Consensus::Params &consensusParams =
        config.GetChainParams().GetConsensus();
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout =
        COutPoint(TxId(cached_tmpl->prev_block_hash),
                  static_cast<uint32_t>(cached_tmpl->next_height));
    coinbaseTx.vin[0].nFlags = 2;
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    coinbaseTx.vout[0].nValue = cached_tmpl->block_reward;
    coinbaseTx.vin[0].scriptSig =
        CScript() << cached_tmpl->next_height << OP_0;
    coinbaseTx.vin[0].fHasCoinbaseData = true;
    coinbaseTx.vin[0].vCoinbaseData.assign(coinbaseTx.vin[0].scriptSig.begin(),
                                           coinbaseTx.vin[0].scriptSig.end());
    const auto minerFundWhitelist = GetMinerFundWhitelist(consensusParams);
    if (!minerFundWhitelist.empty()) {
        const Amount minerFundAmount = GetMinerFundAmount(
            consensusParams, cached_tmpl->block_reward, nullptr);
        coinbaseTx.vout[0].nValue -= minerFundAmount;
        coinbaseTx.vout.emplace_back(
            minerFundAmount,
            GetScriptForDestination(*minerFundWhitelist.begin()));
    }
    uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx);
    if (coinbaseSize < MIN_TX_SIZE) {
        coinbaseTx.vin[0].scriptSig
            << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
        coinbaseTx.vin[0].vCoinbaseData.assign(
            coinbaseTx.vin[0].scriptSig.begin(),
            coinbaseTx.vin[0].scriptSig.end());
    }

    CBlockHeader header;
    header.nHeaderVersion =
        tmpl_compact.find_value("version").getInt<uint32_t>();
    header.hashPrevBlock = cached_tmpl->prev_block_hash;
    header.hashMerkleRoot =
        uint256S(tmpl_compact.find_value("merkleroot").get_str());
    header.hashStateRoot =
        uint256S(tmpl_compact.find_value("stateroot").get_str());
    header.SetBlockTime(tmpl_compact.find_value("curtime").getInt<uint64_t>());
    header.nBits = cached_tmpl->nBits;
    header.nHeight = cached_tmpl->next_height;
    header.nSize =
        ::GetSerializeSize(header) +
        GetSizeOfCompactSize(1 + cached_tmpl->non_coinbase_txs.size()) +
        ::GetSerializeSize(coinbaseTx) + cached_tmpl->non_cb_serialized_size;
    header.nNonce = 0;

    while (!CheckProofOfWork(header.GetHash(), header.nBits, consensusParams)) {
        ++header.nNonce;
    }

    DataStream ss_header{};
    ss_header << header;
    const std::string header_hex = HexStr(ss_header);
    const std::string coinbase_hex = EncodeHexTx(CTransaction(coinbaseTx));

    JSONRPCRequest submit_req;
    submit_req.context = &m_node;
    submit_req.strMethod = "submitsealedheader";
    submit_req.params = UniValue(UniValue::VARR);
    submit_req.params.push_back(header_hex);
    submit_req.params.push_back(coinbase_hex);
    submit_req.params.push_back(template_id);

    UniValue submit_res = tableRPC.execute(config, submit_req);
    BOOST_CHECK(submit_res.isNull());

    JSONRPCRequest count_req;
    count_req.context = &m_node;
    count_req.strMethod = "getblockcount";
    count_req.params = UniValue(UniValue::VARR);
    BOOST_CHECK_EQUAL(tableRPC.execute(config, count_req).getInt<int>(), 101);

    // Also test getblocktemplate with mineraddress + ready-to-hash headerhex /
    // coinbasetxhex / v2target / chainid + submitsealedblock directly.
    CKey address_key;
    address_key.MakeNewKey(true);
    const std::string miner_addr =
        EncodeDestination(PKHash(address_key.GetPubKey()), config);
    JSONRPCRequest gbt2_req;
    gbt2_req.context = &m_node;
    gbt2_req.strMethod = "getblocktemplate";
    UniValue gbt2_param(UniValue::VOBJ);
    gbt2_param.pushKV("mode", "compact_template");
    gbt2_param.pushKV("mineraddress", miner_addr);
    gbt2_req.params = UniValue(UniValue::VARR);
    gbt2_req.params.push_back(std::move(gbt2_param));
    const UniValue tmpl_v2 = tableRPC.execute(config, gbt2_req);

    BOOST_CHECK(tmpl_v2.exists("headerhex"));
    BOOST_CHECK(tmpl_v2.exists("coinbasetxhex"));
    BOOST_CHECK(tmpl_v2.exists("chainid"));
    BOOST_CHECK(tmpl_v2.exists("v2target"));
    BOOST_CHECK(tmpl_v2.exists("blocksize"));
    BOOST_CHECK_EQUAL(tmpl_v2.find_value("headerhex").get_str().size(),
                      lotus::v2::HEADER_SIZE * 2);
    BOOST_CHECK_EQUAL(tmpl_v2.find_value("chainid").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(tmpl_v2.find_value("v2target").get_str().size(), 64U);

    CBlockHeader v2_hdr;
    BOOST_REQUIRE(
        DecodeHexBlockHeader(v2_hdr, tmpl_v2.find_value("headerhex").get_str()));
    while (!CheckProofOfWork(v2_hdr.GetHash(), v2_hdr.nBits, consensusParams)) {
        ++v2_hdr.nNonce;
    }
    DataStream ss_v2_hdr{};
    ss_v2_hdr << v2_hdr;

    JSONRPCRequest sealed_blk_req;
    sealed_blk_req.context = &m_node;
    sealed_blk_req.strMethod = "submitsealedblock";
    sealed_blk_req.params = UniValue(UniValue::VARR);
    sealed_blk_req.params.push_back(HexStr(ss_v2_hdr));
    sealed_blk_req.params.push_back(
        tmpl_v2.find_value("coinbasetxhex").get_str());
    sealed_blk_req.params.push_back(
        tmpl_v2.find_value("templateid").getInt<uint64_t>());

    UniValue sealed_blk_res = tableRPC.execute(config, sealed_blk_req);
    BOOST_CHECK(sealed_blk_res.isNull());
    BOOST_CHECK_EQUAL(tableRPC.execute(config, count_req).getInt<int>(), 102);

    // Passing a valid template_id from height 101 with a header from height 102
    // must return "template-prevblock-mismatch".
    JSONRPCRequest mismatch_req;
    mismatch_req.context = &m_node;
    mismatch_req.strMethod = "submitsealedblock";
    mismatch_req.params = UniValue(UniValue::VARR);
    mismatch_req.params.push_back(HexStr(ss_v2_hdr));
    mismatch_req.params.push_back(
        tmpl_v2.find_value("coinbasetxhex").get_str());
    mismatch_req.params.push_back(template_id);
    UniValue mismatch_res = tableRPC.execute(config, mismatch_req);
    BOOST_CHECK_EQUAL(mismatch_res.get_str(), "template-prevblock-mismatch");

    // Empty or invalid mineraddress string must throw RPC_INVALID_ADDRESS_OR_KEY,
    // and non-string mineraddress must throw RPC_INVALID_PARAMETER.
    for (const std::string &bad_addr :
         {std::string(""), std::string("invalid_lotus_address")}) {
        JSONRPCRequest bad_addr_req;
        bad_addr_req.context = &m_node;
        bad_addr_req.strMethod = "getblocktemplate";
        UniValue bad_param(UniValue::VOBJ);
        bad_param.pushKV("mode", "compact_template");
        bad_param.pushKV("mineraddress", bad_addr);
        bad_addr_req.params = UniValue(UniValue::VARR);
        bad_addr_req.params.push_back(std::move(bad_param));
        BOOST_CHECK_EXCEPTION(
            tableRPC.execute(config, bad_addr_req), UniValue,
            [](const UniValue &e) {
                return e.find_value("code").getInt<int>() ==
                       RPC_INVALID_ADDRESS_OR_KEY;
            });
    }
    {
        JSONRPCRequest nonstr_addr_req;
        nonstr_addr_req.context = &m_node;
        nonstr_addr_req.strMethod = "getblocktemplate";
        UniValue bad_param(UniValue::VOBJ);
        bad_param.pushKV("mode", "compact_template");
        bad_param.pushKV("mineraddress", 12345);
        nonstr_addr_req.params = UniValue(UniValue::VARR);
        nonstr_addr_req.params.push_back(std::move(bad_param));
        BOOST_CHECK_EXCEPTION(
            tableRPC.execute(config, nonstr_addr_req), UniValue,
            [](const UniValue &e) {
                return e.find_value("code").getInt<int>() ==
                       RPC_INVALID_PARAMETER;
            });
    }
}

BOOST_AUTO_TEST_CASE(testrawtxbatch_and_submitrawtxbatch_all_or_nothing) {
    GlobalConfig config;
    const std::vector<uint8_t> v2_op_true_script{0x4e};
    const lotus::v2::Hash v2_op_true_leaf = lotus::v2::BranchLeaf(v2_op_true_script);
    const Amount cb_val = m_coinbase_txns[0]->vout[0].nValue;
    const CMutableTransaction funding_mtx = CreateNativeMempoolTransaction(
        m_coinbase_txns[0], 0, cb_val - 2000 * SATOSHI);
    const CTransactionRef funding_tx = MakeTransactionRef(funding_mtx);
    const CBlock funding_block = MineNativeBlock();
    BOOST_REQUIRE_EQUAL(funding_block.vtx.size(), 2U);
    BOOST_REQUIRE(funding_block.vtx[1]->GetId() == funding_tx->GetId());
    BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 0U);

    auto make_v7_tx = [&](const COutPoint &prevout, Amount out_val) {
        CMutableTransaction mtx;
        mtx.nVersion = 7;
        mtx.fHasV2Lock = true;
        mtx.nV2Lock = 0;
        mtx.nLockTime = 0;
        CTxIn txin(prevout, CScript(), CTxIn::SEQUENCE_FINAL);
        txin.nFlags = 1;
        txin.nPathIndex = 0;
        lotus::v2::BranchWitness wit;
        wit.script = v2_op_true_script;
        txin.vWitnesses = {wit};
        mtx.vin.push_back(std::move(txin));
        lotus::v2::Output v2_out;
        v2_out.flags = 0;
        v2_out.value = static_cast<uint64_t>(out_val / SATOSHI);
        v2_out.branches = {v2_op_true_leaf};
        v2_out.paths = {{0}};
        mtx.vout.push_back(CTxOut::FromV2Output(v2_out));
        return mtx;
    };

    // Create a pure version=7 parent transaction and child transaction spending the parent.
    CMutableTransaction parent_mtx =
        make_v7_tx(COutPoint(funding_tx->GetId(), 0), cb_val - 4000 * SATOSHI);
    CTransactionRef parent_tx = MakeTransactionRef(parent_mtx);

    CMutableTransaction child_mtx =
        make_v7_tx(COutPoint(parent_tx->GetId(), 0), cb_val - 6000 * SATOSHI);
    CTransactionRef child_tx = MakeTransactionRef(child_mtx);

    // Also create an invalid transaction spending a nonexistent outpoint.
    CMutableTransaction invalid_mtx = child_mtx;
    invalid_mtx.vin[0].prevout = COutPoint(TxId(uint256::ONE), 0);
    CTransactionRef invalid_tx = MakeTransactionRef(invalid_mtx);

    const std::string parent_hex = EncodeHexTx(*parent_tx);
    const std::string child_hex = EncodeHexTx(*child_tx);
    const std::string invalid_hex = EncodeHexTx(*invalid_tx);

    // 1. testrawtxbatch([parent, child]) should succeed without mutating mempool.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "testrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(child_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_MESSAGE(res.find_value("allowed").get_bool(), res.write());
        const UniValue &results = res.find_value("results").get_array();
        BOOST_REQUIRE_EQUAL(results.size(), 2U);
        BOOST_CHECK_EQUAL(results[0].find_value("allowed").get_bool(), true);
        BOOST_CHECK_EQUAL(results[1].find_value("allowed").get_bool(), true);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 2. submitrawtxbatch([parent, invalid]) must reject the entire batch
    // (all-or-nothing) and leave mempool empty.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "submitrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(invalid_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_EQUAL(res.find_value("accepted").get_bool(), false);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 3. submitrawtxbatch([parent, child]) must accept both transactions and
    // update the RCU mempool snapshot.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "submitrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(child_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_EQUAL(res.find_value("accepted").get_bool(), true);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 2U);

        JSONRPCRequest mp_req;
        mp_req.context = &m_node;
        mp_req.strMethod = "getrawmempool";
        mp_req.params = UniValue(UniValue::VARR);
        UniValue raw_mp = tableRPC.execute(config, mp_req);
        BOOST_CHECK_EQUAL(raw_mp.get_array().size(), 2U);
    }

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

    // 4. Chain at genesis (chain[1] == nullptr) -> ComputePruneHeight returns std::nullopt
    chain.SetTip(*chain[0]);
    node::PublishChainTipSnapshot(*m_node.chainman, nullptr);
    chain.SetTip(*tip);

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

    // Exercise PublishMempoolUnbroadcastSnapshot fallback when prev->mempool_valid is false
    // and PopulateMiningTemplate when prev->mining_template.template_valid is false
    {
        auto invalid_prev = std::make_shared<node::ChainAndMempoolSnapshot>(
            *publisher.Load());
        invalid_prev->mempool_valid = false;
        invalid_prev->mining_template.template_valid = false;
        publisher.Publish(std::move(invalid_prev));
        m_node.mempool->AddUnbroadcastTx(block_txs[0]->GetId());
        BOOST_CHECK(publisher.Load()->mempool_valid);
    }

    // Exercise blockFitter.testTxFits false branch when -blockmaxsize=1000
    {
        gArgs.ForceSetArg("-blockmaxsize", "1000");
        LOCK(m_node.mempool->cs);
        node::PublishMempoolSnapshot(*m_node.mempool);
        gArgs.ClearForcedArg("-blockmaxsize");
        node::PublishMempoolSnapshot(*m_node.mempool);
    }

    // Exercise lightweight PublishMempoolUnbroadcastSnapshot on AddUnbroadcastTx / RemoveUnbroadcastTx
    m_node.mempool->AddUnbroadcastTx(block_txs[0]->GetId());
    m_node.mempool->RemoveUnbroadcastTx(block_txs[0]->GetId(), /*unchecked=*/false);
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
        BOOST_CHECK_EQUAL(snap_after->mining_template.template_id,
                          snap_before->mining_template.template_id + 1);
        disconnectpool.clear();
    }

    // 4. Incremental O(delta) snapshot append across >20 transactions + lazy
    // EnsureRoots() must remain 100% lock-free while cs_main and mempool.cs
    // are held by a concurrent writer thread.
    {
        gArgs.ForceSetArg("-gbtwithoutpeers", "1");
        if (m_node.args) {
            m_node.args->ForceSetArg("-gbtwithoutpeers", "1");
        }
        GlobalConfig config;
        {
            LOCK(::cs_main);
            node::PublishChainTipSnapshot(*m_node.chainman, m_node.mempool.get());
        }
        CTransactionRef chain_prev = m_coinbase_txns[0];
        Amount chain_val = chain_prev->vout[0].nValue;
        for (size_t i = 0; i < 24; ++i) {
            chain_val -= 2000 * SATOSHI;
            CMutableTransaction mtx = CreateNativeMempoolTransaction(chain_prev, 0, chain_val);
            chain_prev = MakeTransactionRef(mtx);
        }
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 24U);
        auto snap24 = publisher.Load();
        BOOST_REQUIRE(snap24 != nullptr);
        BOOST_CHECK_EQUAL(snap24->mempool_size, 24U);
        BOOST_CHECK_EQUAL(snap24->mempool_entries.size(), 24U);
        BOOST_CHECK_EQUAL(snap24->mining_template.non_coinbase_txs.size(), 24U);
        BOOST_CHECK(!snap24->mining_template.roots_ready);

        std::promise<void> locks_held;
        std::promise<void> release_locks;
        auto release_fut = release_locks.get_future();
        std::thread holder([&]() {
            LOCK2(::cs_main, m_node.mempool->cs);
            locks_held.set_value();
            release_fut.wait();
        });
        locks_held.get_future().wait();

        JSONRPCRequest mp_req;
        mp_req.context = &m_node;
        mp_req.strMethod = "getrawmempool";
        mp_req.params = UniValue(UniValue::VARR);
        UniValue raw_mp = tableRPC.execute(config, mp_req);
        BOOST_CHECK_EQUAL(raw_mp.get_array().size(), 24U);

        JSONRPCRequest gbt_req;
        gbt_req.context = &m_node;
        gbt_req.strMethod = "getblocktemplate";
        UniValue gbt_param(UniValue::VOBJ);
        gbt_param.pushKV("mode", "compact_template");
        gbt_req.params = UniValue(UniValue::VARR);
        gbt_req.params.push_back(std::move(gbt_param));
        // Native root materialization uses the pinned generation even with
        // writers blocked. Cold GBT additionally earns execution provenance;
        // that validation must run after releasing the writer locks.
        snap24->mining_template.EnsureRoots();
        BOOST_CHECK(snap24->mining_template.roots_ready);
        release_locks.set_value();
        holder.join();
        UniValue gbt_res = tableRPC.execute(config, gbt_req);
        BOOST_CHECK(gbt_res.exists("merkleroot"));
        BOOST_CHECK(gbt_res.exists("stateroot"));
    }
}

BOOST_AUTO_TEST_CASE(lazy_native_snapshot_pins_old_generation_after_live_pool_clear) {
    CTransactionRef previous = m_coinbase_txns[0];
    for (size_t i = 0; i < 65; ++i) {
        auto tx = CreateNativeMempoolTransaction(previous, 0,
            previous->vout[0].nValue - 2000 * SATOSHI);
        previous = MakeTransactionRef(tx);
    }
    const auto old = node::GetGlobalSnapshotPublisher().Load();
    BOOST_REQUIRE_EQUAL(old->mempool_size, 65U);
    BOOST_REQUIRE(!old->mining_template_ready);
    m_node.mempool->clear(true);
    old->EnsureMiningTemplate();
    BOOST_CHECK_EQUAL(old->mining_template.non_coinbase_txs.size(), 65U);
    old->EnsureMempoolVectors();
    BOOST_CHECK_EQUAL(old->mempool_entries.size(), 65U);
}

BOOST_AUTO_TEST_SUITE_END()
