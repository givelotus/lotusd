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
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(rpc_coroutine_pool_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(coro_50_waiters_non_blocking_on_4_threads) {
    GlobalConfig config;
    StartRPC();
    {
        LOCK(::cs_main);
        RPCNotifyBlockChange(m_node.chainman->ActiveChain().Tip());
    }

    boost::asio::thread_pool pool(4);
    constexpr int kNumWaiters = 50;
    std::atomic<int> waiters_completed{0};

    BlockHash target_block_hash{};
    {
        uint256 dummy = uint256S("000000000000000000000000000000000000000000000000000000000000beef");
        target_block_hash = BlockHash(dummy);
    }

    for (int i = 0; i < kNumWaiters; ++i) {
        boost::asio::co_spawn(
            pool,
            [this, &config, &pool, &waiters_completed, i, target_block_hash]()
                -> boost::asio::awaitable<void> {
                JSONRPCRequest req;
                req.context = &m_node;
                req.params = UniValue(UniValue::VARR);
                if (i % 3 == 0) {
                    req.strMethod = "waitfornewblock";
                    req.params.push_back(5000);
                } else if (i % 3 == 1) {
                    req.strMethod = "waitforblockheight";
                    req.params.push_back(101);
                    req.params.push_back(5000);
                } else {
                    req.strMethod = "waitforblock";
                    req.params.push_back(target_block_hash.GetHex());
                    req.params.push_back(5000);
                }
                UniValue res = co_await tableRPC.executeAsync(
                    config, req, pool.get_executor());
                if (res.find_value("height").getInt<int>() >= 100) {
                    waiters_completed.fetch_add(1, std::memory_order_relaxed);
                }
            },
            boost::asio::detached);
    }

    while (GetRPCBlockChangeWaiter().WaiterCount() <
           static_cast<size_t>(kNumWaiters)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    // All 50 waiters are suspended on the 4-thread pool. Fast RPCs dispatched
    // onto the same 4-thread pool must execute immediately without starvation.
    constexpr int kFastCalls = 20;
    std::atomic<int> fast_completed{0};
    std::promise<void> all_fast_done;
    auto all_fast_future = all_fast_done.get_future();

    for (int i = 0; i < kFastCalls; ++i) {
        boost::asio::co_spawn(
            pool,
            [this, &config, &pool, &fast_completed, &all_fast_done]()
                -> boost::asio::awaitable<void> {
                JSONRPCRequest req;
                req.context = &m_node;
                req.strMethod = "getblockcount";
                req.params = UniValue(UniValue::VARR);
                UniValue res = co_await tableRPC.executeAsync(
                    config, req, pool.get_executor());
                if (res.getInt<int>() == 100) {
                    if (fast_completed.fetch_add(1,
                                                 std::memory_order_acq_rel) +
                            1 ==
                        kFastCalls) {
                        all_fast_done.set_value();
                    }
                }
            },
            boost::asio::detached);
    }

    const auto status =
        all_fast_future.wait_for(std::chrono::milliseconds(500));
    BOOST_REQUIRE(status == std::future_status::ready);
    BOOST_CHECK_EQUAL(fast_completed.load(), kFastCalls);
    BOOST_CHECK_EQUAL(waiters_completed.load(), 0);

    // Wake all 50 suspended coroutines via RPCNotifyBlockChange.
    CBlockIndex fake_tip;
    fake_tip.nHeight = 101;
    fake_tip.phashBlock = &target_block_hash;
    RPCNotifyBlockChange(&fake_tip);

    pool.join();
    BOOST_CHECK_EQUAL(waiters_completed.load(), kNumWaiters);

    {
        LOCK(::cs_main);
        RPCNotifyBlockChange(m_node.chainman->ActiveChain().Tip());
    }
    InterruptRPC();
    StopRPC();
}

BOOST_AUTO_TEST_SUITE_END()
