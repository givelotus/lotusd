// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/v2_outputs.h>
#include <node/mining_pool.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <lotus_v2/header.h>
#include <lotus_v2/output.h>
#include <node/context.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <string>
#include <thread>

BOOST_FIXTURE_TEST_SUITE(mining_pool_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(unavailable_native_payout_provider_keeps_startup_and_stats) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    BOOST_REQUIRE(pool_ptr);
    auto &pool = *pool_ptr;
    for (const std::string &address : {std::string{}, std::string{"invalid-payout"}}) {
        pool.Reset();
        m_node.args->ForceSetArg("-pooladdress", address);
        BOOST_CHECK_NO_THROW(pool.Configure(*m_node.args, config));
        const UniValue info = pool.GetPoolInfoJSON();
        BOOST_CHECK(!info.find_value("payout_ready").get_bool());
        BOOST_CHECK_EQUAL(info.find_value("payout_error").get_str(),
                          "native-payout-provider-unavailable");
        BOOST_CHECK_EQUAL(info.find_value("active_workers").getInt<uint64_t>(), 0U);
        BOOST_CHECK_EQUAL(info.find_value("blocks_found").getInt<uint64_t>(), 0U);
        BOOST_CHECK_EQUAL(info.find_value("pplns_window_shares").getInt<uint64_t>(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(unavailable_native_payout_provider_rejects_jobs_without_workers) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    BOOST_REQUIRE(pool_ptr);
    auto &pool = *pool_ptr;
    pool.Reset();
    pool.Configure(*m_node.args, config);
    BOOST_CHECK_EXCEPTION(pool.GetMiningJobJSON(config, m_node, "worker_alpha"),
                          std::runtime_error, [](const std::runtime_error &error) {
        return std::string(error.what()) ==
               "Native pool payout provider is unavailable at this prefix";
    });
    const UniValue info = pool.GetPoolInfoJSON();
    BOOST_CHECK_EQUAL(info.find_value("active_workers").getInt<uint64_t>(), 0U);
}

BOOST_AUTO_TEST_CASE(unavailable_native_payout_provider_rejects_shares_before_allocation) {
    const Config &config = GetConfig();
    auto pool_ptr = node::GetMiningPool(m_node);
    BOOST_REQUIRE(pool_ptr);
    auto &pool = *pool_ptr;
    pool.Reset();
    pool.Configure(*m_node.args, config);
    const auto result = pool.SubmitShare(config, m_node, 1, "worker_alpha", std::nullopt, 0);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.block_found);
    BOOST_CHECK_EQUAL(result.reason, "native-payout-provider-unavailable");
    const UniValue info = pool.GetPoolInfoJSON();
    BOOST_CHECK_EQUAL(info.find_value("active_workers").getInt<uint64_t>(), 0U);
    BOOST_CHECK_EQUAL(info.find_value("total_accepted_shares").getInt<uint64_t>(), 0U);
    BOOST_CHECK_EQUAL(info.find_value("pplns_window_shares").getInt<uint64_t>(), 0U);
}

BOOST_AUTO_TEST_CASE(node_owned_runtime_activation_and_isolation) {
    const Config &config = GetConfig();
    ArgsManager args_a, args_b;
    node::NodeContext a, b;
    a.args = &args_a;
    b.args = &args_b;
    node::StartMiningPool(a, config);
    BOOST_CHECK(!node::GetMiningPool(a));
    args_a.ForceSetArg("-server", "1");
    args_a.ForceSetArg("-miningpool", "0");
    node::StartMiningPool(a, config);
    BOOST_CHECK(!node::GetMiningPool(a));

    JSONRPCRequest request;
    request.context = &a;
    request.strMethod = "getpoolinfo";
    request.params = UniValue(UniValue::VARR);
    BOOST_CHECK_EXCEPTION(
        tableRPC.execute(config, request), UniValue, [](const UniValue &error) {
            return error.find_value("code").getInt<int>() == RPC_MISC_ERROR &&
                   error.find_value("message").get_str() ==
                       "Built-in mining pool is disabled";
        });
    args_a.ForceSetArg("-miningpool", "1");
    BOOST_CHECK_EXCEPTION(tableRPC.execute(config, request), UniValue,
                          [](const UniValue &error) {
                              return error.find_value("message").get_str() ==
                                     "Built-in mining pool is unavailable";
                          });
    args_b.ForceSetArg("-server", "1");
    args_b.ForceSetArg("-poolpplnswindow", "17");
    node::StartMiningPool(a, config);
    node::StartMiningPool(b,
                          config); // Default on, without explicit -miningpool.
    auto pa = node::GetMiningPool(a), pb = node::GetMiningPool(b);
    BOOST_REQUIRE(pa);
    BOOST_REQUIRE(pb);
    BOOST_CHECK(pa != pb);
    pa->SetPPLNSWindowSize(9);
    BOOST_CHECK_EQUAL(
        pa->GetPoolInfoJSON().find_value("active_workers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        pb->GetPoolInfoJSON().find_value("active_workers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        pb->GetPoolInfoJSON().find_value("pplns_window_max").getInt<int>(), 17);
    BOOST_CHECK_EQUAL(tableRPC.execute(config, request)
                          .find_value("pplns_window_max")
                          .getInt<int>(),
                      9);
    BOOST_CHECK_THROW(node::StartMiningPool(a, config), std::logic_error);
    node::InterruptMiningPool(a);
    BOOST_CHECK(!pa->IsEnabled());
    BOOST_CHECK(pb->IsEnabled());
    node::StopMiningPool(a);
    node::StopMiningPool(a); // Partial startup/shutdown is idempotent.
    BOOST_CHECK(!node::GetMiningPool(a));
    node::StartMiningPool(a, config);
    BOOST_CHECK(node::GetMiningPool(a) != pa);
    BOOST_CHECK_EQUAL(node::GetMiningPool(a)
                          ->GetPoolInfoJSON()
                          .find_value("active_workers")
                          .getInt<int>(),
                      0);
    BOOST_CHECK_EQUAL(node::GetMiningPool(a)
                          ->GetPoolInfoJSON()
                          .find_value("pplns_window_max")
                          .getInt<int>(),
                      1000);
}

BOOST_AUTO_TEST_SUITE_END()
