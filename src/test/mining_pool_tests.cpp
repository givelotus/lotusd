// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mining_pool.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <lotus_v2/header.h>
#include <lotus_v2/output.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
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

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

BOOST_FIXTURE_TEST_SUITE(mining_pool_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(unavailable_native_payout_provider_keeps_startup_and_stats) {
    const Config &config = GetConfig();
    auto &pool = m_node.mining_pool ? *m_node.mining_pool
                                   : node::GetGlobalMiningPool();
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
    auto &pool = m_node.mining_pool ? *m_node.mining_pool
                                   : node::GetGlobalMiningPool();
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
    auto &pool = m_node.mining_pool ? *m_node.mining_pool
                                   : node::GetGlobalMiningPool();
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

BOOST_AUTO_TEST_SUITE_END()
