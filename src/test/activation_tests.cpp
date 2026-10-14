// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activationtest) {
    /* Place future activation logic tests here. */
}

BOOST_AUTO_TEST_CASE(isexodusenabled) {
    const Consensus::Params &params = m_node.chainman->GetParams().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-exodusactivationtime", params.exodusActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsExodusEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));
}

BOOST_AUTO_TEST_SUITE_END()
