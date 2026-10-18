// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <chainparams.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activationtest) {
    // Compatibility predicates disappear with native admission, but every
    // configured native chain must continue enforcing buried rules at genesis.
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(m_args, chain);
        const auto &consensus = params->GetConsensus();
        BOOST_CHECK_EQUAL(consensus.BIP16Height, 0);
        BOOST_CHECK_EQUAL(consensus.BIP34Height, 0);
        BOOST_CHECK_EQUAL(consensus.BIP65Height, 0);
        BOOST_CHECK_EQUAL(consensus.BIP66Height, 0);
        BOOST_CHECK_EQUAL(consensus.CSVHeight, 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
