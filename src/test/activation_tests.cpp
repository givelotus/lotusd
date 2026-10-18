// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <consensus/activation.h>
#include <consensus/params.h>
#include <chain.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activationtest) {
    Consensus::Params params;
    CBlockIndex genesis_parent;
    genesis_parent.nHeight = 0;
    // All nine retained compatibility APIs enforce from-genesis behavior.
    // Null predecessor denotes the genesis block, not an inactive era.
    BOOST_CHECK(IsUAHFenabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsUAHFenabled(params, &genesis_parent));
    BOOST_CHECK(IsDAAEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsDAAEnabled(params, &genesis_parent));
    BOOST_CHECK(IsMagneticAnomalyEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsMagneticAnomalyEnabled(params, &genesis_parent));
    BOOST_CHECK(IsGravitonEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsGravitonEnabled(params, &genesis_parent));
    BOOST_CHECK(IsPhononEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsPhononEnabled(params, &genesis_parent));
    BOOST_CHECK(IsAxionEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsAxionEnabled(params, &genesis_parent));
    BOOST_CHECK(IsWellingtonEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsWellingtonEnabled(params, &genesis_parent));
    BOOST_CHECK(IsCowperthwaiteEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsCowperthwaiteEnabled(params, &genesis_parent));
    BOOST_CHECK(IsMengerEnabled(params, static_cast<const CBlockIndex *>(nullptr)));
    BOOST_CHECK(IsMengerEnabled(params, &genesis_parent));
    BOOST_CHECK(IsUAHFenabled(params, int(0)));
    BOOST_CHECK(IsDAAEnabled(params, int(0)));
    BOOST_CHECK(IsMagneticAnomalyEnabled(params, int32_t(0)));
    BOOST_CHECK(IsWellingtonEnabled(params, int32_t(0)));
    BOOST_CHECK(IsCowperthwaiteEnabled(params, int32_t(0)));
    BOOST_CHECK(IsMengerEnabled(params, int64_t(0)));

}

BOOST_AUTO_TEST_SUITE_END()
