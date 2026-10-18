// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <blockindex.h>
#include <chainparams.h>
#include <consensus/activation.h>
#include <key_io.h> // For DecodeDestination

#include <test/util/blockindex.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(minerfund_tests, BasicTestingSetup)

static void
CheckWhitelist(const Consensus::Params &consensusParams,
               const CBlockIndex *pindexPrev,
               const std::unordered_set<CTxDestination, TxDestinationHasher>
                   &expectedWhitelist) {
    auto whitelist = GetMinerFundWhitelist(consensusParams);
    BOOST_CHECK_EQUAL(whitelist.size(), expectedWhitelist.size());
    for (const auto &expectedDest : expectedWhitelist) {
        BOOST_CHECK_EQUAL(whitelist.count(expectedDest), 1);
    }
}

BOOST_AUTO_TEST_CASE(minerfund_whitelist) {
    const CChainParams &chainparams = Params();
    const Consensus::Params &consensusParams = chainparams.GetConsensus();

    CBlockIndex block;
    block.nHeight = 1;

    const std::unordered_set<CTxDestination, TxDestinationHasher>
        expectedMinerFund = {DecodeDestination(
            "ecash:prfhcnyqnl5cgrnmlfmms675w93ld7mvvqd0y8lz07", chainparams)};
    CheckWhitelist(consensusParams, &block, expectedMinerFund);
}

BOOST_AUTO_TEST_CASE(minerfund_amount) {
    const CChainParams &chainparams = Params();
    const Consensus::Params &consensusParams = chainparams.GetConsensus();

    CBlockIndex block;

    auto checkMinerFundRatio = [&](int64_t expectedPercent) {
        BOOST_CHECK_EQUAL(
            GetMinerFundAmount(consensusParams, 100 * COIN, &block),
            expectedPercent * COIN);
    };

    block.nHeight = 1;
    checkMinerFundRatio(32);
    block.nHeight = 1000;
    checkMinerFundRatio(32);
}

BOOST_AUTO_TEST_SUITE_END()
