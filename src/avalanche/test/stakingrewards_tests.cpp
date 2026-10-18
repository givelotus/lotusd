// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <avalanche/stakecontender.h>
#include <chainparams.h>
#include <consensus/activation.h>
#include <net_processing.h>
#include <policy/block/stakingrewards.h>
#include <util/chaintype.h>
#include <validation.h>

#include <test/util/blockindex.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <limits>
#include <common/args.h>

using namespace avalanche;

struct StakingRewardsActivationTestingSetup : public TestingSetup {
    void checkStakingRewardsActivation(const ChainType chain_type,
                                       const bool expectActivation) {
        SelectParams(chain_type);
        const Consensus::Params &params = Params().GetConsensus();

        BOOST_CHECK(!IsStakingRewardsActivated(params, nullptr));

        // Staking rewards are controlled by the network default and explicit
        // runtime override; there is no longer a height activation boundary.
        CBlockIndex block;
        for (const int height : {0, 1, std::numeric_limits<int>::max()}) {
            block.nHeight = height;
            BOOST_CHECK_EQUAL(IsStakingRewardsActivated(params, &block),
                              expectActivation);
        }
        for (const bool enabled : {false, true}) {
            gArgs.ForceSetArg("-avalanchestakingrewards", enabled ? "1" : "0");
            BOOST_CHECK(!IsStakingRewardsActivated(params, nullptr));
            BOOST_CHECK_EQUAL(IsStakingRewardsActivated(params, &block), enabled);
        }
        gArgs.ClearForcedArg("-avalanchestakingrewards");
    }
};

BOOST_AUTO_TEST_SUITE(stakingrewards_tests)

BOOST_FIXTURE_TEST_CASE(isstakingrewardsactivated,
                        StakingRewardsActivationTestingSetup) {
    checkStakingRewardsActivation(ChainType::REGTEST, false);
    checkStakingRewardsActivation(ChainType::TESTNET, false);
    checkStakingRewardsActivation(ChainType::MAIN, true);
}

BOOST_FIXTURE_TEST_CASE(stakecontender_computeid, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    ProofId proofid1 = ProofId::fromHex(
        "979dbc3b1351ee12f91f537e04e61fdf93a73d5ebfc317bccd12643b8be87b02");
    BOOST_CHECK_EQUAL(
        "36653907336187a889c93bd9c75c0f3302ad5b24bdc0df51b4eaef914853d480",
        StakeContenderId(chaintip->GetAncestor(0)->GetBlockHash(), proofid1)
            .ToString());

    // Keep the identity vector independent of mined fixture header changes.
    // Independent SHA256d over the explicit LE block/proof bytes.
    const BlockHash other_block{uint256S("0101010101010101010101010101010101010101010101010101010101010101")};
    // Different prevblock should give different hash
    BOOST_CHECK_EQUAL(
        "0739e297f2c71bcb78a28a4043ca095f15125cf12db4829a4434bc5f9d66149e",
        StakeContenderId(other_block, proofid1).ToString());

    // So should a different proof id
    ProofId proofid2 = ProofId::fromHex(
        "e01bac293ed39e8d5e06214e7fe0bceb9646ef253ce501dcd7a475f802ab07f1");
    BOOST_CHECK_EQUAL(
        "e2689332e48406a5bd0da4202a4c39b4c37092131d165380ada3a46709cc0c82",
        StakeContenderId(other_block, proofid2).ToString());
}

BOOST_AUTO_TEST_SUITE_END()
