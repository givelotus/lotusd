// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/v2_outputs.h>
#include <avalanche/avalanche.h>
#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <avalanche/stakecontender.h>
#include <avalanche/test/util.h>
#include <avalanche/treasury.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <node/miner.h>
#include <policy/block/parkingpolicy.h>
#include <policy/block/stakingrewards.h>
#include <policy/block/treasury.h>
#include <pow/pow.h>
#include <util/chaintype.h>
#include <validation.h>

#include <test/util/blockindex.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>

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

BOOST_FIXTURE_TEST_CASE(staking_rewards_amount_is_25_percent, BasicTestingSetup) {
    BOOST_CHECK_EQUAL(GetStakingRewardsAmount(Amount::zero()), Amount::zero());
    BOOST_CHECK_EQUAL(GetStakingRewardsAmount(100 * COIN), 25 * COIN);
    BOOST_CHECK_EQUAL(GetStakingRewardsAmount(260 * COIN), 65 * COIN);
}

BOOST_FIXTURE_TEST_CASE(stakecontender_computeid, TestChain100Setup) {
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    ProofId proofid1 = ProofId::fromHex(
        "979dbc3b1351ee12f91f537e04e61fdf93a73d5ebfc317bccd12643b8be87b02");
    BOOST_CHECK_EQUAL(
        "3a6d3ded7ca5ac807c83806beb8d766cc14d98fdb70cbded5e9e85bc1950f7e7",
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

// This case checks the explicit park/unpark transition. The default work-based
// automatic-unparking behavior is tested separately by the policy chain tests.
struct ManualUnparkingStakingSetup : AvalancheTestChain100Setup {
    ManualUnparkingStakingSetup()
        : AvalancheTestChain100Setup(ChainType::REGTEST,
                                     {"-automaticunparking=0"}) {}
};

BOOST_FIXTURE_TEST_CASE(staking_rewards_policy_and_coinbase_split,
                        ManualUnparkingStakingSetup) {
    BOOST_REQUIRE(!m_node.args->GetBoolArg("-automaticunparking", true));
    gArgs.ForceSetArg("-avalanchestakingrewards", "1");
    gArgs.ForceSetArg("-avalanchetreasury", "1");

    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    const Consensus::Params &consensusParams = Params().GetConsensus();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    const CScript minerScript = CScript() << OP_TRUE;
    const CScript stakerScript = CScript() << OP_DUP << OP_HASH160
                                           << std::vector<uint8_t>(20, 0x11)
                                           << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript treasuryScript = CScript() << OP_DUP << OP_HASH160
                                             << std::vector<uint8_t>(20, 0x22)
                                             << OP_EQUALVERIFY << OP_CHECKSIG;

    const Amount blockSubsidy =
        GetBlockSubsidy(chaintip->nHeight + 1, consensusParams);
    const Amount expectedStakerShare = GetStakingRewardsAmount(blockSubsidy);
    const Amount expectedTreasuryShare = GetTreasuryRewardsAmount(blockSubsidy);
    BOOST_CHECK_EQUAL(expectedStakerShare, (25 * blockSubsidy) / 100);
    BOOST_CHECK_EQUAL(expectedTreasuryShare, (25 * blockSubsidy) / 100);

    // Set staker and treasury winners for chaintip
    BOOST_CHECK(m_node.avalanche->setStakingRewardWinners(
        chaintip, std::vector<CScript>{stakerScript}));
    const TreasuryContenderId treasuryId = m_node.avalanche->addTreasuryContender(
        chaintip->GetBlockHash(),
        std::vector<CTxOut>{CTxOut(expectedTreasuryShare, treasuryScript)},
        expectedTreasuryShare);
    BOOST_CHECK(m_node.avalanche->finalizeTreasuryContender(treasuryId));

    // 1. Before quorum is established:
    // - CreateNewBlock gives 100% of blockSubsidy to miner
    // - StakingRewardsPolicy passes without enforcing staker output
    BOOST_CHECK(!m_node.avalanche->isQuorumEstablished());
    const BlockHash dummyBlockHash(uint256S("01"));
    {
        auto ptemplate =
            node::BlockAssembler(GetConfig(), active_chainstate,
                                 m_node.mempool.get(), m_node.avalanche.get())
                .CreateNewBlock(minerScript);
        BOOST_REQUIRE(ptemplate != nullptr);
        const CTransaction &cb = *ptemplate->block.vtx[0];
        BOOST_CHECK_EQUAL(cb.vout.size(), 1U);
        BOOST_CHECK_EQUAL(cb.vout[0].nValue, blockSubsidy);

        CBlockIndex blockIdx;
        blockIdx.phashBlock = &dummyBlockHash;
        blockIdx.nHeight = chaintip->nHeight + 1;
        blockIdx.pprev = chaintip;
        BlockPolicyValidationState policyState;
        StakingRewardsPolicy policy(*m_node.avalanche, consensusParams,
                                    blockIdx, ptemplate->block, blockSubsidy);
        BOOST_CHECK(policy(policyState));
        BOOST_CHECK(policyState.IsValid());
    }

    // 2. Establish quorum (8 connected nodes with valid proof)
    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
        BOOST_CHECK(pm.registerProof(proof));
        for (NodeId n = 0; n < 8; n++) {
            BOOST_CHECK(pm.addNode(n, proof->getId(),
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        }
    });
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    // 3. With quorum established:
    // - CreateNewBlock splits coinbase 50% miner / 25% staker / 25% treasury
    std::unique_ptr<node::CBlockTemplate> validTemplate;
    {
        validTemplate =
            node::BlockAssembler(GetConfig(), active_chainstate,
                                 m_node.mempool.get(), m_node.avalanche.get())
                .CreateNewBlock(minerScript);
        BOOST_REQUIRE(validTemplate != nullptr);
        const CTransaction &cb = *validTemplate->block.vtx[0];
        BOOST_REQUIRE_EQUAL(cb.vout.size(), 3U);
        BOOST_CHECK_EQUAL(cb.vout[0].nValue,
                          blockSubsidy - expectedStakerShare -
                              expectedTreasuryShare);
        BOOST_CHECK(CoinbaseOutputPaysScript(cb.vout[0], minerScript));
        BOOST_CHECK_EQUAL(cb.vout[1].nValue, expectedStakerShare);
        BOOST_CHECK(CoinbaseOutputPaysScript(cb.vout[1], stakerScript));
        BOOST_CHECK_EQUAL(cb.vout[2].nValue, expectedTreasuryShare);
        BOOST_CHECK(CoinbaseOutputPaysScript(cb.vout[2], treasuryScript));

        CBlockIndex blockIdx;
        blockIdx.phashBlock = &dummyBlockHash;
        blockIdx.nHeight = chaintip->nHeight + 1;
        blockIdx.pprev = chaintip;
        BlockPolicyValidationState policyState;
        StakingRewardsPolicy stakerPolicy(*m_node.avalanche, consensusParams,
                                          blockIdx, validTemplate->block,
                                          blockSubsidy);
        BOOST_CHECK(stakerPolicy(policyState));
        BOOST_CHECK(policyState.IsValid());
    }

    // 4. Block missing staker reward is parked when connected with avalanche
    // quorum active
    {
        CBlock badBlock = CreateBlock({}, minerScript, active_chainstate);
        // badBlock was created without avalanche, so it has only 1 coinbase
        // output (no staker or treasury outputs).
        auto sharedBadBlock = std::make_shared<const CBlock>(badBlock);
        BOOST_CHECK(chainman.ProcessNewBlock(sharedBadBlock, true, true,
                                             /*new_block=*/nullptr,
                                             m_node.avalanche.get()));
        CBlockIndex *pindexBad = WITH_LOCK(
            cs_main,
            return chainman.m_blockman.LookupBlockIndex(badBlock.GetHash()));
        BOOST_REQUIRE(pindexBad != nullptr);
        WITH_LOCK(cs_main, BOOST_CHECK(pindexBad->nStatus.isOnParkedChain()));
        WITH_LOCK(cs_main, BOOST_CHECK(chainman.ActiveTip() == chaintip));

        // UnparkBlock restores the parked block to the active chain when
        // avalanche finalizes it
        WITH_LOCK(cs_main, active_chainstate.UnparkBlock(pindexBad));
        WITH_LOCK(cs_main, BOOST_CHECK(!pindexBad->nStatus.isOnParkedChain()));
    }

    gArgs.ClearForcedArg("-avalanchestakingrewards");
    gArgs.ClearForcedArg("-avalanchetreasury");
}

BOOST_AUTO_TEST_SUITE_END()
