// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/treasury.h>

#include <avalanche/avalanche.h>
#include <avalanche/peermanager.h>
#include <avalanche/processor.h>
#include <avalanche/test/util.h>
#include <chainparams.h>
#include <common/args.h>
#include <config.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <policy/block/parkingpolicy.h>
#include <policy/block/treasury.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <validation.h>

#include <test/util/net.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

using namespace avalanche;

BOOST_AUTO_TEST_SUITE(treasury_tests)

BOOST_FIXTURE_TEST_CASE(treasury_contender_id_and_inv, BasicTestingSetup) {
    const BlockHash prevHash1(uint256S(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"));
    const BlockHash prevHash2(uint256S(
        "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"));

    const CScript script1 = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<uint8_t>(20, 0xaa)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript script2 = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<uint8_t>(20, 0xbb)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;

    const std::vector<CTxOut> outputs1{CTxOut(65 * COIN, script1)};
    const std::vector<CTxOut> outputs2{CTxOut(65 * COIN, script2)};

    // Deterministic BLAKE3 keyed hash ("lotus.v2.ava.treasury_contender")
    const TreasuryContenderId id1a(prevHash1, outputs1);
    const TreasuryContenderId id1b(prevHash1, outputs1);
    BOOST_CHECK(id1a == id1b);
    BOOST_CHECK(!id1a.IsNull());

    // Different prevblockhash or outputs yield distinct IDs
    const TreasuryContenderId id2(prevHash2, outputs1);
    const TreasuryContenderId id3(prevHash1, outputs2);
    BOOST_CHECK(id1a != id2);
    BOOST_CHECK(id1a != id3);
    BOOST_CHECK(id2 != id3);

    // Verify CInv wiring for MSG_AVA_TREASURY_CONTENDER
    CInv inv(MSG_AVA_TREASURY_CONTENDER, id1a);
    BOOST_CHECK_EQUAL(inv.type, uint32_t(0x20000005));
    BOOST_CHECK(inv.IsMsgTreasuryContender());
    BOOST_CHECK_EQUAL(inv.GetKind(), uint32_t(MSG_AVA_TREASURY_CONTENDER));
    BOOST_CHECK_EQUAL(inv.GetMessageType(), NetMsgType::AVATREASURY);
}

BOOST_FIXTURE_TEST_CASE(treasury_contender_cache_operations, BasicTestingSetup) {
    TreasuryContenderCache cache;
    const BlockHash prevHash1(uint256S("01"));
    const BlockHash prevHash2(uint256S("02"));

    const CScript script1 = CScript() << OP_1;
    const CScript script2 = CScript() << OP_2;
    const std::vector<CTxOut> outputs1{CTxOut(25 * COIN, script1)};
    const std::vector<CTxOut> outputs2{CTxOut(25 * COIN, script2)};

    const TreasuryContenderId id1 =
        cache.add(prevHash1, outputs1, 25 * COIN);
    const TreasuryContenderId id2 =
        cache.add(prevHash1, outputs2, 25 * COIN);

    // Newly added contender starts rejected/not accepted locally (status 1)
    BOOST_CHECK_EQUAL(cache.getVoteStatus(id1), 1);
    BOOST_CHECK_EQUAL(cache.getVoteStatus(id2), 1);
    BOOST_CHECK_EQUAL(cache.getVoteStatus(TreasuryContenderId(uint256S("ff"))),
                      -1);

    std::vector<CTxOut> winner;
    BOOST_CHECK(!cache.getWinner(prevHash1, winner));

    // Accept id1 -> vote status becomes 0, best accepted returns outputs1
    BOOST_CHECK(cache.accept(id1));
    BOOST_CHECK_EQUAL(cache.getVoteStatus(id1), 0);
    BOOST_CHECK(cache.getWinner(prevHash1, winner));
    BOOST_REQUIRE_EQUAL(winner.size(), 1U);
    BOOST_CHECK(winner[0].scriptPubKey == script1);

    // Finalize id2 -> overrides accepted contender as finalized winner
    BOOST_CHECK(cache.finalize(id2));
    BOOST_CHECK_EQUAL(cache.getVoteStatus(id2), 0);
    winner.clear();
    BOOST_CHECK(cache.getWinner(prevHash1, winner));
    BOOST_REQUIRE_EQUAL(winner.size(), 1U);
    BOOST_CHECK(winner[0].scriptPubKey == script2);

    // Cleanup removes entries other than keepBlockHash
    cache.add(prevHash2, outputs1, 25 * COIN);
    cache.cleanup(prevHash2);
    BOOST_CHECK_EQUAL(cache.getVoteStatus(id1), -1);
    BOOST_CHECK(cache.getWinner(prevHash1, winner) == false);
}

BOOST_FIXTURE_TEST_CASE(treasury_policy_and_voting,
                        AvalancheTestChain100Setup) {
    gArgs.ForceSetArg("-avalanchetreasury", "1");

    ChainstateManager &chainman = *Assert(m_node.chainman);
    Chainstate &active_chainstate = chainman.ActiveChainstate();
    const Consensus::Params &consensusParams = Params().GetConsensus();
    CBlockIndex *chaintip =
        WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

    const Amount blockSubsidy =
        GetBlockSubsidy(chaintip->nHeight + 1, consensusParams);
    const Amount treasuryReward = GetTreasuryRewardsAmount(blockSubsidy);
    BOOST_CHECK_EQUAL(treasuryReward, (25 * blockSubsidy) / 100);

    const CScript minerScript = CScript() << OP_TRUE;
    const CScript treasuryScript = CScript() << OP_DUP << OP_HASH160
                                             << std::vector<uint8_t>(20, 0x55)
                                             << OP_EQUALVERIFY << OP_CHECKSIG;
    const std::vector<CTxOut> expectedTreasuryOutputs{
        CTxOut(treasuryReward, treasuryScript)};

    const TreasuryContenderId contenderId =
        m_node.avalanche->addTreasuryContender(
            chaintip->GetBlockHash(), expectedTreasuryOutputs, treasuryReward);
    BOOST_CHECK(m_node.avalanche->acceptTreasuryContender(contenderId));
    BOOST_CHECK_EQUAL(m_node.avalanche->getTreasuryContenderStatus(contenderId),
                      0);

    // Establish quorum so TreasuryPolicy and voting are active
    auto proof = buildRandomProof(active_chainstate, MIN_VALID_PROOF_SCORE);
    m_node.avalanche->withPeerManager([&](avalanche::PeerManager &pm) {
        BOOST_CHECK(pm.registerProof(proof));
        for (NodeId n = 0; n < 8; n++) {
            BOOST_CHECK(pm.addNode(n, proof->getId(),
                                   DEFAULT_AVALANCHE_MAX_ELEMENT_POLL));
        }
    });
    BOOST_CHECK(m_node.avalanche->isQuorumEstablished());

    // Contender is already reconciled upon addTreasuryContender; finalize it
    BOOST_CHECK(m_node.avalanche->isPolled(contenderId));
    BOOST_CHECK(m_node.avalanche->finalizeTreasuryContender(contenderId));

    const BlockHash dummyBlockHash(uint256S("01"));
    CBlockIndex blockIdx;
    blockIdx.phashBlock = &dummyBlockHash;
    blockIdx.nHeight = chaintip->nHeight + 1;
    blockIdx.pprev = chaintip;

    // 1. Block missing treasury output is rejected by TreasuryPolicy
    {
        CBlock blockMissingTreasury;
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vout.emplace_back(blockSubsidy, minerScript);
        blockMissingTreasury.vtx.push_back(MakeTransactionRef(cb));

        BlockPolicyValidationState policyState;
        TreasuryPolicy policy(*m_node.avalanche, consensusParams, policyState,
                              &blockIdx, blockMissingTreasury, blockSubsidy);
        BOOST_CHECK(!policy(policyState));
        BOOST_CHECK(!policyState.IsValid());
        BOOST_CHECK_EQUAL(policyState.GetRejectReason(),
                          "bad-cb-treasury-reward");
    }

    // 2. Block with insufficient treasury output value is rejected
    {
        CBlock blockUnderpaidTreasury;
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vout.emplace_back(blockSubsidy - treasuryReward + SATOSHI,
                             minerScript);
        cb.vout.emplace_back(treasuryReward - SATOSHI, treasuryScript);
        blockUnderpaidTreasury.vtx.push_back(MakeTransactionRef(cb));

        BlockPolicyValidationState policyState;
        TreasuryPolicy policy(*m_node.avalanche, consensusParams, policyState,
                              &blockIdx, blockUnderpaidTreasury, blockSubsidy);
        BOOST_CHECK(!policy(policyState));
        BOOST_CHECK(!policyState.IsValid());
    }

    // 3. Block with valid 25% treasury output passes TreasuryPolicy
    {
        CBlock blockValidTreasury;
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vout.emplace_back(blockSubsidy - treasuryReward, minerScript);
        cb.vout.emplace_back(treasuryReward, treasuryScript);
        blockValidTreasury.vtx.push_back(MakeTransactionRef(cb));

        BlockPolicyValidationState policyState;
        TreasuryPolicy policy(*m_node.avalanche, consensusParams, policyState,
                              &blockIdx, blockValidTreasury, blockSubsidy);
        BOOST_CHECK(policy(policyState));
        BOOST_CHECK(policyState.IsValid());

        // Exercise null pprev and unfinalized prev block in TreasuryPolicy
        CBlockIndex genesisIdx;
        genesisIdx.phashBlock = &dummyBlockHash;
        genesisIdx.nHeight = 0;
        genesisIdx.pprev = nullptr;
        BlockPolicyValidationState genState;
        TreasuryPolicy genPolicy(*m_node.avalanche, consensusParams, genState,
                                 &genesisIdx, blockValidTreasury, blockSubsidy);
        BOOST_CHECK(genPolicy(genState));

        const BlockHash unfinalizedHash(uint256S("02"));
        CBlockIndex prevNoWinner;
        prevNoWinner.phashBlock = &unfinalizedHash;
        prevNoWinner.nHeight = chaintip->nHeight;
        CBlockIndex childNoWinner;
        childNoWinner.phashBlock = &dummyBlockHash;
        childNoWinner.nHeight = chaintip->nHeight + 1;
        childNoWinner.pprev = &prevNoWinner;
        BlockPolicyValidationState nwState;
        TreasuryPolicy nwPolicy(*m_node.avalanche, consensusParams, nwState,
                                &childNoWinner, blockValidTreasury, blockSubsidy);
        BOOST_CHECK(nwPolicy(nwState));

        // Exercise used[i] skip on duplicate treasury script outputs and IsTreasuryActivated fallbacks
        const std::vector<CTxOut> twoSameScriptOutputs{
            CTxOut(SATOSHI, treasuryScript),
            CTxOut(SATOSHI, treasuryScript)};
        const TreasuryContenderId twoCid =
            m_node.avalanche->addTreasuryContender(unfinalizedHash,
                                                   twoSameScriptOutputs,
                                                   2 * SATOSHI);
        BOOST_CHECK(m_node.avalanche->finalizeTreasuryContender(twoCid));
        CBlock blockTwoSmall;
        CMutableTransaction cbTwo;
        cbTwo.vin.resize(1);
        cbTwo.vout.emplace_back(SATOSHI, treasuryScript);
        cbTwo.vout.emplace_back(SATOSHI, treasuryScript);
        blockTwoSmall.vtx.push_back(MakeTransactionRef(cbTwo));
        BlockPolicyValidationState twoState;
        TreasuryPolicy twoPolicy(*m_node.avalanche, consensusParams, twoState,
                                 &childNoWinner, blockTwoSmall, blockSubsidy);
        BOOST_CHECK(!twoPolicy(twoState));
        BOOST_CHECK_EQUAL(twoState.GetRejectReason(), "bad-cb-treasury-reward");

        BOOST_CHECK(!IsTreasuryActivated(consensusParams, nullptr));
        gArgs.ClearForcedArg("-avalanchetreasury");
        gArgs.ForceSetArg("-avalanchestakingrewards", "1");
        BOOST_CHECK(IsTreasuryActivated(consensusParams, chaintip));
        gArgs.ClearForcedArg("-avalanchestakingrewards");
        BOOST_CHECK(IsTreasuryActivated(consensusParams, chaintip));
    }

    gArgs.ClearForcedArg("-avalanchetreasury");
}


BOOST_FIXTURE_TEST_CASE(treasury_contender_validation_and_bounded_eviction,
                        BasicTestingSetup) {
    TreasuryContenderCache cache;
    const BlockHash prevHash(uint256S("11"));
    const CScript validScript = CScript() << OP_1;

    // 1. Reject empty outputs
    BOOST_CHECK(cache.add(prevHash, {}, 10 * COIN).IsNull());
    BOOST_CHECK(!cache.add(prevHash, 1, {}));

    // 2. Reject > MAX_TREASURY_OUTPUTS (65 outputs)
    std::vector<CTxOut> tooManyOutputs(MAX_TREASURY_OUTPUTS + 1,
                                       CTxOut(1 * COIN, validScript));
    BOOST_CHECK(
        cache.add(prevHash, tooManyOutputs, 65 * COIN).IsNull());
    BOOST_CHECK(!cache.add(prevHash, 1, tooManyOutputs));

    // 3. Reject zero or negative output amounts
    BOOST_CHECK(
        cache.add(prevHash, {CTxOut(Amount::zero(), validScript)}, Amount::zero())
            .IsNull());
    BOOST_CHECK(
        cache.add(prevHash, {CTxOut(-1 * SATOSHI, validScript)}, 10 * COIN)
            .IsNull());

    // 4. Reject empty or oversized scriptPubKey
    BOOST_CHECK(
        cache.add(prevHash, {CTxOut(10 * COIN, CScript())}, 10 * COIN).IsNull());
    const std::vector<uint8_t> rawOversized(MAX_SCRIPT_SIZE + 1, 0x6a);
    const CScript oversizedScript(rawOversized.begin(), rawOversized.end());
    BOOST_CHECK(
        cache.add(prevHash, {CTxOut(10 * COIN, oversizedScript)}, 10 * COIN)
            .IsNull());

    // 5. Reject mismatched sum(out.nValue) != totalReward
    BOOST_CHECK(
        cache.add(prevHash, {CTxOut(10 * COIN, validScript)}, 11 * COIN)
            .IsNull());

    // 6. Accept valid MAX_TREASURY_OUTPUTS (64 outputs) with matching totalReward
    std::vector<CTxOut> maxValidOutputs(MAX_TREASURY_OUTPUTS,
                                        CTxOut(1 * COIN, validScript));
    const TreasuryContenderId validMaxId =
        cache.add(prevHash, maxValidOutputs, 64 * COIN);
    BOOST_CHECK(!validMaxId.IsNull());
    BOOST_CHECK_EQUAL(cache.getVoteStatus(validMaxId), 1);

    // 7. Enforce bounded cache eviction at MAX_TRACKED_TREASURY_BLOCKS (128)
    TreasuryContenderCache boundedCache;
    std::vector<TreasuryContenderId> addedIds;
    for (size_t i = 0; i < MAX_TRACKED_TREASURY_BLOCKS + 16; ++i) {
        uint256 h{};
        h.begin()[0] = static_cast<uint8_t>((i + 1) & 0xFF);
        h.begin()[1] = static_cast<uint8_t>(((i + 1) >> 8) & 0xFF);
        const BlockHash bh(h);
        const TreasuryContenderId cid =
            boundedCache.add(bh, {CTxOut(5 * COIN, validScript)}, 5 * COIN);
        BOOST_REQUIRE(!cid.IsNull());
        addedIds.push_back(cid);
    }

    BOOST_CHECK_EQUAL(boundedCache.getTrackedBlockCount(),
                      MAX_TRACKED_TREASURY_BLOCKS);
    // Oldest 16 block contenders must have been evicted
    for (size_t i = 0; i < 16; ++i) {
        BOOST_CHECK_EQUAL(boundedCache.getVoteStatus(addedIds[i]), -1);
    }
    // Newest 128 block contenders must remain tracked
    for (size_t i = 16; i < addedIds.size(); ++i) {
        BOOST_CHECK_EQUAL(boundedCache.getVoteStatus(addedIds[i]), 1);
    }

    // 8. Exercise CBlockIndex overloads, outContenderId overload, setWinner,
    // reject, getContender, getOutputs, getPollableContenders, cleanup(height),
    // and cleanupBounded.
    boundedCache.cleanupBounded(64);
    BOOST_CHECK_EQUAL(boundedCache.getTrackedBlockCount(), 64U);

    TreasuryContenderId outCid;
    BOOST_CHECK(!cache.add(BlockHash(), maxValidOutputs, &outCid));
    BOOST_CHECK(outCid.IsNull());

    const BlockHash bh2(uint256S("22"));
    const std::vector<CTxOut> outsA{CTxOut(5 * COIN, CScript() << OP_2)};
    const std::vector<CTxOut> outsB{CTxOut(5 * COIN, CScript() << OP_3)};
    BOOST_CHECK(cache.add(bh2, outsA, &outCid));
    BOOST_CHECK(!outCid.IsNull());

    std::vector<CTxOut> fetchedOuts;
    BOOST_CHECK(cache.getOutputs(outCid, fetchedOuts));
    BOOST_CHECK(fetchedOuts == outsA);
    BOOST_CHECK(!cache.getOutputs(TreasuryContenderId(uint256S("99")), fetchedOuts));

    BOOST_CHECK(cache.accept(outCid));
    BOOST_CHECK_EQUAL(cache.getVoteStatus(outCid), 0);
    BOOST_CHECK(cache.reject(outCid));
    BOOST_CHECK_EQUAL(cache.getVoteStatus(outCid), 1);
    BOOST_CHECK(!cache.reject(TreasuryContenderId(uint256S("99"))));

    CBlockIndex idx2;
    idx2.phashBlock = &bh2;
    idx2.nHeight = 50;
    BOOST_CHECK(!cache.add(static_cast<const CBlockIndex *>(nullptr), outsB));
    BOOST_CHECK(cache.add(&idx2, outsB,
                          avalanche::TreasuryContenderStatus::TREASURY_ACCEPTED));

    std::vector<TreasuryContenderId> pollable;
    BOOST_CHECK_EQUAL(cache.getPollableContenders(bh2, 10, pollable), 2U);
    BOOST_CHECK_EQUAL(pollable[0], TreasuryContenderId(bh2, outsB));
    BOOST_CHECK_EQUAL(pollable[1], outCid);

    BOOST_CHECK(!cache.setWinner(static_cast<const CBlockIndex *>(nullptr), outsA));
    BOOST_CHECK(!cache.setWinner(BlockHash(), 50, outsA));
    BOOST_CHECK(cache.setWinner(&idx2, outsA));
    BOOST_CHECK(cache.setWinner(bh2, 50, outsA));
    BOOST_CHECK_EQUAL(cache.getVoteStatus(outCid), 0);
    std::vector<CTxOut> winnerOuts;
    BOOST_CHECK(cache.getWinner(bh2, winnerOuts));
    BOOST_CHECK(winnerOuts == outsA);

    const BlockHash bh3(uint256S("33"));
    CBlockIndex idx3;
    idx3.phashBlock = &bh3;
    idx3.nHeight = 100;
    BOOST_CHECK(cache.setWinner(&idx3, outsB));
    cache.cleanup(/*requestedMinHeight=*/80);
    BOOST_CHECK(!cache.getWinner(bh2, winnerOuts));
    BOOST_CHECK(cache.getWinner(bh3, winnerOuts));

    // Exercise sum overflow in IsValidTreasuryOutputs, non-existent accept/finalize,
    // equal-status tie-breaking in getPollableContenders and getWinner, and cleanup(keepBlockHash)
    BOOST_CHECK(!avalanche::IsValidTreasuryOutputs(
        {CTxOut(MAX_MONEY, validScript), CTxOut(SATOSHI, validScript)}));
    BOOST_CHECK(!cache.accept(TreasuryContenderId(uint256S("98"))));
    BOOST_CHECK(!cache.finalize(TreasuryContenderId(uint256S("98"))));

    const BlockHash bh4(uint256S("44"));
    BOOST_CHECK(cache.add(
        bh4, 110, outsA,
        avalanche::TreasuryContenderStatus::TREASURY_ACCEPTED));
    BOOST_CHECK(cache.add(
        bh4, 110, outsB,
        avalanche::TreasuryContenderStatus::TREASURY_ACCEPTED));
    BOOST_CHECK_EQUAL(cache.getPollableContenders(bh4, 10, pollable), 2U);
    BOOST_CHECK(cache.getWinner(bh4, winnerOuts));
    // Both in winner set, one rejected -> accepted contender wins tie-breaker
    BOOST_CHECK(cache.finalize(TreasuryContenderId(bh4, outsA)));
    BOOST_CHECK(cache.finalize(TreasuryContenderId(bh4, outsB)));
    BOOST_CHECK(cache.reject(TreasuryContenderId(bh4, outsA)));
    BOOST_CHECK(cache.getWinner(bh4, winnerOuts));
    BOOST_CHECK(winnerOuts == outsB);

    const BlockHash bh5(uint256S("55"));
    BOOST_CHECK(cache.setWinner(bh5, 120, outsA));
    cache.cleanup(bh5);
    BOOST_CHECK(!cache.getWinner(bh3, winnerOuts));
    BOOST_CHECK(cache.getWinner(bh5, winnerOuts));
}

BOOST_FIXTURE_TEST_CASE(default_treasury_proportional_outputs_and_cli_override,
                        AvalancheTestChain100Setup) {
    const Consensus::Params &consensusParams = Params().GetConsensus();
    CBlockIndex *chaintip =
        WITH_LOCK(m_node.chainman->GetMutex(),
                  return m_node.chainman->ActiveTip());
    BOOST_REQUIRE(chaintip != nullptr);

    const Amount blockSubsidy =
        GetBlockSubsidy(chaintip->nHeight + 1, consensusParams);
    const Amount treasuryReward = GetTreasuryRewardsAmount(blockSubsidy);

    const CScript scriptA = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<uint8_t>(20, 0x11)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript scriptB = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<uint8_t>(20, 0x22)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript scriptC = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<uint8_t>(20, 0x33)
                                      << OP_EQUALVERIFY << OP_CHECKSIG;

    // 1. ComputeProportionalTreasuryOutputs: single, multi-recipient, and
    // exact integer division remainder handling (1..63 satoshis on output 0).
    {
        const auto singleOut = ComputeProportionalTreasuryOutputs(
            {{scriptA, 100}}, treasuryReward);
        BOOST_REQUIRE_EQUAL(singleOut.size(), 1U);
        BOOST_CHECK_EQUAL(singleOut[0].nValue, treasuryReward);
        BOOST_CHECK(singleOut[0].scriptPubKey == scriptA);

        // 3 equal weights splitting 100 satoshis -> 34, 33, 33 satoshis
        const auto threeWay = ComputeProportionalTreasuryOutputs(
            {{scriptA, 100}, {scriptB, 100}, {scriptC, 100}}, 100 * SATOSHI);
        BOOST_REQUIRE_EQUAL(threeWay.size(), 3U);
        BOOST_CHECK_EQUAL(threeWay[0].nValue, 34 * SATOSHI);
        BOOST_CHECK_EQUAL(threeWay[1].nValue, 33 * SATOSHI);
        BOOST_CHECK_EQUAL(threeWay[2].nValue, 33 * SATOSHI);
        BOOST_CHECK(IsValidTreasuryOutputs(threeWay, 100 * SATOSHI));

        // 64 equal weights splitting (64 * 10 + 63) satoshis -> remainder of
        // 63 satoshis placed on output 0
        std::vector<std::pair<CScript, uint32_t>> maxTemplate;
        for (size_t i = 0; i < MAX_TREASURY_OUTPUTS; ++i) {
            maxTemplate.emplace_back(scriptA, 10);
        }
        const Amount oddTotal = (64 * 10 + 63) * SATOSHI;
        const auto maxSplit =
            ComputeProportionalTreasuryOutputs(maxTemplate, oddTotal);
        BOOST_REQUIRE_EQUAL(maxSplit.size(), MAX_TREASURY_OUTPUTS);
        BOOST_CHECK_EQUAL(maxSplit[0].nValue, (10 + 63) * SATOSHI);
        for (size_t i = 1; i < MAX_TREASURY_OUTPUTS; ++i) {
            BOOST_CHECK_EQUAL(maxSplit[i].nValue, 10 * SATOSHI);
        }
        BOOST_CHECK(IsValidTreasuryOutputs(maxSplit, oddTotal));

        // Invalid templates return empty
        BOOST_CHECK(
            ComputeProportionalTreasuryOutputs({}, treasuryReward).empty());
        BOOST_CHECK(ComputeProportionalTreasuryOutputs({{scriptA, 0}},
                                                       treasuryReward)
                        .empty());
        BOOST_CHECK(ComputeProportionalTreasuryOutputs({{CScript(), 100}},
                                                       treasuryReward)
                        .empty());
    }

    // 2. Built-in default developer treasury slate in chainparams seeds a
    // local TreasuryContenderEntry as TREASURY_ACCEPTED.
    {
        BOOST_REQUIRE(!consensusParams.defaultTreasuryOutputs.empty());
        const auto expectedDefaultOutputs = ComputeProportionalTreasuryOutputs(
            consensusParams.defaultTreasuryOutputs, treasuryReward);
        BOOST_REQUIRE(!expectedDefaultOutputs.empty());

        TreasuryContenderCache cache;
        const BlockHash tipHash = chaintip->GetBlockHash();

        // When -avalancheusedefaulttreasury=1 is active, getWinner synthesizes
        // the proportional default outputs even before a contender is seeded.
        gArgs.ForceSetArg("-avalancheusedefaulttreasury", "1");
        std::vector<CTxOut> synthesizedWinner;
        BOOST_CHECK(cache.getWinner(tipHash, synthesizedWinner));
        BOOST_CHECK(synthesizedWinner == expectedDefaultOutputs);
        gArgs.ClearForcedArg("-avalancheusedefaulttreasury");

        // Seeding via registerDefaultTreasuryContender on Processor registers
        // the contender as TREASURY_ACCEPTED (vote status 0) and polls it.
        TreasuryContenderId seededId;
        const TreasuryContenderId retId =
            m_node.avalanche->registerDefaultTreasuryContender(
                chaintip, blockSubsidy, &seededId);
        BOOST_CHECK(!retId.IsNull());
        BOOST_CHECK_EQUAL(retId, seededId);
        BOOST_CHECK_EQUAL(
            retId, TreasuryContenderId(tipHash, expectedDefaultOutputs));
        BOOST_CHECK_EQUAL(m_node.avalanche->getTreasuryContenderStatus(retId),
                          0);
        BOOST_CHECK(m_node.avalanche->isPolled(retId));

        std::vector<CTxOut> winnerOutputs;
        BOOST_CHECK(
            m_node.avalanche->getTreasuryRewardWinner(tipHash, winnerOutputs));
        BOOST_CHECK(winnerOutputs == expectedDefaultOutputs);
    }

    // 3. Overriding built-in default with -avalanchetreasuryaddress (single
    // address and multi-output weighted split, both CashAddr and hex script).
    {
        // Single CashAddr override (default weight 100)
        const std::string cashAddr1 =
            "ecash:prfhcnyqnl5cgrnmlfmms675w93ld7mvvqd0y8lz07";
        gArgs.ForceSetArg("-avalanchetreasuryaddress", cashAddr1);

        const auto singleTemplate = GetDefaultTreasuryTemplate(consensusParams);
        BOOST_REQUIRE_EQUAL(singleTemplate.size(), 1U);
        BOOST_CHECK_EQUAL(singleTemplate[0].second,
                          DEFAULT_TREASURY_OUTPUT_WEIGHT);

        const BlockHash overrideBlockHash1(uint256S("a1"));
        const TreasuryContenderId singleCid =
            m_node.avalanche->registerDefaultTreasuryContender(
                overrideBlockHash1, chaintip->nHeight + 1, blockSubsidy);
        BOOST_CHECK(!singleCid.IsNull());
        BOOST_CHECK_EQUAL(
            m_node.avalanche->getTreasuryContenderStatus(singleCid), 0);

        std::vector<CTxOut> singleWinner;
        BOOST_CHECK(m_node.avalanche->getTreasuryRewardWinner(
            overrideBlockHash1, singleWinner));
        BOOST_REQUIRE_EQUAL(singleWinner.size(), 1U);
        BOOST_CHECK_EQUAL(singleWinner[0].nValue, treasuryReward);
        BOOST_CHECK(singleWinner[0].scriptPubKey == singleTemplate[0].first);

        // Multi-output weighted split via comma-separated CashAddr + hex script
        const std::string hexScriptB = HexStr(scriptB);
        const std::string hexScriptC = HexStr(scriptC);
        gArgs.ForceSetArg("-avalanchetreasuryaddress",
                          cashAddr1 + ":50," + hexScriptB + ":30," +
                              hexScriptC + ":20");

        const BlockHash overrideBlockHash2(uint256S("a2"));
        const TreasuryContenderId multiCid =
            m_node.avalanche->registerDefaultTreasuryContender(
                overrideBlockHash2, chaintip->nHeight + 2, blockSubsidy);
        BOOST_CHECK(!multiCid.IsNull());

        std::vector<CTxOut> multiWinner;
        BOOST_CHECK(m_node.avalanche->getTreasuryRewardWinner(
            overrideBlockHash2, multiWinner));
        BOOST_REQUIRE_EQUAL(multiWinner.size(), 3U);
        BOOST_CHECK_EQUAL(multiWinner[0].nValue, (50 * treasuryReward) / 100);
        BOOST_CHECK_EQUAL(multiWinner[1].nValue, (30 * treasuryReward) / 100);
        BOOST_CHECK_EQUAL(multiWinner[2].nValue, (20 * treasuryReward) / 100);
        BOOST_CHECK(multiWinner[0].scriptPubKey == singleTemplate[0].first);
        BOOST_CHECK(multiWinner[1].scriptPubKey == scriptB);
        BOOST_CHECK(multiWinner[2].scriptPubKey == scriptC);

        gArgs.ClearForcedArg("-avalanchetreasuryaddress");
    }

    // 4. Avalanche contender voting / finalize overrides the local default
    // contender when the network votes for a different TreasuryContenderId.
    {
        const BlockHash votingBlockHash(uint256S("b1"));
        const TreasuryContenderId localDefaultCid =
            m_node.avalanche->registerDefaultTreasuryContender(
                votingBlockHash, chaintip->nHeight + 3, blockSubsidy);
        BOOST_REQUIRE(!localDefaultCid.IsNull());
        BOOST_CHECK_EQUAL(
            m_node.avalanche->getTreasuryContenderStatus(localDefaultCid), 0);

        // Network proposes an alternative contender (e.g. a governance payout)
        const std::vector<CTxOut> networkOutputs{
            CTxOut(treasuryReward, scriptC)};
        const TreasuryContenderId networkCid =
            m_node.avalanche->addTreasuryContender(
                votingBlockHash, networkOutputs, treasuryReward);
        BOOST_REQUIRE(!networkCid.IsNull());
        BOOST_CHECK(networkCid != localDefaultCid);
        BOOST_CHECK_EQUAL(
            m_node.avalanche->getTreasuryContenderStatus(networkCid), 1);

        // Before finalization, local default contender is the active winner
        std::vector<CTxOut> activeWinner;
        BOOST_CHECK(m_node.avalanche->getTreasuryRewardWinner(votingBlockHash,
                                                              activeWinner));
        BOOST_CHECK(activeWinner != networkOutputs);

        // Once Avalanche voting finalizes networkCid, it overrides the local
        // default contender
        BOOST_CHECK(m_node.avalanche->finalizeTreasuryContender(networkCid));
        BOOST_CHECK(m_node.avalanche->getTreasuryRewardWinner(votingBlockHash,
                                                              activeWinner));
        BOOST_CHECK(activeWinner == networkOutputs);
    }
}

BOOST_AUTO_TEST_SUITE_END()

