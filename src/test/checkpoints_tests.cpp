// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for block-chain checkpoints
//

#include <checkpoints.h>

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(checkpoints_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(sanity) {
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    const CCheckpointData &checkpoints = params->Checkpoints();
    BlockHash p11111 = BlockHash::fromHex(
        "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d");
    BlockHash p134444 = BlockHash::fromHex(
        "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe");

    /* TODO: Add sanity checks once we have any checkpoints */

    // Wrong hashes without any checkpoints succeeds:
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 11111, p134444));
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 134444, p11111));

    /* TODO: Add sanity checks for heights + 1 */
}

class ChainParamsWithCheckpoints : public CChainParams {
public:
    ChainParamsWithCheckpoints(const CChainParams &chainParams,
                               CCheckpointData &checkpoints)
        : CChainParams(chainParams) {
        checkpointData = checkpoints;
    }
};

class RegtestConfigWithTestCheckpoints : public DummyConfig {
public:
    RegtestConfigWithTestCheckpoints() : DummyConfig(createChainParams()) {}

    static std::unique_ptr<CChainParams> createChainParams() {
        CCheckpointData checkpoints = {
            .mapCheckpoints = {
                {2, BlockHash::fromHex("6ca3646c53dab4ae79cbdee551cd422f210b69d"
                                       "a9971bbc41af38e9c7c972161")},
            }};
        const auto regParams = CreateChainParams(CBaseChainParams::REGTEST);
        return std::make_unique<ChainParamsWithCheckpoints>(*regParams,
                                                            checkpoints);
    }
    uint64_t GetMaxBlockSize() const override { return 0xffffffff; }
};

/**
 * This test has 4 precomputed blocks mined ontop of the genesis block:
 *  G ---> A ---> AA (checkpointed)
 *   \       \
 *    \--> B  \-> AB
 * After the node has accepted only A and AA, these rejects should occur:
 *  * B should be rejected for forking prior to an accepted checkpoint
 *  * AB should be rejected for forking at an accepted checkpoint
 */
BOOST_AUTO_TEST_CASE(ban_fork_prior_to_and_at_checkpoints) {
    RegtestConfigWithTestCheckpoints config;
    const CBlockIndex *pindex = nullptr;

    // Start with regtest genesis block
    CBlockHeader headerG = config.GetChainParams().GenesisBlock();
    BOOST_CHECK_EQUAL(headerG.GetHash(),
                      uint256S("1060508db3b75302e0ee313a7cd1e05999c44974136a113"
                               "8f9b1e68c4dc24b12"));

    {
        BlockValidationState state;
        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlockHeaders(config, {headerG}, state, &pindex));
        pindex = nullptr;
    }

    CBlockHeader headerA = headerG;
    headerA.hashPrevBlock = headerG.GetHash();
    headerA.SetBlockTime(headerG.GetBlockTime() + 120);
    headerA.nNonce = 10001;
    headerA.nHeight = 1;
    BOOST_CHECK_EQUAL(headerA.GetHash(),
                      uint256S("0f0ff9fe39dfeb65298babafdc6044ef165b4dcbecfbe93"
                               "78f9b98de18a8289b"));
    BOOST_CHECK_EQUAL(headerA.hashPrevBlock, headerG.GetHash());

    CBlockHeader headerAA = headerG;
    headerAA.hashPrevBlock = headerA.GetHash();
    headerAA.SetBlockTime(headerA.GetBlockTime() + 120);
    headerAA.nNonce = 10000;
    headerAA.nHeight = 2;
    BOOST_CHECK_EQUAL(headerAA.GetHash(),
                      uint256S("6ca3646c53dab4ae79cbdee551cd422f210b69da9971bbc"
                               "41af38e9c7c972161"));
    BOOST_CHECK_EQUAL(headerAA.hashPrevBlock, headerA.GetHash());

    CBlockHeader headerB = headerG;
    headerB.hashPrevBlock = headerG.GetHash();
    headerB.SetBlockTime(headerG.GetBlockTime() + 1);
    headerB.nNonce = 20001;
    headerB.nHeight = 1;
    BOOST_CHECK_EQUAL(headerB.GetHash(),
                      uint256S("7664062a849c0399478c02cdef7610ff6ddf482034c8151"
                               "b60dab61bc7db2863"));
    BOOST_CHECK_EQUAL(headerB.hashPrevBlock, headerG.GetHash());

    CBlockHeader headerAB = headerG;
    headerAB.hashPrevBlock = headerA.GetHash();
    headerAB.SetBlockTime(headerG.GetBlockTime() + 2);
    headerAB.nNonce = 20002;
    headerAB.nHeight = 2;
    BOOST_CHECK_EQUAL(headerAB.GetHash(),
                      uint256S("373ec21df9f49bc9818e7afa715ed99fd1201a8f88471ad"
                               "11f3f7605242ad7ac"));
    BOOST_CHECK_EQUAL(headerAB.hashPrevBlock, headerA.GetHash());

    // Headers A and AA should be accepted
    {
        BlockValidationState state;
        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlockHeaders(config, {headerA}, state, &pindex));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
    }

    {
        BlockValidationState state;
        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlockHeaders(config, {headerAA}, state, &pindex));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
    }

    // Header B should be rejected
    {
        BlockValidationState state;
        BOOST_CHECK(
            !Assert(m_node.chainman)
                 ->ProcessNewBlockHeaders(config, {headerB}, state, &pindex));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectReason() == "bad-fork-prior-to-checkpoint");
        BOOST_CHECK(pindex == nullptr);
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(headerB.GetHash()) == nullptr);
    }

    // Header AB should be rejected
    {
        BlockValidationState state;
        BOOST_CHECK(
            !Assert(m_node.chainman)
                 ->ProcessNewBlockHeaders(config, {headerAB}, state, &pindex));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectReason() == "checkpoint mismatch");
        BOOST_CHECK(pindex == nullptr);
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(headerAB.GetHash()) == nullptr);
    }
}

BOOST_AUTO_TEST_SUITE_END()
