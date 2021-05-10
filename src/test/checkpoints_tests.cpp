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
                {2, BlockHash::fromHex("184834e12fe7d83c58c5dd50b4a0b2dbfceb859"
                                       "63682eedce497d534330b4316")},
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
                      uint256S("106050de32db2a668422cc34aa0f96d739d4189b8e5d6e7"
                               "63deeca527bba9c9f"));

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
    headerA.nNonce = 10000;
    headerA.nHeight = 1;
    BOOST_CHECK_EQUAL(headerA.GetHash(),
                      uint256S("66fa9236d849a1dabaa4e95afa9806388f720095c15a5be"
                               "c8aed3107000cacd4"));
    BOOST_CHECK_EQUAL(headerA.hashPrevBlock, headerG.GetHash());

    CBlockHeader headerAA = headerG;
    headerAA.hashPrevBlock = headerA.GetHash();
    headerAA.SetBlockTime(headerA.GetBlockTime() + 120);
    headerAA.nNonce = 10000;
    headerAA.nHeight = 2;
    BOOST_CHECK_EQUAL(headerAA.GetHash(),
                      uint256S("184834e12fe7d83c58c5dd50b4a0b2dbfceb85963682eed"
                               "ce497d534330b4316"));
    BOOST_CHECK_EQUAL(headerAA.hashPrevBlock, headerA.GetHash());

    CBlockHeader headerB = headerG;
    headerB.hashPrevBlock = headerG.GetHash();
    headerB.SetBlockTime(headerG.GetBlockTime() + 1);
    headerB.nNonce = 20000;
    headerB.nHeight = 1;
    BOOST_CHECK_EQUAL(headerB.GetHash(),
                      uint256S("540810fbed7684a5c3f55b2b14492b3199fa2725550559a"
                               "3a5aeb22accc2e091"));
    BOOST_CHECK_EQUAL(headerB.hashPrevBlock, headerG.GetHash());

    CBlockHeader headerAB = headerG;
    headerAB.hashPrevBlock = headerA.GetHash();
    headerAB.SetBlockTime(headerG.GetBlockTime() + 2);
    headerAB.nNonce = 20001;
    headerAB.nHeight = 2;
    BOOST_CHECK_EQUAL(headerAB.GetHash(),
                      uint256S("244a4e6240d3374d2a977e37327d3a534fb309a81bf5fa1"
                               "37def5de3d0b01347"));
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
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "bad-fork-prior-to-checkpoint");
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
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "checkpoint mismatch");
        BOOST_CHECK(pindex == nullptr);
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(headerAB.GetHash()) == nullptr);
    }
}

BOOST_AUTO_TEST_SUITE_END()
