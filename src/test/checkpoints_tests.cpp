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
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(checkpoints_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(sanity) {
    // The Lotus V2 networks have no history yet, so mainnet and testnet have
    // no checkpoints.
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    BOOST_CHECK(params->Checkpoints().mapCheckpoints.empty());
    BOOST_CHECK(CreateChainParams(*m_node.args, ChainType::TESTNET)
                    ->Checkpoints()
                    .mapCheckpoints.empty());

    BlockHash p11111 = *BlockHash::FromHex(
        "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d");
    BlockHash p134444 = *BlockHash::FromHex(
        "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe");
    const CCheckpointData checkpoints = {
        .mapCheckpoints = {{11111, p11111}, {134444, p134444}}};
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 11111, p11111));
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 134444, p134444));

    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckBlock(checkpoints, 11111, p134444));
    BOOST_CHECK(!Checkpoints::CheckBlock(checkpoints, 134444, p11111));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 11111 + 1, p134444));
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 134444 + 1, p11111));
}

/**
 * This test has 4 precomputed blocks mined ontop of the genesis block:
 *  G ---> A ---> AA (checkpointed)
 *   \       \
 *    \--> B  \-> AB
 * After the node has accepted only A and AA, these rejects should occur:
 *  * B should be rejected for forking prior to an accepted checkpoint
 *  * AB should be rejected for forking at an accepted checkpoint
 */
BOOST_FIXTURE_TEST_CASE(ban_fork_prior_to_and_at_checkpoints, RegTestingSetup) {
    const CCheckpointData test_checkpoints = {
        .mapCheckpoints = {{2, *BlockHash::FromHex(
                                   "7c4bff5b6456fec88b2fb14e5663259d62eef23"
                                   "44408097e037a2d24e7db7e01")}},
    };
    const CBlockIndex *pindex = nullptr;

    CBlockHeader headerG = Assert(m_node.chainman)->GetParams().GenesisBlock();
    BOOST_CHECK(headerG.GetHash() ==
                uint256S("5297d8c90656af6365bd4c2280f100b13b6fee2e9d909cd29eb509fa3feb7605"));

    {
        BlockValidationState state;
        BOOST_CHECK(m_node.chainman->ProcessNewBlockHeaders(
            {headerG}, true, state, &pindex, test_checkpoints));
        pindex = nullptr;
    }

    CBlockHeader headerA, headerB, headerAA, headerAB;
    headerA.nHeaderVersion = 2;
    headerA.hashPrevBlock = headerG.GetHash();
    headerA.nBits = headerG.nBits;
    headerA.SetBlockTime(headerG.GetBlockTime() + 120);
    headerA.nHeight = 1;
    headerA.nNonce = 10000;
    BOOST_CHECK_EQUAL(headerA.GetHash().GetHex(),
                      "7ed294fadecbb5d13432dfb33b9dd744f0f4adac414c1d75932ffb66d45f7a7b");

    headerAA.nHeaderVersion = 2;
    headerAA.hashPrevBlock = headerA.GetHash();
    headerAA.nBits = headerA.nBits;
    headerAA.SetBlockTime(headerA.GetBlockTime() + 120);
    headerAA.nHeight = 2;
    headerAA.nNonce = 10000;
    BOOST_CHECK_EQUAL(headerAA.GetHash().GetHex(),
                      "7c4bff5b6456fec88b2fb14e5663259d62eef2344408097e037a2d24e7db7e01");

    headerB.nHeaderVersion = 2;
    headerB.hashPrevBlock = headerG.GetHash();
    headerB.nBits = headerG.nBits;
    headerB.SetBlockTime(headerG.GetBlockTime() + 1);
    headerB.nHeight = 1;
    headerB.nNonce = 20001;
    BOOST_CHECK_EQUAL(headerB.GetHash().GetHex(),
                      "527f7ebd88a93c5b4f777a0b1ffd04cef4a895e20a99f32a09b50ff443dbbcf7");

    headerAB.nHeaderVersion = 2;
    headerAB.hashPrevBlock = headerA.GetHash();
    headerAB.nBits = headerA.nBits;
    headerAB.SetBlockTime(headerG.GetBlockTime() + 2);
    headerAB.nHeight = 2;
    headerAB.nNonce = 20004;
    BOOST_CHECK_EQUAL(headerAB.GetHash().GetHex(),
                      "1ec857de7c8e02563b38f1338e621a3304c2ef418f5451e1e1aa26f5727e7682");

    // Headers A and AA should be accepted
    {
        BlockValidationState state;
        BOOST_CHECK(m_node.chainman->ProcessNewBlockHeaders(
            {headerA}, true, state, &pindex, test_checkpoints));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
    }

    {
        BlockValidationState state;
        BOOST_CHECK(m_node.chainman->ProcessNewBlockHeaders(
            {headerAA}, true, state, &pindex, test_checkpoints));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
    }

    // Header B should be rejected
    {
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(
            {headerB}, true, state, &pindex, test_checkpoints));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectReason() == "bad-fork-prior-to-checkpoint");
        BOOST_CHECK(pindex == nullptr);
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->m_blockman.LookupBlockIndex(
                        headerB.GetHash()) == nullptr);
    }

    // Header AB should be rejected
    {
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(
            {headerAB}, true, state, &pindex, test_checkpoints));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectReason() == "checkpoint mismatch");
        BOOST_CHECK(pindex == nullptr);
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(m_node.chainman->m_blockman.LookupBlockIndex(
                        headerAB.GetHash()) == nullptr);
    }
}

BOOST_AUTO_TEST_SUITE_END()
