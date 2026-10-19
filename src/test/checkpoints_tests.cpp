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
                                   "77d41bf0338150d1a01cfe7e6148a6d413d76c6"
                                   "cbcaf128a773a6693815739b8")}},
    };
    const CBlockIndex *pindex = nullptr;

    CBlockHeader headerG = Assert(m_node.chainman)->GetParams().GenesisBlock();
    BOOST_CHECK(headerG.GetHash() ==
                uint256S("720da0e6627eb824fb69ad12fd5162fd02ea91775c4a04e7561c99b7e50723e4"));

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
    BOOST_CHECK(headerA.GetHash() ==
                uint256S("3d1c1248e8bb735664cf223d0cf1ebd398e0854ef215cbdcb89b745a2a7d4fb0"));

    headerAA.nHeaderVersion = 2;
    headerAA.hashPrevBlock = headerA.GetHash();
    headerAA.nBits = headerA.nBits;
    headerAA.SetBlockTime(headerA.GetBlockTime() + 120);
    headerAA.nHeight = 2;
    headerAA.nNonce = 10000;
    BOOST_CHECK(headerAA.GetHash() ==
                uint256S("77d41bf0338150d1a01cfe7e6148a6d413d76c6cbcaf128a773a6693815739b8"));

    headerB.nHeaderVersion = 2;
    headerB.hashPrevBlock = headerG.GetHash();
    headerB.nBits = headerG.nBits;
    headerB.SetBlockTime(headerG.GetBlockTime() + 1);
    headerB.nHeight = 1;
    headerB.nNonce = 20001;
    BOOST_CHECK(headerB.GetHash() ==
                uint256S("7db2a4ce92ad8d70ddfbd8422430be84fc558543c1c95695089b9868ef7bc981"));

    headerAB.nHeaderVersion = 2;
    headerAB.hashPrevBlock = headerA.GetHash();
    headerAB.nBits = headerA.nBits;
    headerAB.SetBlockTime(headerG.GetBlockTime() + 2);
    headerAB.nHeight = 2;
    headerAB.nNonce = 20002;
    BOOST_CHECK(headerAB.GetHash() ==
                uint256S("688395c3bffed1925d633004bca2944518b59a8e1d5a3d82ba034f4eb3f104c1"));

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
