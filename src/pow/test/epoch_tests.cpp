// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/activation.h>
#include <pow/pow.h>
#include <primitives/blockhash.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(epoch_tests, BasicTestingSetup)

static void SetMTP(std::array<CBlockIndex, 12> &blocks, int64_t mtp) {
    size_t len = blocks.size();

    for (size_t i = 0; i < len; ++i) {
        blocks[i].nTime = mtp + (i - (len / 2));
    }

    BOOST_CHECK_EQUAL(blocks.back().GetMedianTimePast(), mtp);
}

static BlockHash BKH(std::string str) {
    return BlockHash(uint256S(str));
}

BOOST_AUTO_TEST_CASE(epoch_test) {
    DummyConfig regConfig(CBaseChainParams::REGTEST);
    const Consensus::Params &regParams =
        regConfig.GetChainParams().GetConsensus();
    // epoch hash for regtest min PoW
    BOOST_CHECK(!CheckProofOfWork(
        BKH("7fffff0000000000000000000000000000000000000000000000000000000001"),
        0x207fffff, regParams));
    BOOST_CHECK(CheckProofOfWork(
        BKH("7fffff0000000000000000000000000000000000000000000000000000000000"),
        0x207fffff, regParams));
    BOOST_CHECK(!IsEpochBlockHash(
        BKH("0006806700000000000000000000000000000000000000000000000000000001"),
        0x207fffff));
    BOOST_CHECK(IsEpochBlockHash(
        BKH("0006806700000000000000000000000000000000000000000000000000000000"),
        0x207fffff));

    DummyConfig mainConfig(CBaseChainParams::MAIN);
    const Consensus::Params &mainParams =
        mainConfig.GetChainParams().GetConsensus();
    // epoch hash for mainnet min pow
    BOOST_CHECK(!CheckProofOfWork(
        BKH("0000000010000000000000000000000000000000000000000000000000000001"),
        0x1c100000, mainParams));
    BOOST_CHECK(CheckProofOfWork(
        BKH("0000000010000000000000000000000000000000000000000000000000000000"),
        0x1c100000, mainParams));
    BOOST_CHECK(!IsEpochBlockHash(
        BKH("000000000000d00d000000000000000000000000000000000000000000000001"),
        0x1c100000));
    BOOST_CHECK(IsEpochBlockHash(
        BKH("000000000000d00d000000000000000000000000000000000000000000000000"),
        0x1c100000));
    // epoch hash for bits 0x1c013b00
    BOOST_CHECK(!CheckProofOfWork(
        BKH("00000000013b0000000000000000000000000000000000000000000000000001"),
        0x1c013b00, mainParams));
    BOOST_CHECK(CheckProofOfWork(
        BKH("00000000013b0000000000000000000000000000000000000000000000000000"),
        0x1c013b00, mainParams));
    BOOST_CHECK(!IsEpochBlockHash(
        BKH("0000000000001000000000000000000000000000000000000000000000000001"),
        0x1c013b00));
    BOOST_CHECK(IsEpochBlockHash(
        BKH("0000000000001000000000000000000000000000000000000000000000000000"),
        0x1c013b00));
}

BOOST_AUTO_TEST_CASE(get_next_epoch_block_hash_test) {
    DummyConfig config(CBaseChainParams::MAIN);
    const Consensus::Params &params = config.GetChainParams().GetConsensus();
    // Check activation
    std::array<CBlockIndex, 12> blocks;
    CBlockIndex *pindex = &blocks.back();
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    const BlockHash prevBlockHash =
        BKH("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    const BlockHash prevEpochHash =
        BKH("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const BlockHash aboveEpochHash =
        BKH("0000000000001000000000000000000000000000000000000000000000000001");
    const BlockHash enoughEpochHash =
        BKH("0000000000001000000000000000000000000000000000000000000000000000");
    pindex->hashEpochBlock = prevEpochHash;
    pindex->pprev->phashBlock = &prevBlockHash;
    const auto activation = gArgs.GetArg("-leviticusactivationtime",
                                         params.leviticusActivationTime);

    // before activation
    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsLeviticusEnabled(params, pindex));
    CBlockHeader header;
    pindex->nBits = 0x1c013b00;

    // old system: before block 5040, lucky hash ignored
    pindex->phashBlock = &enoughEpochHash;
    pindex->nHeight = 5038; // next block is 5039
    BOOST_CHECK(!IsEpochBlock(params, pindex));
    BOOST_CHECK_EQUAL(prevEpochHash, GetNextEpochBlockHash(params, pindex));

    // old system: after block 5040, unlucky hash ignored
    pindex->nHeight = 5039; // next block is 5040
    BOOST_CHECK(IsEpochBlock(params, pindex));
    pindex->phashBlock = &aboveEpochHash;
    BOOST_CHECK_EQUAL(aboveEpochHash, GetNextEpochBlockHash(params, pindex));

    // after activation
    SetMTP(blocks, activation);
    BOOST_CHECK(IsExodusEnabled(params, pindex));

    // new system: before block 5040, hash not sufficient for new epoch
    pindex->phashBlock = &aboveEpochHash;
    pindex->nHeight = 5038; // next block is 5039 (but: ignored)
    BOOST_CHECK(!IsEpochBlock(params, pindex));
    BOOST_CHECK_EQUAL(prevEpochHash, GetNextEpochBlockHash(params, pindex));

    // new system: after block 5040, hash still not sufficient for new epoch
    pindex->nHeight = 5039; // next block is 5040 (but: ignored)
    BOOST_CHECK(!IsEpochBlock(params, pindex));
    BOOST_CHECK_EQUAL(prevEpochHash, GetNextEpochBlockHash(params, pindex));

    // new system: before block 5040, prev hash sufficient for new epoch
    pindex->phashBlock = &enoughEpochHash;
    pindex->nHeight = 5038; // next block is 5039 (but: ignored)
    BOOST_CHECK(IsEpochBlock(params, pindex));
    BOOST_CHECK_EQUAL(enoughEpochHash, GetNextEpochBlockHash(params, pindex));

    // new system: after block 5040, prev hash sufficient for new epoch
    pindex->phashBlock = &enoughEpochHash;
    pindex->nHeight = 5039; // next block is 5040 (but: ignored)
    BOOST_CHECK(IsEpochBlock(params, pindex));
    BOOST_CHECK_EQUAL(enoughEpochHash, GetNextEpochBlockHash(params, pindex));
}

BOOST_AUTO_TEST_SUITE_END()
