// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <chainparams.h>
#include <clientversion.h>
#include <config.h>
#include <consensus/consensus.h>
#include <net.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <util/system.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdio>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

/**
 * Make sure the block subsidy is really constant.
 */
static void TestBlockSubsidyConstant(const Consensus::Params &consensusParams) {
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1d00ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1d008000, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1e7fffff, consensusParams));
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1c2a1115, consensusParams)); // block 50000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1b04864c, consensusParams)); // block 100000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1a05db8b, consensusParams)); // block 200000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1900896c, consensusParams)); // block 300000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1806b99f, consensusParams)); // block 400000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x18009645, consensusParams)); // block 500000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x1715a35c, consensusParams)); // block 600000 on BTC
    BOOST_CHECK_EQUAL(
        SUBSIDY,
        GetBlockSubsidy(0x170bef93, consensusParams)); // block 680603 on BTC
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x1000ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x0500ffff, consensusParams));
    BOOST_CHECK_EQUAL(SUBSIDY, GetBlockSubsidy(0x0300ffff, consensusParams));
}

static void TestBlockSubsidyConstant(int nSubsidyHalvingInterval) {
    Consensus::Params consensusParams;
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    TestBlockSubsidyConstant(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test) {
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    // As in main
    TestBlockSubsidyConstant(chainParams->GetConsensus());
    // As in regtest
    TestBlockSubsidyConstant(150);
    // Just another interval
    TestBlockSubsidyConstant(1000);
}

static CBlock makeLargeDummyBlock(const size_t num_tx) {
    CBlock block;
    block.vtx.reserve(num_tx);

    CTransaction tx;
    for (size_t i = 0; i < num_tx; i++) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

/**
 * Test that LoadExternalBlockFile works with the buffer size set below the
 * size of a large block. Currently, LoadExternalBlockFile has the buffer size
 * for CBufferedFile set to 2 * MAX_TX_SIZE. Test with a value of
 * 10 * MAX_TX_SIZE.
 */
BOOST_AUTO_TEST_CASE(validation_load_external_block_file) {
    fs::path tmpfile_name = GetDataDir() / "block.dat";

    FILE *fp = fopen(tmpfile_name.string().c_str(), "wb+");

    BOOST_CHECK(fp != nullptr);

    const Config &config = GetConfig();
    const CChainParams &chainparams = config.GetChainParams();

    // serialization format is:
    // message start magic, size of block, block

    size_t nwritten = fwrite(std::begin(chainparams.DiskMagic()),
                             CMessageHeader::MESSAGE_START_SIZE, 1, fp);

    BOOST_CHECK_EQUAL(nwritten, 1UL);

    CTransaction empty_tx;
    size_t empty_tx_size = GetSerializeSize(empty_tx, CLIENT_VERSION);

    size_t num_tx = (10 * MAX_TX_SIZE) / empty_tx_size;

    CBlock block = makeLargeDummyBlock(num_tx);

    BOOST_CHECK(GetSerializeSize(block, CLIENT_VERSION) > 2 * MAX_TX_SIZE);

    unsigned int size = GetSerializeSize(block, CLIENT_VERSION);
    {
        CAutoFile outs(fp, SER_DISK, CLIENT_VERSION);
        outs << size;
        outs << block;
        outs.release();
    }

    fseek(fp, 0, SEEK_SET);
    BOOST_CHECK_NO_THROW({ LoadExternalBlockFile(config, fp, 0); });
}

BOOST_AUTO_TEST_SUITE_END()
