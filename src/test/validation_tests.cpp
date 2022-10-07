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
#include <test/lcg.h>
#include <util/system.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

// Whether to check all possible nBits in the block subsidy test (takes ~20s)
#define IS_CHECK_SUBSIDY_EXHAUSTIVE 0

static double ApproxTarget(const uint32_t nBits) {
    const uint32_t exp = nBits >> 24;
    double factor = exp > 3 ? pow(256, exp - 3) : 1.0 / pow(256, 3 - exp);
    return (nBits & 0xff'ff'ff) * factor;
}

static void TestBlockSubsidyLogarithmic(const Consensus::Params &params) {
    const std::vector<std::pair<uint32_t, Amount>> test_cases = {
        {0x1c100000, 1 * SUBSIDY},
        {0x1c0fffff, 1 * SUBSIDY + 359 * SATOSHI},
        {0x1c080000, 2 * SUBSIDY},
        {0x1c07ffff, 2 * SUBSIDY + 717 * SATOSHI},
        {0x1c040000, 3 * SUBSIDY},
        {0x1c03ffff, 3 * SUBSIDY + 1432 * SATOSHI},
        {0x1c020000, 4 * SUBSIDY},
        {0x1c01ffff, 4 * SUBSIDY + 2864 * SATOSHI},
        {0x1c010000, 5 * SUBSIDY},
        {0x1c00ffff, 5 * SUBSIDY + 5725 * SATOSHI},
        {0x1c008000, 6 * SUBSIDY},
        {0x1b7fffff, 6 * SUBSIDY + 47 * SATOSHI},
        {0x1b400000, 7 * SUBSIDY},
        {0x1b3fffff, 7 * SUBSIDY + 92 * SATOSHI},
        {0x1b200000, 8 * SUBSIDY},
        {0x1b1fffff, 8 * SUBSIDY + 181 * SATOSHI},
        {0x1b100000, 9 * SUBSIDY},
        {0x1b0fffff, 9 * SUBSIDY + 359 * SATOSHI},
        {0x1b080000, 10 * SUBSIDY},
        {0x1b07ffff, 10 * SUBSIDY + 717 * SATOSHI},
        {0x1b040000, 11 * SUBSIDY},
        {0x1b03ffff, 11 * SUBSIDY + 1432 * SATOSHI},
        {0x1b020000, 12 * SUBSIDY},
        {0x1b01ffff, 12 * SUBSIDY + 2864 * SATOSHI},
        {0x1b010000, 13 * SUBSIDY},
        {0x1b00ffff, 13 * SUBSIDY + 5725 * SATOSHI},
        {0x1b008000, 14 * SUBSIDY},
        {0x1a7fffff, 14 * SUBSIDY + 47 * SATOSHI},
        {0x1a400000, 15 * SUBSIDY},
        {0x1a3fffff, 15 * SUBSIDY + 92 * SATOSHI},
        {0x1a200000, 16 * SUBSIDY},
        {0x18200000, 32 * SUBSIDY},
        {0x14200000, 64 * SUBSIDY},
        {0x0c200000, 128 * SUBSIDY},
        {0x01010000, 221 * SUBSIDY}, // Max possible difficulty
        {0x1b04864c, int64_t(2'813'774'771) * SATOSHI},  // block 100000 on BTC
        {0x1a05db8b, int64_t(4'796'920'144) * SATOSHI},  // block 200000 on BTC
        {0x1900896c, int64_t(7'773'358'358) * SATOSHI},  // block 300000 on BTC
        {0x1806b99f, int64_t(8'905'116'497) * SATOSHI},  // block 400000 on BTC
        {0x18009645, int64_t(9'819'833'738) * SATOSHI},  // block 500000 on BTC
        {0x1715a35c, int64_t(10'546'769'112) * SATOSHI}, // block 600000 on BTC
        {0x170bef93, int64_t(10'769'920'772) * SATOSHI}, // block 680603 on BTC
        {0x1000ffff, int64_t(26'260'005'725) * SATOSHI},
        {0x0500ffff, int64_t(49'140'005'725) * SATOSHI},
        {0x0300ffff, int64_t(53'300'005'725) * SATOSHI},
        {0x1c100001, 1 * SUBSIDY}, // for testnet
        {0x1d00ffff, 1 * SUBSIDY}, // for testnet
    };
    for (const auto &pair : test_cases) {
        const Amount subsidy = GetBlockSubsidy(pair.first, params);
        BOOST_CHECK_MESSAGE(pair.second == subsidy,
                            "Subsidy test failed: "
                                << std::dec << pair.second << " != " << subsidy
                                << " for 0x" << std::hex << pair.first);
    }
#if IS_CHECK_SUBSIDY_EXHAUSTIVE
    std::vector<uint32_t> test_mantissa_cases(257); // +1 for the rng one
    std::iota(test_mantissa_cases.begin(), test_mantissa_cases.end() - 1, 0);
#else
    std::vector<uint32_t> test_mantissa_cases = {0x00, 0x01, 0x80,
                                                 0xfe, 0xff, 0};
#endif
    MMIXLinearCongruentialGenerator lcg;
    // check nBits exhaustively
    for (uint32_t exp = 0x1c; exp >= 0x01; --exp) {
        double max_rel_error = 0;
        uint32_t max_rel_error_nBits;
        double max_abs_error = 0;
        uint32_t max_abs_error_nBits;
        for (uint32_t mantissa_upper = 0x7f'ff00; mantissa_upper >= 0x8000;
             mantissa_upper -= 0x100) {
            test_mantissa_cases.back() = lcg.next() & 0xff; // last is random
            for (uint32_t mantissa_lower : test_mantissa_cases) {
                uint32_t mantissa = mantissa_upper | mantissa_lower;
                if (exp == 0x1c && mantissa > 0x100000) {
                    continue;
                }
                if (exp == 0x01 && mantissa < 0x10000) {
                    continue;
                }
                uint32_t nBits = (exp << 24) | mantissa;
                double approx_target = ApproxTarget(nBits);
                double approx_max_target = ApproxTarget(0x1c100000);
                double approx_log_difficulty =
                    log2(approx_max_target) - log2(approx_target);
                double approx_subsidy =
                    (SUBSIDY / SATOSHI) * (approx_log_difficulty + 1);
                double actual_subsidy =
                    GetBlockSubsidy(nBits, params) / SATOSHI;
                double abs_error = abs(actual_subsidy - approx_subsidy);
                double rel_error = abs_error / approx_subsidy;
                if (abs_error > max_abs_error) {
                    max_abs_error = abs_error;
                    max_abs_error_nBits = nBits;
                }
                if (rel_error > max_rel_error) {
                    max_rel_error = rel_error;
                    max_rel_error_nBits = nBits;
                }
            }
        }
        constexpr double MAX_EXPECTED_ABS_ERROR = 5.39298629760743;
        BOOST_CHECK_MESSAGE(
            max_abs_error < MAX_EXPECTED_ABS_ERROR,
            strprintf("Subsidy approximation failed, absolute error too large: "
                      "%.16f >= %.16f, for nBits = %08x",
                      max_abs_error, MAX_EXPECTED_ABS_ERROR,
                      max_abs_error_nBits));
        constexpr double MAX_EXPECTED_REL_ERROR = 0.00000001573502;
        BOOST_CHECK_MESSAGE(
            max_rel_error < MAX_EXPECTED_REL_ERROR,
            strprintf("Subsidy approximation failed, relative error too large: "
                      "%.16f >= %.16f, for nBits = %08x",
                      max_rel_error, MAX_EXPECTED_REL_ERROR,
                      max_rel_error_nBits));
    }
}

/**
 * Make sure the block subsidy is constant.
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

BOOST_AUTO_TEST_CASE(block_subsidy_test) {
    TestBlockSubsidyLogarithmic(
        CreateChainParams(CBaseChainParams::MAIN)->GetConsensus());
    TestBlockSubsidyLogarithmic(
        CreateChainParams(CBaseChainParams::TESTNET)->GetConsensus());
    TestBlockSubsidyConstant(
        CreateChainParams(CBaseChainParams::REGTEST)->GetConsensus());
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

    FILE *fp = fopen(fs::PathToString(tmpfile_name).c_str(), "wb+");

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
