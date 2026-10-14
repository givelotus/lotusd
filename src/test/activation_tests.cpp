// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <util/time.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

static void SetMTP(std::array<CBlockIndex, 12> &blocks, int64_t mtp) {
    size_t len = blocks.size();

    for (size_t i = 0; i < len; ++i) {
        blocks[i].nTime = mtp + (i - (len / 2));
    }

    BOOST_CHECK_EQUAL(blocks.back().GetMedianTimePast(), mtp);
}

BOOST_AUTO_TEST_CASE(isexodusenabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-exodusactivationtime", params.exodusActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsExodusEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsExodusEnabled(params, &blocks.back()));
}

BOOST_AUTO_TEST_CASE(is_leviticus_enabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-leviticusactivationtime", params.leviticusActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsLeviticusEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsLeviticusEnabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsLeviticusEnabled(params, &blocks.back()));
}

BOOST_AUTO_TEST_CASE(is_numbers_enabled) {
    const Consensus::Params &params = Params().GetConsensus();
    const auto activation =
        gArgs.GetIntArg("-numbersactivationtime", params.numbersActivationTime);
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsNumbersEnabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsNumbersEnabled(params, &blocks.back()));
    BOOST_CHECK_EQUAL(
        IsNumbersEnabled(params, &blocks.back()),
        IsNumbersEnabled(params, blocks.back().GetMedianTimePast()));
}

BOOST_AUTO_TEST_SUITE_END()
