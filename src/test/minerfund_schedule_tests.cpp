// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <blockindex.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(minerfund_schedule_tests, BasicTestingSetup)

// The miner fund output required on mainnet around the 2026-12-21 network
// upgrade (2nd Kings), with no activation-time overrides.
BOOST_AUTO_TEST_CASE(minerfund_second_kings_schedule) {
    const ArgsManager unused_argsman{};
    const auto mainNetParams =
        CreateChainParams(unused_argsman, ChainType::MAIN);
    const Consensus::Params &consensus = mainNetParams->GetConsensus();
    const Amount reward = 260 * COIN;

    // P2PKH scripts of the 1st Kings and 2nd Kings miner fund addresses.
    const CScript firstKings = CScript() << OP_DUP << OP_HASH160
        << ParseHex("f25618088e97b0ebfddfa9d6a528f09dc6430542")
        << OP_EQUALVERIFY << OP_CHECKSIG;
    const CScript secondKings = CScript() << OP_DUP << OP_HASH160
        << ParseHex("d03a7e6b979b705c931d137762582b27b10f442c")
        << OP_EQUALVERIFY << OP_CHECKSIG;

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = 1400000 + i;
    }
    auto RequiredAt = [&](int64_t mtp) {
        for (size_t i = 0; i < blocks.size(); ++i) {
            blocks[i].nTime = mtp + (int64_t(i) - int64_t(blocks.size() / 2));
        }
        BOOST_REQUIRE_EQUAL(blocks.back().GetMedianTimePast(), mtp);
        return GetMinerFundRequiredOutputs(consensus, true, &blocks.back(),
                                           reward);
    };

    const int64_t activation = 1797886200; // 2026-12-21T20:50:00Z
    BOOST_CHECK_EQUAL(consensus.secondKingsActivationTime, activation);

    const std::vector<CTxOut> before = RequiredAt(activation - 1);
    BOOST_REQUIRE_EQUAL(before.size(), 1U);
    BOOST_CHECK(before[0].scriptPubKey == firstKings);
    BOOST_CHECK_EQUAL(before[0].nValue, reward / 2);

    // From the upgrade (and past the 1st Chronicles time, which schedules no
    // new addresses), the single 2nd Kings address receives half the reward.
    for (const int64_t mtp :
         {activation, activation + 1, int64_t(1813587000)}) {
        const std::vector<CTxOut> after = RequiredAt(mtp);
        BOOST_REQUIRE_EQUAL(after.size(), 1U);
        BOOST_CHECK(after[0].scriptPubKey == secondKings);
        BOOST_CHECK_EQUAL(after[0].nValue, reward / 2);
        BOOST_CHECK(CheckMinerFund(consensus, true, after, reward,
                                   &blocks.back()));
        BOOST_CHECK(!CheckMinerFund(consensus, true, before, reward,
                                    &blocks.back()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
