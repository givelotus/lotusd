// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresses/xaddress.h>
#include <blockdb.h>
#include <cashaddrenc.h> // For DecodeCashAddrContent
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <miner.h>
#include <minerfund.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <script/standard.h>
#include <uint256.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <random>
#include <string>

#include <minerfund.h>
#include <util/strencodings.h>

BOOST_FIXTURE_TEST_SUITE(minerfund_tests, TestChain100Setup)

static void TestOutputsInSet(
    const std::vector<CTxOut> &outputs,
    const std::vector<CTxOut> &coinbaseOutputs,
    std::vector<std::vector<CTxDestination>> &allowedDestinationSets) {
    std::vector<CTxDestination> emptySet;
    // Check random funding address outputs
    auto outputsIt = outputs.begin();
    auto coinbaseOutsIt = coinbaseOutputs.begin() + 2;
    for (size_t idx = 0; idx < 12; idx++) {
        const auto &allowedSet = allowedDestinationSets[idx];
        BOOST_CHECK_MESSAGE(outputsIt->scriptPubKey ==
                                coinbaseOutsIt->scriptPubKey,
                            "Mismatched scriptPubKey on coinbase");
        BOOST_CHECK_MESSAGE(outputsIt->nValue == coinbaseOutsIt->nValue,
                            "Mismatched coinbase value of output");

        CTxDestination dest;
        ExtractDestination(outputsIt->scriptPubKey, dest);

        const auto foundTx =
            std::find_if(allowedSet.begin(), allowedSet.end(),
                         [dest](const auto &a) -> bool { return dest == a; });
        BOOST_CHECK_MESSAGE(
            foundTx != allowedSet.end(),
            "Infrastructure coinbase payout not found in allowable set");

        // Check that we're ensuring destinations match
        const auto isInEmptySet =
            std::find_if(emptySet.begin(), emptySet.end(),
                         [dest](const auto &a) -> bool { return dest == a; });
        BOOST_CHECK_MESSAGE(isInEmptySet == emptySet.end(),
                            "CTxDestination operator equality failing");
        outputsIt++;
        coinbaseOutsIt++;
    }
}

static size_t CompareOutputs(const std::vector<CTxOut> &outputsA,
                             const std::vector<CTxOut> &outputsB) {
    std::vector<CTxDestination> emptySet;
    // Check random funding address outputs only
    auto outputsAIt = outputsA.begin() + 2;
    auto outputsBIt = outputsB.begin() + 2;
    BOOST_CHECK_MESSAGE(outputsA.size() == outputsB.size(),
                        "Mismatched coinbase output count");
    size_t matches = 0;
    for (size_t idx = 2; idx < outputsA.size(); idx++) {
        BOOST_CHECK_MESSAGE(outputsAIt->nValue == outputsBIt->nValue,
                            "Mismatched coinbase value of output");
        matches += outputsAIt->scriptPubKey != outputsBIt->scriptPubKey;
        outputsAIt++;
        outputsBIt++;
    }
    return matches < outputsA.size() - 2;
}

BOOST_AUTO_TEST_CASE(test_outputs) {
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    // Don't check this functionality in this test.
    config.SetEnableMinerFund(true);
    const CChainParams &chainparams = config.GetChainParams();
    // We mine some blocks, thus we need some basic setup.
    BlockAssembler::Options options;
    options.blockMinFeeRate = CFeeRate(1000 * SATOSHI, 1000);
    options.enableMinerFund = config.EnableMinerFund();
    auto testAssembler = BlockAssembler(chainparams, *m_node.mempool, options);

    const auto &consensus = chainparams.GetConsensus();
    // Simple consensus transaction.
    CScript scriptPubKey = CScript() << OP_RETURN;
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    fCheckpointsEnabled = false;

    const auto mainNetParams = CreateChainParams(CBaseChainParams::MAIN);

    // Normalize addresses for search purposes
    std::vector<std::vector<CTxDestination>> payoutAddressDestinations;
    for (const auto &addressSet : consensus.payoutAddressSets) {
        payoutAddressDestinations.emplace_back(std::vector<CTxDestination>());
        for (const auto &address : addressSet) {
            auto dest = DecodeDestination(address, *mainNetParams);
            if(!IsValidDestination(dest)) {
            // Try the ecash cashaddr prefix.
                dest = DecodeCashAddrDestination(DecodeCashAddrContent(address, "bitcoincash"));
            }
            payoutAddressDestinations.back().emplace_back(dest);
        }
    }

    // At least two blocks should have different epochs
    size_t differentBlocks = 0;
    for (size_t i = 0; i < 5002; i++) {
        // Simple block creation
        BOOST_CHECK(pblocktemplate =
                        testAssembler.CreateNewBlock(scriptPubKey));
        CBlock *pblock = &pblocktemplate->block;
        const auto &coinbaseOutputs = pblock->vtx[0]->vout;
        const auto pPrev = ::ChainActive().Tip();
        const auto pPrevPrev = pPrev->pprev;

        // Output hashes are based on previous block's epoch.
        if (pPrev->hashEpochBlock != pPrevPrev->hashEpochBlock) {
            differentBlocks++;
            CBlock block;
            ReadBlockFromDisk(block, pPrev,
                              config.GetChainParams().GetConsensus());

            const auto commonOutputs =
                CompareOutputs(block.vtx[0]->vout, coinbaseOutputs);
            BOOST_CHECK_MESSAGE(
                commonOutputs < 5,
                "Coinbase outputs matched when they should not have: "
                    << commonOutputs);
        }
        const auto subsidy =
            GetBlockSubsidy(::ChainActive().Tip()->nBits, consensus);
        const auto outputs = GetMinerFundRequiredOutputs(
            consensus, true, ::ChainActive().Tip(), subsidy);
        // outputs + 2 for OP_RETURN for block height unique hash, and
        // coinbase output
        BOOST_CHECK_MESSAGE(outputs.size() + 2 == coinbaseOutputs.size(),
                            "Mismatch coinbase size");

        // OP_RETURN Commitment, Miner payout, and funding set
        BOOST_CHECK_EQUAL(coinbaseOutputs.size(), 15);

        // Check random funding address outputs
        TestOutputsInSet(outputs, coinbaseOutputs, payoutAddressDestinations);

        // Update block so it can be connected, and the epoch will update
        // through this test.
        UpdateTime(pblock, chainparams, ::ChainActive().Tip());
        pblock->nNonce = 0;
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        const Consensus::Params &params =
            config.GetChainParams().GetConsensus();
        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, params)) {
            ++pblock->nNonce;
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);

        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlock(config, shared_pblock, true, nullptr));
    }

    BOOST_CHECK_MESSAGE(differentBlocks > 0,
                        "Should have passed through an epoch");
}

double TestVariance(size_t epochs, std::map<uint256, size_t> &histogram) {
    double variance = 0;
    double expectation = epochs / histogram.size();
    for (const auto &match : histogram) {
        // std::cout << match.first << " : " << match.second << std::endl;
        variance += (match.second - expectation) * (match.second - expectation);
    }
    variance *= histogram.size();
    variance /= epochs;
    // std::cout << variance << std::endl;

    return variance;
}

bool TestRandomEpochHashes(std::vector<std::string> &addressList, size_t epochs,
                           double threshold) {
    std::map<uint256, size_t> histogram;
    // Different epochs produce different results.
    for (size_t i = 0; i < epochs; i++) {
        const auto fakeEpochHash = InsecureRand256();
        const CTxOut output =
            BuildRandomOutput(addressList, 1, 260 * LOTUS, fakeEpochHash);
        const auto scriptPubKeyBytes = Hash(ToByteVector(output.scriptPubKey));
        histogram[scriptPubKeyBytes]++;
    }
    return TestVariance(epochs, histogram) > threshold;
}

bool TestRandomSlots(std::vector<std::string> &addressList, size_t epochs,
                     double threshold) {
    std::map<uint256, size_t> histogram;
    // Different epochs produce different results.
    for (size_t i = 0; i < epochs; i++) {
        const auto fakeEpochHash = InsecureRand256();
        const CTxOut output =
            BuildRandomOutput(addressList, 1, 260 * LOTUS, fakeEpochHash);
        const auto scriptPubKeyBytes = Hash(ToByteVector(output.scriptPubKey));
        histogram[scriptPubKeyBytes]++;
    }
    return TestVariance(epochs, histogram) > threshold;
}

BOOST_AUTO_TEST_CASE(test_randomness) {
    std::random_device rd;
    const auto mainNetParams = *CreateChainParams(CBaseChainParams::MAIN);
    auto gen = [&rd]() { return uint8_t(rd()); };

    // Using 52 epochs for a year to compare hits
    // The threshold should fail once out of every 1000 tests for these
    // parameters.
    // Degrees of freedom tested
    size_t df = 9;
    // Test is independent of number of samples. Minimized for speed.
    const size_t totalEpochsToCheck = 52;
    const size_t trials = 1000;
    const double criticalThreshold = 27.877;
    const uint32_t maxFailures = 2 * trials / 1000;
    // Generate some addresses
    std::vector<std::string> addressList;
    for (size_t i = 0; i < df + 1; i++) {
        std::vector<uint8_t> fakeKeyBytes(32);
        std::generate(begin(fakeKeyBytes), end(fakeKeyBytes), gen);
        const CTxDestination dest = PKHash(Hash160(fakeKeyBytes));
        addressList.emplace_back(EncodeDestination(dest, mainNetParams));
    }

    uint32_t failures = 0;
    for (size_t i = 0; i < trials; i++) {
        failures += TestRandomEpochHashes(addressList, totalEpochsToCheck,
                                          criticalThreshold);
    }
    BOOST_CHECK_MESSAGE(failures <= maxFailures,
                        "Uniformity test failed too many times: " << failures);

    failures = 0;
    for (size_t i = 0; i < trials; i++) {
        failures +=
            TestRandomSlots(addressList, totalEpochsToCheck, criticalThreshold);
    }
    BOOST_CHECK_MESSAGE(failures <= maxFailures,
                        "Uniformity test failed too many times: " << failures);
}

BOOST_AUTO_TEST_SUITE_END()
