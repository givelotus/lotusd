// Copyright (c) 2021 The Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <minerfund.h>

#include <addresses/xaddress.h>
#include <cashaddrenc.h> // For DecodeCashAddrContent
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <key_io.h>
#include <node/blockfitter.h>
#include <node/miner.h>
#include <pow/pow.h>
#include <script/standard.h>
#include <timedata.h>
#include <util/chaintype.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

using node::BlockAssembler;
using node::BlockFitter;
using node::CBlockTemplate;
using node::UpdateTime;

BOOST_FIXTURE_TEST_SUITE(minerfund_tests, TestChain100Setup)

static void
CheckMinerfundOutputs(const std::vector<CTxOut> &outputs,
                      const std::vector<std::string> &expectedAddresses,
                      const Amount expectedAmount) {
    BOOST_CHECK_EQUAL(outputs.size(), expectedAddresses.size());
    const ArgsManager unused_argsman{};
    const auto mainNetParams =
        CreateChainParams(unused_argsman, ChainType::MAIN);
    for (size_t i = 0; i < outputs.size(); ++i) {
        const CTxOut &output = outputs[i];
        const std::string &expectedAddress = expectedAddresses[i];
        CTxDestination dst = DecodeDestination(expectedAddress, *mainNetParams);
        if (!IsValidDestination(dst)) {
            // Try the bitcoincash cashaddr prefix.
            dst = DecodeCashAddrDestination(
                DecodeCashAddrContent(expectedAddress, "bitcoincash"));
        }
        const CScript expectedScript = GetScriptForDestination(dst);
        BOOST_CHECK(output.scriptPubKey == expectedScript);
        BOOST_CHECK_EQUAL(output.nValue, expectedAmount);
    }
}

BOOST_AUTO_TEST_CASE(test_minerfund_required_outputs) {
    // Note that by default, these tests run with size accounting enabled.
    Config &config = const_cast<Config &>(GetConfig());
    // Do check this functionality in this test.
    config.SetEnableMinerFund(true);
    const CChainParams &chainparams = config.GetChainParams();
    const Consensus::Params &consensus = chainparams.GetConsensus();
    // We mine some blocks, thus we need some basic setup.
    BlockFitter::Options fitter_options;
    fitter_options.blockMinFeeRate = CFeeRate(1000 * SATOSHI, 1000);
    BlockAssembler::Options assembler_options;
    assembler_options.enableMinerFund = config.EnableMinerFund();
    BlockAssembler testAssembler{
        BlockFitter(fitter_options), m_node.chainman->ActiveChainstate(),
        m_node.mempool.get(), assembler_options};

    // Simple consensus transaction.
    CScript scriptPubKey = CScript() << OP_RETURN;
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    for (size_t i = 0; i < 100; i++) {
        // Simple block creation
        BOOST_CHECK(pblocktemplate =
                        testAssembler.CreateNewBlock(scriptPubKey));
        CBlock *pblock = &pblocktemplate->block;
        const std::vector<CTxOut> &coinbaseOutputs = pblock->vtx[0]->vout;
        const CBlockIndex *pPrev =
            WITH_LOCK(cs_main, return m_node.chainman->ActiveTip());

        const Amount subsidy = GetBlockSubsidy(pPrev->nBits, consensus);
        const std::vector<CTxOut> outputs =
            GetMinerFundRequiredOutputs(consensus, true, pPrev, subsidy);
        // outputs + 2 for OP_RETURN for block height unique hash, and
        // coinbase output
        BOOST_CHECK_MESSAGE(outputs.size() + 2 == coinbaseOutputs.size(),
                            "Mismatch coinbase size");

        // OP_RETURN Commitment, Miner payout, and funding set
        BOOST_CHECK_EQUAL(coinbaseOutputs.size(), 15);

        // Check funding address outputs
        CheckMinerfundOutputs(
            outputs, consensus.coinbasePayoutAddresses.genesis, subsidy / 26);

        // Update block so it can be connected, and the epoch will update
        // through this test.
        UpdateTime(pblock, chainparams, pPrev,
                   TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()));
        pblock->nNonce = 0;
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, consensus)) {
            ++pblock->nNonce;
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);

        BOOST_CHECK(Assert(m_node.chainman)
                        ->ProcessNewBlock(shared_pblock, true, true, nullptr));
    }
}

BOOST_AUTO_TEST_SUITE_END()
