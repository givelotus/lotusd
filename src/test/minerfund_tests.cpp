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

static void
CheckPayoutOutputs(const std::vector<CTxOut> &outputs,
                   const std::vector<std::string> &expectedAddresses,
                   const Amount expectedAmount) {
    BOOST_CHECK_EQUAL(outputs.size(), expectedAddresses.size());
    const CChainParams mainNetParams =
        *CreateChainParams(CBaseChainParams::MAIN);
    for (size_t i = 0; i < outputs.size(); ++i) {
        const CTxOut &output = outputs[i];
        const std::string &expectedAddress = expectedAddresses[i];
        CTxDestination dst = DecodeDestination(expectedAddress, mainNetParams);
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
    GlobalConfig config;
    // Do check this functionality in this test.
    config.SetEnableMinerFund(true);
    const CChainParams &chainparams = config.GetChainParams();
    const Consensus::Params &consensus = chainparams.GetConsensus();
    // We mine some blocks, thus we need some basic setup.
    BlockAssembler::Options options;
    options.blockMinFeeRate = CFeeRate(1000 * SATOSHI, 1000);
    options.enableMinerFund = config.EnableMinerFund();
    BlockAssembler testAssembler(chainparams, *m_node.mempool, options);

    const int64_t activationTime =
        gArgs.GetArg("-exodusactivationtime", consensus.exodusActivationTime);

    if (::ChainActive().Tip()->GetMedianTimePast() > activationTime) {
        // This test doesn't work if -exodusactivationtime is in the past
        return;
    }

    // Simple consensus transaction.
    CScript scriptPubKey = CScript() << OP_RETURN;
    std::unique_ptr<CBlockTemplate> pblocktemplate;

    fCheckpointsEnabled = false;

    // Some block num where the activation occurrs
    size_t forkBlockNum = 50;

    for (size_t blockNum = 0; blockNum < 100; blockNum++) {
        // Simple block creation
        BOOST_CHECK(pblocktemplate =
                        testAssembler.CreateNewBlock(scriptPubKey));
        CBlock *pblock = &pblocktemplate->block;
        if (blockNum == forkBlockNum) {
            SetMockTime(activationTime);
            pblock->SetBlockTime(activationTime);
        }
        const std::vector<CTxOut> &coinbaseOutputs = pblock->vtx[0]->vout;
        const CBlockIndex *pPrev = ::ChainActive().Tip();

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
        // New addresses activate 6 blocks after the block time got bumped (MTP)
        if (blockNum < forkBlockNum + 6) {
            CheckPayoutOutputs(outputs,
                               consensus.coinbasePayoutAddresses.genesis,
                               subsidy / 26);
        } else {
            CheckPayoutOutputs(outputs,
                               consensus.coinbasePayoutAddresses.exodus,
                               subsidy / 26);
        }

        // Update block so it can be connected, and the epoch will update
        // through this test.
        UpdateTime(pblock, chainparams, pPrev);
        pblock->nNonce = 0;
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, consensus)) {
            ++pblock->nNonce;
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);

        BOOST_CHECK(
            Assert(m_node.chainman)
                ->ProcessNewBlock(config, shared_pblock, true, nullptr));
    }
}

BOOST_AUTO_TEST_SUITE_END()
