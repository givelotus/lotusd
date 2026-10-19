// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_TEST_UTIL_NATIVE_SNAPSHOT_SETUP_H
#define BITCOIN_TEST_UTIL_NATIVE_SNAPSHOT_SETUP_H

#include <config.h>
#include <lotus_v2/commitment.h>
#include <node/miner.h>
#include <pow/pow.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <boost/test/unit_test.hpp>

// RPC lock/coherence coverage needs spendable native coins, not legacy signing.
struct NativeSnapshotChainSetup : TestingSetup {
    const std::vector<uint8_t> program{0x4e}; // Lotus V2 OP_1.
    std::vector<CTransactionRef> m_coinbase_txns;

    NativeSnapshotChainSetup() : TestingSetup(ChainType::REGTEST) {
        SetMockTime(1598887952);
        const auto &config = GetConfig();
        const auto &consensus = config.GetChainParams().GetConsensus();
        lotus::v2::Output payout;
        payout.branches = {lotus::v2::BranchLeaf(program)};
        payout.paths = {{0}};
        const auto destination = CTxOut::FromV2Output(payout);
        for (int height = 1; height <= COINBASE_MATURITY; ++height) {
            auto block = node::BlockAssembler(
                             config, m_node.chainman->ActiveChainstate(), nullptr)
                             .CreateNewBlock(destination)->block;
            while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
                ++block.nNonce;
            }
            BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
                std::make_shared<const CBlock>(block), true, true, nullptr));
            BOOST_REQUIRE_EQUAL(
                WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->nHeight),
                height);
            m_coinbase_txns.push_back(block.vtx[0]);
            SetMockTime(GetTime() + 1);
        }
    }

    ~NativeSnapshotChainSetup() { SetMockTime(0); }

    CMutableTransaction CreateNativeMempoolTransaction(
        CTransactionRef previous, uint32_t index, Amount output_amount,
        const std::vector<uint8_t> &destination = {}) {
        CMutableTransaction tx;
        tx.nVersion = 7;
        tx.nV2Lock = 0;
        CTxIn input(COutPoint(previous->GetId(), index));
        input.nFlags = 1;
        input.nPathIndex = 0;
        lotus::v2::BranchWitness witness;
        witness.script = program;
        input.vWitnesses = {witness};
        tx.vin.push_back(std::move(input));
        const auto &output_program = destination.empty() ? program : destination;
        lotus::v2::Output output;
        output.value = static_cast<uint64_t>(output_amount / SATOSHI);
        output.branches = {lotus::v2::BranchLeaf(output_program)};
        output.paths = {{0}};
        tx.vout.push_back(CTxOut::FromV2Output(output));
        LOCK(cs_main);
        const auto accepted = m_node.chainman->ProcessTransaction(MakeTransactionRef(tx));
        BOOST_REQUIRE_MESSAGE(
            accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
            accepted.m_state.ToString());
        return tx;
    }
};

#endif // BITCOIN_TEST_UTIL_NATIVE_SNAPSHOT_SETUP_H
