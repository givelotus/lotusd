// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/tx_verify.h>
#include <coins.h>
#include <consensus/validation.h>
#include <chain.h>
#include <validation.h>
#include <config.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <timedata.h>

#include <test/util/mining.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(v2_finality_tests, BasicTestingSetup)

namespace {
/** A v7 spend of one coin with the given V2 lock and input sequence. */
CTransaction V7WithLock(uint64_t lock, uint32_t sequence) {
    lotus::v2::Transaction tx;
    tx.lock = lock;
    lotus::v2::Input in;
    in.prev_txid.fill(0x11);
    in.prev_index = 0;
    in.sequence = sequence;
    in.flags = 1;
    in.witnesses.push_back({{0x4e}, {}, {}});
    tx.inputs.push_back(in);
    lotus::v2::Output out;
    out.value = 1000;
    out.branches.push_back(lotus::v2::Hash32{});
    out.branches[0].fill(0x33);
    out.paths.push_back({0});
    tx.outputs.push_back(out);
    return CTransaction(CMutableTransaction::FromV2Transaction(tx));
}

} // namespace

// A v7 input sequence is a BIP68 relative lock, which ConnectBlock enforces.
// The mempool must compute the same lock points instead of assuming final
// sequences, or it accepts a transaction no block may contain.
BOOST_AUTO_TEST_CASE(v7_relative_lock_points_at_tip) {
    constexpr int COIN_HEIGHT = 50;
    constexpr uint32_t DELAY = 10;
    const CTransaction tx = V7WithLock(0, DELAY);

    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(tx.vin[0].prevout,
                 Coin(CTxOut(1000 * SATOSHI, CScript() << OP_TRUE),
                      COIN_HEIGHT, false),
                 false);

    for (const int tip_height : {COIN_HEIGHT + 5, COIN_HEIGHT + int(DELAY)}) {
        CBlockIndex tip;
        tip.nHeight = tip_height;
        const auto lock_points = CalculateLockPointsAtTip(&tip, view, tx);
        BOOST_REQUIRE(lock_points.has_value());
        BOOST_CHECK_EQUAL(lock_points->height,
                          COIN_HEIGHT + int(DELAY) - 1);
        // The next block (tip + 1) may hold the spend once DELAY blocks
        // have passed since the coin's block.
        BOOST_CHECK_EQUAL(CheckSequenceLocksAtTip(&tip, *lock_points),
                          tip_height + 1 >= COIN_HEIGHT + int(DELAY));
    }
}

namespace {
struct TestNetSetup : public TestingSetup {
    TestNetSetup() : TestingSetup(ChainType::TESTNET) {}
};
struct RegTestSetup : public TestingSetup {
    RegTestSetup() : TestingSetup(ChainType::REGTEST) {}
};

std::string ValidateWithStateRoot(node::NodeContext &node, bool null_root) {
    std::shared_ptr<CBlock> block =
        PrepareBlock(GetConfig(), node, CScript() << OP_TRUE);
    if (null_root) block->hashStateRoot.SetNull();
    LOCK(cs_main);
    Chainstate &chainstate = node.chainman->ActiveChainstate();
    BlockValidationState state;
    const bool ok = TestBlockValidity(
        state, GetConfig().GetChainParams(), chainstate, *block,
        node.chainman->ActiveTip(), GetAdjustedTime,
        BlockValidationOptions(GetConfig()).withCheckPoW(false));
    return ok ? "valid" : state.GetRejectReason();
}
} // namespace

// Only regtest may skip the state root check for a null root (blocks built by
// the functional test framework). Testnet, which shares regtest's
// min-difficulty rule, must check it like mainnet.
BOOST_FIXTURE_TEST_CASE(null_state_root_rejected_on_testnet, TestNetSetup) {
    BOOST_CHECK_EQUAL(ValidateWithStateRoot(m_node, false), "valid");
    BOOST_CHECK_EQUAL(ValidateWithStateRoot(m_node, true),
                      "bad-blk-stateroot");
}

BOOST_FIXTURE_TEST_CASE(null_state_root_accepted_on_regtest, RegTestSetup) {
    BOOST_CHECK_EQUAL(ValidateWithStateRoot(m_node, true), "valid");
}

BOOST_AUTO_TEST_SUITE_END()
