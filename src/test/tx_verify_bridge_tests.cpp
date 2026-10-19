// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Legacy (version 1 and 2) transactions on the V2 chain: they spend and
// create only legacy coins (rule A2/A3), carry the V2 input and output caps,
// and a legacy coinbase follows BIP34 and BIP30 on regtest only (A9).

#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <minerfund.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <primitives/v2_outputs.h>
#include <script/standard.h>
#include <timedata.h>
#include <validation.h>

#include <test/util/mining.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tx_verify_bridge_tests, TestChain100Setup)

namespace {
const CScript kOpTrue = CScript() << OP_TRUE;
const CScript kP2PKH = CScript() << OP_DUP << OP_HASH160
                                 << std::vector<uint8_t>(20, 0xab)
                                 << OP_EQUALVERIFY << OP_CHECKSIG;

/**
 * A standard legacy version 2 spend of the given coin (a P2PKH payment
 * padded past the minimum transaction size).
 */
CMutableTransaction LegacySpend(const COutPoint &prevout, Amount value) {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(prevout, CScript() << OP_TRUE);
    mtx.vout.emplace_back(value, kP2PKH);
    mtx.vout.emplace_back(Amount::zero(),
                          CScript() << OP_RETURN
                                    << std::vector<uint8_t>(20, 0x00));
    return mtx;
}

std::string MempoolReason(ChainstateManager &chainman,
                          const CMutableTransaction &mtx) {
    LOCK(cs_main);
    const MempoolAcceptResult result = chainman.ProcessTransaction(
        MakeTransactionRef(mtx), /*test_accept=*/true);
    return result.m_result_type == MempoolAcceptResult::ResultType::VALID
               ? "valid"
               : result.m_state.GetRejectReason();
}

std::string BlockReason(ChainstateManager &chainman, const CBlock &block) {
    LOCK(cs_main);
    BlockValidationState state;
    const bool ok = TestBlockValidity(
        state, GetConfig().GetChainParams(), chainman.ActiveChainstate(),
        block, chainman.ActiveTip(), GetAdjustedTime,
        BlockValidationOptions(GetConfig()).withCheckPoW(false));
    return ok ? "valid" : state.GetRejectReason();
}

/** Recompute the commitments of a block whose transactions were changed. */
void Recommit(CBlock &block, const CBlockIndex *tip) {
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.hashStateRoot = ComputeV2BlockStateRoot(
        block, block.hashPrevBlock, block.nHeight,
        uint64_t(tip->GetMedianTimePast()), false);
    block.SetSize(::GetSerializeSize(block));
}
} // namespace

// A2: a legacy input can spend only a legacy coin, in the mempool and in a
// block. A V2 coin's scriptPubKey is its V2 wire encoding, which the legacy
// interpreter would otherwise run as a legacy script.
BOOST_AUTO_TEST_CASE(legacy_tx_cannot_spend_v2_coin) {
    const CTransactionRef funding =
        MineV2Coinbase({OpTrueOutput(10 * COIN), OpTrueOutput(10 * COIN)});
    const CMutableTransaction spend =
        LegacySpend(COutPoint(funding->GetId(), 0), 9 * COIN);

    BOOST_CHECK_EQUAL(MempoolReason(*m_node.chainman, spend),
                      "bad-txns-legacy-spends-v2-coin");

    {
        LOCK(cs_main);
        const CCoinsViewCache &view =
            m_node.chainman->ActiveChainstate().CoinsTip();
        TxValidationState state;
        Amount fee;
        BOOST_CHECK(!Consensus::CheckTxInputs(
            CTransaction(spend), state, view,
            m_node.chainman->ActiveHeight() + 1, fee));
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "bad-txns-legacy-spends-v2-coin");

        std::vector<Coin> spent{view.AccessCoin(spend.vin[0].prevout)};
        TxValidationState state2;
        BOOST_CHECK(!Consensus::CheckTxInputsFromSpentCoins(
            CTransaction(spend), spent, state2,
            m_node.chainman->ActiveHeight() + 1, fee));
        BOOST_CHECK_EQUAL(state2.GetRejectReason(),
                          "bad-txns-legacy-spends-v2-coin");
    }

    const CBlock block = CreateBlock(
        {spend}, kOpTrue, m_node.chainman->ActiveChainstate());
    BOOST_CHECK_EQUAL(BlockReason(*m_node.chainman, block),
                      "bad-txns-legacy-spends-v2-coin");

    // The same input data in a version 1 transaction is refused too.
    CMutableTransaction v1 = spend;
    v1.nVersion = 1;
    BOOST_CHECK_EQUAL(MempoolReason(*m_node.chainman, v1),
                      "bad-txns-legacy-spends-v2-coin");
}

// A3/A4: the version of the creating transaction, coinbase included, decides
// the coin kind. Legacy coins are spent by legacy transactions as in eCash.
BOOST_AUTO_TEST_CASE(created_coins_carry_the_kind_of_their_transaction) {
    // The inherited chain's coinbases are legacy.
    {
        LOCK(cs_main);
        const CCoinsViewCache &view =
            m_node.chainman->ActiveChainstate().CoinsTip();
        const Coin &cb = view.AccessCoin(COutPoint(m_coinbase_txns[0]->GetId(), 0));
        BOOST_REQUIRE(!cb.IsSpent());
        BOOST_CHECK(cb.IsLegacy());
    }

    // A legacy spend of a legacy coin is accepted and creates a legacy coin.
    const CMutableTransaction legacy = CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 0, coinbaseKey, kP2PKH, 10 * COIN,
        /*submit=*/false);
    BOOST_CHECK_EQUAL(MempoolReason(*m_node.chainman, legacy), "valid");
    CreateAndProcessBlock({legacy}, kOpTrue);

    // A V2 coinbase creates V2 coins.
    const CTransactionRef v2cb = MineV2Coinbase({OpTrueOutput(5 * COIN)});
    BOOST_CHECK_EQUAL(v2cb->nVersion, 7);

    LOCK(cs_main);
    const CCoinsViewCache &view =
        m_node.chainman->ActiveChainstate().CoinsTip();
    const Coin &out = view.AccessCoin(COutPoint(CTransaction(legacy).GetId(), 0));
    BOOST_REQUIRE(!out.IsSpent());
    BOOST_CHECK(out.IsLegacy());
    const Coin &v2 = view.AccessCoin(COutPoint(v2cb->GetId(), 0));
    BOOST_REQUIRE(!v2.IsSpent());
    BOOST_CHECK(!v2.IsLegacy());
}

// The V2 caps of 256 inputs and 256 outputs apply to legacy transactions.
BOOST_AUTO_TEST_CASE(legacy_tx_has_the_v2_caps) {
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    for (uint32_t i = 0; i < MAX_V2_TX_INPUTS; ++i) {
        mtx.vin.emplace_back(COutPoint(TxId(uint256S("01")), i),
                             CScript() << OP_TRUE);
    }
    mtx.vout.emplace_back(1 * COIN, kOpTrue);
    {
        TxValidationState state;
        BOOST_CHECK(CheckRegularTransaction(CTransaction(mtx), state));
    }
    mtx.vin.emplace_back(COutPoint(TxId(uint256S("01")), MAX_V2_TX_INPUTS),
                         CScript() << OP_TRUE);
    {
        TxValidationState state;
        BOOST_CHECK(!CheckRegularTransaction(CTransaction(mtx), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "bad-txns-v2-too-many-inputs");
    }

    CMutableTransaction outs;
    outs.nVersion = 1;
    outs.vin.emplace_back(COutPoint(TxId(uint256S("02")), 0),
                          CScript() << OP_TRUE);
    for (uint32_t i = 0; i <= MAX_V2_TX_OUTPUTS; ++i) {
        outs.vout.emplace_back(1000 * SATOSHI, kOpTrue);
    }
    TxValidationState state;
    BOOST_CHECK(!CheckRegularTransaction(CTransaction(outs), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-v2-too-many-outputs");
}

// A9: a legacy coinbase starts its scriptSig with the BIP34 height.
BOOST_AUTO_TEST_CASE(legacy_coinbase_bip34_height) {
    CBlock block =
        CreateBlock({}, kOpTrue, m_node.chainman->ActiveChainstate());
    BOOST_REQUIRE_EQUAL(block.vtx[0]->nVersion, 2);
    BOOST_CHECK_EQUAL(BlockReason(*m_node.chainman, block), "valid");

    const CBlockIndex *tip =
        WITH_LOCK(cs_main, return m_node.chainman->ActiveTip());
    CMutableTransaction cb{*block.vtx[0]};
    cb.vin[0].scriptSig = CScript() << (tip->nHeight + 2) << OP_0;
    node::PadCoinbaseToMinSize(cb);
    block.vtx[0] = MakeTransactionRef(cb);
    Recommit(block, tip);
    BOOST_CHECK_EQUAL(BlockReason(*m_node.chainman, block), "bad-cb-height");
}

// A9: BIP30 applies to a legacy coinbase (a V2 coinbase is unique by its
// input, which commits to the parent block and height).
BOOST_AUTO_TEST_CASE(legacy_coinbase_bip30_duplicate) {
    const CBlock block =
        CreateBlock({}, kOpTrue, m_node.chainman->ActiveChainstate());
    BOOST_REQUIRE_EQUAL(block.vtx[0]->nVersion, 2);
    const COutPoint dup(block.vtx[0]->GetId(), 0);
    {
        LOCK(cs_main);
        m_node.chainman->ActiveChainstate().CoinsTip().AddCoin(
            dup, Coin(CTxOut(1 * COIN, kOpTrue), 1, true), false);
    }
    BOOST_CHECK_EQUAL(BlockReason(*m_node.chainman, block), "bad-txns-BIP30");
    {
        LOCK(cs_main);
        m_node.chainman->ActiveChainstate().CoinsTip().SpendCoin(dup);
    }
    BOOST_CHECK_EQUAL(BlockReason(*m_node.chainman, block), "valid");
}

// The miner fund (mainnet whitelist) is paid by a legacy output holding the
// fund's script in a legacy coinbase, or by the V0-leaf V2 output over that
// script in a V2 coinbase.
BOOST_AUTO_TEST_CASE(miner_fund_paid_by_legacy_or_v2_output) {
    const auto main_params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params &params = main_params->GetConsensus();
    const auto whitelist = GetMinerFundWhitelist(params);
    BOOST_REQUIRE_EQUAL(whitelist.size(), 1U);
    const CScript fund = GetScriptForDestination(*whitelist.begin());
    const Amount reward = 100 * COIN;
    const Amount required = GetMinerFundAmount(params, reward, nullptr);
    BOOST_REQUIRE(required > Amount::zero());

    const std::vector<CTxOut> legacy{CTxOut(reward - required, kOpTrue),
                                     CTxOut(required, fund)};
    BOOST_CHECK(CheckMinerFund(params, legacy, reward, nullptr));
    const std::vector<CTxOut> v2{V0LeafOutput(reward - required, kOpTrue),
                                 V0LeafOutput(required, fund)};
    BOOST_CHECK(CheckMinerFund(params, v2, reward, nullptr));

    // Too little, or paid to another script, does not count.
    const std::vector<CTxOut> short_legacy{
        CTxOut(required - SATOSHI, fund)};
    BOOST_CHECK(!CheckMinerFund(params, short_legacy, reward, nullptr));
    const std::vector<CTxOut> other_v2{V0LeafOutput(required, kOpTrue)};
    BOOST_CHECK(!CheckMinerFund(params, other_v2, reward, nullptr));
    // A legacy output whose script is the V2 encoding of the fund output is
    // not the fund's script.
    const std::vector<CTxOut> lookalike{
        CTxOut(required, V0LeafOutput(required, fund).scriptPubKey)};
    BOOST_CHECK(!CheckMinerFund(params, lookalike, reward, nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
