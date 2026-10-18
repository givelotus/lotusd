// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup) {
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey())
                                     << OP_CHECKSIG;
    CMutableTransaction coinbaseTx;

    coinbaseTx.nVersion = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result =
        m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type ==
                MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccesful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-tx-coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

// Exercise the optimized pre-spent interface against the consensus entrypoint,
// including combinations of invalid inputs so error precedence cannot drift.
BOOST_FIXTURE_TEST_CASE(spent_input_differential, BasicTestingSetup) {
    FastRandomContext rng(true);
    for (unsigned trial = 0; trial < 1000; ++trial) {
        CCoinsView base;
        CCoinsViewCache view(&base);
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        std::vector<Coin> spent;
        const unsigned count = 2 + rng.randrange(7);
        Amount total = Amount::zero();
        for (unsigned i = 0; i < count; ++i) {
            const COutPoint op{TxId(rng.rand256()), i};
            mtx.vin.emplace_back(op);
            const bool missing = (trial % 7 == 0 && i + 1 == count);
            const bool coinbase = (trial % 3 == 0 && i == 0);
            const int height = coinbase ? 150 : rng.randrange(200);
            const Amount amount = static_cast<int64_t>(1 + rng.randrange(100000)) * SATOSHI;
            total += amount;
            Coin coin{CTxOut{amount, CScript() << OP_TRUE},
                      static_cast<uint32_t>(height), coinbase};
            if (missing) {
                spent.emplace_back();
            } else {
                spent.push_back(coin);
                view.AddCoin(op, std::move(coin), false);
            }
        }
        mtx.vout.emplace_back(total + (trial % 5 == 0 ? 1 : -1) * SATOSHI,
                              CScript() << OP_TRUE);
        const CTransaction tx{mtx};
        TxValidationState reference, fused;
        Amount reference_fee{}, fused_fee{};
        const bool expected = Consensus::CheckTxInputs(
            tx, reference, view, 200, reference_fee);
        const bool actual = Consensus::CheckTxInputsFromSpentCoins(
            tx, spent, fused, 200, fused_fee);
        BOOST_REQUIRE_EQUAL(actual, expected);
        // ConnectBlock calls the fused API only after every SpendCoin succeeds.
        // Missing-coin mixtures exercise defensive rejection outside that
        // precondition; error precedence is intentionally not promised there.
        const bool all_available = std::all_of(spent.begin(), spent.end(),
            [](const Coin &coin) { return !coin.IsSpent(); });
        BOOST_CHECK(actual ? fused_fee == reference_fee :
                     (!all_available || fused.GetResult() == reference.GetResult()));
        if (!actual && all_available) {
            BOOST_CHECK_EQUAL(fused.GetRejectReason(), reference.GetRejectReason());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
