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
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <streams.h>
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

// Legacy versions 1 and 2 enter the mempool; version 3 does not decode.
BOOST_FIXTURE_TEST_CASE(tx_mempool_accepts_legacy_versions, TestChain100Setup) {
    const CScript p2pkh = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    // A version 1 spend of a mature coinbase, then a version 2 spend of it.
    CTransactionRef input = m_coinbase_txns[0];
    for (const int32_t version : {1, 2}) {
        CMutableTransaction mtx;
        mtx.nVersion = version;
        mtx.vin.emplace_back(COutPoint(input->GetId(), 0));
        mtx.vout.emplace_back(input->vout[0].nValue - 10 * COIN, p2pkh);
        FillableSigningProvider keystore;
        keystore.AddKey(coinbaseKey);
        std::map<COutPoint, Coin> coins;
        coins.emplace(mtx.vin[0].prevout, Coin(input->vout[0], 0, input->IsCoinBase()));
        std::map<int, std::string> errors;
        BOOST_REQUIRE(SignTransaction(mtx, &keystore, coins,
                                      SigHashType().withForkId(), errors));
        LOCK(cs_main);
        const size_t before = m_node.mempool->size();
        const MempoolAcceptResult result =
            m_node.chainman->ProcessTransaction(MakeTransactionRef(mtx));
        BOOST_CHECK_MESSAGE(result.m_result_type ==
                                MempoolAcceptResult::ResultType::VALID,
                            result.m_state.GetRejectReason());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), before + 1);
        input = MakeTransactionRef(mtx);
    }

    CMutableTransaction mtx = CreateValidMempoolTransaction(
        m_coinbase_txns[1], 0, 0, coinbaseKey, p2pkh, 10 * COIN,
        /*submit=*/false);
    DataStream stream{};
    stream << CTransaction(mtx);
    // The version is the first four bytes, little endian.
    stream[0] = std::byte{3};
    CMutableTransaction decoded;
    try {
        stream >> decoded;
        BOOST_ERROR("version 3 decoded");
    } catch (const std::ios_base::failure &e) {
        BOOST_CHECK(std::string(e.what()).find("bad-txns-version") !=
                    std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE_END()
