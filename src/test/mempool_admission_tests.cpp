// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/validation.h>
#include <test/util/admission.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

using admission_test::SignedSpend;
using admission_test::Wallet;

namespace {

struct AdmissionSetup : public TestChain100Setup {
    Wallet wallet{admission_test::MakeWallet()};
    AdmissionSetup() { admission_test::FundWallet(*this, wallet, 64); }

    Chainstate &Active() { return m_node.chainman->ActiveChainstate(); }

    std::vector<CTxOut> SpentOutputs(const CTransaction &tx) {
        LOCK2(cs_main, m_node.mempool->cs);
        CCoinsViewMemPool view(&Active().CoinsTip(), *m_node.mempool);
        std::vector<CTxOut> out;
        for (const CTxIn &in : tx.vin) {
            std::optional<Coin> coin = view.GetCoin(in.prevout);
            BOOST_REQUIRE(coin.has_value());
            out.push_back(coin->GetTxOut());
        }
        return out;
    }

    PrecomputedAdmissionChecks Precompute(const CTransactionRef &tx,
                                          std::vector<CTxOut> spent) {
        const uint32_t flags =
            WITH_LOCK(cs_main, return GetMempoolScriptFlags(Active()));
        PrecomputedAdmissionChecks checks;
        checks.spent_outputs = std::move(spent);
        ComputeAdmissionChecks(*tx, flags, m_node.chainman->m_validation_cache,
                               checks);
        return checks;
    }

    MempoolAcceptResult
    Admit(const CTransactionRef &tx,
          const PrecomputedAdmissionChecks *checks = nullptr) {
        LOCK(cs_main);
        return AcceptToMemoryPool(Active(), tx, GetTime(),
                                  /*bypass_limits=*/false,
                                  /*test_accept=*/false, 0, {}, checks);
    }
};

CTransactionRef WithBadSignature(const CTransactionRef &tx) {
    CMutableTransaction mtx(*tx);
    // Flip a bit inside the first signature push (after the push opcode).
    mtx.vin[0].scriptSig[5] ^= 0x01;
    return MakeTransactionRef(std::move(mtx));
}

void CheckSameResult(const MempoolAcceptResult &a,
                     const MempoolAcceptResult &b) {
    BOOST_CHECK(a.m_result_type == b.m_result_type);
    BOOST_CHECK(a.m_state.GetResult() == b.m_state.GetResult());
    BOOST_CHECK_EQUAL(a.m_state.GetRejectReason(), b.m_state.GetRejectReason());
    BOOST_CHECK_EQUAL(a.m_state.GetDebugMessage(), b.m_state.GetDebugMessage());
    BOOST_CHECK_MESSAGE(a.m_vsize == b.m_vsize,
        "admission vsize differs: " << a.m_vsize.value_or(-1)
        << " versus " << b.m_vsize.value_or(-1));
    BOOST_CHECK(a.m_base_fees == b.m_base_fees);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mempool_admission_tests, AdmissionSetup)

BOOST_AUTO_TEST_CASE(precomputed_checks_give_serial_verdicts) {
    // A valid ECDSA and a valid Schnorr spend, each admitted once with
    // checks computed outside the locks and compared with the verdict of an
    // identical transaction admitted the ordinary way.
    for (const bool schnorr : {false, true}) {
        const size_t base = schnorr ? 0 : 2;
        const auto tx_pre =
            SignedSpend(wallet, {wallet.outputs[base]}, 2, schnorr);
        const auto checks = Precompute(tx_pre, SpentOutputs(*tx_pre));
        BOOST_CHECK(checks.standard.ran && !checks.standard.error_result);
        BOOST_CHECK(checks.consensus.ran && !checks.consensus.error_result);
        BOOST_CHECK_EQUAL(checks.standard.sigchecks, 1);
        const auto r_pre = Admit(tx_pre, &checks);
        // Compare the identical signed bytes: separate ECDSA spends may have
        // different DER signature lengths and therefore different valid sizes.
        {
            LOCK(m_node.mempool->cs);
            m_node.mempool->removeRecursive(*tx_pre, MemPoolRemovalReason::CONFLICT);
        }
        BOOST_CHECK(!m_node.mempool->exists(tx_pre->GetId()));
        const auto r_plain = Admit(tx_pre);
        BOOST_CHECK(r_pre.m_result_type ==
                    MempoolAcceptResult::ResultType::VALID);
        CheckSameResult(r_pre, r_plain);
        BOOST_CHECK(m_node.mempool->exists(tx_pre->GetId()));
    }

    // An invalid signature: the precomputed verdict and the ordinary one
    // carry the same result, reason and debug message.
    const auto good = SignedSpend(wallet, {wallet.outputs[10]}, 1, false);
    const auto bad = WithBadSignature(good);
    const auto checks = Precompute(bad, SpentOutputs(*bad));
    BOOST_CHECK(checks.standard.error_result.has_value());
    const auto r_pre = Admit(bad, &checks);
    const auto r_plain = Admit(bad);
    BOOST_CHECK(r_pre.m_result_type ==
                MempoolAcceptResult::ResultType::INVALID);
    CheckSameResult(r_pre, r_plain);
    BOOST_CHECK(r_plain.m_state.GetResult() ==
                TxValidationResult::TX_CONSENSUS);
}

BOOST_AUTO_TEST_CASE(precomputed_checks_used_only_when_they_match) {
    const auto tx = SignedSpend(wallet, {wallet.outputs[20]}, 1, true);

    // A matching outcome is what admission uses: a (deliberately false)
    // recorded failure for exactly these spent outputs and flags is reported.
    auto forged = Precompute(tx, SpentOutputs(*tx));
    forged.standard.error_result = TxValidationResult::TX_NOT_STANDARD;
    forged.standard.error_reason = "forged-for-test";
    BOOST_CHECK_EQUAL(Admit(tx, &forged).m_state.GetRejectReason(),
                      "forged-for-test");

    // Different spent outputs (amount, then script): ignored, scripts run.
    auto wrong_amount = forged;
    wrong_amount.spent_outputs[0].nValue += SATOSHI;
    auto wrong_script = forged;
    wrong_script.spent_outputs[0].scriptPubKey = CScript() << OP_TRUE;
    // Different flags: ignored.
    auto wrong_flags = forged;
    wrong_flags.standard.flags ^= SCRIPT_VERIFY_NULLFAIL;
    // Checks for a different transaction: ignored.
    auto wrong_tx = forged;
    wrong_tx.txid = TxId(uint256::ONE);

    for (const auto *checks :
         {&wrong_amount, &wrong_script, &wrong_flags, &wrong_tx}) {
        const auto r = Admit(tx, checks);
        BOOST_CHECK(r.m_result_type == MempoolAcceptResult::ResultType::VALID);
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*tx, MemPoolRemovalReason::CONFLICT);
    }

    // A missing input still fails as an orphan, whatever was precomputed.
    const auto parent = SignedSpend(wallet, {wallet.outputs[21]}, 1, false);
    const auto child = admission_test::SignedChild(wallet, parent, 0, false);
    auto child_checks = Precompute(child, {parent->vout[0]});
    BOOST_CHECK(!child_checks.standard.error_result);
    const auto r = Admit(child, &child_checks);
    BOOST_CHECK(r.m_state.GetResult() == TxValidationResult::TX_MISSING_INPUTS);
}

BOOST_AUTO_TEST_SUITE_END()
