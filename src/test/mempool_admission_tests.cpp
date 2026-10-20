// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/validation.h>
#include <random.h>
#include <script/standard.h>
#include <test/util/admission.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

using admission_test::SignedSpend;
using admission_test::Wallet;

namespace {

struct AdmissionSetup : public TestChain100Setup {
    Wallet wallet{admission_test::MakeWallet()};
    AdmissionSetup() { admission_test::FundWallet(*this, wallet, 512); }

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

/** A P2PKH spend with full control over amounts, locktime and sequence. */
CTransactionRef
BuildSpend(const Wallet &wallet,
           const std::vector<admission_test::SpendableOutput> &inputs,
           const std::vector<Amount> &output_amounts, bool schnorr,
           uint32_t locktime = 0, uint32_t sequence = CTxIn::SEQUENCE_FINAL) {
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = locktime;
    std::vector<Amount> spent;
    for (const auto &in : inputs) {
        tx.vin.emplace_back(in.outpoint, CScript(), sequence);
        spent.push_back(in.amount);
    }
    for (const Amount &a : output_amounts) {
        tx.vout.emplace_back(a, wallet.script_pub_key);
    }
    admission_test::SignP2PKH(tx, wallet, spent, schnorr);
    return MakeTransactionRef(std::move(tx));
}

/**
 * A shuffled mix of everything admission has to decide: valid ECDSA,
 * Schnorr and multi-input spends, dependent chains (sometimes child first),
 * double spends, bad signatures, orphans, duplicates, transactions below
 * the relay fee, with dust outputs, not yet final, and children of invalid
 * parents. Uses each wallet output at most once (double spends excepted).
 */
std::vector<CTransactionRef> MakeScenario(FastRandomContext &rng,
                                          const Wallet &wallet, size_t first,
                                          size_t count, int tip_height) {
    std::vector<std::vector<CTransactionRef>> groups;
    size_t pos = first;
    auto next = [&]() { return wallet.outputs.at(pos++); };
    while (pos < first + count - 4) {
        const bool schnorr = rng.randbool();
        std::vector<CTransactionRef> g;
        switch (rng.randrange(11)) {
            case 0:
            case 1:
                g.push_back(SignedSpend(wallet, {next()}, 2, schnorr));
                break;
            case 2:
                g.push_back(
                    SignedSpend(wallet, {next(), next(), next()}, 1, schnorr));
                break;
            case 3: {
                const auto p = SignedSpend(wallet, {next()}, 1, schnorr);
                const auto c =
                    admission_test::SignedChild(wallet, p, 0, rng.randbool());
                const auto gc =
                    admission_test::SignedChild(wallet, c, 0, rng.randbool());
                if (rng.randbool()) {
                    g = {p, c, gc};
                } else {
                    g = {c, p, gc};
                }
                break;
            }
            case 4: {
                const auto o = next();
                g.push_back(SignedSpend(wallet, {o}, 1, schnorr, 1));
                g.push_back(SignedSpend(wallet, {o}, 2, !schnorr, 2));
                break;
            }
            case 5: {
                const auto good = SignedSpend(wallet, {next()}, 1, schnorr);
                const auto bad = WithBadSignature(good);
                g.push_back(bad);
                g.push_back(
                    admission_test::SignedChild(wallet, bad, 0, schnorr));
                break;
            }
            case 6: {
                const auto unseen = SignedSpend(wallet, {next()}, 1, schnorr);
                g.push_back(
                    admission_test::SignedChild(wallet, unseen, 0, schnorr));
                break;
            }
            case 7: {
                const auto tx = SignedSpend(wallet, {next()}, 1, schnorr);
                g = {tx, tx};
                break;
            }
            case 8: {
                const auto o = next();
                g.push_back(BuildSpend(wallet, {o}, {o.amount}, schnorr));
                break;
            }
            case 9: {
                const auto o = next();
                g.push_back(BuildSpend(
                    wallet, {o}, {100 * SATOSHI, o.amount - 2000 * SATOSHI},
                    schnorr));
                break;
            }
            case 10: {
                const auto o = next();
                g.push_back(BuildSpend(wallet, {o}, {o.amount - 1000 * SATOSHI},
                                       schnorr, tip_height + 10, 0));
                break;
            }
        }
        groups.push_back(std::move(g));
    }
    Shuffle(groups.begin(), groups.end(), rng);
    std::vector<CTransactionRef> out;
    for (auto &g : groups) {
        for (auto &tx : g) {
            out.push_back(std::move(tx));
        }
    }
    return out;
}

void CheckSameResults(
    const std::vector<MempoolAcceptResult> &serial,
    const std::vector<std::optional<MempoolAcceptResult>> &staged) {
    BOOST_REQUIRE_EQUAL(serial.size(), staged.size());
    for (size_t i = 0; i < serial.size(); ++i) {
        BOOST_REQUIRE(staged[i].has_value());
        CheckSameResult(serial[i], *staged[i]);
        BOOST_CHECK(serial[i].m_effective_feerate ==
                    staged[i]->m_effective_feerate);
    }
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

namespace {
std::vector<std::pair<TxId, Amount>> MempoolContents(const CTxMemPool &pool) {
    LOCK(pool.cs);
    std::vector<std::pair<TxId, Amount>> out;
    for (const auto &info : pool.infoAll()) {
        out.emplace_back(info.tx->GetId(), info.fee);
    }
    std::sort(out.begin(), out.end());
    return out;
}
} // namespace

BOOST_AUTO_TEST_CASE(staged_admission_matches_serial_admission) {
    // Differential test: the same shuffled scenario admitted serially, then
    // (after clearing the mempool) staged with several batch splits and
    // thread counts, must give identical per-transaction results and the
    // identical final mempool.
    FastRandomContext rng(/*fDeterministic=*/true);
    const int height = WITH_LOCK(cs_main, return Active().m_chain.Height());
    CTxMemPool &pool = *m_node.mempool;
    size_t first = 0;
    for (const size_t threads : {1, 4, 8}) {
        const auto txs = MakeScenario(rng, wallet, first, 120, height);
        first += 120;

        pool.clear();
        std::vector<MempoolAcceptResult> serial;
        {
            LOCK(cs_main);
            for (const auto &tx : txs) {
                serial.push_back(m_node.chainman->ProcessTransaction(tx));
            }
        }
        const auto serial_pool = MempoolContents(pool);
        size_t admitted = 0;
        for (const auto &r : serial) {
            admitted +=
                r.m_result_type == MempoolAcceptResult::ResultType::VALID;
        }
        BOOST_CHECK(admitted > 20 && admitted < txs.size());

        for (int round = 0; round < 2; ++round) {
            pool.clear();
            std::vector<std::optional<MempoolAcceptResult>> staged;
            size_t precomputed = 0;
            size_t pos = 0;
            while (pos < txs.size()) {
                const size_t len = std::min<size_t>(
                    txs.size() - pos, 1 + rng.randrange(round ? 120 : 16));
                std::vector<CTransactionRef> batch(txs.begin() + pos,
                                                   txs.begin() + pos + len);
                StagedAdmissionOptions options;
                options.script_threads = threads;
                StagedAdmissionStats stats;
                auto res = AcceptToMemoryPoolStaged(*m_node.chainman, batch,
                                                    options, &stats);
                precomputed += stats.precomputed;
                for (auto &r : res) {
                    staged.push_back(std::move(r));
                }
                pos += len;
            }
            BOOST_CHECK(precomputed > admitted / 2);
            CheckSameResults(serial, staged);
            BOOST_CHECK(MempoolContents(pool) == serial_pool);
            WITH_LOCK(cs_main, pool.check(Active().CoinsTip(), height + 1));
        }
    }
}

BOOST_AUTO_TEST_CASE(staged_cheap_rejects_do_not_run_unlocked_scripts) {
    const auto &out = wallet.outputs[0];
    const auto free_tx = BuildSpend(wallet, {out}, {out.amount}, true);
    const int height = WITH_LOCK(cs_main, return Active().m_chain.Height());
    const auto future_tx = BuildSpend(
        wallet, {wallet.outputs[1]},
        {wallet.outputs[1].amount - 10000 * SATOSHI}, false, height + 10, 0);
    for (const auto &tx : {free_tx, future_tx}) {
        const auto serial = Admit(tx);
        StagedAdmissionStats stats;
        const auto staged =
            AcceptToMemoryPoolStaged(*m_node.chainman, {tx}, {}, &stats);
        BOOST_CHECK_EQUAL(stats.precomputed, 0U);
        CheckSameResult(serial, *staged[0]);
    }
    const auto tx = SignedSpend(wallet, {wallet.outputs[2]}, 1, true);
    MempoolAdmissionLimits limits;
    limits.max_fee = 1 * SATOSHI;
    const auto checks =
        PrecomputeMempoolAdmission(*m_node.chainman, tx, limits);
    BOOST_CHECK(!checks.standard.ran);
    // Advisory work cannot insert or skip the caller's authoritative fee check.
    BOOST_CHECK(!m_node.mempool->exists(tx->GetId()));
}

BOOST_AUTO_TEST_CASE(staged_double_spend_race_first_in_order_wins) {
    const auto o = wallet.outputs[0];
    const auto a = SignedSpend(wallet, {o}, 1, /*schnorr=*/false, 1);
    const auto b = SignedSpend(wallet, {o}, 2, /*schnorr=*/true, 2);
    StagedAdmissionOptions options;
    options.script_threads = 4;
    for (const bool a_first : {true, false}) {
        m_node.mempool->clear();
        std::vector<CTransactionRef> batch{a, b};
        if (!a_first) {
            std::swap(batch[0], batch[1]);
        }
        StagedAdmissionStats stats;
        const auto res =
            AcceptToMemoryPoolStaged(*m_node.chainman, batch, options, &stats);
        // The second spend is not even verified: phase A sees the conflict.
        BOOST_CHECK_EQUAL(stats.precomputed, 1U);
        BOOST_CHECK(res[0]->m_result_type ==
                    MempoolAcceptResult::ResultType::VALID);
        BOOST_CHECK(res[1]->m_state.GetResult() ==
                    TxValidationResult::TX_AVALANCHE_RECONSIDERABLE);
        BOOST_CHECK_EQUAL(res[1]->m_state.GetRejectReason(),
                          "txn-mempool-conflict");
        BOOST_CHECK(m_node.mempool->exists(batch[0]->GetId()));
        BOOST_CHECK(!m_node.mempool->exists(batch[1]->GetId()));
    }

    // Two callers racing with the two spends: exactly one wins, and the
    // loser gets the serial conflict verdict.
    for (int round = 0; round < 20; ++round) {
        m_node.mempool->clear();
        std::optional<MempoolAcceptResult> ra, rb;
        std::thread ta([&] {
            ra.emplace(
                *AcceptToMemoryPoolStaged(*m_node.chainman, {a}, options)[0]);
        });
        std::thread tb([&] {
            rb.emplace(
                *AcceptToMemoryPoolStaged(*m_node.chainman, {b}, options)[0]);
        });
        ta.join();
        tb.join();
        const bool a_won =
            ra->m_result_type == MempoolAcceptResult::ResultType::VALID;
        const bool b_won =
            rb->m_result_type == MempoolAcceptResult::ResultType::VALID;
        BOOST_CHECK(a_won != b_won);
        BOOST_CHECK_EQUAL((a_won ? rb : ra)->m_state.GetRejectReason(),
                          "txn-mempool-conflict");
    }
}

BOOST_AUTO_TEST_CASE(staged_chain_in_one_batch_is_not_an_orphan) {
    const auto p = SignedSpend(wallet, {wallet.outputs[0]}, 2, true);
    const auto c = admission_test::SignedChild(wallet, p, 0, false);
    const auto gc = admission_test::SignedChild(wallet, c, 0, true);
    const auto c2 = admission_test::SignedChild(wallet, p, 1, true);
    StagedAdmissionOptions options;
    options.script_threads = 4;
    StagedAdmissionStats stats;
    // Children whose parents are only in the same batch (verified in
    // parallel with them) are resolved from the batch and admitted.
    const auto res = AcceptToMemoryPoolStaged(*m_node.chainman, {p, c, gc, c2},
                                              options, &stats);
    BOOST_CHECK_EQUAL(stats.precomputed, 4U);
    for (const auto &r : res) {
        BOOST_CHECK(r->m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    // A child ahead of its parent is an orphan, exactly as when admitted
    // serially in that order; the parent is still admitted.
    m_node.mempool->clear();
    const auto res2 =
        AcceptToMemoryPoolStaged(*m_node.chainman, {c, p}, options, &stats);
    BOOST_CHECK(res2[0]->m_state.GetResult() ==
                TxValidationResult::TX_MISSING_INPUTS);
    BOOST_CHECK(res2[1]->m_result_type ==
                MempoolAcceptResult::ResultType::VALID);

    // A child of a parent that fails its scripts in the same batch is an
    // orphan too (the parent never reaches the mempool).
    m_node.mempool->clear();
    const auto bad = WithBadSignature(p);
    const auto bad_child = admission_test::SignedChild(wallet, bad, 0, false);
    const auto res3 =
        AcceptToMemoryPoolStaged(*m_node.chainman, {bad, bad_child}, options);
    BOOST_CHECK(res3[0]->m_state.GetResult() ==
                TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK(res3[1]->m_state.GetResult() ==
                TxValidationResult::TX_MISSING_INPUTS);
}

BOOST_AUTO_TEST_CASE(staged_block_between_phases) {
    // A block connected while scripts are being verified outside the locks.
    const auto keep = SignedSpend(wallet, {wallet.outputs[0]}, 1, false);
    const auto spent_in_block =
        SignedSpend(wallet, {wallet.outputs[1]}, 1, true, 1);
    const auto conflicting =
        SignedSpend(wallet, {wallet.outputs[1]}, 1, false, 2);
    const auto mined = SignedSpend(wallet, {wallet.outputs[2]}, 1, true);
    const auto mined_child =
        admission_test::SignedChild(wallet, mined, 0, true);
    StagedAdmissionOptions options;
    options.script_threads = 4;
    const int height_before =
        WITH_LOCK(cs_main, return Active().m_chain.Height());
    options.test_between_phases = [&] {
        CreateAndProcessBlock(
            {CMutableTransaction(*conflicting), CMutableTransaction(*mined)},
            wallet.script_pub_key);
    };
    StagedAdmissionStats stats;
    const auto res = AcceptToMemoryPoolStaged(
        *m_node.chainman, {keep, spent_in_block, mined, mined_child}, options,
        &stats);
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return Active().m_chain.Height()),
                      height_before + 1);
    BOOST_CHECK_EQUAL(stats.precomputed, 4U);
    // Unaffected: admitted on the new tip.
    BOOST_CHECK(res[0]->m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    // Its input was spent by the block: missing inputs, as serial admission
    // after the block would say.
    BOOST_CHECK(res[1]->m_state.GetResult() ==
                TxValidationResult::TX_MISSING_INPUTS);
    // Already confirmed.
    BOOST_CHECK(res[2]->m_result_type !=
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK_EQUAL(res[2]->m_state.GetRejectReason(), "txn-already-known");
    // Its parent was resolved from the batch in phase A but is now
    // confirmed; the child is admitted against the confirmed output.
    BOOST_CHECK(res[3]->m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(m_node.mempool->exists(mined_child->GetId()));
}

BOOST_AUTO_TEST_CASE(staged_skip_at_commit) {
    const auto a = SignedSpend(wallet, {wallet.outputs[0]}, 1, false);
    const auto b = SignedSpend(wallet, {wallet.outputs[1]}, 1, true);
    StagedAdmissionOptions options;
    options.skip_at_commit = [&](const CTransactionRef &tx) {
        AssertLockHeld(cs_main);
        return tx == a;
    };
    const auto res =
        AcceptToMemoryPoolStaged(*m_node.chainman, {a, b}, options);
    BOOST_CHECK(!res[0].has_value());
    BOOST_CHECK(res[1]->m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(!m_node.mempool->exists(a->GetId()));
}

BOOST_AUTO_TEST_CASE(staged_concurrent_callers_and_blocks) {
    // Several threads admit overlapping batches (shared transactions and
    // double spends) while the main thread connects blocks. Run under
    // ThreadSanitizer to check the unlocked phase. Afterwards the mempool
    // must be consistent and hold at most one side of each double spend.
    FastRandomContext rng(/*fDeterministic=*/true);
    std::vector<CTransactionRef> pool_txs;
    std::vector<std::pair<TxId, TxId>> double_spends;
    for (size_t i = 0; i < 160; ++i) {
        const auto o = wallet.outputs[i];
        const auto a = SignedSpend(wallet, {o}, 1, i % 2 == 0, 1);
        pool_txs.push_back(a);
        if (i % 4 == 0) {
            const auto b = SignedSpend(wallet, {o}, 1, i % 2 == 1, 2);
            pool_txs.push_back(b);
            double_spends.emplace_back(a->GetId(), b->GetId());
        }
        if (i % 5 == 0) {
            pool_txs.push_back(admission_test::SignedChild(wallet, a, 0, true));
        }
    }
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            FastRandomContext trng(uint256{uint8_t(t + 1)});
            StagedAdmissionOptions options;
            options.script_threads = 1 + t;
            while (!stop) {
                std::vector<CTransactionRef> batch;
                const size_t start = trng.randrange(pool_txs.size());
                const size_t len = 1 + trng.randrange(32);
                for (size_t k = 0; k < len; ++k) {
                    batch.push_back(pool_txs[(start + k) % pool_txs.size()]);
                }
                AcceptToMemoryPoolStaged(*m_node.chainman, batch, options);
            }
        });
    }
    for (int b = 0; b < 4; ++b) {
        UninterruptibleSleep(std::chrono::milliseconds{50});
        CreateAndProcessBlock({}, wallet.script_pub_key);
    }
    UninterruptibleSleep(std::chrono::milliseconds{50});
    stop = true;
    for (auto &th : threads) {
        th.join();
    }
    const int height = WITH_LOCK(cs_main, return Active().m_chain.Height());
    WITH_LOCK(cs_main, m_node.mempool->check(Active().CoinsTip(), height + 1));
    for (const auto &[a, b] : double_spends) {
        BOOST_CHECK(!(m_node.mempool->exists(a) && m_node.mempool->exists(b)));
    }
    BOOST_CHECK(m_node.mempool->size() > 0);
}

BOOST_AUTO_TEST_SUITE_END()
