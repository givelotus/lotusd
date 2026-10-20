// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <kernel/mempool_entry.h>
#include <test/util/admission.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <thread>
#include <vector>

/**
 * Mempool admission of independently signed P2PKH transactions (half ECDSA,
 * half Schnorr). Every iteration admits a set of transactions that has never
 * been verified before, so the signature cache starts cold, as it does for
 * transactions first seen from the network. The mempool is cleared between
 * iterations; the cost reported is per transaction.
 */
namespace {

constexpr size_t TXS_PER_SET = 2000;
constexpr size_t SETS = 12;

struct SignedSets {
    std::vector<std::vector<CTransactionRef>> sets;
};

SignedSets MakeSets(TestChain100Setup &setup) {
    admission_test::Wallet wallet = admission_test::MakeWallet();
    admission_test::FundWallet(setup, wallet, TXS_PER_SET);
    SignedSets out;
    for (size_t s = 0; s < SETS; ++s) {
        std::vector<CTransactionRef> set;
        set.reserve(TXS_PER_SET);
        for (size_t i = 0; i < TXS_PER_SET; ++i) {
            set.push_back(admission_test::SignedSpend(
                wallet, {wallet.outputs[i]}, 2, /*schnorr=*/i % 2 == 1,
                /*salt=*/uint32_t(s)));
        }
        out.sets.push_back(std::move(set));
    }
    return out;
}

} // namespace

static void MempoolAdmissionSignedSerial(benchmark::Bench &bench) {
    // No per-admission mempool consistency check (regtest defaults to one).
    auto setup = MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST,
                                                         {"-checkmempool=0"});
    const SignedSets sets = MakeSets(*setup);
    Chainstate &chainstate = setup->m_node.chainman->ActiveChainstate();
    CTxMemPool &mempool = *setup->m_node.mempool;
    size_t next = 0;
    bench.epochs(SETS).epochIterations(1).batch(TXS_PER_SET).unit("tx");
    bench.run([&] {
        const auto &set = sets.sets.at(next++ % SETS);
        LOCK(::cs_main);
        for (const auto &tx : set) {
            const MempoolAcceptResult result = AcceptToMemoryPool(
                chainstate, tx, GetTime(), /*bypass_limits=*/false);
            Assert(result.m_result_type ==
                   MempoolAcceptResult::ResultType::VALID);
        }
        mempool.clear();
    });
}

/**
 * The same sets through AcceptToMemoryPoolStaged in batches of 256: inputs
 * resolved under cs_main, scripts verified on `threads` threads without
 * locks, then committed in order. Reports the same per-transaction cost.
 */
static void StagedAdmission(benchmark::Bench &bench, size_t threads) {
    // No per-admission mempool consistency check (regtest defaults to one).
    auto setup = MakeNoLogFileContext<TestChain100Setup>(ChainType::REGTEST,
                                                         {"-checkmempool=0"});
    const SignedSets sets = MakeSets(*setup);
    CTxMemPool &mempool = *setup->m_node.mempool;
    StagedAdmissionOptions options;
    options.script_threads =
        threads ? threads : std::max(1U, std::thread::hardware_concurrency());
    size_t next = 0;
    bench.epochs(SETS).epochIterations(1).batch(TXS_PER_SET).unit("tx");
    bench.run([&] {
        const auto &set = sets.sets.at(next++ % SETS);
        constexpr size_t BATCH = 256;
        for (size_t pos = 0; pos < set.size(); pos += BATCH) {
            std::vector<CTransactionRef> batch(
                set.begin() + pos,
                set.begin() + std::min(set.size(), pos + BATCH));
            const auto results = AcceptToMemoryPoolStaged(
                *setup->m_node.chainman, batch, options);
            for (const auto &r : results) {
                Assert(r && r->m_result_type ==
                                MempoolAcceptResult::ResultType::VALID);
            }
        }
        mempool.clear();
    });
}

static void MempoolAdmissionSignedStaged1(benchmark::Bench &bench) {
    StagedAdmission(bench, 1);
}
static void MempoolAdmissionSignedStaged4(benchmark::Bench &bench) {
    StagedAdmission(bench, 4);
}
static void MempoolAdmissionSignedStaged8(benchmark::Bench &bench) {
    StagedAdmission(bench, 8);
}
static void MempoolAdmissionSignedStagedAll(benchmark::Bench &bench) {
    StagedAdmission(bench, 0);
}

BENCHMARK(MempoolAdmissionSignedSerial);
BENCHMARK(MempoolAdmissionSignedStaged1);
BENCHMARK(MempoolAdmissionSignedStaged4);
BENCHMARK(MempoolAdmissionSignedStaged8);
BENCHMARK(MempoolAdmissionSignedStagedAll);
