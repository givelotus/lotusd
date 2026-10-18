// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>
#include <rpc/mempool.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

#include <univalue.h>

static void AddTx(const CTransactionRef &tx, const Amount &fee,
                  CTxMemPool &pool) EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
    LockPoints lp;
    pool.addUnchecked(CTxMemPoolEntryRef::make(tx, fee, /*time=*/0,
                                               /*height=*/1,
                                               /*_sigChecks=*/1, lp));
}

static void RpcMempool(benchmark::Bench &bench) {
    const TestingSetup test_setup{
        ChainType::MAIN,
        /* extra_args */
        {
            "-nodebuglogfile",
            "-nodebug",
        },
    };
    CTxMemPool &pool = *Assert(test_setup.m_node.mempool);
    LOCK2(cs_main, pool.cs);

    for (int i = 0; i < 1000; ++i) {
        CMutableTransaction tx = CMutableTransaction();
        tx.vin.resize(1);
        tx.vin[0].scriptSig = CScript() << OP_1;
        tx.vout.resize(1);
        tx.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
        tx.vout[0].nValue = i * COIN;
        const CTransactionRef tx_r{MakeTransactionRef(tx)};
        AddTx(tx_r, /* fee */ i * COIN, pool);
    }

    bench.run([&] { (void)MempoolToJSON(pool, /*verbose*/ true); });
}

static void RpcMempoolInfo(benchmark::Bench &bench) {
    const TestingSetup test_setup{
        ChainType::MAIN,
        /* extra_args */
        {
            "-nodebuglogfile",
            "-nodebug",
        },
    };
    CTxMemPool &pool = *Assert(test_setup.m_node.mempool);
    {
        LOCK2(cs_main, pool.cs);
        for (int i = 0; i < 1000; ++i) {
            CMutableTransaction tx = CMutableTransaction();
            tx.vin.resize(1);
            tx.vin[0].scriptSig = CScript() << OP_1;
            tx.vout.resize(1);
            tx.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
            tx.vout[0].nValue = i * COIN;
            const CTransactionRef tx_r{MakeTransactionRef(tx)};
            AddTx(tx_r, /* fee */ i * COIN, pool);
        }
    }

    bench.run([&] {
        auto info = MempoolInfoToJSON(pool);
        ankerl::nanobench::doNotOptimizeAway(info);
    });
}

static void MempoolAcceptSingleBatch32(benchmark::Bench &bench) {
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(
        ChainType::REGTEST, {"-nodebuglogfile", "-nodebug"});
    Chainstate &active_chainstate =
        testing_setup->m_node.chainman->ActiveChainstate();
    CScript dest = GetScriptForDestination(PKHash(testing_setup->coinbaseKey.GetPubKey()));

    std::vector<CTransactionRef> batch;
    batch.reserve(32);
    for (size_t i = 0; i < 32; ++i) {
        const auto &cb = testing_setup->m_coinbase_txns[i];
        CMutableTransaction mtx = testing_setup->CreateValidMempoolTransaction(
            cb, 0, static_cast<int>(i + 1), testing_setup->coinbaseKey, dest,
            cb->vout[0].nValue - 2000 * SATOSHI, /*submit=*/false);
        batch.push_back(MakeTransactionRef(mtx));
    }

    bench.batch(batch.size()).unit("tx").run([&] {
        LOCK(cs_main);
        for (const auto &tx : batch) {
            auto res = AcceptToMemoryPool(active_chainstate, tx, GetTime(),
                                          /*bypass_limits=*/false,
                                          /*test_accept=*/true);
            bool ok = res.m_state.IsValid();
            ankerl::nanobench::doNotOptimizeAway(ok);
        }
    });
}

static void MempoolAcceptCoalescedBatch32(benchmark::Bench &bench) {
    auto testing_setup = MakeNoLogFileContext<TestChain100Setup>(
        ChainType::REGTEST, {"-nodebuglogfile", "-nodebug"});
    Chainstate &active_chainstate =
        testing_setup->m_node.chainman->ActiveChainstate();
    CTxMemPool &pool = *Assert(testing_setup->m_node.mempool);
    CScript dest = GetScriptForDestination(PKHash(testing_setup->coinbaseKey.GetPubKey()));

    std::vector<CTransactionRef> batch;
    batch.reserve(32);
    for (size_t i = 0; i < 32; ++i) {
        const auto &cb = testing_setup->m_coinbase_txns[i];
        CMutableTransaction mtx = testing_setup->CreateValidMempoolTransaction(
            cb, 0, static_cast<int>(i + 1), testing_setup->coinbaseKey, dest,
            cb->vout[0].nValue - 2000 * SATOSHI, /*submit=*/false);
        batch.push_back(MakeTransactionRef(mtx));
    }

    bench.batch(batch.size()).unit("tx").run([&] {
        LOCK(cs_main);
        auto res = ProcessRawTxBatch(active_chainstate, pool, batch,
                                     /*test_accept=*/true);
        bool ok = res.m_state.IsValid();
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

BENCHMARK(RpcMempool);
BENCHMARK(RpcMempoolInfo);
BENCHMARK(MempoolAcceptSingleBatch32);
BENCHMARK(MempoolAcceptCoalescedBatch32);
