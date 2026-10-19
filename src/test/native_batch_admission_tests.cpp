// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <config.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/transaction.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(native_batch_admission_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(capacity_rejection_preserves_existing_native_transactions) {
    const std::vector<uint8_t> program{0x4e};
    lotus::v2::Output output;
    output.value = 100000;
    output.branches = {lotus::v2::BranchLeaf(program)};
    output.paths = {{0}};
    const CTxOut funding = CTxOut::FromV2Output(output);
    auto &chainstate = m_node.chainman->ActiveChainstate();
    std::vector<CTransactionRef> transactions;
    const std::array<const char *, 3> ids{"1001", "1002", "1003"};
    const std::array<int64_t, 3> fees{4000, 2000, 1000};
    {
        LOCK(cs_main);
        for (size_t i = 0; i < ids.size(); ++i) {
            const COutPoint prevout(TxId(uint256S(ids[i])), 0);
            chainstate.CoinsTip().AddCoin(prevout, Coin(funding, 100, false), false);
            CMutableTransaction tx;
            tx.nVersion = 7;
            tx.nV2Lock = 0;
            CTxIn input(prevout);
            input.nFlags = 1;
            input.nPathIndex = 0;
            lotus::v2::BranchWitness witness;
            witness.script = program;
            input.vWitnesses = {witness};
            tx.vin.push_back(std::move(input));
            auto next = output;
            next.value -= fees[i];
            tx.vout.push_back(CTxOut::FromV2Output(next));
            transactions.push_back(MakeTransactionRef(std::move(tx)));
        }

        // Establish validity with the actual native admission path before
        // testing a capacity failure in a separate bounded pool.
        const auto control = ProcessRawTxBatch(chainstate, *m_node.mempool,
                                               transactions, true);
        BOOST_REQUIRE_MESSAGE(control.m_state.IsValid(), control.m_state.ToString());
        BOOST_REQUIRE_EQUAL(control.m_tx_results.size(), transactions.size());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    auto options = m_node.mempool->m_opts;
    options.signals = nullptr;
    size_t capacity;
    {
        CTxMemPool measured(GetConfig(), options);
        LOCK2(cs_main, measured.cs);
        for (size_t i = 0; i < 2; ++i) {
            measured.addUnchecked(TestMemPoolEntryHelper()
                                      .Fee(fees[i] * SATOSHI)
                                      .FromTx(transactions[i]));
        }
        capacity = measured.DynamicMemoryUsage();
    }
    options.max_size_bytes = capacity;
    CTxMemPool bounded(GetConfig(), options);
    {
        LOCK(cs_main);
        const auto existing = ProcessRawTxBatch(chainstate, bounded,
                                                {transactions[0]}, false);
        BOOST_REQUIRE_MESSAGE(existing.m_state.IsValid(), existing.m_state.ToString());
        BOOST_REQUIRE_EQUAL(bounded.size(), 1U);
        const auto result = ProcessRawTxBatch(chainstate, bounded,
                                              {transactions[1], transactions[2]}, false);
        BOOST_CHECK(result.m_state.IsInvalid());
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "mempool full");
        BOOST_CHECK_EQUAL(bounded.size(), 1U);
        BOOST_CHECK(bounded.exists(transactions[0]->GetId()));
        BOOST_CHECK(!bounded.exists(transactions[1]->GetId()));
        BOOST_CHECK(!bounded.exists(transactions[2]->GetId()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
