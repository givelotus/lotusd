// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <policy/policy.h>
#include <core_io.h>
#include <kernel/disconnected_transactions.h>
#include <key_io.h>
#include <minerfund.h>
#include <node/snapshot.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <script/standard.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(rpc_batch_snapshot_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(testrawtxbatch_and_submitrawtxbatch_all_or_nothing) {
    GlobalConfig config;
    CKey parent_key;
    parent_key.MakeNewKey(true);
    CScript parent_spk =
        GetScriptForDestination(PKHash(parent_key.GetPubKey()));

    CKey child_key;
    child_key.MakeNewKey(true);
    CScript child_spk = GetScriptForDestination(PKHash(child_key.GetPubKey()));

    // Create a parent transaction and a child transaction spending the parent.
    const Amount cb_val = m_coinbase_txns[0]->vout[0].nValue;
    CMutableTransaction parent_mtx = CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey, parent_spk,
        cb_val - 2000 * SATOSHI, /*submit=*/false);
    CTransactionRef parent_tx = MakeTransactionRef(parent_mtx);

    CMutableTransaction child_mtx = CreateValidMempoolTransaction(
        parent_tx, 0, 101, parent_key, child_spk, cb_val - 4000 * SATOSHI,
        /*submit=*/false);
    CTransactionRef child_tx = MakeTransactionRef(child_mtx);

    // Also create an invalid transaction spending a nonexistent outpoint.
    CMutableTransaction invalid_mtx = child_mtx;
    invalid_mtx.vin[0].prevout = COutPoint(TxId(uint256::ONE), 0);
    CTransactionRef invalid_tx = MakeTransactionRef(invalid_mtx);

    const std::string parent_hex = EncodeHexTx(*parent_tx);
    const std::string child_hex = EncodeHexTx(*child_tx);
    const std::string invalid_hex = EncodeHexTx(*invalid_tx);

    // 1. testrawtxbatch([parent, child]) should succeed without mutating mempool.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "testrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(child_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_MESSAGE(res.find_value("allowed").get_bool(), res.write());
        const UniValue &results = res.find_value("results").get_array();
        BOOST_REQUIRE_EQUAL(results.size(), 2U);
        BOOST_CHECK_EQUAL(results[0].find_value("allowed").get_bool(), true);
        BOOST_CHECK_EQUAL(results[1].find_value("allowed").get_bool(), true);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 2. submitrawtxbatch([parent, invalid]) must reject the entire batch
    // (all-or-nothing) and leave mempool empty.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "submitrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(invalid_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_EQUAL(res.find_value("accepted").get_bool(), false);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 3. submitrawtxbatch([parent, child]) must accept both transactions and
    // update the RCU mempool snapshot.
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.strMethod = "submitrawtxbatch";
        UniValue arr(UniValue::VARR);
        arr.push_back(parent_hex);
        arr.push_back(child_hex);
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(std::move(arr));

        UniValue res = tableRPC.execute(config, req);
        BOOST_CHECK_EQUAL(res.find_value("accepted").get_bool(), true);
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 2U);

        JSONRPCRequest mp_req;
        mp_req.context = &m_node;
        mp_req.strMethod = "getrawmempool";
        mp_req.params = UniValue(UniValue::VARR);
        UniValue raw_mp = tableRPC.execute(config, mp_req);
        BOOST_CHECK_EQUAL(raw_mp.get_array().size(), 2U);
    }

}

BOOST_AUTO_TEST_CASE(atomic_batch_rejects_capacity_without_partial_admission) {
    const CScript spk = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    const Amount value = m_coinbase_txns[0]->vout[0].nValue;
    const auto parent = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey, spk, value - 2000 * SATOSHI, false));
    const auto child = MakeTransactionRef(CreateValidMempoolTransaction(
        parent, 0, 101, coinbaseKey, spk, value - 4000 * SATOSHI, false));
    auto options = m_node.mempool->m_opts;
    options.max_size_bytes = 1;
    CTxMemPool small_pool(GetConfig(), options);
    {
        LOCK(cs_main);
        const auto result = ProcessRawTxBatch(m_node.chainman->ActiveChainstate(),
                                              small_pool, {parent, child}, false);
        BOOST_CHECK(!result.m_state.IsValid());
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "mempool full");
    }
    BOOST_CHECK_EQUAL(small_pool.size(), 0U);
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}

BOOST_AUTO_TEST_CASE(atomic_batch_capacity_accounts_for_parent_child_links) {
    CMutableTransaction parent;
    parent.vin.emplace_back(COutPoint(TxId(uint256S("1234")), 0));
    parent.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    parent.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    CMutableTransaction child;
    child.vin.emplace_back(COutPoint(parent.GetId(), 0));
    child.vin.emplace_back(COutPoint(parent.GetId(), 1));
    child.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    auto options = m_node.mempool->m_opts;
    options.signals = nullptr;
    size_t measured_usage;
    {
        CTxMemPool measured(GetConfig(), options);
        LOCK2(cs_main, measured.cs);
        measured.addUnchecked(TestMemPoolEntryHelper().FromTx(parent));
        measured.addUnchecked(TestMemPoolEntryHelper().FromTx(child));
        measured_usage = measured.DynamicMemoryUsage();
    }
    for (const bool exact_fit : {false, true}) {
        options.max_size_bytes = measured_usage - (exact_fit ? 0 : 1);
        CTxMemPool bounded(GetConfig(), options);
        LOCK2(cs_main, bounded.cs);
        bounded.addUnchecked(TestMemPoolEntryHelper().FromTx(parent));
        auto entry = TestMemPoolEntryHelper().FromTx(child);
        BOOST_CHECK_EQUAL(bounded.CanFitRawTxBatch({entry.get()}), exact_fit);
        BOOST_CHECK_EQUAL(bounded.size(), 1U);
        if (exact_fit) {
            bounded.addUnchecked(entry);
            BOOST_CHECK_EQUAL(bounded.DynamicMemoryUsage(), measured_usage);
        }
    }
}

BOOST_AUTO_TEST_CASE(parallel_batch_decode_reports_earliest_error_without_admission) {
    GlobalConfig config;
    const auto tx = CreateValidMempoolTransaction(m_coinbase_txns[0], 0, 1,
        coinbaseKey, GetScriptForRawPubKey(coinbaseKey.GetPubKey()),
        m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI, false);
    JSONRPCRequest req;
    req.context = &m_node; req.strMethod = "submitrawtxbatch";
    req.params = UniValue(UniValue::VARR);
    UniValue batch(UniValue::VARR);
    for (size_t i = 0; i < 40; ++i) {
        batch.push_back(i == 7 ? "badhex-at-seven" :
                       i == 35 ? "badhex-at-thirtyfive" : EncodeHexTx(CTransaction(tx)));
    }
    req.params.push_back(std::move(batch));
    BOOST_CHECK_EXCEPTION(tableRPC.execute(config, req), UniValue, [](const UniValue &e) {
        return e.find_value("message").get_str() == "TX decode failed: badhex-at-seven";
    });
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
}


BOOST_AUTO_TEST_CASE(batch_decode_preserves_order_after_reused_worker_failures) {
    GlobalConfig config;
    std::vector<std::string> hexes, ids;
    for (size_t i = 0; i < 40; ++i) {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.emplace_back(COutPoint(TxId(uint256::ONE), uint32_t(i)));
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        const auto immutable = MakeTransactionRef(std::move(tx));
        hexes.push_back(EncodeHexTx(*immutable));
        ids.push_back(immutable->GetId().GetHex());
    }
    for (const auto *method : {"testrawtxbatch", "submitrawtxbatch"}) {
        for (unsigned pass = 0; pass < 4; ++pass) {
            JSONRPCRequest req;
            req.context = &m_node;
            req.strMethod = method;
            req.params = UniValue(UniValue::VARR);
            UniValue batch(UniValue::VARR);
            for (size_t i = 0; i < hexes.size(); ++i) {
                batch.push_back(pass % 2 && i == 3 ? "bad-first" :
                                pass % 2 && i == 35 ? "bad-later" : hexes[i]);
            }
            req.params.push_back(std::move(batch));
            if (pass % 2) {
                BOOST_CHECK_EXCEPTION(tableRPC.execute(config, req), UniValue,
                    [](const UniValue &error) {
                        return error.find_value("message").get_str() ==
                               "TX decode failed: bad-first";
                    });
            } else {
                const auto result = tableRPC.execute(config, req);
                const auto &rows = result.find_value("results").get_array();
                BOOST_REQUIRE_EQUAL(rows.size(), ids.size());
                for (size_t i = 0; i < ids.size(); ++i) {
                    BOOST_CHECK_EQUAL(rows[i].find_value("txid").get_str(), ids[i]);
                }
            }
            BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
        }
    }
}

BOOST_AUTO_TEST_CASE(batch_resolved_inputs_consensus_differential) {
    FastRandomContext rng(true);
    auto options = m_node.mempool->m_opts;
    options.require_standard = false;
    CTxMemPool pool(GetConfig(), options);
    LOCK(cs_main);
    auto &chainstate = m_node.chainman->ActiveChainstate();
    CBlockIndex *tip = chainstate.m_chain.Tip();
    CBlockIndex next;
    next.pprev = tip;
    next.nHeight = tip->nHeight + 1;
    for (unsigned trial = 0; trial < 500; ++trial) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        std::vector<int> heights;
        const unsigned count = 1 + rng.randrange(4);
        for (unsigned i = 0; i < count; ++i) {
            const COutPoint op{TxId(rng.rand256()), i};
            uint32_t sequence = rng.randrange(128);
            if (trial % 3 == 0) sequence |= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
            if (trial % 7 == 0) sequence |= CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
            mtx.vin.emplace_back(op, CScript(), sequence);
            const unsigned height = rng.randrange(tip->nHeight + 1);
            heights.push_back(height);
            chainstate.CoinsTip().AddCoin(op,
                Coin{CTxOut{1000000 * SATOSHI, CScript() << OP_TRUE},
                     height, trial % 11 == 0}, false);
        }
        mtx.vout.emplace_back(static_cast<int64_t>(count * 1000000 - 10000) * SATOSHI,
                              CScript() << std::vector<uint8_t>(80, 0)
                                        << OP_DROP << OP_TRUE);
        const auto tx = MakeTransactionRef(mtx);
        TxValidationState expected_state;
        Amount expected_fee{};
        const bool expected = SequenceLocks(*tx, STANDARD_LOCKTIME_VERIFY_FLAGS,
                                             heights, next) &&
            Consensus::CheckTxInputs(*tx, expected_state, chainstate.CoinsTip(),
                                     next.nHeight, expected_fee);
        const auto result = ProcessRawTxBatch(chainstate, pool, {tx}, true);
        const auto it = result.m_tx_results.find(tx->GetId());
        BOOST_REQUIRE(it != result.m_tx_results.end());
        BOOST_CHECK_EQUAL(it->second.m_result_type ==
                          MempoolAcceptResult::ResultType::VALID, expected);
        BOOST_CHECK_EQUAL(pool.size(), 0U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
