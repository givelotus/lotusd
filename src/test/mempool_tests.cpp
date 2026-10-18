// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>
#include <test/util/logging.h>
#include <node/snapshot.h>

#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <mempool_args.h>
#include <consensus/tx_verify.h>
#include <kernel/disconnected_transactions.h>
#include <kernel/mempool_entry.h>
#include <logging.h>
#include <policy/settings.h>
#include <reverse_iterator.h>
#include <univalue.h>
#include <util/time.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mempool_tests, TestingSetup)

static constexpr auto REMOVAL_REASON_DUMMY = MemPoolRemovalReason::CONFLICT;

BOOST_AUTO_TEST_CASE(optional_consistency_check_default_and_override) {
    // Native fixtures deliberately keep checking every mutation. Startup's
    // mempool-specific default must not change the block-index diagnostic.
    BOOST_CHECK_EQUAL(m_node.mempool->m_opts.check_ratio, 1);
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        ArgsManager args;
        args.AddArg("-checkmempool=<n>", "", ArgsManager::ALLOW_ANY,
                    OptionsCategory::DEBUG_TEST);
        const auto params{CreateChainParams(args, chain)};
        BOOST_CHECK_EQUAL(params->DefaultConsistencyChecks(), chain == ChainType::REGTEST);
        CTxMemPool::Options options;
        BOOST_CHECK_EQUAL(options.check_ratio, 0);
        BOOST_CHECK(!ApplyArgsManOptions(args, *params, options));
        BOOST_CHECK_EQUAL(options.check_ratio, 0);
        for (const int ratio : {1, 17, 0}) {
            args.ForceSetArg("-checkmempool", std::to_string(ratio));
            BOOST_CHECK(!ApplyArgsManOptions(args, *params, options));
            BOOST_CHECK_EQUAL(options.check_ratio, ratio);
        }
    }
}

BOOST_AUTO_TEST_CASE(optional_consistency_check_long_chain_repeated_parent_inputs) {
    CTxMemPool pool{GetConfig(), CTxMemPool::Options{.check_ratio = 1}};
    LOCK2(cs_main, pool.cs);
    CCoinsView view;
    CCoinsViewCache coins{&view};
    const COutPoint funding{TxId{uint256{uint8_t(1)}}, 0};
    coins.AddCoin(funding, Coin{CTxOut{100000 * SATOSHI, CScript() << OP_TRUE},
                              1, false}, false);
    TestMemPoolEntryHelper entry;
    entry.SigChecks(0);
    std::vector<CTransactionRef> chain;
    CMutableTransaction tx;
    tx.vin.emplace_back(funding);
    Amount value{100000 * SATOSHI};
    for (size_t i{0}; i < 512; ++i) {
        value -= SATOSHI;
        tx.vout = {CTxOut{value - SATOSHI, CScript() << OP_TRUE},
                   CTxOut{SATOSHI, CScript() << OP_TRUE}};
        chain.push_back(MakeTransactionRef(tx));
        pool.addUnchecked(entry.Fee(SATOSHI).FromTx(chain.back()));
        tx.vin.clear();
        tx.vin.emplace_back(chain.back()->GetId(), 0);
        tx.vin.emplace_back(chain.back()->GetId(), 1);
    }
    BOOST_REQUIRE_EQUAL(pool.size(), chain.size());
    for (const auto &item : pool.mapTx.get<entry_id>()) {
        if (item->GetTx().GetId() == chain.front()->GetId()) continue;
        BOOST_CHECK_EQUAL(item->GetMemPoolParentsConst().size(), 1U);
    }
    // Direct calls execute the real checker independently of startup defaults.
    pool.check(coins, 2);
    pool.removeRecursive(*chain[256], REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(pool.size(), 256U);
    pool.check(coins, 2);
    for (size_t i{256}; i < chain.size(); ++i)
        pool.addUnchecked(entry.Fee(SATOSHI).FromTx(chain[i]));
    pool.check(coins, 2);
    pool.removeRecursive(*chain.front(), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    pool.check(coins, 2);
}

BOOST_AUTO_TEST_CASE(optional_consistency_check_diamond_mined_parent_and_reaccept) {
    CTxMemPool pool{GetConfig(), CTxMemPool::Options{.check_ratio = 1}};
    LOCK2(cs_main, pool.cs);
    CCoinsView view;
    CCoinsViewCache coins{&view};
    const COutPoint funding{TxId{uint256{uint8_t(2)}}, 0};
    const CTxOut funded{100000 * SATOSHI, CScript() << OP_TRUE};
    coins.AddCoin(funding, Coin{CTxOut{funded}, 1, false}, false);
    TestMemPoolEntryHelper entry;
    entry.SigChecks(0);
    const auto make_tx = [&](std::vector<COutPoint> inputs,
                             std::vector<Amount> amounts) {
        CMutableTransaction tx;
        for (const auto &input : inputs) tx.vin.emplace_back(input);
        for (const auto amount : amounts)
            tx.vout.emplace_back(amount, CScript() << OP_TRUE);
        return MakeTransactionRef(tx);
    };
    const auto root{make_tx({funding}, {60000 * SATOSHI, 39000 * SATOSHI})};
    const auto left{make_tx({COutPoint{root->GetId(), 0}},
                            {20000 * SATOSHI, 39000 * SATOSHI})};
    const auto right{make_tx({COutPoint{root->GetId(), 1}}, {38000 * SATOSHI})};
    const auto join{make_tx({COutPoint{left->GetId(), 0}, COutPoint{left->GetId(), 1},
                             COutPoint{right->GetId(), 0}}, {96000 * SATOSHI})};
    const std::vector<CTransactionRef> graph{root, left, right, join};
    for (const auto &tx : graph) pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
    BOOST_CHECK_EQUAL((*pool.mapTx.find(join->GetId()))->GetMemPoolParentsConst().size(), 2U);
    pool.check(coins, 2);
    pool.removeRecursive(*left, REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(pool.size(), 2U); // root and right survive the diamond cut.
    pool.check(coins, 2);
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(left));
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(join));
    pool.check(coins, 2);

    // Actual block-removal API changes a mempool parent into confirmed coins.
    DisconnectedBlockTransactions disconnected;
    disconnected.removeForBlock({root}, pool);
    BOOST_CHECK_EQUAL(pool.size(), 3U);
    BOOST_CHECK(coins.SpendCoin(funding));
    AddCoins(coins, *root, 2);
    pool.check(coins, 3);

    // Recreate the disconnected coin view and reaccept in parent-first order.
    // This checks graph rebuilding, not transaction admission or chain consensus.
    for (const auto &tx : graph) pool.removeRecursive(*tx, REMOVAL_REASON_DUMMY);
    BOOST_CHECK(coins.SpendCoin(COutPoint{root->GetId(), 0}));
    BOOST_CHECK(coins.SpendCoin(COutPoint{root->GetId(), 1}));
    coins.AddCoin(funding, Coin{CTxOut{funded}, 1, false}, false);
    for (const auto &tx : graph) pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
    BOOST_CHECK_EQUAL(pool.size(), 4U);
    pool.check(coins, 2);
}

BOOST_AUTO_TEST_CASE(
    logging_finalization_missing_transaction_keeps_id_and_state) {
    LogInstance().Flush();
    struct RestoreFormat {
        BCLog::LogFormat previous{LogInstance().m_log_format};
        ~RestoreFormat() {
            LogInstance().Flush();
            LogInstance().m_log_format = previous;
        }
    } restore;
    LogInstance().m_log_format = BCLog::LogFormat::JSON;
    CTxMemPool &pool = *Assert(m_node.mempool);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    CMutableTransaction tx;
    tx.vin.emplace_back(TxId{uint256{uint8_t(41)}}, 0);
    tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    const auto transaction{MakeTransactionRef(tx)};
    const auto entry{TestMemPoolEntryHelper().FromTx(transaction)};
    std::string rendered;
    {
        DebugLogHelper capture("mempool_finalization_transaction_missing",
                               [&](const std::string *line) {
                                   if (line) rendered = *line;
                                   return false; // Check missing capture as a
                                                 // normal test assertion.
                               });
        LOCK2(cs_main, pool.cs);
        std::vector<TxId> finalized;
        BOOST_CHECK(!pool.setAvalancheFinalized(
            entry, chainman.GetConsensus(), *Assert(chainman.ActiveTip()),
            chainman.ActiveChainstate(), finalized));
        BOOST_CHECK(finalized.empty());
        BOOST_CHECK_EQUAL(pool.size(), 0U);
    } // DebugLogHelper flushes the async consumer before inspecting its result.
    UniValue row;
    BOOST_REQUIRE(row.read(rendered));
    BOOST_CHECK_EQUAL(row["event"].get_str(),
                      "mempool_finalization_transaction_missing");
    BOOST_CHECK_EQUAL(row["txid"].get_str(), transaction->GetId().ToString());
    BOOST_CHECK_EQUAL(row["message"].get_str(),
                      "Trying to finalize tx " +
                          transaction->GetId().ToString() +
                          " that is not in the mempool");
    BOOST_CHECK_EQUAL(row["level"].get_str(), "info");
    BOOST_CHECK(row["fields_truncated"].isNull());
}

BOOST_AUTO_TEST_CASE(MempoolRemoveTest) {
    // Test CTxMemPool::remove functionality

    TestMemPoolEntryHelper entry;
    // Parent transaction with three children, and three grand-children:
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++) {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000 * SATOSHI;
    }
    CMutableTransaction txChild[3];
    for (int i = 0; i < 3; i++) {
        txChild[i].vin.resize(1);
        txChild[i].vin[0].scriptSig = CScript() << OP_11;
        txChild[i].vin[0].prevout = COutPoint(txParent.GetId(), i);
        txChild[i].vout.resize(1);
        txChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txChild[i].vout[0].nValue = 11000 * SATOSHI;
    }
    CMutableTransaction txGrandChild[3];
    for (int i = 0; i < 3; i++) {
        txGrandChild[i].vin.resize(1);
        txGrandChild[i].vin[0].scriptSig = CScript() << OP_11;
        txGrandChild[i].vin[0].prevout = COutPoint(txChild[i].GetId(), 0);
        txGrandChild[i].vout.resize(1);
        txGrandChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txGrandChild[i].vout[0].nValue = 11000 * SATOSHI;
    }

    CTxMemPool &testPool = *Assert(m_node.mempool);
    LOCK2(::cs_main, testPool.cs);

    // Nothing in pool, remove should do nothing:
    unsigned int poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);

    // Just the parent:
    testPool.addUnchecked(entry.FromTx(txParent));
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 1);

    // Parent, children, grandchildren:
    testPool.addUnchecked(entry.FromTx(txParent));
    for (int i = 0; i < 3; i++) {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Remove Child[0], GrandChild[0] should be removed:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txChild[0]), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 2);
    // ... make sure grandchild and child are gone:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txGrandChild[0]),
                             REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txChild[0]), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    // Remove parent, all children/grandchildren should go:
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 5);
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);

    // Add children and grandchildren, but NOT the parent (simulate the parent
    // being in a block)
    for (int i = 0; i < 3; i++) {
        testPool.addUnchecked(entry.FromTx(txChild[i]));
        testPool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }

    // Now remove the parent, as might happen if a block-re-org occurs but the
    // parent cannot be put into the mempool (maybe because it is non-standard):
    poolSize = testPool.size();
    testPool.removeRecursive(CTransaction(txParent), REMOVAL_REASON_DUMMY);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 6);
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);
}

BOOST_AUTO_TEST_CASE(MempoolClearTest) {
    // Test CTxMemPool::clear functionality

    TestMemPoolEntryHelper entry;
    // Create a transaction
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++) {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000 * SATOSHI;
    }

    CTxMemPool &testPool = *Assert(m_node.mempool);
    LOCK2(cs_main, testPool.cs);

    // Nothing in pool, clear should do nothing:
    testPool.clear();
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);

    // Add the transaction
    testPool.addUnchecked(entry.FromTx(txParent));
    BOOST_CHECK_EQUAL(testPool.size(), 1UL);
    BOOST_CHECK_EQUAL(testPool.mapTx.size(), 1UL);
    BOOST_CHECK_EQUAL(testPool.mapNextTx.size(), 1UL);

    // CTxMemPool's members should be empty after a clear
    testPool.clear();
    BOOST_CHECK_EQUAL(testPool.size(), 0UL);
    BOOST_CHECK_EQUAL(testPool.mapTx.size(), 0UL);
    BOOST_CHECK_EQUAL(testPool.mapNextTx.size(), 0UL);
}

template <typename name>
static void CheckSort(CTxMemPool &pool, std::vector<std::string> &sortedOrder,
                      const std::string &testcase)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs) {
    BOOST_CHECK_EQUAL(pool.size(), sortedOrder.size());
    typename CTxMemPool::indexed_transaction_set::index<name>::type::iterator
        it = pool.mapTx.get<name>().begin();
    int count = 0;
    for (; it != pool.mapTx.get<name>().end(); ++it, ++count) {
        BOOST_CHECK_MESSAGE((*it)->GetTx().GetId().ToString() ==
                                sortedOrder[count],
                            (*it)->GetTx().GetId().ToString()
                                << " != " << sortedOrder[count] << " in test "
                                << testcase << ":" << count);
    }
}

BOOST_AUTO_TEST_CASE(MempoolIndexingTest) {
    CTxMemPool &pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    /**
     * Remove the default nonzero sigChecks, since the below tests are
     * focussing on fee-based ordering and involve some artificially very tiny
     * 21-byte transactions without any inputs.
     */
    entry.SigChecks(0);

    /* 3rd highest fee */
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;

    /* highest fee */
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(entry.Fee(20000 * SATOSHI).FromTx(tx2));

    /* lowest fee */
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(entry.Fee(Amount::zero()).FromTx(tx3));

    /* 2nd highest fee */
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(entry.Fee(15000 * SATOSHI).FromTx(tx4));

    /* equal fee rate to tx1, but arrived later to the mempool */
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    pool.addUnchecked(entry.Fee(10000 * SATOSHI).Time(100).FromTx(tx1));
    pool.addUnchecked(entry.Fee(10000 * SATOSHI).Time(200).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5UL);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx2.GetId().ToString(); // 20000
    sortedOrder[1] = tx4.GetId().ToString(); // 15000
    sortedOrder[3] = tx5.GetId().ToString(); // 10000
    sortedOrder[2] = tx1.GetId().ToString(); // 10000
    sortedOrder[4] = tx3.GetId().ToString(); // 0
    CheckSort<modified_feerate>(pool, sortedOrder, "MempoolIndexingTest1");
}

BOOST_AUTO_TEST_CASE(MempoolSizeLimitTest) {
    CTxMemPool &pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    Amount feeIncrement = MEMPOOL_FULL_FEE_INCREMENT.GetFeePerK();
    // Fee-eviction ratios apply to removable per-transaction memory. Slab
    // chunks/bucket arrays are real retained storage, not a per-node expense;
    // a fraction of the whole arena can be below the cost of even one node.
    auto fraction_limit = [&pool](size_t numerator, size_t denominator)
        EXCLUSIVE_LOCKS_REQUIRED(pool.cs) {
        const size_t retained =
            pool.mapTx.get_allocator().resource()->TotalAllocatedBytes() +
            pool.mapNextTx.get_allocator().resource()->TotalAllocatedBytes();
        const size_t usage = pool.DynamicMemoryUsage();
        BOOST_REQUIRE_GE(usage, retained);
        return retained + (usage - retained) * numerator / denominator;
    };

    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vin.resize(1);
    tx1.vin[0].scriptSig = CScript() << OP_1;
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_1 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(20000 * SATOSHI).FromTx(tx1));

    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vin.resize(1);
    tx2.vin[0].scriptSig = CScript() << OP_2;
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_2 << OP_EQUAL;
    tx2.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(4000 * SATOSHI).FromTx(tx2));

    // should do nothing
    pool.TrimToSize(pool.DynamicMemoryUsage());
    BOOST_CHECK(pool.exists(tx1.GetId()));
    BOOST_CHECK(pool.exists(tx2.GetId()));

    // should remove the lower-feerate transaction
    pool.TrimToSize(fraction_limit(3, 4));
    BOOST_CHECK(pool.exists(tx1.GetId()));
    BOOST_CHECK(!pool.exists(tx2.GetId()));

    pool.addUnchecked(entry.FromTx(tx2));
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vin.resize(1);
    tx3.vin[0].prevout = COutPoint(tx2.GetId(), 0);
    tx3.vin[0].scriptSig = CScript() << OP_2;
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_3 << OP_EQUAL;
    tx3.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(entry.Fee(16000 * SATOSHI).FromTx(tx3));

    // tx2 should be removed, tx3 is a child of tx2, so it should be removed
    // even though it has highest fee.
    pool.TrimToSize(fraction_limit(3, 4));
    BOOST_CHECK(pool.exists(tx1.GetId()));
    BOOST_CHECK(!pool.exists(tx2.GetId()));
    BOOST_CHECK(!pool.exists(tx3.GetId()));

    // mempool is limited to tx1's size in memory usage, so nothing fits
    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(CTransaction(tx1).GetTotalSize(), &vNoSpendsRemaining);
    BOOST_CHECK(!pool.exists(tx1.GetId()));
    BOOST_CHECK(!pool.exists(tx2.GetId()));
    BOOST_CHECK(!pool.exists(tx3.GetId()));
    // This vector should only contain 'root' (not unconfirmed) outpoints
    // Though both tx2 and tx3 were removed, tx3's input came from tx2.
    BOOST_CHECK_EQUAL(vNoSpendsRemaining.size(), 1);
    BOOST_CHECK(vNoSpendsRemaining == std::vector<COutPoint>{COutPoint()});

    // maxFeeRateRemoved was set by the transaction with the highest fee,
    // that was not removed because it was a child of another tx.
    CFeeRate maxFeeRateRemoved(20000 * SATOSHI,
                               CTransaction(tx1).GetTotalSize());
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(),
                      maxFeeRateRemoved.GetFeePerK() + feeIncrement);

    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vin.resize(2);
    tx4.vin[0].prevout = COutPoint();
    tx4.vin[0].scriptSig = CScript() << OP_4;
    tx4.vin[1].prevout = COutPoint();
    tx4.vin[1].scriptSig = CScript() << OP_4;
    tx4.vout.resize(2);
    tx4.vout[0].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[0].nValue = 10 * COIN;
    tx4.vout[1].scriptPubKey = CScript() << OP_4 << OP_EQUAL;
    tx4.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vin.resize(2);
    tx5.vin[0].prevout = COutPoint(tx4.GetId(), 0);
    tx5.vin[0].scriptSig = CScript() << OP_4;
    tx5.vin[1].prevout = COutPoint();
    tx5.vin[1].scriptSig = CScript() << OP_5;
    tx5.vout.resize(2);
    tx5.vout[0].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[0].nValue = 10 * COIN;
    tx5.vout[1].scriptPubKey = CScript() << OP_5 << OP_EQUAL;
    tx5.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vin.resize(2);
    tx6.vin[0].prevout = COutPoint(tx4.GetId(), 1);
    tx6.vin[0].scriptSig = CScript() << OP_4;
    tx6.vin[1].prevout = COutPoint();
    tx6.vin[1].scriptSig = CScript() << OP_6;
    tx6.vout.resize(2);
    tx6.vout[0].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[0].nValue = 10 * COIN;
    tx6.vout[1].scriptPubKey = CScript() << OP_6 << OP_EQUAL;
    tx6.vout[1].nValue = 10 * COIN;

    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(2);
    tx7.vin[0].prevout = COutPoint(tx5.GetId(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_5;
    tx7.vin[1].prevout = COutPoint(tx6.GetId(), 0);
    tx7.vin[1].scriptSig = CScript() << OP_6;
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_7 << OP_EQUAL;
    tx7.vout[1].nValue = 10 * COIN;

    pool.addUnchecked(entry.Fee(7000 * SATOSHI).FromTx(tx4));
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx5));
    pool.addUnchecked(entry.Fee(1100 * SATOSHI).FromTx(tx6));
    pool.addUnchecked(entry.Fee(9000 * SATOSHI).FromTx(tx7));

    // we only require this to remove, at max, 2 txn, because it's not clear
    // what we're really optimizing for aside from that
    pool.TrimToSize(pool.DynamicMemoryUsage() - 1);
    BOOST_CHECK(pool.exists(tx4.GetId()));
    BOOST_CHECK(pool.exists(tx6.GetId()));
    BOOST_CHECK(!pool.exists(tx7.GetId()));

    if (!pool.exists(tx5.GetId())) {
        pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx5));
    }
    pool.addUnchecked(entry.Fee(9000 * SATOSHI).FromTx(tx7));

    // should maximize mempool size by only removing 5/7
    pool.TrimToSize(fraction_limit(1, 2));
    BOOST_CHECK(pool.exists(tx4.GetId()));
    BOOST_CHECK(!pool.exists(tx5.GetId()));
    BOOST_CHECK(pool.exists(tx6.GetId()));
    BOOST_CHECK(!pool.exists(tx7.GetId()));

    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx5));
    pool.addUnchecked(entry.Fee(9000 * SATOSHI).FromTx(tx7));

    std::vector<CTransactionRef> vtx;
    SetMockTime(42);
    SetMockTime(42 + CTxMemPool::ROLLING_FEE_HALFLIFE);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(),
                      maxFeeRateRemoved.GetFeePerK() + feeIncrement);
    // ... we should keep the same min fee until we get a block
    DisconnectedBlockTransactions disconnectedBlockTxs;
    disconnectedBlockTxs.removeForBlock(vtx, pool);
    SetMockTime(42 + 2 * CTxMemPool::ROLLING_FEE_HALFLIFE);
    BOOST_CHECK_EQUAL(pool.GetMinFee(1).GetFeePerK(),
                      (maxFeeRateRemoved.GetFeePerK() + feeIncrement) / 2);
    // ... then feerate should drop 1/2 each halflife

    SetMockTime(42 + 2 * CTxMemPool::ROLLING_FEE_HALFLIFE +
                CTxMemPool::ROLLING_FEE_HALFLIFE / 2);

    BOOST_CHECK_EQUAL(
        pool.GetMinFee(pool.DynamicMemoryUsage() * 5 / 2).GetFeePerK(),
        (maxFeeRateRemoved.GetFeePerK() + feeIncrement) / 4);
    // ... with a 1/2 halflife when mempool is < 1/2 its target size

    SetMockTime(42 + 2 * CTxMemPool::ROLLING_FEE_HALFLIFE +
                CTxMemPool::ROLLING_FEE_HALFLIFE / 2 +
                CTxMemPool::ROLLING_FEE_HALFLIFE / 4);
    BOOST_CHECK_EQUAL(
        pool.GetMinFee(pool.DynamicMemoryUsage() * 9 / 2).GetFeePerK(),
        (maxFeeRateRemoved.GetFeePerK() + feeIncrement) / 8 + SATOSHI);
    // ... with a 1/4 halflife when mempool is < 1/4 its target size
}

// expectedSize can be smaller than correctlyOrderedIds.size(), since we
// might be testing intermediary states. Just avoiding some slice operations,
void CheckDisconnectPoolOrder(DisconnectedBlockTransactions &disconnectPool,
                              std::vector<TxId> correctlyOrderedIds,
                              unsigned int expectedSize) {
    int i = 0;
    BOOST_CHECK_EQUAL(disconnectPool.GetQueuedTx().size(), expectedSize);
    // Txns in queuedTx's insertion_order index are sorted from children to
    // parent txn
    for (const CTransactionRef &tx :
         reverse_iterate(disconnectPool.GetQueuedTx().get<insertion_order>())) {
        BOOST_CHECK(tx->GetId() == correctlyOrderedIds[i]);
        i++;
    }
}

typedef std::vector<CMutableTransaction *> vecptx;

BOOST_AUTO_TEST_CASE(TestImportMempool) {
    CMutableTransaction chainedTxn[5];
    std::vector<TxId> correctlyOrderedIds;
    COutPoint lastOutpoint;

    // Construct a chain of 5 transactions
    for (int i = 0; i < 5; i++) {
        chainedTxn[i].vin.emplace_back(lastOutpoint);
        chainedTxn[i].vout.emplace_back(10 * SATOSHI, CScript() << OP_TRUE);
        correctlyOrderedIds.push_back(chainedTxn[i].GetId());
        lastOutpoint = COutPoint(correctlyOrderedIds[i], 0);
    }

    // The first 3 txns simulate once confirmed transactions that have been
    // disconnected. We test 3 different orders: in order, one case of mixed
    // order and inverted order.
    vecptx disconnectedTxnsInOrder = {&chainedTxn[0], &chainedTxn[1],
                                      &chainedTxn[2]};
    vecptx disconnectedTxnsMixedOrder = {&chainedTxn[1], &chainedTxn[2],
                                         &chainedTxn[0]};
    vecptx disconnectedTxnsInvertedOrder = {&chainedTxn[2], &chainedTxn[1],
                                            &chainedTxn[0]};

    // The last 2 txns simulate a chain of unconfirmed transactions in the
    // mempool. We test 2 different orders: in and out of order.
    vecptx unconfTxnsInOrder = {&chainedTxn[3], &chainedTxn[4]};
    vecptx unconfTxnsOutOfOrder = {&chainedTxn[4], &chainedTxn[3]};

    // Now we test all combinations of the previously defined orders for
    // disconnected and unconfirmed txns. The expected outcome is to have these
    // transactions in the correct order in queuedTx, as defined in
    // correctlyOrderedIds.
    for (auto &disconnectedTxns :
         {disconnectedTxnsInOrder, disconnectedTxnsMixedOrder,
          disconnectedTxnsInvertedOrder}) {
        for (auto &unconfTxns : {unconfTxnsInOrder, unconfTxnsOutOfOrder}) {
            CTxMemPool &testPool = *Assert(m_node.mempool);
            // addForBlock inserts disconnectTxns in disconnectPool. They
            // simulate transactions that were once confirmed in a block
            std::vector<CTransactionRef> vtx;
            vtx.reserve(disconnectedTxns.size());
            for (auto tx : disconnectedTxns) {
                vtx.push_back(MakeTransactionRef(*tx));
            }
            DisconnectedBlockTransactions disconnectPool;
            LOCK2(cs_main, testPool.cs);
            {
                disconnectPool.addForBlock(vtx, testPool);
                CheckDisconnectPoolOrder(disconnectPool, correctlyOrderedIds,
                                         disconnectedTxns.size());

                // If the mempool is empty, importMempool doesn't change
                // disconnectPool
                disconnectPool.importMempool(testPool);
                CheckDisconnectPoolOrder(disconnectPool, correctlyOrderedIds,
                                         disconnectedTxns.size());

                // Add all unconfirmed transactions in testPool
                for (auto tx : unconfTxns) {
                    TestMemPoolEntryHelper entry;
                    testPool.addUnchecked(entry.FromTx(*tx));
                }

                // Now we test importMempool with a non empty mempool
                disconnectPool.importMempool(testPool);
            }
            CheckDisconnectPoolOrder(disconnectPool, correctlyOrderedIds,
                                     disconnectedTxns.size() +
                                         unconfTxns.size());
            // We must clear disconnectPool to not trigger the assert in its
            // destructor
            disconnectPool.clear();
        }
    }
}

inline CTransactionRef
make_tx(std::vector<Amount> &&output_values,
        std::vector<CTransactionRef> &&inputs = std::vector<CTransactionRef>(),
        std::vector<uint32_t> &&input_indices = std::vector<uint32_t>()) {
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(inputs.size());
    tx.vout.resize(output_values.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.vin[i].prevout =
            COutPoint(inputs[i]->GetId(),
                      input_indices.size() > i ? input_indices[i] : 0);
    }
    for (size_t i = 0; i < output_values.size(); ++i) {
        tx.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        tx.vout[i].nValue = output_values[i];
    }
    return MakeTransactionRef(tx);
}

BOOST_AUTO_TEST_CASE(GetModifiedFeeRateTest) {
    CMutableTransaction tx = CMutableTransaction();
    tx.vin.resize(1);

    // Make tx exactly 1000 bytes.
    const size_t dummyDataSize =
        1000 - (GetSerializeSize(tx) + 5 /* OP_PUSHDATA2 and ?? */);

    tx.vin[0].scriptSig << std::vector<uint8_t>(dummyDataSize);
    assert(GetSerializeSize(tx) == 1000);

    TestMemPoolEntryHelper entry;

    auto entryNormal = entry.Fee(1000 * SATOSHI).FromTx(tx);
    BOOST_CHECK_EQUAL(1000 * SATOSHI,
                      entryNormal->GetModifiedFeeRate().GetFee(1000));

    // Add modified fee
    CTxMemPoolEntryRef entryFeeModified = entry.Fee(1000 * SATOSHI).FromTx(tx);
    entryFeeModified->UpdateModifiedFee(1000 * SATOSHI);
    BOOST_CHECK_EQUAL(2000 * SATOSHI,
                      entryFeeModified->GetModifiedFeeRate().GetFee(1000));

    // Excessive sigop count "modifies" size
    CTxMemPoolEntryRef entrySizeModified =
        entry.Fee(1000 * SATOSHI)
            .SigChecks(2000 / DEFAULT_BYTES_PER_SIGCHECK)
            .FromTx(tx);
    BOOST_CHECK_EQUAL(500 * SATOSHI,
                      entrySizeModified->GetModifiedFeeRate().GetFee(1000));
}

BOOST_AUTO_TEST_CASE(CompareTxMemPoolEntryByModifiedFeeRateTest) {
    CTransactionRef a = make_tx(/* output_values */ {1 * COIN});
    CTransactionRef b = make_tx(/* output_values */ {2 * COIN});

    // For this test, we want b to have lower txid.
    if (a->GetId() < b->GetId()) {
        std::swap(a, b);
    }
    BOOST_CHECK_GT(a->GetId(), b->GetId());

    TestMemPoolEntryHelper entry;
    CompareTxMemPoolEntryByModifiedFeeRate compare;

    auto checkOrdering = [&compare](const auto &a, const auto &b) {
        BOOST_CHECK(compare(a, b));
        BOOST_CHECK(!compare(b, a));
    };

    // If the fees and entryId are the same, lower TxId should sort before
    checkOrdering(entry.Fee(100 * SATOSHI).FromTx(b),
                  entry.Fee(100 * SATOSHI).FromTx(a));
    // Earlier entryId, same fee, should sort before
    checkOrdering(entry.Fee(100 * SATOSHI).EntryId(1).FromTx(a),
                  entry.Fee(100 * SATOSHI).EntryId(2).FromTx(b));
    // Higher fee, earlier entryId should sort before
    checkOrdering(entry.Fee(101 * SATOSHI).EntryId(1).FromTx(a),
                  entry.Fee(100 * SATOSHI).EntryId(2).FromTx(b));
    // Higher fee, same entryId should sort before
    checkOrdering(entry.Fee(101 * SATOSHI).FromTx(a),
                  entry.Fee(100 * SATOSHI).FromTx(b));

    // Same with fee delta.
    {
        CTxMemPoolEntryRef entryA = entry.Fee(100 * SATOSHI).FromTx(a);
        CTxMemPoolEntryRef entryB = entry.Fee(200 * SATOSHI).FromTx(b);
        // .. A and B have same modified fee, ordering is by lowest txid
        entryA->UpdateModifiedFee(100 * SATOSHI);
        checkOrdering(entryB, entryA);
    }
    // .. A is first entering the mempool
    CTxMemPoolEntryRef entryA = entry.Fee(100 * SATOSHI).EntryId(1).FromTx(a);
    CTxMemPoolEntryRef entryB = entry.Fee(100 * SATOSHI).EntryId(2).FromTx(b);
    checkOrdering(entryA, entryB);
    // .. B has higher modified fee.
    entryB->UpdateModifiedFee(1 * SATOSHI);
    checkOrdering(entryB, entryA);
}

BOOST_AUTO_TEST_CASE(remove_for_finalized_block) {
    CTxMemPool &pool = *Assert(m_node.mempool);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const Consensus::Params &params = chainman.GetConsensus();
    TestMemPoolEntryHelper entry;

    LOCK2(cs_main, pool.cs);
    const CBlockIndex &tip = *Assert(chainman.ActiveTip());

    Package txs;
    txs.reserve(100);
    for (size_t i = 0; i < 100; i++) {
        CMutableTransaction mtx(*make_tx({int64_t(i + 1) * COIN}));
        mtx.vout[0].scriptPubKey << std::vector<uint8_t>(MIN_TX_SIZE, 0);
        CTransactionRef tx = MakeTransactionRef(std::move(mtx));
        const TxId &txid = tx->GetId();
        auto mempoolEntry = entry.Fee(1000 * SATOSHI).FromTx(tx);

        pool.addUnchecked(mempoolEntry);
        BOOST_CHECK(pool.exists(txid));

        std::vector<TxId> finalizedTxIds;
        BOOST_CHECK(pool.setAvalancheFinalized(mempoolEntry, params, tip,
                                               chainman.ActiveChainstate(),
                                               finalizedTxIds));
        BOOST_CHECK(pool.isAvalancheFinalizedPreConsensus(txid));
        BOOST_CHECK_EQUAL(finalizedTxIds.size(), 1);
        BOOST_CHECK_EQUAL(finalizedTxIds[0], txid);

        txs.push_back(std::move(tx));
    }

    // Mine the first 50 transactions and assume the block is finalized
    Package minedTxsInFinalBlock(txs.begin(), txs.begin() + 50);
    DisconnectedBlockTransactions disconnectedBlockTxs;
    disconnectedBlockTxs.removeForBlock(minedTxsInFinalBlock, pool);
    disconnectedBlockTxs.clear();

    pool.removeForFinalizedBlock({});

    for (const auto &tx : minedTxsInFinalBlock) {
        // No longer in the radix tree
        BOOST_CHECK(!pool.isAvalancheFinalizedPreConsensus(tx->GetId()));
    }
    // Other txs are still there
    for (size_t i = 50; i < 100; i++) {
        BOOST_CHECK(pool.isAvalancheFinalizedPreConsensus(txs[i]->GetId()));
    }

    // Repeat is no op
    pool.removeForFinalizedBlock({});
    for (const auto &tx : minedTxsInFinalBlock) {
        // No longer in the radix tree
        BOOST_CHECK(!pool.isAvalancheFinalizedPreConsensus(tx->GetId()));
    }
    // Other txs are still there
    for (size_t i = 50; i < 100; i++) {
        BOOST_CHECK(pool.isAvalancheFinalizedPreConsensus(txs[i]->GetId()));
    }

    // Mine 20 more txs but assume the block is not finalized
    Package minedTxsInNonFinalBlock(txs.begin() + 50, txs.begin() + 70);
    disconnectedBlockTxs.removeForBlock(minedTxsInNonFinalBlock, pool);
    disconnectedBlockTxs.clear();

    std::unordered_set<TxId, SaltedTxIdHasher> minedTxIdsInNonFinalBlock;
    for (const auto &tx : minedTxsInNonFinalBlock) {
        minedTxIdsInNonFinalBlock.insert(tx->GetId());
    }
    pool.removeForFinalizedBlock(minedTxIdsInNonFinalBlock);

    for (const auto &tx : minedTxsInFinalBlock) {
        // No longer in the radix tree
        BOOST_CHECK(!pool.isAvalancheFinalizedPreConsensus(tx->GetId()));
    }
    // Check that the 50 last txs including the mined ones are still in the
    // radix tree
    for (size_t i = 50; i < 100; i++) {
        BOOST_CHECK(pool.isAvalancheFinalizedPreConsensus(txs[i]->GetId()));
    }

    // Remove them all
    disconnectedBlockTxs.removeForBlock(txs, pool);
    disconnectedBlockTxs.clear();
    pool.removeForFinalizedBlock({});
    for (const auto &tx : txs) {
        // No longer in the radix tree
        BOOST_CHECK(!pool.isAvalancheFinalizedPreConsensus(tx->GetId()));
    }
}

BOOST_AUTO_TEST_CASE(setAvalancheFinalized_ContextualCheckTransactionFailures) {
    CTxMemPool &mempool = *Assert(m_node.mempool);
    const Consensus::Params &params = Assert(m_node.chainman)->GetConsensus();
    TestMemPoolEntryHelper entry;

    // Fake chain tip
    CBlockIndex active_chain_tip;
    active_chain_tip.nHeight = 100;

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].nHeight = active_chain_tip.nHeight - i - 1;
        blocks[i].nTime = LOCKTIME_THRESHOLD + i;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
    }
    active_chain_tip.pprev = &blocks.back();
    BOOST_CHECK_GE(active_chain_tip.GetMedianTimePast(), LOCKTIME_THRESHOLD);

    // Create a base transaction
    CMutableTransaction good_tx;
    good_tx.vin.resize(1);
    good_tx.vin[0].prevout = COutPoint(TxId{FastRandomContext().rand256()}, 0);
    CScript scriptSig;
    for (int i = 0; i < 100; ++i) {
        scriptSig << OP_1;
    }
    good_tx.vin[0].scriptSig = scriptSig;
    good_tx.vout.resize(1);
    good_tx.vout[0].nValue = 1000 * SATOSHI;
    good_tx.nLockTime = 0;
    BOOST_CHECK_GE(entry.Fee(1000 * SATOSHI).FromTx(good_tx)->GetTxSize(),
                   MIN_TX_SIZE);

    LOCK2(cs_main, mempool.cs);

    auto checkTx = [&](const CMutableTransaction &bad,
                       const CMutableTransaction &good,
                       const std::string &&reason) NO_THREAD_SAFETY_ANALYSIS {
        auto bad_entry = entry.Fee(1000 * SATOSHI).FromTx(bad);
        // Add the entry to the mempool
        mempool.addUnchecked(bad_entry);
        BOOST_CHECK(mempool.exists(bad.GetId()));

        // Check it fails for the expected reasons
        TxValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            active_chain_tip, params, bad_entry->GetTx(), state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);

        // Check it can't be finalized
        std::vector<TxId> finalizedTxIds;
        BOOST_CHECK(!mempool.setAvalancheFinalized(
            bad_entry, params, active_chain_tip,
            m_node.chainman->ActiveChainstate(), finalizedTxIds));
        BOOST_CHECK(finalizedTxIds.empty());

        mempool.clear(/*include_finalized_txs=*/true);

        // Check the good transaction can be finalized
        auto good_entry = entry.Fee(1000 * SATOSHI).FromTx(good);
        mempool.addUnchecked(good_entry);
        BOOST_CHECK(mempool.exists(good.GetId()));

        BOOST_CHECK(mempool.setAvalancheFinalized(
            good_entry, params, active_chain_tip,
            m_node.chainman->ActiveChainstate(), finalizedTxIds));
        BOOST_CHECK_EQUAL(finalizedTxIds.size(), 1);

        mempool.clear(/*include_finalized_txs=*/true);
    };

    // Locked by a higher block height
    {
        CMutableTransaction bad_tx{good_tx};
        // Next block is at height + 1, so we lock for the subsequent block
        bad_tx.nLockTime = active_chain_tip.nHeight + 1;
        bad_tx.vin[0].nSequence = 0;
        checkTx(bad_tx, good_tx, "bad-txns-nonfinal");
    }

    // Locked by a time in the future
    {
        CMutableTransaction bad_tx{good_tx};
        bad_tx.nLockTime = active_chain_tip.GetMedianTimePast() + 1;
        bad_tx.vin[0].nSequence = 0;
        checkTx(bad_tx, good_tx, "bad-txns-nonfinal");
    }

    // Transaction size is below 100 bytes
    {
        CMutableTransaction bad_tx{good_tx};
        bad_tx.vin.clear();
        bad_tx.vin.resize(1);
        BOOST_CHECK_LT(entry.Fee(1000 * SATOSHI).FromTx(bad_tx)->GetTxSize(),
                       MIN_TX_SIZE);
        checkTx(bad_tx, good_tx, "bad-txns-undersize");
    }

    // Transaction version is 3
    {
        CMutableTransaction bad_tx{good_tx};
        bad_tx.nVersion = 3;
        checkTx(bad_tx, good_tx, "bad-txns-version");
    }
}

BOOST_AUTO_TEST_CASE(setAvalancheFinalized_chained_txs) {
    CTxMemPool &pool = *Assert(m_node.mempool);
    ChainstateManager &chainman = *Assert(m_node.chainman);
    const Consensus::Params &params = chainman.GetConsensus();
    TestMemPoolEntryHelper entry;

    LOCK2(cs_main, pool.cs);
    const CBlockIndex &tip = *Assert(chainman.ActiveTip());

    CScript scriptSig;
    for (int i = 0; i < 100; ++i) {
        scriptSig << OP_1;
    }

    std::vector<CTxMemPoolEntryRef> entries;
    entries.reserve(100);
    TxId prevId{FastRandomContext().rand256()};
    for (size_t i = 0; i < 100; ++i) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(prevId, 0);
        mtx.vin[0].scriptSig = scriptSig;
        mtx.vout.emplace_back((100000 - int64_t(i) * 1000) * SATOSHI,
                              CScript() << OP_TRUE);
        CTransactionRef tx = MakeTransactionRef(mtx);
        prevId = tx->GetId();

        auto mempoolEntry = entry.Fee(1000 * SATOSHI).FromTx(tx);
        pool.addUnchecked(mempoolEntry);
        entries.push_back(mempoolEntry);
    }

    // Finalize the 50th transaction in the chain: all 50 ancestors (0..49)
    // should finalize together.
    std::vector<TxId> finalizedTxIds;
    BOOST_CHECK(pool.setAvalancheFinalized(
        entries[49], params, tip, chainman.ActiveChainstate(), finalizedTxIds));
    BOOST_CHECK_EQUAL(finalizedTxIds.size(), 50U);
    BOOST_CHECK_EQUAL(pool.GetFinalizedTxCount(), 50U);
    for (size_t i = 0; i < 50; ++i) {
        BOOST_CHECK(
            pool.isAvalancheFinalizedPreConsensus(entries[i]->GetTx().GetId()));
    }
    for (size_t i = 50; i < 100; ++i) {
        BOOST_CHECK(!pool.isAvalancheFinalizedPreConsensus(
            entries[i]->GetTx().GetId()));
    }

    // Verify CalculateMemPoolAncestors stops at already-finalized ancestors
    // when fSearchFinalized is false (both with and without fSearchForParents).
    for (const bool fSearchForParents : {false, true}) {
        CTxMemPool::setEntries unfinalizedAncestors;
        pool.CalculateMemPoolAncestors(entries[52], unfinalizedAncestors,
                                       fSearchForParents,
                                       /*fSearchFinalized=*/false);
        BOOST_CHECK_EQUAL(unfinalizedAncestors.size(), 2U);

        CTxMemPool::setEntries allAncestors;
        pool.CalculateMemPoolAncestors(entries[52], allAncestors,
                                       fSearchForParents,
                                       /*fSearchFinalized=*/true);
        BOOST_CHECK_EQUAL(allAncestors.size(), 52U);
    }

    // Re-finalizing an already-finalized transaction is a no-op that succeeds
    // with an empty newly-finalized list.
    BOOST_CHECK(pool.setAvalancheFinalized(
        entries[25], params, tip, chainman.ActiveChainstate(), finalizedTxIds));
    BOOST_CHECK(finalizedTxIds.empty());
    BOOST_CHECK_EQUAL(pool.GetFinalizedTxCount(), 50U);

    // Finalizing the remaining descendants one by one should only finalize the
    // new child each time without re-walking or re-reporting finalized parents.
    for (size_t i = 50; i < 100; ++i) {
        BOOST_CHECK(pool.setAvalancheFinalized(entries[i], params, tip,
                                               chainman.ActiveChainstate(),
                                               finalizedTxIds));
        BOOST_CHECK_EQUAL(finalizedTxIds.size(), 1U);
        BOOST_CHECK_EQUAL(finalizedTxIds[0], entries[i]->GetTx().GetId());
        BOOST_CHECK_EQUAL(pool.GetFinalizedTxCount(), i + 1);
        BOOST_CHECK(
            pool.isAvalancheFinalizedPreConsensus(entries[i]->GetTx().GetId()));
    }
}

BOOST_AUTO_TEST_CASE(unchecked_long_chain_storage) {
    // Exercise the unchecked mempool container with a 100-transaction chain.
    // addUnchecked bypasses input/script checks and admission policy; this is
    // not evidence that ProcessTransaction accepts such a chain. No consensus
    // or ancestor/descendant admission limit is changed by this fixture.
    // Each transaction references the preceding transaction's single output.
    // Verify all entries remain present in the container.
    TestMemPoolEntryHelper entry;
    entry.SigChecks(0);
    LOCK2(cs_main, m_node.mempool->cs);

    CMutableTransaction first;
    first.vin.resize(1);
    first.vin[0].scriptSig = CScript();
    first.vout.emplace_back(10000 * SATOSHI, CScript() << OP_TRUE);
    m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(first));

    TxId prevId = first.GetId();
    for (int i = 1; i < 100; i++) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(prevId, 0);
        tx.vout.emplace_back(9000 * SATOSHI, CScript() << OP_TRUE);
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
        prevId = tx.GetId();
    }

    BOOST_CHECK_EQUAL(m_node.mempool->size(), 100UL);
}

BOOST_AUTO_TEST_CASE(bulk_clear_requires_exact_unique_transaction_set) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    std::vector<CTransactionRef> txs;
    for (uint32_t i = 0; i < 2; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(TxId{uint256{uint8_t(i + 1)}}, 0);
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        txs.push_back(MakeTransactionRef(tx));
        pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(txs.back()));
    }
    const auto updates = pool.GetTransactionsUpdated();
    const auto sequence = pool.GetSequence();
    BOOST_CHECK(!pool.TryClearAllForConnectedBlock({txs[0], txs[0], txs[0]}));
    BOOST_CHECK_EQUAL(pool.size(), 2U);
    BOOST_CHECK_EQUAL(pool.GetTransactionsUpdated(), updates);
    BOOST_CHECK_EQUAL(pool.GetSequence(), sequence);
}

BOOST_AUTO_TEST_CASE(bulk_clear_preserves_fee_history_and_frozen_epochs) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    CMutableTransaction tx;
    tx.vin.emplace_back(TxId{uint256{uint8_t(1)}}, 0);
    tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    auto ref = MakeTransactionRef(tx);
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(ref));
    pool.TrimToSize(0);
    BOOST_REQUIRE_GT(pool.GetRollingMinimumFeeRate(), 0);
    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(ref));
    pool.FreezeEpochBatch();
    const auto fee = pool.GetRollingMinimumFeeRate();
    const auto updates = pool.GetTransactionsUpdated();
    const auto sequence = pool.GetSequence();
    BOOST_REQUIRE(pool.TryClearAllForConnectedBlock({ref, ref}));
    BOOST_CHECK_EQUAL(pool.GetRollingMinimumFeeRate(), fee);
    BOOST_CHECK_EQUAL(pool.GetTransactionsUpdated(), updates + 1);
    BOOST_CHECK_EQUAL(pool.GetSequence(), sequence + 1);
    BOOST_CHECK_EQUAL(pool.GetMerklixOverlay().GetFrozenEpochs().size(), 1U);
    BOOST_CHECK_EQUAL(pool.GetMerklixOverlay().GetSpeculativeOverlay().GetTxCount(), 0U);
}

BOOST_AUTO_TEST_CASE(bulk_clear_matches_staged_block_removal_state) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper helper;
    std::vector<CTransactionRef> txs;
    for (uint32_t i = 0; i < 3; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(TxId{uint256{uint8_t(i + 1)}}, 0);
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        txs.push_back(MakeTransactionRef(tx));
    }
    const auto exercise = [&](bool bulk) EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs) {
        pool.clear(true);
        pool.GetUtxoFastFilter().ClearAll();
        pool.addUnchecked(helper.Fee(1000 * SATOSHI).FromTx(txs[0]));
        pool.TrimToSize(0);
        for (const auto &tx : txs) {
            pool.addUnchecked(helper.Fee(1000 * SATOSHI).FromTx(tx));
            pool.AddUnbroadcastTx(tx->GetId());
        }
        pool.FreezeEpochBatch();
        const auto updates = pool.GetTransactionsUpdated();
        const auto sequence = pool.GetSequence();
        const auto before = node::GetGlobalSnapshotPublisher().Load();
        const auto before_template = before->GetMiningTemplate().template_id;
        {
            CTxMemPool::ScopedSnapshotDefer defer(pool);
            if (bulk) {
                auto block_txs = txs;
                block_txs.insert(block_txs.begin(), txs[0]);
                BOOST_REQUIRE(pool.TryClearAllForConnectedBlock(block_txs));
            } else {
                CTxMemPool::setEntries all;
                for (auto it = pool.mapTx.begin(); it != pool.mapTx.end(); ++it) all.insert(it);
                pool.RemoveStaged(all, MemPoolRemovalReason::BLOCK);
                pool.updateFeeForBlock();
            }
        }
        const auto after = node::GetGlobalSnapshotPublisher().Load();
        const auto &overlay = pool.GetMerklixOverlay();
        return std::make_tuple(pool.size(), pool.mapNextTx.size(),
            pool.GetTotalTxSize(), pool.GetTotalFee(), pool.DynamicMemoryUsage(),
            pool.GetTransactionsUpdated() - updates, pool.GetSequence() - sequence,
            pool.GetRollingMinimumFeeRate(), pool.GetUnbroadcastTxCount(),
            pool.GetUtxoFastFilter().MempoolSpentCount(),
            pool.GetUtxoFastFilter().UnspentCount(), overlay.GetFrozenEpochs().size(),
            overlay.GetSpeculativeOverlay().GetTxCount(), after->mempool_size,
            after->GetMiningTemplate().template_id - before_template);
    };
    const auto staged = exercise(false);
    const auto bulk = exercise(true);
    BOOST_CHECK(staged == bulk);
}

BOOST_AUTO_TEST_CASE(deferred_overlay_remove_readd_matches_authoritative_pool) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    std::vector<CTransactionRef> txs;
    for (uint32_t i = 0; i < 3; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(TxId{uint256{uint8_t(i + 1)}}, 0);
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        txs.push_back(MakeTransactionRef(tx));
        pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(txs.back()));
    }
    const auto before = pool.GetMerklixOverlay().GetSpeculativeOverlay().GetSubtreeARoot();
    {
        CTxMemPool::ScopedSnapshotDefer defer(pool);
        pool.removeRecursive(*txs[0], MemPoolRemovalReason::MANUAL);
        pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(txs[0]));
    }
    BOOST_CHECK_EQUAL(pool.size(), 3U);
    const auto &spec = pool.GetMerklixOverlay().GetSpeculativeOverlay();
    BOOST_CHECK_EQUAL(spec.GetTxCount(), pool.size());
    BOOST_CHECK(spec.GetSubtreeARoot() == before);
}

BOOST_AUTO_TEST_CASE(deferred_overlay_randomized_operations_match_full_rebuild) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    FastRandomContext random(uint256{uint8_t(9)});
    std::vector<CTransactionRef> txs;
    for (uint32_t i = 0; i < 8; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(TxId{uint256{uint8_t(i + 1)}}, 0);
        tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
        txs.push_back(MakeTransactionRef(tx));
    }
    for (size_t round = 0; round < 64; ++round) {
        {
            CTxMemPool::ScopedSnapshotDefer defer(pool);
            for (size_t op = 0; op < 8; ++op) {
                const auto &tx = txs[random.randrange(txs.size())];
                if (pool.exists(tx->GetId())) {
                    pool.removeRecursive(*tx, MemPoolRemovalReason::MANUAL);
                } else {
                    pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
                }
            }
        }
        lotus::v2::MerklixOverlayManager rebuilt;
        std::vector<std::tuple<CTransactionRef, int64_t, int64_t>> current;
        for (const auto &item : pool.mapTx.get<entry_id>()) {
            current.emplace_back(item->GetSharedTx(), item->GetFee() / SATOSHI,
                                 item->GetSigChecks());
        }
        AddTransactionsToOverlayBatch(rebuilt, current);
        const auto &actual = pool.GetMerklixOverlay().GetSpeculativeOverlay();
        const auto &expected = rebuilt.GetSpeculativeOverlay();
        BOOST_CHECK_EQUAL(actual.GetTxCount(), expected.GetTxCount());
        BOOST_CHECK(actual.GetSubtreeARoot() == expected.GetSubtreeARoot());
    }
}

BOOST_AUTO_TEST_CASE(contended_overlay_warm_reports_skip_and_reader_flushes) {
    CTxMemPool &pool = *m_node.mempool;
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;
    CMutableTransaction tx;
    tx.vin.emplace_back(TxId{uint256{uint8_t(1)}}, 0);
    tx.vout.emplace_back(1000 * SATOSHI, CScript() << OP_TRUE);
    auto ref = MakeTransactionRef(tx);
    pool.addUnchecked(entry.FromTx(ref));
    bool logged = false;
    const bool was_enabled = LogInstance().WillLogCategory(BCLog::MEMPOOL);
    LogInstance().EnableCategory(BCLog::MEMPOOL);
    {
        DebugLogHelper capture("Merklix overlay warm deferred: mempool lock busy",
            [&](const std::string *line) { if (line) logged = true; return false; });
        std::thread warmer([&] {
            pool.WarmMerklixOverlayIfNeeded(BlockHash(uint256{uint8_t(1)}), 1, 0);
        });
        warmer.join();
    }
    if (!was_enabled) LogInstance().DisableCategory(BCLog::MEMPOOL);
    BOOST_CHECK(logged);
    BOOST_CHECK_EQUAL(pool.GetMerklixOverlay().GetSpeculativeOverlay().GetTxCount(), 1U);
}

BOOST_AUTO_TEST_CASE(mempool_slab_allocator_churn) {
    // 1. Direct ChunkedSlabAllocator unit tests: single-slot bump allocation,
    // multi-chunk growth, LIFO intrusive freelist reuse, rebind sharing, and
    // n > 1 array allocation fallback.
    {
        ChunkedSlabAllocator<uint64_t, 4> alloc;
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 0U);

        uint64_t *p0 = alloc.allocate(1);
        uint64_t *p1 = alloc.allocate(1);
        uint64_t *p2 = alloc.allocate(1);
        uint64_t *p3 = alloc.allocate(1);
        *p0 = 10;
        *p1 = 20;
        *p2 = 30;
        *p3 = 40;
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 1U);
        BOOST_CHECK_EQUAL(alloc.arena()->FreeListCount(), 0U);
        // Contiguous bump slots within the same chunk:
        BOOST_CHECK_EQUAL(reinterpret_cast<std::byte *>(p1) -
                              reinterpret_cast<std::byte *>(p0),
                          static_cast<std::ptrdiff_t>(sizeof(uint64_t)));

        // 5th allocation triggers a 2nd chunk when SlotsPerChunk == 4:
        uint64_t *p4 = alloc.allocate(1);
        *p4 = 50;
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 2U);

        // Return p1 and p3 to the intrusive freelist and verify LIFO reuse:
        alloc.deallocate(p1, 1);
        alloc.deallocate(p3, 1);
        BOOST_CHECK_EQUAL(alloc.arena()->FreeListCount(), 2U);

        uint64_t *r1 = alloc.allocate(1);
        uint64_t *r2 = alloc.allocate(1);
        BOOST_CHECK_EQUAL(r1, p3);
        BOOST_CHECK_EQUAL(r2, p1);
        BOOST_CHECK_EQUAL(alloc.arena()->FreeListCount(), 0U);
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 2U);

        // Rebind to a larger node type and verify shared resource:
        struct DummyNode {
            uint64_t a;
            uint64_t b;
            uint64_t c;
        };
        ChunkedSlabAllocator<uint64_t, 4>::rebind<DummyNode>::other rebound(
            alloc);
        BOOST_CHECK(rebound == alloc);
        DummyNode *dn = rebound.allocate(1);
        dn->a = 1;
        dn->b = 2;
        dn->c = 3;
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 3U);
        rebound.deallocate(dn, 1);
        BOOST_CHECK_EQUAL(rebound.arena()->FreeListCount(), 1U);

        // Multi-element (n > 1) bucket-array fallback does not allocate slab
        // chunks:
        uint64_t *arr = alloc.allocate(32);
        for (size_t i = 0; i < 32; ++i) {
            arr[i] = i;
        }
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 3U);
        alloc.deallocate(arr, 32);

        alloc.deallocate(p0, 1);
        alloc.deallocate(r2, 1);
        alloc.deallocate(p2, 1);
        alloc.deallocate(r1, 1);
        alloc.deallocate(p4, 1);
        BOOST_CHECK_EQUAL(alloc.arena()->FreeListCount(), 5U);
    }

    // A live sentinel must pin only its own chunk, rather than the whole
    // high-water allocation. Regrowth must not reuse freed chunk pointers.
    {
        ChunkedSlabAllocator<uint64_t, 4> alloc;
        std::vector<uint64_t *> nodes;
        for (uint64_t i = 0; i < 13; ++i) {
            auto *node = alloc.allocate(1);
            *node = i;
            nodes.push_back(node);
        }
        for (size_t i = 1; i < nodes.size(); ++i) alloc.deallocate(nodes[i], 1);
        alloc.resource()->ReleaseUnusedChunks();
        BOOST_CHECK_EQUAL(alloc.resource()->NumAllocatedChunks(), 1U);
        BOOST_CHECK_EQUAL(*nodes[0], 0U);
        nodes.resize(1);
        for (uint64_t i = 1; i < 13; ++i) {
            auto *node = alloc.allocate(1);
            *node = i;
            nodes.push_back(node);
        }
        for (size_t i = 0; i < nodes.size(); ++i) {
            BOOST_CHECK_EQUAL(*nodes[i], i);
            alloc.deallocate(nodes[i], 1);
        }
        alloc.resource()->ReleaseUnusedChunks();
        BOOST_CHECK_EQUAL(alloc.resource()->TotalAllocatedChunkBytes(), 0U);
    }

    // 2. CTxMemPool mapTx and mapNextTx insertion/removal churn test:
    CTxMemPool &pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    pool.clear(/*include_finalized_txs=*/true);

    TestMemPoolEntryHelper entry;
    entry.SigChecks(0);

    constexpr size_t BATCH_SIZE = 64;
    std::vector<CTransactionRef> active_txs;
    active_txs.reserve(BATCH_SIZE);

    auto makeChurnTx = [](int64_t round, int64_t idx) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(2);
        mtx.vin[0].prevout = COutPoint(TxId{FastRandomContext().rand256()}, 0);
        mtx.vin[1].prevout = COutPoint(TxId{FastRandomContext().rand256()}, 1);
        mtx.vout.emplace_back((10000 + round * 100 + idx) * SATOSHI,
                              CScript() << OP_TRUE);
        mtx.vout.emplace_back((20000 + round * 100 + idx) * SATOSHI,
                              CScript() << OP_TRUE);
        return MakeTransactionRef(mtx);
    };

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        CTransactionRef tx = makeChurnTx(0, static_cast<int64_t>(i));
        pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
        active_txs.push_back(std::move(tx));
    }

    BOOST_CHECK_EQUAL(pool.size(), BATCH_SIZE);
    BOOST_CHECK_EQUAL(pool.mapNextTx.size(), BATCH_SIZE * 2);

    const size_t tx_chunks_initial =
        pool.mapTx.get_allocator().resource()->NumAllocatedChunks();
    const size_t next_chunks_initial =
        pool.mapNextTx.get_allocator().resource()->NumAllocatedChunks();
    BOOST_CHECK_GE(tx_chunks_initial, 1U);
    BOOST_CHECK_GE(next_chunks_initial, 1U);

    const size_t slab_bytes =
        pool.mapTx.get_allocator().resource()->TotalAllocatedChunkBytes() +
        pool.mapNextTx.get_allocator().resource()->TotalAllocatedChunkBytes();
    BOOST_CHECK_GE(pool.DynamicMemoryUsage(), slab_bytes);
    const size_t peak_usage = pool.DynamicMemoryUsage();

    // Churn through 3 rounds of evicting half the mempool and refilling back to
    // BATCH_SIZE, verifying slab freelist slot reuse without new chunk growth.
    for (int64_t round = 1; round <= 3; ++round) {
        for (size_t i = 0; i < BATCH_SIZE / 2; ++i) {
            pool.removeRecursive(*active_txs[i], REMOVAL_REASON_DUMMY);
        }
        active_txs.erase(active_txs.begin(),
                         active_txs.begin() + (BATCH_SIZE / 2));
        BOOST_CHECK_EQUAL(pool.size(), BATCH_SIZE / 2);
        BOOST_CHECK_EQUAL(pool.mapNextTx.size(), BATCH_SIZE);

        for (size_t i = 0; i < BATCH_SIZE / 2; ++i) {
            CTransactionRef tx = makeChurnTx(round, static_cast<int64_t>(i));
            pool.addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx));
            active_txs.push_back(std::move(tx));
        }
        BOOST_CHECK_EQUAL(pool.size(), BATCH_SIZE);
        BOOST_CHECK_EQUAL(pool.mapNextTx.size(), BATCH_SIZE * 2);
        BOOST_CHECK_EQUAL(
            pool.mapTx.get_allocator().resource()->NumAllocatedChunks(),
            tx_chunks_initial);
        BOOST_CHECK_EQUAL(
            pool.mapNextTx.get_allocator().resource()->NumAllocatedChunks(),
            next_chunks_initial);
    }

    pool.clear(/*include_finalized_txs=*/true);
    BOOST_CHECK_EQUAL(pool.size(), 0UL);
    BOOST_CHECK(pool.mapNextTx.empty());
    BOOST_CHECK_LT(pool.DynamicMemoryUsage(), peak_usage);
    BOOST_CHECK_EQUAL(
        pool.mapNextTx.get_allocator().resource()->TotalAllocatedChunkBytes(), 0U);

}

BOOST_AUTO_TEST_CASE(MakeTransactionRefConcurrentChurn) {
    // CTransactionRefs are created on network/RPC threads and released on
    // validation threads. Churn them through a bounded queue from 8
    // producers to 4 consumers and check every transaction arrives intact.
    constexpr uint32_t PRODUCERS{8};
    constexpr uint32_t CONSUMERS{4};
    constexpr uint32_t PER_PRODUCER{20000};
    constexpr size_t QUEUE_CAPACITY{1024};

    std::mutex mutex;
    std::condition_variable cv_not_full, cv_not_empty;
    std::deque<CTransactionRef> queue;
    uint32_t producers_done{0};

    std::vector<std::thread> threads;
    for (uint32_t p = 0; p < PRODUCERS; ++p) {
        threads.emplace_back([&, p] {
            for (uint32_t i = 0; i < PER_PRODUCER; ++i) {
                CMutableTransaction mtx;
                mtx.nLockTime = p;
                mtx.vin.emplace_back(TxId{uint256{uint8_t(p + 1)}}, i);
                mtx.vout.emplace_back(int64_t(p) * PER_PRODUCER * SATOSHI +
                                          int64_t(i) * SATOSHI,
                                      CScript() << OP_TRUE);
                CTransactionRef tx = MakeTransactionRef(std::move(mtx));
                std::unique_lock lock(mutex);
                cv_not_full.wait(
                    lock, [&] { return queue.size() < QUEUE_CAPACITY; });
                queue.push_back(std::move(tx));
                cv_not_empty.notify_one();
            }
            std::lock_guard lock(mutex);
            ++producers_done;
            cv_not_empty.notify_all();
        });
    }

    std::vector<uint64_t> consumed(CONSUMERS, 0);
    std::vector<uint64_t> errors(CONSUMERS, 0);
    std::vector<std::unordered_set<const CTransaction *>> addresses(CONSUMERS);
    for (uint32_t c = 0; c < CONSUMERS; ++c) {
        threads.emplace_back([&, c] {
            while (true) {
                CTransactionRef tx;
                {
                    std::unique_lock lock(mutex);
                    cv_not_empty.wait(lock, [&] {
                        return !queue.empty() || producers_done == PRODUCERS;
                    });
                    if (queue.empty()) {
                        return;
                    }
                    tx = std::move(queue.front());
                    queue.pop_front();
                    cv_not_full.notify_one();
                }
                const Amount expected{
                    int64_t(tx->nLockTime) * PER_PRODUCER * SATOSHI +
                    int64_t(tx->vin[0].prevout.GetN()) * SATOSHI};
                if (tx->vin.size() != 1 || tx->vout.size() != 1 ||
                    tx->vout[0].nValue != expected ||
                    (consumed[c] % 64 == 0 &&
                     tx->GetId() != CMutableTransaction(*tx).GetId())) {
                    ++errors[c];
                }
                addresses[c].insert(tx.get());
                ++consumed[c];
                // tx is released here, on a different thread than the one
                // that allocated it.
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    uint64_t total{0};
    std::unordered_set<const CTransaction *> distinct;
    for (uint32_t c = 0; c < CONSUMERS; ++c) {
        BOOST_CHECK_EQUAL(errors[c], 0U);
        total += consumed[c];
        distinct.insert(addresses[c].begin(), addresses[c].end());
    }
    BOOST_CHECK_EQUAL(total, uint64_t{PRODUCERS} * PER_PRODUCER);
    // At most QUEUE_CAPACITY + a few in-flight transactions and per-thread
    // magazines are live at once, so slots must be recycled.
    BOOST_CHECK_LT(distinct.size(), total / 8);

    // References created after the churn still work normally.
    CMutableTransaction mtx;
    mtx.vout.emplace_back(SATOSHI, CScript() << OP_TRUE);
    const CTransactionRef tx = MakeTransactionRef(mtx);
    BOOST_CHECK(tx->GetId() == mtx.GetId());
}

BOOST_AUTO_TEST_CASE(DeserializeTransactionRef) {
    // CTransactionRefs read from the network or from blocks are deserialized
    // through the slab-backed Unserialize overload.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(TxId{uint256{uint8_t(7)}}, 3);
    mtx.vout.emplace_back(42 * SATOSHI, CScript() << OP_TRUE);
    const CTransactionRef expected = MakeTransactionRef(mtx);

    DataStream ss{};
    ss << expected;
    CTransactionRef ptx;
    ss >> ptx;
    BOOST_REQUIRE(ptx);
    BOOST_CHECK(ptx->GetHash() == expected->GetHash());

    std::vector<CTransactionRef> vtx{expected, expected};
    DataStream block_ss{};
    block_ss << vtx;
    std::vector<CTransactionRef> decoded;
    block_ss >> decoded;
    BOOST_REQUIRE_EQUAL(decoded.size(), 2U);
    BOOST_CHECK(decoded[0]->GetHash() == expected->GetHash());
    BOOST_CHECK(decoded[0] != decoded[1]);
}

BOOST_AUTO_TEST_SUITE_END()
