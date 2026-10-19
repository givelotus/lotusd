// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/processor.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <node/transaction.h>
#include <primitives/block.h>
#include <scheduler.h>
#include <script/standard.h>
#include <shutdown.h>
#include <txmempool.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <util/bounded_task_queue.h>
#include <util/threadnames.h>
#include <util/validation_queue_memory.h>

#include <test/util/setup_common.h>
#include <test/util/logging.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <future>
#include <util/task_runner.h>

BOOST_FIXTURE_TEST_SUITE(validationinterface_tests, ChainTestingSetup)

struct TestSubscriberNoop final : public CValidationInterface {
    void BlockChecked(const CBlock &, const BlockValidationState &) override {}
};

BOOST_AUTO_TEST_CASE(unregister_validation_interface_race) {
    std::atomic<bool> generate{true};

    // Start thread to generate notifications
    std::thread gen{[&] {
        const CBlock block_dummy;
        BlockValidationState state_dummy;
        while (generate) {
            m_node.validation_signals->BlockChecked(block_dummy, state_dummy);
        }
    }};

    // Start thread to consume notifications
    std::thread sub{[&] {
        // keep going for about 1 sec, which is 250k iterations
        for (int i = 0; i < 250000; i++) {
            auto subscriber = std::make_shared<TestSubscriberNoop>();
            m_node.validation_signals->RegisterSharedValidationInterface(
                subscriber);
            m_node.validation_signals->UnregisterSharedValidationInterface(
                subscriber);
        }
        // tell the other thread we are done
        generate = false;
    }};

    gen.join();
    sub.join();
    BOOST_CHECK(!generate);
}

class TestInterface : public CValidationInterface {
public:
    TestInterface(
        ValidationSignals &signals,
        std::function<void()> onBlockChecked_call = nullptr,
        std::function<void(const CBlockIndex *)> onBlockFinalized_call =
            nullptr,
        std::function<void(const CBlockIndex *,
                           const std::shared_ptr<const CBlock> &)>
            onBlockInvalidated_call = nullptr,
        std::function<void(const CTransactionRef &,
                           std::shared_ptr<const std::vector<Coin>>, uint64_t)>
            onTransactionAddedToMempool_call = nullptr,
        std::function<void(const CTransactionRef &)>
            onTransactionFinalized_call = nullptr,
        std::function<void(const CTransactionRef &,
                           std::shared_ptr<const std::vector<Coin>>)>
            onTransactionInvalidated_call = nullptr,
        std::function<void()> on_destroy = nullptr)
        : m_onBlockChecked_call(std::move(onBlockChecked_call)),
          m_onBlockFinalized_call(std::move(onBlockFinalized_call)),
          m_onBlockInvalidated_call(std::move(onBlockInvalidated_call)),
          m_onTransactionAddedToMempool_call(
              std::move(onTransactionAddedToMempool_call)),
          m_onTransactionFinalized_call(std::move(onTransactionFinalized_call)),
          m_onTransactionInvalidated_call(
              std::move(onTransactionInvalidated_call)),
          m_on_destroy(std::move(on_destroy)), m_signals{signals} {}
    virtual ~TestInterface() {
        if (m_on_destroy) {
            m_on_destroy();
        }
    }
    void BlockChecked(const CBlock &block,
                      const BlockValidationState &state) override {
        if (m_onBlockChecked_call) {
            m_onBlockChecked_call();
        }
    }
    void CallBlockChecked() {
        CBlock block;
        BlockValidationState state;
        m_signals.BlockChecked(block, state);
    }

    void BlockFinalized(const CBlockIndex *pindex) override {
        if (m_onBlockFinalized_call) {
            m_onBlockFinalized_call(pindex);
        }
    }

    void CallBlockFinalized(const CBlockIndex *pindex) {
        m_signals.BlockFinalized(pindex);
    }

    void BlockInvalidated(const CBlockIndex *pindex,
                          const std::shared_ptr<const CBlock> &block) override {
        if (m_onBlockInvalidated_call) {
            m_onBlockInvalidated_call(pindex, block);
        }
    }

    void CallBlockInvalidated(const CBlockIndex *pindex,
                              const std::shared_ptr<const CBlock> &block) {
        m_signals.BlockInvalidated(pindex, block);
    }

    void TransactionAddedToMempool(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<Coin>> spent_coins,
        uint64_t mempool_sequence) override {
        if (m_onTransactionAddedToMempool_call) {
            m_onTransactionAddedToMempool_call(tx, spent_coins,
                                               mempool_sequence);
        }
    }

    void CallTransactionAddedToMempool(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<Coin>> spent_coins,
        uint64_t mempool_sequence) {
        m_signals.TransactionAddedToMempool(tx, spent_coins, mempool_sequence);
    }

    void TransactionFinalized(const CTransactionRef &tx) override {
        if (m_onTransactionFinalized_call) {
            m_onTransactionFinalized_call(tx);
        }
    }

    void CallTransactionFinalized(const CTransactionRef &tx) {
        m_signals.TransactionFinalized(tx);
    }

    void TransactionInvalidated(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<Coin>> spent_coins) override {
        if (m_onTransactionInvalidated_call) {
            m_onTransactionInvalidated_call(tx, spent_coins);
        }
    }

    void CallTransactionInvalidated(
        const CTransactionRef &tx,
        std::shared_ptr<const std::vector<Coin>> spent_coins) {
        m_signals.TransactionInvalidated(tx, spent_coins);
    }

    std::function<void()> m_onBlockChecked_call;
    std::function<void(const CBlockIndex *)> m_onBlockFinalized_call;
    std::function<void(const CBlockIndex *,
                       const std::shared_ptr<const CBlock> &)>
        m_onBlockInvalidated_call;
    std::function<void(const CTransactionRef &,
                       std::shared_ptr<const std::vector<Coin>>, uint64_t)>
        m_onTransactionAddedToMempool_call;
    std::function<void(const CTransactionRef &)> m_onTransactionFinalized_call;
    std::function<void(const CTransactionRef &,
                       std::shared_ptr<const std::vector<Coin>>)>
        m_onTransactionInvalidated_call;
    std::function<void()> m_on_destroy;
    ValidationSignals &m_signals;
};

// Regression test to ensure UnregisterAllValidationInterfaces calls don't
// destroy a validation interface while it is being called. Bug:
// https://github.com/bitcoin/bitcoin/pull/18551
BOOST_AUTO_TEST_CASE(unregister_all_during_call) {
    bool destroyed = false;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals,
        [&] {
            // First call should decrements reference count 2 -> 1
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
            // Second call should not decrement reference count 1 -> 0
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
        },
        nullptr, nullptr, nullptr, nullptr, nullptr,
        [&] { destroyed = true; })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);
    BOOST_CHECK(shared.use_count() == 2);
    shared->CallBlockChecked();
    BOOST_CHECK(shared.use_count() == 1);
    BOOST_CHECK(!destroyed);
    shared.reset();
    BOOST_CHECK(destroyed);
}

BOOST_FIXTURE_TEST_CASE(block_finalized, TestChain100Setup) {
    uint32_t callCount = 0;
    const CBlockIndex *calledIndex;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals, nullptr, [&](const CBlockIndex *pindex) {
            callCount++;
            calledIndex = pindex;
        })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);

    for (size_t i = 0; i < 10; i++) {
        shared->CallBlockFinalized(nullptr);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);
    BOOST_CHECK_EQUAL(calledIndex, nullptr);

    CBlockIndex *tip = WITH_LOCK(m_node.chainman->GetMutex(),
                                 return m_node.chainman->ActiveTip());
    int tipHeight = WITH_LOCK(m_node.chainman->GetMutex(),
                              return m_node.chainman->ActiveHeight());

    // If pindex is null the following test is pointless
    BOOST_CHECK_NE(tip, nullptr);

    callCount = 0;
    CBlockIndex *pindex = tip;
    while (pindex) {
        shared->CallBlockFinalized(pindex);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(calledIndex, pindex);
        pindex = pindex->pprev;
    }

    // Make sure the test function was actually called
    BOOST_CHECK_EQUAL(callCount, tipHeight + 1);

    bilingual_str error;
    auto avalanche = avalanche::Processor::MakeProcessor(
        *m_node.args, *m_node.chain, m_node.connman.get(), *m_node.chainman,
        m_node.mempool.get(), *m_node.scheduler, error);

    // Check calling from AvalancheFinalizedBlock
    Chainstate &activeChainState = m_node.chainman->ActiveChainstate();

    callCount = 0;
    calledIndex = nullptr;
    {
        LOCK(::cs_main);
        BOOST_CHECK(
            !activeChainState.AvalancheFinalizeBlock(nullptr, *avalanche));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 0);
    BOOST_CHECK_EQUAL(calledIndex, nullptr);

    {
        LOCK(::cs_main);
        BOOST_CHECK(activeChainState.AvalancheFinalizeBlock(tip, *avalanche));
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 1);
    BOOST_CHECK_EQUAL(calledIndex, tip);

    // Successive calls won't call the validation again, because the block is
    // already finalized.
    for (size_t i = 0; i < 10; i++) {
        {
            LOCK(::cs_main);
            BOOST_CHECK(
                activeChainState.AvalancheFinalizeBlock(tip, *avalanche));
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, 1);
        BOOST_CHECK_EQUAL(calledIndex, tip);
    }
}

BOOST_FIXTURE_TEST_CASE(block_invalidated, TestChain100Setup) {
    uint32_t callCount = 0;
    const CBlockIndex *calledIndex;
    std::shared_ptr<const CBlock> calledBlock;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals, nullptr, nullptr,
        [&](const CBlockIndex *pindex,
            const std::shared_ptr<const CBlock> &block) {
            callCount++;
            calledIndex = pindex;
            calledBlock = block;
        })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);

    for (size_t i = 0; i < 10; i++) {
        shared->CallBlockInvalidated(nullptr, nullptr);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);
    BOOST_CHECK_EQUAL(calledIndex, nullptr);
    BOOST_CHECK_EQUAL(calledBlock, nullptr);

    callCount = 0;

    CBlockIndex index;
    for (size_t i = 0; i < 10; i++) {
        shared->CallBlockInvalidated(&index, nullptr);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);
    BOOST_CHECK_EQUAL(calledIndex, &index);
    BOOST_CHECK_EQUAL(calledBlock, nullptr);

    callCount = 0;

    auto block = std::make_shared<const CBlock>();
    for (size_t i = 0; i < 10; i++) {
        shared->CallBlockInvalidated(nullptr, block);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);
    BOOST_CHECK_EQUAL(calledIndex, nullptr);
    BOOST_CHECK_EQUAL(calledBlock, block);

    callCount = 0;

    for (size_t i = 0; i < 10; i++) {
        shared->CallBlockInvalidated(&index, block);
    }
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);
    BOOST_CHECK_EQUAL(calledIndex, &index);
    BOOST_CHECK_EQUAL(calledBlock, block);
}

BOOST_FIXTURE_TEST_CASE(transaction_added_to_mempool, TestChain100Setup) {
    uint32_t callCount{0};
    TxId calledTxId;
    std::shared_ptr<const std::vector<Coin>> calledSpentCoins;
    uint64_t calledMempoolSequence{0};
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals, nullptr, nullptr, nullptr,
        [&](const CTransactionRef &tx,
            std::shared_ptr<const std::vector<Coin>> spentCoins,
            uint64_t mempool_sequence) {
            callCount++;
            calledTxId = tx->GetId();
            calledSpentCoins = spentCoins;
            calledMempoolSequence = mempool_sequence;
        },
        nullptr, nullptr)};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    COutPoint outpoint{TxId(FastRandomContext().rand256()), 0};
    mtx.vin.emplace_back(outpoint);
    CScript scriptPubKey;
    for (size_t i = 0; i < 100; i++) {
        // Make sure the tx size is larger than 100 bytes
        scriptPubKey << OP_11;
    }
    mtx.vout.emplace_back(1 * COIN, scriptPubKey);

    auto &chainman = *Assert(m_node.chainman);
    Coin coin{mtx.vout[0], 100, false};
    const std::vector<Coin> coins({coin});
    auto spentCoins = std::make_shared<const std::vector<Coin>>(coins);

    {
        LOCK(cs_main);
        CCoinsViewCache &coinsViewCache =
            chainman.ActiveChainstate().CoinsTip();
        coinsViewCache.AddCoin(outpoint, coin, false);
    }

    {
        CTransactionRef tx = MakeTransactionRef(mtx);
        for (size_t i = 0; i < 10; i++) {
            shared->CallTransactionAddedToMempool(tx, spentCoins, i);
            m_node.validation_signals->SyncWithValidationInterfaceQueue();

            BOOST_CHECK_EQUAL(callCount, i + 1);
            BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
            BOOST_CHECK_EQUAL(calledMempoolSequence, i);
            BOOST_CHECK_EQUAL(calledSpentCoins->size(), 1);
            const Coin &calledCoin = (*calledSpentCoins)[0];
            BOOST_CHECK(calledCoin.GetTxOut() == coin.GetTxOut());
            BOOST_CHECK_EQUAL(calledCoin.GetHeight(), coin.GetHeight());
            BOOST_CHECK_EQUAL(calledCoin.IsCoinBase(), coin.IsCoinBase());
        }
    }

    callCount = 0;
    calledTxId = TxId();
    calledMempoolSequence = 0;

    for (size_t i = 0; i < 10; i++) {
        COutPoint _outpoint{TxId(FastRandomContext().rand256()), 0};
        mtx.vin[0] = CTxIn(_outpoint);
        CTransactionRef tx = MakeTransactionRef(mtx);

        {
            LOCK(cs_main);
            CCoinsViewCache &coinsViewCache =
                chainman.ActiveChainstate().CoinsTip();
            coinsViewCache.AddCoin(_outpoint, coin, false);
        }
        calledSpentCoins.reset();
        shared->CallTransactionAddedToMempool(tx, spentCoins, 100 + i);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();

        BOOST_CHECK_EQUAL(callCount, i + 1);
        BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
        BOOST_CHECK_EQUAL(calledMempoolSequence, 100 + i);
        BOOST_CHECK_EQUAL(calledSpentCoins->size(), 1);
        const Coin &calledCoin = (*calledSpentCoins)[0];
        BOOST_CHECK(calledCoin.GetTxOut() == coin.GetTxOut());
        BOOST_CHECK_EQUAL(calledCoin.GetHeight(), coin.GetHeight());
        BOOST_CHECK_EQUAL(calledCoin.IsCoinBase(), coin.IsCoinBase());
    }

    callCount = 0;
    calledTxId = TxId();
    calledSpentCoins = spentCoins;
    calledMempoolSequence = 0;

    {
        CTransactionRef tx = MakeTransactionRef(mtx);
        for (size_t i = 0; i < 10; i++) {
            shared->CallTransactionAddedToMempool(tx, nullptr, 200 + i);
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            BOOST_CHECK_EQUAL(callCount, i + 1);
            BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
            BOOST_CHECK_EQUAL(calledMempoolSequence, 200 + i);
            BOOST_CHECK(!calledSpentCoins);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(transaction_finalized, TestChain100Setup) {
    uint32_t callCount = 0;
    std::vector<TxId> calledTxIds;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals, nullptr, nullptr, nullptr, nullptr,
        [&](const CTransactionRef &tx) {
            callCount++;
            calledTxIds.push_back(tx->GetId());
        })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint{TxId(FastRandomContext().rand256()), 0});
    CScript scriptPubKey;
    for (size_t i = 0; i < 100; i++) {
        // Make sure the tx size is larger than 100 bytes
        scriptPubKey << OP_11;
    }
    mtx.vout.emplace_back(1 * COIN, scriptPubKey);

    {
        CTransactionRef tx = MakeTransactionRef(mtx);
        for (size_t i = 0; i < 10; i++) {
            shared->CallTransactionFinalized(tx);
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, 10);
        BOOST_CHECK_EQUAL(calledTxIds[9], tx->GetId());
    }

    callCount = 0;
    calledTxIds.clear();

    for (size_t i = 0; i < 10; i++) {
        mtx.vin[0] = CTxIn(COutPoint{TxId(FastRandomContext().rand256()), 0});
        CTransactionRef tx = MakeTransactionRef(mtx);

        shared->CallTransactionFinalized(tx);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();

        BOOST_CHECK_EQUAL(callCount, i + 1);
        BOOST_CHECK_EQUAL(calledTxIds[i], tx->GetId());
    }

    callCount = 0;
    calledTxIds.clear();

    bilingual_str error;
    auto avalanche = avalanche::Processor::MakeProcessor(
        *m_node.args, *m_node.chain, m_node.connman.get(), *m_node.chainman,
        m_node.mempool.get(), *m_node.scheduler, error);

    TestMemPoolEntryHelper entryHelper;

    for (size_t i = 0; i < 10; i++) {
        mtx.vin[0] = CTxIn(COutPoint{TxId(FastRandomContext().rand256()), 0});
        CTransactionRef tx = MakeTransactionRef(mtx);

        auto entry = entryHelper.Fee(1000 * SATOSHI).FromTx(tx);

        std::vector<TxId> finalizedTxIds;
        {
            LOCK2(::cs_main, m_node.mempool->cs);
            m_node.mempool->addUnchecked(entry);
            BOOST_CHECK(m_node.mempool->setAvalancheFinalized(
                entry, m_node.chainman->GetConsensus(),
                *m_node.chainman->ActiveChain().Tip(),
                m_node.chainman->ActiveChainstate(), finalizedTxIds));
        }
        BOOST_CHECK_EQUAL(finalizedTxIds.size(), 1);
        BOOST_CHECK_EQUAL(finalizedTxIds[0], tx->GetId());

        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, i + 1);
        BOOST_CHECK_EQUAL(calledTxIds[i], tx->GetId());

        // Successive calls won't call the validation again, because the
        // transaction is already finalized.
        finalizedTxIds.clear();
        {
            LOCK2(::cs_main, m_node.mempool->cs);
            BOOST_CHECK(m_node.mempool->setAvalancheFinalized(
                entry, m_node.chainman->GetConsensus(),
                *m_node.chainman->ActiveChain().Tip(),
                m_node.chainman->ActiveChainstate(), finalizedTxIds));
        }
        BOOST_CHECK_EQUAL(finalizedTxIds.size(), 0);

        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, i + 1);
        BOOST_CHECK_EQUAL(calledTxIds[i], tx->GetId());
    }

    // Chained txs: if the child finalizes, the parents notifications are fired
    // as well
    callCount = 0;
    calledTxIds.clear();
    TxId lastTxId(FastRandomContext().rand256());
    CTxMemPoolEntryRef last_entry;
    std::vector<TxId> expectedTxIds;
    for (size_t i = 0; i < 10; i++) {
        CMutableTransaction chained_mtx;
        chained_mtx.nVersion = 2;
        chained_mtx.vin.emplace_back(COutPoint{lastTxId, 0});
        chained_mtx.vout.emplace_back(1 * COIN, scriptPubKey);
        lastTxId = chained_mtx.GetId();
        expectedTxIds.push_back(lastTxId);

        CTransactionRef tx = MakeTransactionRef(chained_mtx);
        last_entry = entryHelper.Fee(int64_t(1000 + i) * SATOSHI).FromTx(tx);
        {
            LOCK2(::cs_main, m_node.mempool->cs);
            m_node.mempool->addUnchecked(last_entry);
        }
    }
    std::vector<TxId> finalizedTxIds;
    {
        LOCK2(::cs_main, m_node.mempool->cs);
        BOOST_CHECK(m_node.mempool->setAvalancheFinalized(
            last_entry, m_node.chainman->GetConsensus(),
            *m_node.chainman->ActiveChain().Tip(),
            m_node.chainman->ActiveChainstate(), finalizedTxIds));
    }
    BOOST_CHECK_EQUAL(finalizedTxIds.size(), 10);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(callCount, 10);

    // Check that all the txids finalization callbacks were called. Ordering is
    // not important so we sort the vectors first.
    std::sort(finalizedTxIds.begin(), finalizedTxIds.end());
    std::sort(calledTxIds.begin(), calledTxIds.end());
    std::sort(expectedTxIds.begin(), expectedTxIds.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(finalizedTxIds.begin(), finalizedTxIds.end(),
                                  calledTxIds.begin(), calledTxIds.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(calledTxIds.begin(), calledTxIds.end(),
                                  expectedTxIds.begin(), expectedTxIds.end());
}

BOOST_FIXTURE_TEST_CASE(transaction_invalidated, TestChain100Setup) {
    uint32_t callCount = 0;
    TxId calledTxId;
    std::shared_ptr<const std::vector<Coin>> calledSpentCoins;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals, nullptr, nullptr, nullptr, nullptr, nullptr,
        [&](const CTransactionRef &tx,
            std::shared_ptr<const std::vector<Coin>> spentCoins) {
            callCount++;
            calledTxId = tx->GetId();
            calledSpentCoins = spentCoins;
        })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    COutPoint outpoint{TxId(FastRandomContext().rand256()), 0};
    mtx.vin.emplace_back(outpoint);
    CScript scriptPubKey;
    for (size_t i = 0; i < 100; i++) {
        // Make sure the tx size is larger than 100 bytes
        scriptPubKey << OP_11;
    }
    mtx.vout.emplace_back(1 * COIN, scriptPubKey);

    auto &chainman = *Assert(m_node.chainman);
    Coin coin{mtx.vout[0], 100, false};
    const std::vector<Coin> coins({coin});
    auto spentCoins = std::make_shared<const std::vector<Coin>>(coins);

    {
        LOCK(cs_main);
        CCoinsViewCache &coinsViewCache =
            chainman.ActiveChainstate().CoinsTip();
        coinsViewCache.AddCoin(outpoint, coin, false);
    }

    {
        CTransactionRef tx = MakeTransactionRef(mtx);
        for (size_t i = 0; i < 10; i++) {
            shared->CallTransactionInvalidated(tx, spentCoins);
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, 10);
        BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
        BOOST_CHECK_EQUAL(calledSpentCoins->size(), 1);
        const Coin &calledCoin = (*calledSpentCoins)[0];
        BOOST_CHECK(calledCoin.GetTxOut() == coin.GetTxOut());
        BOOST_CHECK_EQUAL(calledCoin.GetHeight(), coin.GetHeight());
        BOOST_CHECK_EQUAL(calledCoin.IsCoinBase(), coin.IsCoinBase());
    }

    callCount = 0;
    calledTxId = TxId();

    for (size_t i = 0; i < 10; i++) {
        COutPoint _outpoint{TxId(FastRandomContext().rand256()), 0};
        mtx.vin[0] = CTxIn(_outpoint);
        CTransactionRef tx = MakeTransactionRef(mtx);

        {
            LOCK(cs_main);
            CCoinsViewCache &coinsViewCache =
                chainman.ActiveChainstate().CoinsTip();
            coinsViewCache.AddCoin(_outpoint, coin, false);
        }
        calledSpentCoins.reset();
        shared->CallTransactionInvalidated(tx, spentCoins);
        m_node.validation_signals->SyncWithValidationInterfaceQueue();

        BOOST_CHECK_EQUAL(callCount, i + 1);
        BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
        BOOST_CHECK_EQUAL(calledSpentCoins->size(), 1);
        const Coin &calledCoin = (*calledSpentCoins)[0];
        BOOST_CHECK(calledCoin.GetTxOut() == coin.GetTxOut());
        BOOST_CHECK_EQUAL(calledCoin.GetHeight(), coin.GetHeight());
        BOOST_CHECK_EQUAL(calledCoin.IsCoinBase(), coin.IsCoinBase());
    }

    callCount = 0;
    calledTxId = TxId();
    calledSpentCoins = spentCoins;

    {
        CTransactionRef tx = MakeTransactionRef(mtx);
        for (size_t i = 0; i < 10; i++) {
            shared->CallTransactionInvalidated(tx, nullptr);
        }
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
        BOOST_CHECK_EQUAL(callCount, 10);
        BOOST_CHECK_EQUAL(calledTxId, tx->GetId());
        BOOST_CHECK(!calledSpentCoins);
    }
}


// A subscriber with an independently scheduled FIFO, like Chronik. Latches
// establish ordering: no timing delay is used to infer that the fence blocked.
class SecondaryQueueSubscriber final : public CValidationInterface {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::function<void()>> queue;
    bool stopping{false};
    std::thread worker;

    void Enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            queue.push_back(std::move(task));
        }
        ready.notify_one();
    }

public:
    std::promise<void> release_indexing;
    std::future<void> release{release_indexing.get_future()};
    std::atomic<bool> indexed{false};
    std::mutex observation_mutex;
    std::condition_variable observation;
    bool fence_entered{false};
    bool sync_returned{false};

    SecondaryQueueSubscriber() : worker([this] {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex);
                ready.wait(lock, [&] { return stopping || !queue.empty(); });
                if (queue.empty()) return;
                task = std::move(queue.front());
                queue.pop_front();
            }
            task();
        }
    }) {}

    ~SecondaryQueueSubscriber() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
        }
        ready.notify_one();
        worker.join();
    }

    void TransactionFinalized(const CTransactionRef &) override {
        Enqueue([this] {
            release.wait();
            indexed = true;
        });
    }

    void SyncTransactionQueue() override {
        auto promise = std::make_shared<std::promise<void>>();
        auto completed = promise->get_future();
        Enqueue([promise] { promise->set_value(); });
        {
            std::lock_guard<std::mutex> lock(observation_mutex);
            fence_entered = true;
        }
        observation.notify_one();
        completed.wait();
    }
};

static void CheckSecondaryQueueFence(bool flush) {
    ValidationSignals signals(std::make_unique<util::ImmediateTaskRunner>());
    auto subscriber = std::make_shared<SecondaryQueueSubscriber>();
    signals.RegisterSharedValidationInterface(subscriber);
    signals.TransactionFinalized(MakeTransactionRef());
    auto sync = std::async(std::launch::async, [&] {
        if (flush) signals.FlushBackgroundCallbacks();
        else signals.SyncWithValidationInterfaceQueue();
        {
            std::lock_guard<std::mutex> lock(subscriber->observation_mutex);
            subscriber->sync_returned = true;
        }
        subscriber->observation.notify_one();
    });
    {
        std::unique_lock<std::mutex> lock(subscriber->observation_mutex);
        // Without the hook, sync_returned wakes us and both assertions fail;
        // the regression never hangs waiting for an absent hook.
        subscriber->observation.wait(lock, [&] {
            return subscriber->fence_entered || subscriber->sync_returned;
        });
        BOOST_CHECK(subscriber->fence_entered);
        BOOST_CHECK(!subscriber->sync_returned);
        BOOST_CHECK(!subscriber->indexed);
    }
    subscriber->release_indexing.set_value();
    sync.get();
    BOOST_CHECK(subscriber->indexed);
    signals.UnregisterAllValidationInterfaces();
}

BOOST_AUTO_TEST_CASE(flush_waits_for_secondary_queue) {
    CheckSecondaryQueueFence(true);
}

BOOST_AUTO_TEST_CASE(sync_waits_for_secondary_queue) {
    CheckSecondaryQueueFence(false);
}

BOOST_AUTO_TEST_CASE(bounded_worker_overflow_keeps_scheduler_responsive) {
    using namespace std::chrono_literals;
    std::atomic<unsigned> fatal{0};
    std::promise<void> started, release;
    auto released = release.get_future().share();
    std::vector<unsigned> order;
    BoundedTaskQueue queue(300, 3, [&] { ++fatal; });
    BOOST_REQUIRE(queue.Enqueue(100, [&] {
        started.set_value();
        released.wait();
        order.push_back(1);
    }));
    started.get_future().wait();
    BOOST_REQUIRE(queue.Enqueue(100, [&] { order.push_back(2); }));
    BOOST_REQUIRE(queue.Enqueue(100, [&] { order.push_back(3); }));
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 300);
    auto scheduler = std::async(std::launch::async, [&] {
        return queue.Enqueue(1, [] {});
    });
    const bool responsive = scheduler.wait_for(100ms) == std::future_status::ready;
    // Release even on failure, so a failing old implementation cannot hang the suite.
    if (!responsive) release.set_value();
    BOOST_CHECK(responsive);
    BOOST_CHECK(!scheduler.get());
    BOOST_CHECK_EQUAL(fatal.load(), 1);
    BOOST_CHECK(!queue.Enqueue(1, [] {}));
    auto fence = std::async(std::launch::async, [&] { queue.Sync(); });
    if (responsive) {
        BOOST_CHECK(fence.wait_for(50ms) == std::future_status::timeout);
        release.set_value();
    }
    BOOST_REQUIRE(fence.wait_for(1s) == std::future_status::ready);
    const std::vector<unsigned> expected{1, 2, 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(), expected.end());
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 0);
    queue.Stop();
    BoundedTaskQueue oversized(8, 3, [&] { ++fatal; });
    BOOST_CHECK(!oversized.Enqueue(9, [] {}));
    BOOST_CHECK_EQUAL(oversized.BytesRetained(), 0);
    oversized.Stop();
    BOOST_CHECK_EQUAL(fatal.load(), 2);
    BoundedTaskQueue reentrant(8, 3, [&] { ++fatal; });
    BOOST_REQUIRE(reentrant.Enqueue(1, [&] { reentrant.Sync(); }));
    reentrant.Sync();
    reentrant.Stop();
}

BOOST_AUTO_TEST_CASE(bounded_worker_exception_is_fatal_and_drains_accepted_work) {
    std::atomic<unsigned> fatal{0}, completed{0};
    std::promise<void> started, release;
    auto released = release.get_future().share();
    BoundedTaskQueue queue(10, 10, [&] { ++fatal; });
    BOOST_REQUIRE(queue.Enqueue(1, [&] {
        started.set_value();
        released.wait();
        throw std::runtime_error("injected indexer failure");
    }));
    started.get_future().wait();
    BOOST_REQUIRE(queue.Enqueue(1, [&] { ++completed; }));
    release.set_value();
    queue.Sync();
    BOOST_CHECK_EQUAL(fatal.load(), 1);
    BOOST_CHECK_EQUAL(completed.load(), 1);
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 0);
    BOOST_CHECK(!queue.Enqueue(1, [] {}));
    queue.Stop();
}

BOOST_AUTO_TEST_CASE(bounded_worker_block_policy_waits_for_space) {
    using namespace std::chrono_literals;
    std::atomic<unsigned> fatal{0};
    std::promise<void> started, release;
    auto released = release.get_future().share();
    std::mutex order_mutex;
    std::vector<unsigned> order;
    auto record = [&](unsigned value) {
        std::lock_guard<std::mutex> lock(order_mutex);
        order.push_back(value);
    };
    BoundedTaskQueue queue(
        1000, 2, [&] { ++fatal; }, BoundedTaskQueue::Overflow::BLOCK);
    BOOST_REQUIRE(queue.Enqueue(1, [&] {
        started.set_value();
        released.wait();
        record(1);
    }));
    started.get_future().wait();
    BOOST_REQUIRE(queue.Enqueue(1, [&] { record(2); }));
    auto producer = std::async(std::launch::async, [&] {
        return queue.Enqueue(1, [&] { record(3); });
    });
    const bool blocked = producer.wait_for(50ms) == std::future_status::timeout;
    release.set_value();
    BOOST_CHECK(blocked);
    BOOST_REQUIRE(producer.wait_for(10s) == std::future_status::ready);
    BOOST_CHECK(producer.get());
    queue.Sync();
    const std::vector<unsigned> expected{1, 2, 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(order.begin(), order.end(), expected.begin(),
                                  expected.end());
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 0);
    BOOST_CHECK_EQUAL(fatal.load(), 0);
    queue.Stop();
}

BOOST_AUTO_TEST_CASE(bounded_worker_block_policy_admits_oversized_when_empty) {
    using namespace std::chrono_literals;
    std::atomic<unsigned> fatal{0}, completed{0};
    std::promise<void> started, release;
    auto released = release.get_future().share();
    BoundedTaskQueue queue(
        8, 10, [&] { ++fatal; }, BoundedTaskQueue::Overflow::BLOCK);
    auto oversized = std::async(std::launch::async, [&] {
        return queue.Enqueue(9, [&] {
            started.set_value();
            released.wait();
            ++completed;
        });
    });
    BOOST_REQUIRE(oversized.wait_for(10s) == std::future_status::ready);
    BOOST_CHECK(oversized.get());
    started.get_future().wait();
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 9);
    auto small = std::async(std::launch::async, [&] {
        return queue.Enqueue(1, [&] { ++completed; });
    });
    const bool blocked = small.wait_for(50ms) == std::future_status::timeout;
    release.set_value();
    BOOST_CHECK(blocked);
    BOOST_REQUIRE(small.wait_for(10s) == std::future_status::ready);
    BOOST_CHECK(small.get());
    queue.Sync();
    BOOST_CHECK_EQUAL(completed.load(), 2);
    BOOST_CHECK_EQUAL(queue.BytesRetained(), 0);
    BOOST_CHECK_EQUAL(fatal.load(), 0);
    queue.Stop();
}

BOOST_AUTO_TEST_CASE(bounded_worker_block_policy_stop_releases_producer) {
    using namespace std::chrono_literals;
    std::atomic<unsigned> fatal{0}, completed{0};
    std::promise<void> started, release;
    auto released = release.get_future().share();
    BoundedTaskQueue queue(
        1000, 2, [&] { ++fatal; }, BoundedTaskQueue::Overflow::BLOCK);
    BOOST_REQUIRE(queue.Enqueue(1, [&] {
        started.set_value();
        released.wait();
        ++completed;
    }));
    started.get_future().wait();
    BOOST_REQUIRE(queue.Enqueue(1, [&] { ++completed; }));
    bool late_ran = false;
    auto producer = std::async(std::launch::async, [&] {
        return queue.Enqueue(1, [&] { late_ran = true; });
    });
    BOOST_CHECK(producer.wait_for(50ms) == std::future_status::timeout);
    // Stop() joins the worker, which is still held: run it on a helper.
    auto stopper = std::async(std::launch::async, [&] { queue.Stop(); });
    BOOST_REQUIRE(producer.wait_for(10s) == std::future_status::ready);
    BOOST_CHECK(!producer.get());
    release.set_value();
    BOOST_REQUIRE(stopper.wait_for(10s) == std::future_status::ready);
    stopper.get();
    // Accepted tasks still ran; the rejected one did not.
    BOOST_CHECK_EQUAL(completed.load(), 2);
    BOOST_CHECK(!late_ran);
    BOOST_CHECK(!queue.Enqueue(1, [] {}));
    BOOST_CHECK_EQUAL(fatal.load(), 0);
}

BOOST_AUTO_TEST_CASE(bounded_worker_block_policy_names_its_thread) {
    BoundedTaskQueue queue(
        10, 10, [] {}, BoundedTaskQueue::Overflow::BLOCK, "walletnotify");
    std::string name;
    BOOST_REQUIRE(
        queue.Enqueue(1, [&] { name = util::ThreadGetInternalName(); }));
    queue.Sync();
    BOOST_CHECK_EQUAL(name, "walletnotify");
    queue.Stop();
}

/** Forwards mempool additions to its own worker queue, which a test holds. */
struct MempoolSecondaryQueueSubscriber final : public CValidationInterface {
    std::promise<void> release_indexing;
    std::shared_future<void> release{release_indexing.get_future().share()};
    std::atomic<bool> indexed{false};
    BoundedTaskQueue queue{1 << 20, 1024, [] {}};

    using CValidationInterface::TransactionAddedToMempool;
    void TransactionAddedToMempool(const CTransactionRef &,
                                   std::shared_ptr<const std::vector<Coin>>,
                                   uint64_t) override {
        queue.Enqueue(1, [this] {
            release.wait();
            indexed = true;
        });
    }
    void SyncTransactionQueue() override { queue.Sync(); }
};

BOOST_FIXTURE_TEST_CASE(broadcast_wait_fences_secondary_queue,
                        TestChain100Setup) {
    using namespace std::chrono_literals;
    auto subscriber = std::make_shared<MempoolSecondaryQueueSubscriber>();
    m_node.validation_signals->RegisterSharedValidationInterface(subscriber);
    const auto spend = MakeTransactionRef(CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey,
        GetScriptForRawPubKey(coinbaseKey.GetPubKey()),
        m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI,
        /*submit=*/false));
    auto broadcast = std::async(std::launch::async, [&] {
        std::string err;
        return node::BroadcastTransaction(m_node, spend, err, Amount::zero(),
                                          /*relay=*/false,
                                          /*wait_callback=*/true);
    });
    // The main queue drains at once; the held worker queue does not.
    const bool waited =
        broadcast.wait_for(100ms) == std::future_status::timeout;
    subscriber->release_indexing.set_value();
    BOOST_CHECK(waited);
    BOOST_REQUIRE(broadcast.wait_for(60s) == std::future_status::ready);
    BOOST_CHECK(broadcast.get() == node::TransactionError::OK);
    // Returned only after the worker had applied the event.
    BOOST_CHECK(subscriber->indexed);
    m_node.validation_signals->UnregisterSharedValidationInterface(subscriber);
}

namespace {
/** Records Chain::Notifications in the order they arrive. */
struct RecordingNotifications final : public interfaces::Chain::Notifications {
    std::mutex mutex;
    std::vector<std::string> events;
    //! Called with the height before a blockConnected is recorded.
    std::function<void(int)> on_block_connected;

    void Record(std::string event) {
        std::lock_guard<std::mutex> lock(mutex);
        events.push_back(std::move(event));
    }
    std::vector<std::string> Events() {
        std::lock_guard<std::mutex> lock(mutex);
        return events;
    }
    void transactionAddedToMempool(const CTransactionRef &tx,
                                   uint64_t) override {
        Record("added " + tx->GetId().ToString());
    }
    void transactionRemovedFromMempool(const CTransactionRef &tx,
                                       MemPoolRemovalReason reason,
                                       uint64_t) override {
        Record("removed " + tx->GetId().ToString() + " " +
               RemovalReasonToString(reason));
    }
    void blockConnected(ChainstateRole, const CBlock &block,
                        int height) override {
        if (on_block_connected) {
            on_block_connected(height);
        }
        Record(
            strprintf("connected %d %s", height, block.GetHash().ToString()));
    }
    void blockDisconnected(const CBlock &block, int height) override {
        Record(strprintf("disconnected %d %s", height,
                         block.GetHash().ToString()));
    }
    void updatedBlockTip() override { Record("tip"); }
    void chainStateFlushed(ChainstateRole, const CBlockLocator &) override {
        Record("flushed");
    }
};

/** Main-queue-only fence: does not wait for subscribers' worker queues. */
bool MainQueueDrains(ValidationSignals &signals) {
    using namespace std::chrono_literals;
    auto promise = std::make_shared<std::promise<void>>();
    auto drained = promise->get_future();
    signals.CallFunctionInValidationInterfaceQueue(
        [promise] { promise->set_value(); });
    return drained.wait_for(60s) == std::future_status::ready;
}

size_t CountPrefix(const std::vector<std::string> &events,
                   const std::string &prefix) {
    return std::count_if(events.begin(), events.end(), [&](const auto &e) {
        return e.rfind(prefix, 0) == 0;
    });
}

constexpr auto DEDICATED_WORKER =
    interfaces::Chain::NotificationDelivery::DEDICATED_WORKER;
} // namespace

BOOST_FIXTURE_TEST_CASE(async_notifications_offload_scheduler,
                        TestChain100Setup) {
    // Fixture callbacks predate this subscriber and its causal event oracle.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    using namespace std::chrono_literals;
    std::promise<void> release;
    auto released = release.get_future().share();
    auto fake = std::make_shared<RecordingNotifications>();
    fake->on_block_connected = [released](int) { released.wait(); };
    auto handler = m_node.chain->handleNotifications(fake, DEDICATED_WORKER);
    const int start =
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());

    mineBlocks(3);
    // The scheduler is not held by the blocked subscriber...
    const bool offloaded = MainQueueDrains(*m_node.validation_signals);
    // ...but the full fence still waits for it.
    auto sync = std::async(std::launch::async, [&] {
        m_node.validation_signals->SyncWithValidationInterfaceQueue();
    });
    const bool fenced = sync.wait_for(100ms) == std::future_status::timeout;
    release.set_value();
    BOOST_CHECK(offloaded);
    BOOST_CHECK(fenced);
    BOOST_REQUIRE(sync.wait_for(60s) == std::future_status::ready);
    sync.get();

    std::vector<int> heights;
    size_t last_connected = 0, last_tip = 0;
    const auto events = fake->Events();
    for (size_t i = 0; i < events.size(); ++i) {
        int height;
        if (sscanf(events[i].c_str(), "connected %d", &height) == 1) {
            heights.push_back(height);
            last_connected = i;
        } else if (events[i] == "tip") {
            last_tip = i;
        }
    }
    const std::vector<int> expected{start + 1, start + 2, start + 3};
    BOOST_CHECK_EQUAL_COLLECTIONS(heights.begin(), heights.end(),
                                  expected.begin(), expected.end());
    BOOST_CHECK_GT(last_tip, last_connected);
    handler.reset();
}

BOOST_FIXTURE_TEST_CASE(async_notifications_preserve_order_across_reorg,
                        TestChain100Setup) {
    // Fixture callbacks predate this subscriber and its causal event oracle.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    auto async_fake = std::make_shared<RecordingNotifications>();
    auto sync_fake = std::make_shared<RecordingNotifications>();
    auto async_handler =
        m_node.chain->handleNotifications(async_fake, DEDICATED_WORKER);
    auto sync_handler = m_node.chain->handleNotifications(sync_fake);

    const CScript spk = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    // A mempool transaction, then a block that confirms it.
    const auto mtx = CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, 1, coinbaseKey, spk,
        m_coinbase_txns[0]->vout[0].nValue - 2000 * SATOSHI);
    // Its child stays in the mempool after the block.
    const auto child = CreateValidMempoolTransaction(
        MakeTransactionRef(mtx), 0, 101, coinbaseKey, spk,
        m_coinbase_txns[0]->vout[0].nValue - 4000 * SATOSHI);
    CreateAndProcessBlock({mtx}, spk);
    mineBlocks(1);
    // Reorg: disconnect both blocks, then mine a longer empty branch.
    {
        BlockValidationState state;
        CBlockIndex *fork = WITH_LOCK(
            cs_main,
            return m_node.chainman
                ->ActiveChain()[m_node.chainman->ActiveChain().Height() - 1]);
        BOOST_REQUIRE(
            m_node.chainman->ActiveChainstate().InvalidateBlock(state, fork));
    }
    mineBlocks(3);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    const auto async_events = async_fake->Events();
    const auto sync_events = sync_fake->Events();
    BOOST_CHECK_EQUAL_COLLECTIONS(async_events.begin(), async_events.end(),
                                  sync_events.begin(), sync_events.end());
    // The sequence covers every kind of event.
    BOOST_CHECK_GE(CountPrefix(sync_events, "added "), 2U);
    BOOST_CHECK_GE(CountPrefix(sync_events, "disconnected "), 2U);
    BOOST_CHECK_GE(CountPrefix(sync_events, "connected "), 5U);
    BOOST_CHECK_GE(CountPrefix(sync_events, "tip"), 1U);
    async_handler.reset();
    sync_handler.reset();
}

BOOST_FIXTURE_TEST_CASE(async_notifications_disconnect_drains,
                        TestChain100Setup) {
    // Fixture callbacks predate this subscriber and its causal event oracle.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    using namespace std::chrono_literals;
    std::promise<void> release;
    auto released = release.get_future().share();
    auto fake = std::make_shared<RecordingNotifications>();
    fake->on_block_connected = [released](int) { released.wait(); };
    auto handler = m_node.chain->handleNotifications(fake, DEDICATED_WORKER);
    auto control = std::make_shared<RecordingNotifications>();
    auto control_handler = m_node.chain->handleNotifications(control);

    // Five blocks queue at least ten events behind the held worker.
    mineBlocks(5);
    BOOST_REQUIRE(MainQueueDrains(*m_node.validation_signals));
    const size_t queued = control->Events().size();
    BOOST_CHECK_GE(queued, 10U);
    BOOST_CHECK(fake->Events().empty());

    auto disconnect = std::async(std::launch::async, [&] { handler.reset(); });
    const bool drained_first =
        disconnect.wait_for(100ms) == std::future_status::timeout;
    release.set_value();
    BOOST_CHECK(drained_first);
    BOOST_REQUIRE(disconnect.wait_for(60s) == std::future_status::ready);
    disconnect.get();
    // Every event accepted before disconnect ran, in order.
    BOOST_CHECK(fake->Events() == control->Events());

    // Events generated after the disconnect are not delivered.
    mineBlocks(1);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(fake->Events().size(), queued);
    BOOST_CHECK_GT(control->Events().size(), queued);
    control_handler.reset();
}

BOOST_FIXTURE_TEST_CASE(async_notifications_worker_exception_discards_rest,
                        TestChain100Setup) {
    ASSERT_DEBUG_LOG("Wallet notification callback exception: injected wallet failure");
    // Fixture mining may still have callbacks queued. They predate both
    // subscribers and must not enter the three-block causal event oracle.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    std::promise<void> release;
    auto released = release.get_future().share();
    auto fake = std::make_shared<RecordingNotifications>();
    const int start =
        WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Height());
    fake->on_block_connected = [released, start](int height) {
        released.wait();
        if (height == start + 2) {
            throw std::runtime_error("injected wallet failure");
        }
    };
    auto handler = m_node.chain->handleNotifications(fake, DEDICATED_WORKER);
    auto control = std::make_shared<RecordingNotifications>();
    auto control_handler = m_node.chain->handleNotifications(control);

    // Queue everything first, so the failure cannot affect generation.
    mineBlocks(3);
    m_node.chainman->ActiveChainstate().ForceFlushStateToDisk();
    BOOST_REQUIRE(MainQueueDrains(*m_node.validation_signals));
    BOOST_CHECK(!ShutdownRequested());

    release.set_value();
    // The fence still completes: discarded callbacks count as completed.
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK(ShutdownRequested());

    // The subscriber saw exactly the events before the failing callback.
    const auto all = control->Events();
    const auto failed_at =
        std::find_if(all.begin(), all.end(), [&](const std::string &e) {
            return e.rfind(strprintf("connected %d ", start + 2), 0) == 0;
        });
    BOOST_REQUIRE(failed_at != all.end());
    const std::vector<std::string> before(all.begin(), failed_at);
    const std::vector<std::string> after(failed_at, all.end());
    BOOST_CHECK(fake->Events() == before);
    BOOST_CHECK_EQUAL(CountPrefix(before, "connected "), 1U);
    // Neither the third block nor the later flush reached the subscriber.
    BOOST_CHECK_EQUAL(CountPrefix(after, "connected "), 2U);
    BOOST_CHECK_GE(CountPrefix(after, "flushed"), 1U);
    handler.reset();
    control_handler.reset();
    AbortShutdown();
}

BOOST_AUTO_TEST_CASE(queued_payload_charges_retained_shared_ownership) {
    auto tx = MakeTransactionRef();
    const size_t control = sizeof(memusage::stl_shared_counter);
    BOOST_CHECK_GE(validation_queue::TxBytes(tx),
                   sizeof(CTransaction) + RecursiveDynamicUsage(*tx) + control);
    auto block = std::make_shared<CBlock>();
    block->vtx = {tx, MakeTransactionRef()};
    size_t minimum = sizeof(CBlock) + control + block->vtx.capacity() * sizeof(CTransactionRef);
    for (const auto &item : block->vtx)
        minimum += sizeof(CTransaction) + RecursiveDynamicUsage(*item) + control;
    BOOST_CHECK_GE(validation_queue::BlockBytes(block), minimum);
    auto coins = std::make_shared<std::vector<Coin>>(1);
    BOOST_CHECK_GE(validation_queue::CoinBytes(coins),
                   sizeof(*coins) + control + coins->capacity() * sizeof(Coin));
}

BOOST_AUTO_TEST_SUITE_END()
