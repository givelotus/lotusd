// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/processor.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <scheduler.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <util/bounded_task_queue.h>
#include <util/threadnames.h>
#include <util/validation_queue_memory.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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
